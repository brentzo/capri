"""Android APK validation, inventory, and private range transfer."""
import hashlib
import os
import re
import xml.etree.ElementTree as ET

from harness.sandbox.base import SandboxError
from harness.mobile.code_analysis import assess_apk

ANDROID = "http://schemas.android.com/apk/res/android"
APK_IN_ATTACKER = "/tmp/hc-mobile.apk"


class MobileError(SandboxError):
    """An APK could not be inventoried or the managed Android device failed."""


def _int(node, attribute):
    """An integer manifest attribute, or None when absent or not a plain number."""
    value = node.get(f"{{{ANDROID}}}{attribute}") if node is not None else None
    return int(value) if value is not None and value.isdigit() else None


def _flag(node, attribute, default):
    value = node.get(f"{{{ANDROID}}}{attribute}")
    return default if value is None else value.lower() == "true"


def _effective_export(tag, declared, has_filter, target_sdk):
    """Whether other apps can reach a component, by Android's rules for the target SDK.

    An explicit value wins. Providers defaulted to exported only below SDK 17. An intent
    filter implies export below SDK 31; from 31 the attribute is mandatory, so a missing
    value is undecidable (None) and reported rather than guessed."""
    if declared is not None:
        return declared
    if tag == "provider":
        return target_sdk is not None and target_sdk < 17
    if has_filter:
        return True if target_sdk is None or target_sdk < 31 else None
    return False


def inventory_manifest(xml_text):
    """Return package/components/deep links from apkanalyzer's decoded manifest XML."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise MobileError("Android manifest is malformed") from exc
    package = root.get("package", "")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", package):
        raise MobileError("Android manifest has no valid package name")

    components, links = [], []
    app = root.find("application")
    if app is None:
        raise MobileError("Android manifest has no application element")
    uses_sdk = root.find("uses-sdk")
    sdk = {"min": _int(uses_sdk, "minSdkVersion"), "target": _int(uses_sdk, "targetSdkVersion")}
    for node in app:
        if node.tag not in {"activity", "activity-alias", "service", "receiver", "provider"}:
            continue
        name = node.get(f"{{{ANDROID}}}name", "")
        if not name:
            continue
        if name.startswith("."):
            name = package + name
        elif "." not in name:
            name = package + "." + name
        exported_text = node.get(f"{{{ANDROID}}}exported")
        declared = (exported_text.lower() == "true") if exported_text is not None else None
        has_filter = node.find("intent-filter") is not None
        component = {"name": name, "type": node.tag,
                     "exported": _effective_export(node.tag, declared, has_filter, sdk["target"]),
                     "exported_declared": declared,
                     "permission": node.get(f"{{{ANDROID}}}permission"),
                     "has_intent_filter": has_filter}
        if node.tag == "provider":
            component.update(
                authorities=[value for value in node.get(f"{{{ANDROID}}}authorities", "").split(";")
                             if value],
                grant_uri_permissions=_flag(node, "grantUriPermissions", False),
                read_permission=node.get(f"{{{ANDROID}}}readPermission"),
                write_permission=node.get(f"{{{ANDROID}}}writePermission"))
        components.append(component)
        if node.tag not in ("activity", "activity-alias"):
            continue
        for filter_index, intent_filter in enumerate(node.findall("intent-filter")):
            actions = {a.get(f"{{{ANDROID}}}name") for a in intent_filter.findall("action")}
            categories = {c.get(f"{{{ANDROID}}}name") for c in intent_filter.findall("category")}
            if ("android.intent.action.VIEW" not in actions
                    or "android.intent.category.BROWSABLE" not in categories):
                continue
            schemes, hosts, paths = set(), set(), set()
            for data in intent_filter.findall("data"):
                if data.get(f"{{{ANDROID}}}scheme"):
                    schemes.add(data.get(f"{{{ANDROID}}}scheme"))
                if data.get(f"{{{ANDROID}}}host"):
                    hosts.add(data.get(f"{{{ANDROID}}}host"))
                for key in ("path", "pathPrefix", "pathPattern"):
                    value = data.get(f"{{{ANDROID}}}{key}")
                    if value:
                        paths.add(value)
            if not schemes:
                continue
            if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]{0,31}", value)
                   for value in schemes):
                continue
            if any(not re.fullmatch(r"(?:\*\.)?[A-Za-z0-9.-]{1,253}", value)
                   for value in hosts):
                continue
            if any(not re.fullmatch(r"/[A-Za-z0-9._~/%-]*", value) for value in paths):
                continue
            for scheme in sorted(schemes):
                for host in sorted(hosts or {""}):
                    for path in sorted(paths or {"/"}):
                        links.append({"id": f"link-{len(links) + 1:04d}",
                                      "component": name, "filter_index": filter_index,
                                      "scheme": scheme,
                                      "host": ("capri." + host[2:] if host.startswith("*.") else host),
                                      "path": path})
    return {"package": package,
            "version": {"name": root.get(f"{{{ANDROID}}}versionName"),
                        "code": _int(root, "versionCode")},
            "sdk": sdk,
            "application": {
                # Android's own defaults apply when an attribute is omitted.
                "allow_backup": _flag(app, "allowBackup", True),
                "debuggable": _flag(app, "debuggable", False),
                "uses_cleartext_traffic": _flag(app, "usesCleartextTraffic", None),
                "network_security_config": app.get(f"{{{ANDROID}}}networkSecurityConfig") is not None},
            "permissions": sorted(p.get(f"{{{ANDROID}}}name", "")
                                  for p in root.findall("uses-permission")
                                  if p.get(f"{{{ANDROID}}}name")),
            "components": components,
            "deep_links": links}


def _signing_digest(run, attacker):
    """SHA-256 of the APK's signing certificate, or None when the JRE cannot read one."""
    result = run(["docker", "exec", attacker, "keytool", "-printcert", "-jarfile",
                  APK_IN_ATTACKER])
    match = re.search(r"SHA-?256:\s*([0-9A-Fa-f:]+)", result.out or "") if result.rc == 0 else None
    return match.group(1).replace(":", "").lower() if match else None


def inspect_apk(apk_path, attacker, *, run, cleanup=True, static_depth="manifest"):
    """Hash and inspect an APK inside the isolated attacker container, then delete it."""
    if not isinstance(apk_path, str) or not os.path.isfile(apk_path):
        raise MobileError("engagement.android_app.apk must name an existing APK file")
    digest = hashlib.sha256()
    with open(apk_path, "rb") as apk:
        for chunk in iter(lambda: apk.read(1024 * 1024), b""):
            digest.update(chunk)
    copied = run(["docker", "cp", apk_path, f"{attacker}:{APK_IN_ATTACKER}"])
    if copied.rc != 0:
        raise MobileError("could not copy APK into the isolated range")
    try:
        result = run(["docker", "exec", attacker, "apkanalyzer", "manifest", "print",
                      APK_IN_ATTACKER])
        if result.rc != 0:
            raise MobileError("apkanalyzer could not read the APK manifest")
        inventory = {**inventory_manifest(result.out), "sha256": digest.hexdigest(),
                     "signing_sha256": _signing_digest(run, attacker),
                     "static_depth": static_depth}
        if static_depth == "code":
            findings, status, reason = assess_apk(run, attacker, APK_IN_ATTACKER)
            inventory.update(code_advisories=findings, code_status=status,
                             code_reason=reason)
        return inventory
    finally:
        if cleanup:
            run(["docker", "exec", attacker, "rm", "-f", APK_IN_ATTACKER])
