"""Bounded Android APK inventory and deep-link probe helpers (HC-MOB-01)."""
import hashlib
import os
import re
import secrets
import urllib.parse
import xml.etree.ElementTree as ET

from harness.sandbox.base import SandboxError
from harness.substrate.scope import MOBILE_TARGET

ANDROID = "http://schemas.android.com/apk/res/android"
APK_IN_ATTACKER = "/tmp/hc-mobile.apk"
ANDROID_EMULATOR_IMAGE = (
    "us-docker.pkg.dev/android-emulator-268719/images/30-google-x64-no-metrics"
    "@sha256:e78ac1816acef59e40285e90003acd490ef54bb3242ed088afa31bc982577050"
)


class MobileError(SandboxError):
    """An APK could not be inventoried or the managed Android device failed."""


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
        exported = (exported_text.lower() == "true") if exported_text is not None else None
        components.append({"name": name, "type": node.tag, "exported": exported})
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
            "permissions": sorted(p.get(f"{{{ANDROID}}}name", "")
                                  for p in root.findall("uses-permission")
                                  if p.get(f"{{{ANDROID}}}name")),
            "components": components,
            "deep_links": links}


def inspect_apk(apk_path, attacker, *, run, cleanup=True):
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
        return {**inventory_manifest(result.out), "sha256": digest.hexdigest()}
    finally:
        if cleanup:
            run(["docker", "exec", attacker, "rm", "-f", APK_IN_ATTACKER])


class DeepLinkProbe:
    """Only invokes manifest-discovered links with a harness-created range callback."""

    local_mobile_target = True

    def __init__(self, package, links, *, adb, collaborator, collab_addr, expected_source):
        self.package = package
        self.links = {link["id"]: link for link in links}
        self.adb = adb
        self.collaborator = collaborator
        self.collab_addr = collab_addr
        self.expected_source = expected_source

    def run(self, req):
        args = req.get("args") or {}
        link_id = args.get("link_id")
        link = self.links.get(link_id) if isinstance(link_id, str) else None
        if link is None or not self.collab_addr or not self.collaborator:
            return {"status": "error", "parsed": {"error": "unknown_link"},
                    "request_bytes": b"mobile deep-link", "response_bytes": b"",
                    "deterministic_signals": {"hit": False, "confidence": 0.0}}
        if (not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]{0,31}", link["scheme"])
                or not re.fullmatch(r"(?:[A-Za-z0-9.-]{1,253})?", link["host"])
                or not re.fullmatch(r"/[A-Za-z0-9._~/%-]*", link["path"])):
            return {"status": "error", "parsed": {"error": "unsupported_link_syntax"},
                    "request_bytes": b"mobile deep-link", "response_bytes": b"",
                    "deterministic_signals": {"hit": False, "confidence": 0.0}}
        nonce = "hc" + secrets.token_hex(12)
        callback = f"http://{self.collab_addr}/{nonce}"
        url = urllib.parse.urlunsplit((link["scheme"], link["host"], link["path"],
                                       urllib.parse.urlencode({"url": callback}), ""))
        cleared = self.adb(["shell", "pm", "clear", self.package])
        if cleared.rc != 0 or "success" not in (cleared.out or "").lower():
            raise MobileError("could not reset the Android app to its clean baseline")
        launched = self.adb(["shell", "am", "start", "-W", "-a",
                             "android.intent.action.VIEW", "-c",
                             "android.intent.category.BROWSABLE", "-d", url,
                             self.package])
        log = self.collaborator()
        hit = False
        if launched.rc == 0:
            for line in (log or "").splitlines():
                fields = line.rsplit(maxsplit=1)
                if len(fields) == 2 and fields[0] == f"/{nonce}" and fields[1] == self.expected_source:
                    hit = True
                    break
        return {"status": "ok" if hit else "error",
                "parsed": {"package": self.package, "link_id": link["id"],
                           "launch_succeeded": launched.rc == 0, "oob_fired": hit},
                "request_bytes": url.encode("utf-8"),
                "response_bytes": f"oob={hit}".encode("ascii"),
                "deterministic_signals": {"hit": hit, "oob_fired": hit,
                                           "confidence": 0.95 if hit else 0.0}}
