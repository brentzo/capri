"""Mobile static assessment: advisory findings read from the APK manifest.

Everything here is an observation about what the APK declares, never a verified
vulnerability. Each advisory finding names the runtime technique cards it makes
worth running, so the agent tests what the static view suggests, but only a
harness-observed signal reproduced by the independent Verifier can confirm a finding.
MASVS control ids are v2 identifiers; MASTG test ids are pinned separately against a
specific MASTG release.
"""

CARD_DEEPLINK = "KB-MOBILE-LINK-DEEPLINK-001"
CARD_EXPORTED = "KB-MOBILE-COMP-EXPORTED-001"
CARD_PROVIDER = "KB-MOBILE-COMP-PROVIDER-SQLI-001"
CARD_BACKUP = "KB-MOBILE-STORAGE-BACKUP-001"
CARD_CLEARTEXT = "KB-MOBILE-NET-CLEARTEXT-001"
CARD_WEBVIEW = "KB-MOBILE-IPC-WEBVIEW-001"

# Surfaces this assessment never examines; listed so a quiet report is not read as clean.
NOT_ASSESSED = (
    "screens and business workflows behind the declared entry points",
    "code-level issues such as cryptography, embedded secrets and WebView bridges",
    "bundled library versions and vulnerability reachability",
    "authentication and session behavior",
    "runtime behavior beyond the techniques recorded in coverage",
)


def _protected(component):
    return bool(
        component["permission"]
        or (component.get("read_permission") and component.get("write_permission"))
    )


def exported_components(inventory):
    return [c for c in inventory["components"] if c["exported"]]


def assess(inventory):
    """Return the advisory findings, coverage and not-applicable techniques for an inventory."""
    app, sdk = inventory["application"], inventory["sdk"]
    findings = []

    def add(rule_id, title, confidence, cards, masvs, locations=()):
        findings.append(
            {
                "rule_id": rule_id,
                "title": title,
                "confidence": confidence,
                "related_cards": list(cards),
                "masvs": list(masvs),
                "locations": sorted(locations),
            }
        )

    if app["debuggable"]:
        add(
            "debuggable-app",
            "The app is built as debuggable",
            "high",
            [],
            ["MASVS-RESILIENCE-2"],
        )
    if app["allow_backup"]:
        add(
            "backup-allowed",
            "App data may be extracted through backup",
            "medium",
            [CARD_BACKUP],
            ["MASVS-STORAGE-2"],
        )
    implied_cleartext = (
        app["uses_cleartext_traffic"] is None
        and not app["network_security_config"]
        and sdk["target"] is not None
        and sdk["target"] < 28
    )
    if app["uses_cleartext_traffic"] or implied_cleartext:
        add(
            "cleartext-permitted",
            "The app permits cleartext network traffic",
            "high" if app["uses_cleartext_traffic"] else "medium",
            [CARD_CLEARTEXT],
            ["MASVS-NETWORK-1"],
        )

    exposed = [
        c
        for c in exported_components(inventory)
        if c["type"] != "provider" and not _protected(c)
    ]
    if exposed:
        only_activities = all(
            c["type"] in ("activity", "activity-alias") for c in exposed
        )
        add(
            "exported-component-unprotected",
            "Exported components can be started by any other app",
            "low" if only_activities else "medium",
            [CARD_EXPORTED],
            ["MASVS-PLATFORM-1"],
            [c["name"] for c in exposed],
        )
    providers = [
        c
        for c in exported_components(inventory)
        if c["type"] == "provider" and not _protected(c)
    ]
    if providers:
        add(
            "exported-provider-unprotected",
            "Exported content providers have no protecting permission",
            "medium",
            [CARD_PROVIDER],
            ["MASVS-PLATFORM-1"],
            [c["name"] for c in providers],
        )
    undecidable = [c["name"] for c in inventory["components"] if c["exported"] is None]
    if undecidable:
        add(
            "export-attribute-missing",
            "Components with intent filters omit the mandatory exported attribute",
            "high",
            [],
            ["MASVS-PLATFORM-1"],
            undecidable,
        )
    if inventory["deep_links"]:
        add(
            "deep-link-declared",
            "The app declares browsable deep links",
            "low",
            [CARD_DEEPLINK],
            ["MASVS-PLATFORM-1"],
            [link["component"] for link in inventory["deep_links"]],
        )

    findings.extend(inventory.get("code_advisories", []))

    applicable = {
        CARD_DEEPLINK: bool(inventory["deep_links"]),
        CARD_EXPORTED: bool(exported_components(inventory)),
        CARD_PROVIDER: bool(exported_components(inventory)),
        CARD_BACKUP: app["allow_backup"],
    }
    reasons = {
        CARD_DEEPLINK: "no browsable deep link is declared",
        CARD_EXPORTED: "no component is exported",
        CARD_PROVIDER: "no component is exported",
        CARD_BACKUP: "the manifest disallows backup",
    }
    code_status = inventory.get("code_status", "not_run")
    has_webview_bridge = any(CARD_WEBVIEW in item.get("related_cards", [])
                             for item in inventory.get("code_advisories", []))
    not_applicable = [
        {"card": card, "reason": reasons[card]}
        for card, ok in applicable.items()
        if not ok
    ]
    not_run = []
    if inventory.get("static_depth", "manifest") != "code":
        not_run.append({"card": CARD_WEBVIEW, "reason": "static_depth is manifest"})
    elif code_status != "complete":
        not_run.append({"card": CARD_WEBVIEW,
                        "reason": inventory.get("code_reason") or "code analysis was incomplete"})
    elif not has_webview_bridge:
        not_applicable.append({"card": CARD_WEBVIEW,
                               "reason": "code-level analysis found no JavaScript bridge"})
    not_assessed = list(NOT_ASSESSED)
    if code_status == "complete":
        not_assessed.remove("code-level issues such as cryptography, embedded secrets and WebView bridges")
    return {
        "advisory_findings": findings,
        "coverage": {
            "manifest": "complete",
            "code": code_status,
            "code_reason": inventory.get("code_reason", "static_depth is manifest"),
        },
        "not_applicable": not_applicable,
        "not_run": not_run,
        "not_assessed": not_assessed,
    }
