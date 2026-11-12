"""Run the pinned, local-only Android decompilation and advisory rules."""

import json
import re
import subprocess

OUTPUT = "/tmp/hc-mobile-decompiled"
RULES = "/opt/hc/mobile-rules.yaml"


def parse_semgrep(stdout):
    """Keep only redacted rule metadata and source locations from Semgrep output."""
    try:
        report = json.loads(stdout)
    except (TypeError, json.JSONDecodeError):
        raise ValueError("Semgrep returned invalid JSON") from None
    if report.get("errors"):
        raise ValueError("Semgrep reported an incomplete scan")
    findings = []
    for result in report.get("results", []):
        rule = result.get("check_id", "").rsplit(".", 1)[-1]
        if rule not in {"webview-bridge", "weak-crypto", "hardcoded-secret"}:
            continue
        masvs = {"webview-bridge": ["MASVS-PLATFORM-1"],
                 "weak-crypto": ["MASVS-CRYPTO-1"],
                 "hardcoded-secret": ["MASVS-CODE-2"]}[rule]
        metadata = (result.get("extra") or {}).get("metadata") or {}
        raw_path = str(result.get("path", ""))
        path = re.sub(r"[^A-Za-z0-9_./$-]", "_", raw_path)[:160]
        line = (result.get("start") or {}).get("line")
        findings.append({"rule_id": f"code-{rule}",
                         "title": metadata.get("title", "Mobile code pattern requires review"),
                         "confidence": metadata.get("confidence", "medium"),
                         "related_cards": (["KB-MOBILE-IPC-WEBVIEW-001"]
                                            if rule == "webview-bridge" else []),
                         "masvs": masvs,
                         "locations": [f"{path}:{line}" if isinstance(line, int) else path]})
    return findings


def assess_apk(run, attacker, apk_path):
    """Decompile and scan the hostile APK inside the attacker container; return advisories."""
    findings, status, reason = [], "partial", "APK decompilation or scan failed"
    try:
        run(["docker", "exec", attacker, "rm", "-rf", OUTPUT])
        decompiled = run(["docker", "exec", attacker, "jadx", "-q", "-j", "2",
                          "-d", OUTPUT, apk_path], timeout=300)
        if decompiled.rc != 0:
            reason = "APK decompilation failed"
        else:
            scanned = run(["docker", "exec", attacker, "semgrep", "scan", "--config", RULES,
                           "--metrics=off", "--disable-version-check", "--json", "--quiet", OUTPUT],
                          timeout=300)
            if scanned.rc != 0:
                reason = "mobile Semgrep scan failed"
            else:
                findings = parse_semgrep(scanned.out)
                status, reason = "complete", None
    except (OSError, subprocess.TimeoutExpired):
        reason = "mobile code analysis timed out or could not start"
    except ValueError:
        reason = "mobile Semgrep scan was incomplete"
    cleanup = run(["docker", "exec", attacker, "rm", "-rf", OUTPUT])
    if cleanup.rc != 0:
        return [], "partial", "decompiled source cleanup failed"
    return findings, status, reason
