"""Report builder and ship-gating validator (HC-FIND-01 §7).

build_report assembles the §7.1 report from the store: confirmed vulnerabilities,
hardening notes, and the coverage summary straight from the ledger, so the report
answers "what did we try," not only "what did we find." validate_report is the
zero-dependency gate: the report does not ship unless every §7.2 check passes.
One of those checks is that user-facing text is target-neutral and free of raw
internal error detail, so an operator-facing report never leaks a stack trace or
exception string (the server keeps that; the report does not).
"""
import re

from harness.store import findings, ledger
from harness.store.db import now

# raw internal detail that must never reach a user-facing report
_LEAKY = re.compile(
    r"Traceback \(most recent call last\)"
    r"|\b\w*(Error|Exception):"
    r"|at 0x[0-9a-fA-F]+"
    r"|stack trace",
    re.IGNORECASE)


def build_report(conn, eng, *, mode="sandboxed", kb_version=None, generated_at=None,
                 objective=None):
    confirmed = [] if mode == "passive-only" else findings.confirmed(conn, eng.id)
    vulns = [findings.to_record(conn, r) for r in confirmed]
    hards = [findings.to_record(conn, r) for r in findings.hardening_notes(conn, eng.id)]
    cov = ledger.summary(conn, eng.id)
    return {
        "engagement_id": eng.id,
        "window": {"start": eng.window_start.isoformat(), "end": eng.window_end.isoformat()},
        "scope_summary": {"in_scope_hosts": list(eng.in_scope_hosts),
                          "max_blast_tier": eng.max_blast_tier},
        "mode": mode,
        "coverage_summary": cov,
        "findings": vulns,
        "hardening_notes": hards,
        "objective_outcome": objective or {"id": None, "status": "not_applicable"},
        "method_summary": _method_summary(cov, vulns, hards, kb_version, mode),
        "generated_at": generated_at or now(),
    }


def _method_summary(cov, vulns, hards, kb_version, mode):
    attempted = sum(v for k, v in cov.items() if k not in ("pending",))
    kb = f", KB {kb_version}" if kb_version else ""
    passive = ("Passive-only: this run did not have continuously proven sandbox containment; "
               "active probing stopped at the first failed proof check. "
               "Previously confirmed findings are omitted from this report. "
               if mode == "passive-only" else "")
    return (f"{passive}{attempted} technique/asset pairs evaluated{kb}; "
            f"{len(vulns)} confirmed vulnerabilities, {len(hards)} hardening notes.")


def validate_report(report, known_pairs):
    """Return ('ok', []) or ('errors', [reasons]). The report ships only on ok."""
    known = set(known_pairs)
    errs = []
    vulns = report.get("findings", []) or []
    hards = report.get("hardening_notes", []) or []

    # 1: finder is not verifier on every finding
    for f in vulns + hards:
        if f.get("verified_by") is not None and f.get("verified_by") == f.get("found_by"):
            errs.append(f"{f.get('id')}: found_by == verified_by")

    # 5: only confirmed items appear in the vulnerability findings list
    for f in vulns:
        if f.get("verdict") != "confirmed":
            errs.append(f"{f.get('id')}: non-confirmed verdict {f.get('verdict')!r} in findings")

    # 2: every confirmed finding is backed by a verifier event and a repro
    for f in vulns:
        if not f.get("verified_by_event_ids"):
            errs.append(f"{f.get('id')}: confirmed finding has no verified_by_event_ids")
        if not f.get("repro"):
            errs.append(f"{f.get('id')}: confirmed finding has empty repro")

    # 3: vulnerabilities carry cvss + >=1 cwe; hardening notes carry neither
    for f in vulns:
        if not f.get("cvss"):
            errs.append(f"{f.get('id')}: vulnerability missing cvss")
        if not f.get("cwe"):
            errs.append(f"{f.get('id')}: vulnerability missing cwe")
    for f in hards:
        if f.get("cvss") or f.get("cwe"):
            errs.append(f"{f.get('id')}: hardening_note must not carry cvss/cwe")

    # 4: technique_id + technique_version resolve to a known card
    for f in vulns + hards:
        if (f.get("technique_id"), f.get("technique_version")) not in known:
            errs.append(f"{f.get('id')}: technique "
                        f"{f.get('technique_id')}@{f.get('technique_version')} is not a known card")

    # 6: user-facing text is target-neutral, no raw internal error detail
    for f in vulns + hards:
        for field in ("impact", "remediation"):
            txt = f.get(field)
            if txt and _LEAKY.search(txt):
                errs.append(f"{f.get('id')}: {field} carries raw internal error detail")
    if report.get("method_summary") and _LEAKY.search(report["method_summary"]):
        errs.append("method_summary carries raw internal error detail")

    # 7: passive-only mode ships no confirmed vulnerabilities (HC-FIND-01 §9)
    if report.get("mode") == "passive-only" and vulns:
        errs.append("passive-only report must not contain confirmed vulnerabilities")

    # 9: mobile advisory findings are static observations and never carry a verdict
    for a in (report.get("mobile_static_assessment") or {}).get("advisory_findings", []):
        if "verdict" in a or "verified_by" in a:
            errs.append(f"{a.get('rule_id')}: advisory finding carries a runtime verdict")

    # 8: the objective outcome is internally consistent (HC-OBJ-01 §9.2)
    _validate_objective_outcome(report.get("objective_outcome"), report.get("mode"), vulns, errs)

    return ("errors", errs) if errs else ("ok", [])


def _validate_objective_outcome(outcome, mode, vulns, errs):
    if outcome is None:
        return
    status = outcome.get("status")
    if status not in ("achieved", "not_achieved", "not_applicable"):
        errs.append(f"objective_outcome.status {status!r} is not a known status")
    if status == "achieved":
        # an objective is proven, never asserted: the chain must be verified findings
        # resolving to a matched proof, and passive-only can never reach one.
        if mode == "passive-only":
            errs.append("objective achieved cannot appear in passive-only mode")
        proof = outcome.get("proof") or {}
        if proof.get("kind") == "canary" and not proof.get("sha256_matched"):
            errs.append("objective achieved by canary requires proof.sha256_matched")
        if proof.get("kind") == "oob_marker" and not proof.get("marker_fired"):
            errs.append("objective achieved by reach requires its in-sandbox marker to have fired")
        path = outcome.get("attack_path") or []
        if not path:
            errs.append("objective achieved must list a non-empty attack_path")
        by_id = {f.get("id"): f for f in vulns}
        for step in path:
            sid = step.get("finding_id")
            f = by_id.get(sid)
            if f is None:
                errs.append(f"attack_path step {sid} is not a confirmed finding in the report")
            elif f.get("verified_by") is None or f.get("verified_by") == f.get("found_by"):
                errs.append(f"attack_path step {sid} is not independently verified")
    if status == "not_achieved" and "reached_facts" not in outcome:
        errs.append("objective not_achieved must list reached_facts")
