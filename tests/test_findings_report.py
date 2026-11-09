#!/usr/bin/env python3
"""Adversarial tests for the finding/report layer (HC-FIND-01 §7, §9; §5 severity).

Covers the predicate DSL, the severity rubric (§207 band/score toggling), the
finding record + verifier label, and the report builder + ship-gating validator:
finder != verifier, confirmed-needs-verifier-events-and-repro, vuln-has-cvss+cwe,
hardening-has-neither, technique-resolves-to-a-known-card, no raw internal error
text, and passive-only ships nothing confirmed. Zero-dependency.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import kb, predicates, report, severity                 # noqa: E402
from harness.predicates import evaluate                              # noqa: E402
from harness.store import blobstore, db, evidence, findings          # noqa: E402
from harness.substrate import contract                               # noqa: E402

CONTRACT = """
engagement:
  id: eng-find-001
  authorized_by: test
  window: { start: 2026-11-08T20:00, end: 2026-11-08T23:59 }
  max_blast_tier: 2
scope:
  in_scope_hosts: [api.sandbox.local]
  in_scope_cidrs: [10.10.0.0/24]
  allowed_ports: { default: [443] }
"""

CARD = {
    "id": "KB-WEB-INJ-SQLI-001", "version": "1.0.0", "blast_tier": 1,
    "taxonomy": {"attack": {"technique": "T1190"}, "cwe": ["CWE-89"]},
    "severity_rubric": {"base": "high",
                        "raise_if": [{"when": "asset.writable", "to": "critical"}],
                        "lower_if": [{"when": "asset.read_only", "to": "medium"}],
                        "cvss_base_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
}


def _eng():
    eng, errs = contract.parse(CONTRACT)
    assert not errs, errs
    return eng


def _event(conn, blobs, role):
    return evidence.record_probe_event(
        conn, blobs, engagement_id="eng-find-001", role=role, phase="hunting",
        snapshot_id="golden", technique_id=CARD["id"], technique_version=CARD["version"],
        tool="httpx", target_asset="api.sandbox.local", request_bytes=b"GET /orders?id=1",
        response_bytes=b"db error fingerprint")


# --- predicate DSL -------------------------------------------------------
def test_predicate_bare_fact_and_missing():
    assert evaluate("asset.writable", {"asset.writable": True}) is True
    assert evaluate("asset.writable", {"asset.writable": False}) is False
    assert evaluate("asset.writable", {}) is False            # missing is falsey, not an error


def test_predicate_equality_and_bool_ops():
    f = {"asset.type": "orchestrator_api", "reachable": True}
    assert evaluate('asset.type == "orchestrator_api"', f) is True
    assert evaluate('asset.type == "db"', f) is False
    assert evaluate('asset.type == "orchestrator_api" && reachable', f) is True
    assert evaluate('asset.type == "db" || reachable', f) is True
    assert evaluate("!reachable", f) is False


def test_predicate_exists_matches_in():
    f = {"banner": "Server: nginx/1.25", "tags": ["pii", "export"]}
    assert evaluate("exists(banner)", f) is True
    assert evaluate("exists(missing)", f) is False
    assert evaluate("matches(banner, /nginx/)", f) is True
    assert evaluate("matches(banner, /apache/)", f) is False
    assert evaluate('"pii" in tags', f) is True


def test_predicate_rejects_disallowed_function():
    try:
        evaluate("eval(x)", {})
        raise AssertionError("expected a disallowed-function error")
    except predicates.PredicateError:
        pass


def test_predicate_identifiers_are_the_facts_read():
    # the facts an objective needs, for the §9 backward trace: keywords, functions,
    # and literals drop out; `[*]` suffixes and string contents are not facts.
    assert predicates.identifiers("exists(db_admin)") == {"db_admin"}
    assert predicates.identifiers('foothold.host == "db" && exists(cred)') == {"foothold.host", "cred"}
    assert predicates.identifiers('"pii" in tags[*]') == {"tags"}
    assert predicates.identifiers("") == set()
    assert predicates.identifiers("((((") == set()               # malformed yields nothing, never raises


# --- severity rubric (§5, §207) -----------------------------------------
def test_severity_base_band():
    s = severity.score(CARD["severity_rubric"], {})
    assert s["band"] == "high" and s["score"] == 8.0
    assert s["vector"].startswith("CVSS:4.0/")


def test_severity_raise_if_changes_band_and_score():
    low = severity.score(CARD["severity_rubric"], {})
    high = severity.score(CARD["severity_rubric"], {"asset.writable": True})
    assert low["band"] == "high" and high["band"] == "critical"
    assert high["score"] > low["score"]                       # §207: fact toggles score and band


def test_severity_lower_if_only_lowers():
    s = severity.score(CARD["severity_rubric"], {"asset.read_only": True})
    assert s["band"] == "medium" and s["score"] == 5.0
    # a lower clause cannot raise above base
    rubric = {"base": "low", "lower_if": [{"when": "x", "to": "critical"}]}
    assert severity.score(rubric, {"x": True})["band"] == "low"


# --- the happy path: a confirmed vulnerability validates ----------------
def _confirmed_setup(root):
    conn = db.connect()
    blobs = blobstore.BlobStore(root)
    eng = _eng()
    op_ev, ver_ev = _event(conn, blobs, "operator"), _event(conn, blobs, "verifier")
    findings.emit_lead(conn, "F-2026-0001", eng.id, CARD, "api.sandbox.local/orders?id=",
                       found_by="operator-A", facts={"asset.writable": True},
                       repro=["baseline GET", "inject payload", "observe db error fingerprint"],
                       impact="read arbitrary rows from the orders table",
                       remediation="parameterize the query; see CWE-89",
                       event_ids=[op_ev])
    findings.confirm(conn, "F-2026-0001", verified_by="verifier-B", events=[ver_ev])
    return conn, eng


def test_confirmed_vulnerability_report_validates():
    with tempfile.TemporaryDirectory() as root:
        conn, eng = _confirmed_setup(root)
        rep = report.build_report(conn, eng, mode="sandboxed", kb_version="2026.11")
        assert len(rep["findings"]) == 1 and rep["hardening_notes"] == []
        f = rep["findings"][0]
        assert f["cvss"]["band"] == "critical" and f["cwe"] == ["CWE-89"]
        assert f["found_by"] != f["verified_by"]
        assert f["verified_by_event_ids"] and f["repro"]
        verdict, errs = report.validate_report(rep, {(CARD["id"], CARD["version"])})
        assert verdict == "ok", errs


def test_verifier_label_emitted_on_confirm():
    with tempfile.TemporaryDirectory() as root:
        conn, _ = _confirmed_setup(root)
        row = conn.execute("SELECT * FROM label WHERE decision_point='verdict'").fetchone()
        assert row["value"] == "confirmed" and row["source"] == "verifier" and row["tier"] == "silver"


# --- validator rejects malformed reports (§7.2, §9) ---------------------
def test_report_rejects_found_equals_verified():
    rep = {"findings": [{"id": "F-x", "technique_id": CARD["id"],
                         "technique_version": CARD["version"], "verdict": "confirmed",
                         "found_by": "same", "verified_by": "same",
                         "verified_by_event_ids": ["pe_1"], "repro": ["s"],
                         "cvss": {"band": "high"}, "cwe": ["CWE-89"]}],
           "hardening_notes": []}
    verdict, errs = report.validate_report(rep, {(CARD["id"], CARD["version"])})
    assert verdict == "errors" and any("found_by == verified_by" in e for e in errs)


def test_confirmed_without_verifier_events_or_repro_rejected():
    with tempfile.TemporaryDirectory() as root:
        conn = db.connect()
        blobs = blobstore.BlobStore(root)
        eng = _eng()
        op_ev = _event(conn, blobs, "operator")
        findings.emit_lead(conn, "F-1", eng.id, CARD, "a", found_by="op-A",
                           facts={}, repro=[], event_ids=[op_ev])   # empty repro
        findings.confirm(conn, "F-1", verified_by="ver-B")          # no verifier events
        rep = report.build_report(conn, eng)
        verdict, errs = report.validate_report(rep, {(CARD["id"], CARD["version"])})
        assert verdict == "errors"
        assert any("verified_by_event_ids" in e for e in errs)
        assert any("empty repro" in e for e in errs)


def test_hardening_note_has_no_cvss_or_cwe():
    with tempfile.TemporaryDirectory() as root:
        conn = db.connect()
        blobs = blobstore.BlobStore(root)
        eng = _eng()
        ev = _event(conn, blobs, "operator")
        findings.classify_hardening(conn, "H-1", eng.id, CARD, "api.sandbox.local",
                                    found_by="op-A", note="missing security header", event_ids=[ev])
        rep = report.build_report(conn, eng)
        assert rep["findings"] == [] and len(rep["hardening_notes"]) == 1
        h = rep["hardening_notes"][0]
        assert h["cvss"] is None and h["cwe"] is None
        verdict, _ = report.validate_report(rep, {(CARD["id"], CARD["version"])})
        assert verdict == "ok"
        # a hand-built hardening note that smuggles a cvss is rejected
        rep["hardening_notes"][0]["cvss"] = {"band": "high"}
        verdict, errs = report.validate_report(rep, {(CARD["id"], CARD["version"])})
        assert verdict == "errors" and any("must not carry" in e for e in errs)


def test_rejected_and_inconclusive_not_in_findings():
    with tempfile.TemporaryDirectory() as root:
        conn = db.connect()
        blobs = blobstore.BlobStore(root)
        eng = _eng()
        for fid in ("F-r", "F-i"):
            findings.emit_lead(conn, fid, eng.id, CARD, "a", found_by="op-A", facts={},
                               repro=["s"], event_ids=[_event(conn, blobs, "operator")])
        findings.reject(conn, "F-r", reason="known false positive")
        findings.mark_inconclusive(conn, "F-i", reason="env/time")
        rep = report.build_report(conn, eng)
        assert rep["findings"] == []                           # neither ships as a vulnerability
        verdict, _ = report.validate_report(rep, {(CARD["id"], CARD["version"])})
        assert verdict == "ok"


def test_deterministic_lead_still_needs_verification():
    with tempfile.TemporaryDirectory() as root:
        conn = db.connect()
        blobs = blobstore.BlobStore(root)
        eng = _eng()
        findings.emit_lead(conn, "F-1", eng.id, CARD, "a", found_by="op-A",
                           facts={}, signal_confidence=1.0, repro=["s"],
                           event_ids=[_event(conn, blobs, "operator")])
        rep = report.build_report(conn, eng)
        assert rep["findings"] == []                           # a 1.0 lead is not confirmed


def test_unknown_technique_rejected():
    with tempfile.TemporaryDirectory() as root:
        conn, eng = _confirmed_setup(root)
        rep = report.build_report(conn, eng)
        verdict, errs = report.validate_report(rep, set())     # empty card index
        assert verdict == "errors" and any("not a known card" in e for e in errs)


def test_text_neutrality_blocks_raw_internal_error():
    with tempfile.TemporaryDirectory() as root:
        conn = db.connect()
        blobs = blobstore.BlobStore(root)
        eng = _eng()
        op_ev, ver_ev = _event(conn, blobs, "operator"), _event(conn, blobs, "verifier")
        findings.emit_lead(conn, "F-1", eng.id, CARD, "a", found_by="op-A", facts={},
                           repro=["s"], impact="Traceback (most recent call last): KeyError: 'id'",
                           event_ids=[op_ev])
        findings.confirm(conn, "F-1", verified_by="ver-B", events=[ver_ev])
        rep = report.build_report(conn, eng)
        verdict, errs = report.validate_report(rep, {(CARD["id"], CARD["version"])})
        assert verdict == "errors" and any("raw internal error" in e for e in errs)


def test_passive_only_mode_ships_nothing_confirmed():
    with tempfile.TemporaryDirectory() as root:
        conn, eng = _confirmed_setup(root)
        rep = report.build_report(conn, eng, mode="passive-only")
        assert rep["mode"] == "passive-only"
        assert rep["findings"] == []
        assert len(findings.confirmed(conn, eng.id)) == 1  # keep stored evidence intact
        assert "Previously confirmed findings are omitted" in rep["method_summary"]
        verdict, errs = report.validate_report(rep, {(CARD["id"], CARD["version"])})
        assert verdict == "ok", errs


def test_finder_is_not_verifier_enforced_at_db():
    with tempfile.TemporaryDirectory() as root:
        import sqlite3
        conn = db.connect()
        blobs = blobstore.BlobStore(root)
        eng = _eng()
        findings.emit_lead(conn, "F-1", eng.id, CARD, "a", found_by="op-A", facts={},
                           repro=["s"], event_ids=[_event(conn, blobs, "operator")])
        try:
            findings.confirm(conn, "F-1", verified_by="op-A")   # same identity
            raise AssertionError("expected the DB CHECK to reject verified_by == found_by")
        except sqlite3.IntegrityError:
            pass


# --- kb index integration ------------------------------------------------
def test_kb_index_loads_real_tree():
    index = kb.load()
    assert len(index) == 107
    pairs = kb.known_pairs(index)
    assert ("KB-CLOUD-K8S-ANON-001", "1.0.0") in pairs


# --- objective_outcome validator (HC-OBJ-01 §9.2) -----------------------
def _vuln(fid):
    return {"id": fid, "technique_id": CARD["id"], "technique_version": CARD["version"],
            "verdict": "confirmed", "found_by": "op-A", "verified_by": "ver-B",
            "verified_by_event_ids": ["pe_1"], "repro": ["s"],
            "cvss": {"band": "high"}, "cwe": ["CWE-89"]}


def _report_with_outcome(outcome, *, mode="sandboxed", findings_=None):
    return {"mode": mode, "findings": findings_ if findings_ is not None else [_vuln("F-1")],
            "hardening_notes": [], "objective_outcome": outcome}


def _validate(rep):
    return report.validate_report(rep, {(CARD["id"], CARD["version"])})


def test_achieved_outcome_with_verified_chain_validates():
    rep = _report_with_outcome(
        {"id": "obj-1", "status": "achieved", "proof": {"kind": "capability"},
         "attack_path": [{"step": 1, "finding_id": "F-1"}], "reached_facts": []})
    verdict, errs = _validate(rep)
    assert verdict == "ok", errs


def test_achieved_cannot_appear_in_passive_only():
    rep = _report_with_outcome(
        {"id": "obj-1", "status": "achieved", "proof": {"kind": "capability"},
         "attack_path": [{"step": 1, "finding_id": "F-1"}]},
        mode="passive-only", findings_=[])
    verdict, errs = _validate(rep)
    assert verdict == "errors" and any("passive-only" in e for e in errs)


def test_achieved_canary_needs_matched_hash():
    rep = _report_with_outcome(
        {"id": "obj-1", "status": "achieved",
         "proof": {"kind": "canary", "sha256_matched": False},
         "attack_path": [{"step": 1, "finding_id": "F-1"}]})
    verdict, errs = _validate(rep)
    assert verdict == "errors" and any("sha256_matched" in e for e in errs)


def test_achieved_path_step_must_be_a_confirmed_verified_finding():
    # a step whose finding is not in the confirmed list cannot anchor the kill chain
    rep = _report_with_outcome(
        {"id": "obj-1", "status": "achieved", "proof": {"kind": "capability"},
         "attack_path": [{"step": 1, "finding_id": "F-missing"}]})
    verdict, errs = _validate(rep)
    assert verdict == "errors" and any("not a confirmed finding" in e for e in errs)


def test_achieved_must_list_a_non_empty_attack_path():
    rep = _report_with_outcome(
        {"id": "obj-1", "status": "achieved", "proof": {"kind": "capability"},
         "attack_path": []})
    verdict, errs = _validate(rep)
    assert verdict == "errors" and any("non-empty attack_path" in e for e in errs)


def test_not_achieved_must_list_reached_facts():
    rep = _report_with_outcome({"id": "obj-1", "status": "not_achieved"}, findings_=[])
    verdict, errs = _validate(rep)
    assert verdict == "errors" and any("reached_facts" in e for e in errs)


def test_not_applicable_outcome_validates():
    rep = _report_with_outcome({"id": None, "status": "not_applicable"}, findings_=[])
    verdict, errs = _validate(rep)
    assert verdict == "ok", errs


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERR  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
