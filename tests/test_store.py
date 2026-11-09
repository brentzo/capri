#!/usr/bin/env python3
"""Adversarial tests for the M1 store invariants (HC-DATA-01 §11, HC-SAFE-01 §10).

Proves the database-level guarantees: finder != verifier (CHECK), append-only
evidence (triggers), atomic verdict transitions, and a tamper-evident audit
chain. Zero-dependency: `python3 tests/test_store.py`.
"""
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.store import db, ledger, findings, audit  # noqa: E402


def _pe(conn, pid, role="operator"):
    with conn:
        conn.execute(
            """INSERT INTO probe_event (id, engagement_id, ts, provenance, split_bucket,
                   phase, role, target_asset, snapshot_id, technique_id,
                   technique_version, tool, request_raw_uri, content_hash)
               VALUES (?, 'eng-1', '2026-11-08T20:00:00+00:00', 'live_engagement',
                   'train', 'hunting', ?, 'api.sandbox.local', 'snap-1',
                   'KB-WEB-INJ-SQLI-001', '1.0.0', 'httpx', 'blob://abc', 'h1')""",
            (pid, role))
    return pid


def _lead(conn):
    _pe(conn, "pe_op", "operator")
    findings.insert_lead(conn, "F-2026-0001", "eng-1", "KB-WEB-INJ-SQLI-001",
                         "1.0.0", "api.sandbox.local/orders?id=", found_by="op-A")


# --- finder != verifier (DB CHECK) ---------------------------------------
def test_finder_not_verifier_rejected_by_db():
    conn = db.connect()
    _lead(conn)
    try:
        findings.confirm(conn, "F-2026-0001", verified_by="op-A")  # same as found_by
        raise AssertionError("expected the DB CHECK to reject verified_by == found_by")
    except sqlite3.IntegrityError:
        pass
    # the failed confirm rolled back atomically: still a lead, no stray status row
    assert findings.current(conn, "F-2026-0001")["verdict"] == "lead"
    assert [r["to_state"] for r in findings.history(conn, "F-2026-0001")] == ["lead"]


def test_distinct_verifier_confirms():
    conn = db.connect()
    _lead(conn)
    findings.confirm(conn, "F-2026-0001", verified_by="ver-B")
    f = findings.current(conn, "F-2026-0001")
    assert f["verdict"] == "confirmed" and f["verified_by"] == "ver-B"
    assert f["resolved_at"] is not None
    assert [r["to_state"] for r in findings.history(conn, "F-2026-0001")] == ["lead", "confirmed"]


def test_reject_and_inconclusive():
    conn = db.connect()
    _lead(conn)
    findings.reject(conn, "F-2026-0001", reason="known false positive")
    assert findings.current(conn, "F-2026-0001")["verdict"] == "rejected"
    conn2 = db.connect()
    _pe(conn2, "pe_op", "operator")
    findings.insert_lead(conn2, "F-2", "eng-1", "KB-X", "1.0.0", "a", found_by="op-A")
    findings.mark_inconclusive(conn2, "F-2", reason="env/time")
    assert findings.current(conn2, "F-2")["verdict"] == "inconclusive"


# --- append-only evidence (triggers) -------------------------------------
def test_probe_event_append_only():
    conn = db.connect()
    _pe(conn, "pe_1")
    for sql in ("UPDATE probe_event SET tool='x' WHERE id='pe_1'",
                "DELETE FROM probe_event WHERE id='pe_1'"):
        try:
            with conn:
                conn.execute(sql)
            raise AssertionError(f"append-only trigger did not fire for: {sql}")
        except sqlite3.Error:
            pass


def test_label_append_only():
    conn = db.connect()
    _pe(conn, "pe_1")
    with conn:
        conn.execute(
            """INSERT INTO label (probe_event_id, ts, decision_point, value, source, tier)
               VALUES ('pe_1', '2026-11-08T20:00:00+00:00', 'success_signal', 'hit',
                   'verifier', 'silver')""")
    for sql in ("UPDATE label SET value='miss'", "DELETE FROM label"):
        try:
            with conn:
                conn.execute(sql)
            raise AssertionError(f"append-only trigger did not fire for: {sql}")
        except sqlite3.Error:
            pass


# --- coverage ledger -----------------------------------------------------
def test_ledger_mark_done_summary():
    conn = db.connect()
    assert not ledger.done(conn, "eng-1", "a", "KB-X")
    ledger.mark(conn, "eng-1", "a", "KB-X", "pending")
    assert not ledger.done(conn, "eng-1", "a", "KB-X")          # pending is not done
    ledger.mark(conn, "eng-1", "a", "KB-X", "confirmed")        # upsert
    assert ledger.done(conn, "eng-1", "a", "KB-X")
    ledger.mark(conn, "eng-1", "b", "KB-Y", "not_applicable")
    assert ledger.summary(conn, "eng-1") == {"confirmed": 1, "not_applicable": 1}


def test_ledger_rejects_unknown_status():
    conn = db.connect()
    try:
        ledger.mark(conn, "eng-1", "a", "KB-X", "banana")
        raise AssertionError("expected unknown status to be rejected")
    except ValueError:
        pass


def test_ledger_records_a_sub_reason_detail():
    conn = db.connect()
    ledger.mark(conn, "eng-1", "a", "KB-X", "blocked_by_policy", detail="blocked_lateral")
    assert ledger.detail(conn, "eng-1", "a", "KB-X") == "blocked_lateral"
    assert ledger.summary(conn, "eng-1") == {"blocked_by_policy": 1}   # detail does not split the summary
    ledger.mark(conn, "eng-1", "a", "KB-X", "confirmed")              # upsert clears the stale detail
    assert ledger.detail(conn, "eng-1", "a", "KB-X") is None
    assert ledger.detail(conn, "eng-1", "a", "missing") is None


# --- tamper-evident audit log --------------------------------------------
def test_audit_chain_verifies():
    conn = db.connect()
    audit.record(conn, "eng-1", "harness", "guard_decision", decision="deny",
                 reason="out_of_scope")
    audit.record(conn, "eng-1", "operator", "tool_request", decision="exec")
    audit.record(conn, "eng-1", "watchdog", "kill", decision="stop")
    assert audit.verify_chain(conn) == ("ok", None)


def test_audit_tamper_detected():
    conn = db.connect()
    for i in range(3):
        audit.record(conn, "eng-1", "harness", "guard_decision", reason=f"r{i}")
    # simulate storage-level tampering by bypassing the append-only trigger
    conn.execute("DROP TRIGGER audit_log_no_update")
    with conn:
        conn.execute("UPDATE audit_log SET reason='tampered' WHERE seq=2")
    verdict, seq = audit.verify_chain(conn)
    assert verdict == "tamper" and seq == 2


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
