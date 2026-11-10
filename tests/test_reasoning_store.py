#!/usr/bin/env python3
"""Tests for the write-only reasoning record and its read API (HC-REPORT-01 §3).

Each Operator/Verifier turn's verbatim proposal is captured as a `role_turn` row so the
operator can later read what the agent proposed, step by step. The record is untrusted,
display-only data: write-only from the loop, read-only from the dashboard, append-only in
the store. These drive the store against an in-memory SQLite DB (no Docker, no model plane)
and assert the roundtrip, the per-run filter, the parsed/rejection shape, and that a captured
turn cannot be rewritten.

Zero-dependency: `python3 tests/test_reasoning_store.py`.
"""
import os
import sqlite3
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from harness.store import db, engagements, reasoning  # noqa: E402


def _probe_request(tool="sqli", target="t1.sandbox.local", port=80):
    return {"tool": tool, "intent": "probe", "target": target, "port": port, "args": {"q": "' OR 1=1"}}


def test_record_then_read_roundtrips_with_parsed_decoded():
    c = db.connect()
    reasoning.record(c, engagement_id="eng-1", role="operator", session_id="vk-op-a",
                     asset="t1", technique_id="KB-WEB-INJ-SQLI-001", step=0,
                     raw="I will try a classic tautology on the login form.",
                     parsed=_probe_request(), probe_event_id="pe_001")
    turns = reasoning.for_run(c, "eng-1")
    assert len(turns) == 1
    t = turns[0]
    assert t["role"] == "operator" and t["session_id"] == "vk-op-a" and t["step"] == 0
    assert t["raw"].startswith("I will try")
    assert t["parsed"]["tool"] == "sqli" and t["parsed"]["args"]["q"] == "' OR 1=1"  # decoded object
    assert t["rejection"] is None and t["probe_event_id"] == "pe_001"
    assert t["at"]                                                # stamped


def test_rows_are_ordered_by_capture_sequence():
    c = db.connect()
    for i in range(3):
        reasoning.record(c, engagement_id="eng-1", role="operator", session_id="vk-op-a",
                         asset="t1", technique_id="KB-X", step=i, raw=f"turn {i}")
    steps = [t["step"] for t in reasoning.for_run(c, "eng-1")]
    assert steps == [0, 1, 2]


def test_a_rejected_turn_stores_the_reason_and_a_null_action():
    c = db.connect()
    reasoning.record(c, engagement_id="eng-1", role="operator", session_id="vk-op-a",
                     asset="t1", technique_id="KB-X", step=0,
                     raw="here is my plan in prose, no json", parsed=None, rejection="not_json")
    t = reasoning.for_run(c, "eng-1")[0]
    assert t["parsed"] is None and t["rejection"] == "not_json" and t["probe_event_id"] is None


def test_operator_and_verifier_turns_stay_distinct_sessions():
    c = db.connect()
    reasoning.record(c, engagement_id="eng-1", role="operator", session_id="vk-op-a",
                     asset="t1", technique_id="KB-X", step=0, raw="found it",
                     parsed=_probe_request(), probe_event_id="pe_001")
    reasoning.record(c, engagement_id="eng-1", role="verifier", session_id="vk-vf-b",
                     asset="t1", technique_id="KB-X", step=0, raw="reproduced on fresh snap",
                     parsed=_probe_request(), probe_event_id="pe_002")
    turns = reasoning.for_run(c, "eng-1")
    by_role = {t["role"]: t for t in turns}
    assert by_role["operator"]["session_id"] == "vk-op-a"
    assert by_role["verifier"]["session_id"] == "vk-vf-b"
    assert by_role["operator"]["session_id"] != by_role["verifier"]["session_id"]  # finder != verifier


def test_read_is_scoped_to_one_run():
    c = db.connect()
    reasoning.record(c, engagement_id="eng-1", role="operator", session_id="a",
                     asset="t1", technique_id="KB-X", step=0, raw="run one")
    reasoning.record(c, engagement_id="eng-2", role="operator", session_id="a",
                     asset="t1", technique_id="KB-X", step=0, raw="run two")
    assert [t["raw"] for t in reasoning.for_run(c, "eng-1")] == ["run one"]
    assert [t["raw"] for t in reasoning.for_run(c, "eng-2")] == ["run two"]


def test_engagements_reasoning_reads_the_same_records():
    c = db.connect()
    reasoning.record(c, engagement_id="eng-1", role="operator", session_id="a",
                     asset="t1", technique_id="KB-X", step=0, raw="via engagements")
    assert engagements.reasoning(c, "eng-1") == reasoning.for_run(c, "eng-1")


def test_a_captured_turn_cannot_be_rewritten_or_removed():
    c = db.connect()
    reasoning.record(c, engagement_id="eng-1", role="operator", session_id="a",
                     asset="t1", technique_id="KB-X", step=0, raw="immutable")
    c.commit()                                                   # the run's final save commits it
    for stmt, args in (("UPDATE role_turn SET raw=? WHERE engagement_id=?", ("tampered", "eng-1")),
                       ("DELETE FROM role_turn WHERE engagement_id=?", ("eng-1",))):
        try:
            with c:
                c.execute(stmt, args)
            raise AssertionError("expected the append-only trigger to abort")
        except sqlite3.Error:
            pass
    assert reasoning.for_run(c, "eng-1")[0]["raw"] == "immutable"   # unchanged


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
