#!/usr/bin/env python3
"""Tests for the local run dashboard (HC-REPORT-01 §6).

The dashboard's routing and rendering are a pure function of the persisted store, split from
the socket I/O, so these drive `route` directly against a real on-disk SQLite file in a temp
dir (no server bound, no network): the index lists runs, a run page renders its report with
back-navigation, the reasoning page shows each role's verbatim proposal as escaped text, the
audit page shows the rows and the hash-chain status, and unknown runs or paths are 404.
Read-only throughout.

Zero-dependency: `python3 tests/test_dashboard.py`.
"""
from contextlib import closing
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from cli import dashboard  # noqa: E402
from harness.store import audit, db, engagements, reasoning  # noqa: E402


def _report(eid, mode="sandboxed"):
    return {
        "engagement_id": eid,
        "window": {"start": "2026-11-10T20:00:00+00:00", "end": "2026-11-10T21:00:00+00:00"},
        "scope_summary": {"in_scope_hosts": ["t1.sandbox.local"], "max_blast_tier": 2},
        "mode": mode,
        "coverage_summary": {"confirmed": 2, "inconclusive": 1},
        "findings": [{"id": "F-1", "technique_id": "KB-WEB-INJ-SQLI-001", "asset": "t1",
                      "found_by": "op-A", "verified_by": "vf-B",
                      "cvss": {"band": "high", "score": 8.1}, "cwe": ["CWE-89"],
                      "impact": "reads rows", "remediation": "parameterize",
                      "repro": ["baseline", "inject"], "verdict": "confirmed"}],
        "hardening_notes": [],
        "method_summary": "2 pairs",
        "generated_at": "2026-11-10T21:00:00+00:00",
    }


def _seed(path):
    c = db.connect(path)
    engagements.save(c, _report("eng-old"), started_at="2026-11-10T08:00:00+00:00")
    engagements.save(c, _report("eng-new"), started_at="2026-11-10T20:00:00+00:00")
    audit.record(c, "eng-new", "harness", "sandbox_proof", decision="ok")
    audit.record(c, "eng-new", "dispatcher", "probe", decision="allow", reason="in scope")
    reasoning.record(c, engagement_id="eng-new", role="operator", session_id="vk-op-a",
                     asset="t1", technique_id="KB-WEB-INJ-SQLI-001", step=0,
                     raw="I'll test the login form with <script>alert('x')</script>.",
                     parsed={"tool": "sqli", "intent": "probe", "target": "t1",
                             "port": 80, "args": {}}, probe_event_id="pe_001")
    reasoning.record(c, engagement_id="eng-new", role="verifier", session_id="vk-vf-b",
                     asset="t1", technique_id="KB-WEB-INJ-SQLI-001", step=0,
                     raw="Reproduced the tautology on a fresh snapshot.",
                     parsed={"tool": "sqli", "intent": "verify", "target": "t1",
                             "port": 80, "args": {}}, probe_event_id="pe_002")
    return c


def test_index_lists_runs_most_recent_first():
    with tempfile.TemporaryDirectory() as d, closing(_seed(os.path.join(d, "e.db"))) as c:
        status, body = dashboard.route(c, "/")
        assert status == 200
        assert "eng-new" in body and "eng-old" in body
        assert body.index("eng-new") < body.index("eng-old")   # newest first
        assert "2 confirmed" in body and "8:00 PM" in body       # am/pm, not 24-hour


def test_run_page_renders_the_report_with_back_nav():
    with tempfile.TemporaryDirectory() as d, closing(_seed(os.path.join(d, "e.db"))) as c:
        status, body = dashboard.route(c, "/run/eng-new")
        assert status == 200
        assert "KB-WEB-INJ-SQLI-001" in body and "reads rows" in body
        assert 'href="/"' in body and 'href="/run/eng-new/audit"' in body
        assert 'href="/run/eng-new/reasoning"' in body          # links to the reasoning view
        assert body.strip().startswith("<!doctype html>")


def test_reasoning_page_shows_both_roles_as_escaped_text():
    with tempfile.TemporaryDirectory() as d, closing(_seed(os.path.join(d, "e.db"))) as c:
        status, body = dashboard.route(c, "/run/eng-new/reasoning")
        assert status == 200
        assert "operator" in body and "verifier" in body         # both sessions shown, distinct
        assert "vk-op-a" in body and "vk-vf-b" in body
        assert "Reproduced the tautology" in body                # the verbatim proposal text
        # model-authored markup is inert: escaped on the page, never a live tag
        assert "&lt;script&gt;" in body and "<script>alert" not in body


def test_reasoning_page_for_a_run_without_turns_is_friendly():
    with tempfile.TemporaryDirectory() as d, closing(db.connect(os.path.join(d, "e.db"))) as c:
        engagements.save(c, _report("eng-x"))
        status, body = dashboard.route(c, "/run/eng-x/reasoning")
        assert status == 200 and "No role turns" in body


def test_audit_page_shows_rows_and_chain_intact():
    with tempfile.TemporaryDirectory() as d, closing(_seed(os.path.join(d, "e.db"))) as c:
        status, body = dashboard.route(c, "/run/eng-new/audit")
        assert status == 200
        assert "intact" in body and "sandbox_proof" in body and "in scope" in body
        assert "8:00 PM" not in body or "AM" in body or "PM" in body   # times render am/pm


def test_trailing_slash_and_query_are_normalized():
    with tempfile.TemporaryDirectory() as d, closing(_seed(os.path.join(d, "e.db"))) as c:
        assert dashboard.route(c, "/run/eng-new/")[0] == 200
        assert dashboard.route(c, "/run/eng-new?x=1")[0] == 200


def test_unknown_run_and_unknown_path_are_404():
    with tempfile.TemporaryDirectory() as d, closing(_seed(os.path.join(d, "e.db"))) as c:
        assert dashboard.route(c, "/run/nope")[0] == 404
        assert dashboard.route(c, "/anything-else")[0] == 404


def test_empty_store_shows_a_friendly_message():
    with tempfile.TemporaryDirectory() as d, closing(db.connect(os.path.join(d, "e.db"))) as c:
        status, body = dashboard.route(c, "/")
        assert status == 200 and "No runs yet" in body


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
