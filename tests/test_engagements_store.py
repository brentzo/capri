#!/usr/bin/env python3
"""Tests for durable run persistence and the dashboard read API (HC-REPORT-01 §2).

A finished run is saved as one `engagement` summary row carrying its validated report,
so it must still list and re-open after the connection that wrote it is closed, which is
how the dashboard reads a run the engagement process has long since exited. These drive
the store against a real on-disk SQLite file in a temp dir (no Docker, no model plane),
reopening it between write and read to prove the data survives the process.

Zero-dependency: `python3 tests/test_engagements_store.py`.
"""
from contextlib import closing
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from harness.store import audit, datadir, db, engagements  # noqa: E402


def _report(eid="eng-test-001", mode="sandboxed"):
    return {
        "engagement_id": eid,
        "window": {"start": "2026-11-10T20:00:00+00:00", "end": "2026-11-10T21:00:00+00:00"},
        "scope_summary": {"in_scope_hosts": ["t1.sandbox.local"], "max_blast_tier": 2},
        "mode": mode,
        "coverage_summary": {"confirmed": 3, "inconclusive": 1, "not_applicable": 5},
        "findings": [{"id": "F-1", "technique_id": "KB-WEB-INJ-SQLI-001", "asset": "t1",
                      "found_by": "op-A", "verified_by": "vf-B",
                      "cvss": {"band": "high", "score": 8.1}, "cwe": ["CWE-89"],
                      "impact": "reads rows", "remediation": "parameterize", "verdict": "confirmed"}],
        "hardening_notes": [],
        "method_summary": "1 pair evaluated",
        "generated_at": "2026-11-10T21:00:00+00:00",
    }


def test_a_saved_run_lists_and_reopens_after_the_writer_is_closed():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "engagements.db")
        w = db.connect(path)
        engagements.save(w, _report("eng-1"), valid=True)
        w.close()                                             # the engagement process exits

        with closing(db.connect(path)) as r:                  # the dashboard opens it later
            rows = engagements.list_all(r)
            got = engagements.get(r, "eng-1")
        assert len(rows) == 1 and rows[0]["id"] == "eng-1"
        assert rows[0]["mode"] == "sandboxed" and rows[0]["valid"] is True
        assert rows[0]["coverage_summary"]["confirmed"] == 3
        assert rows[0]["in_scope_hosts"] == ["t1.sandbox.local"]
        assert got["report"]["findings"][0]["technique_id"] == "KB-WEB-INJ-SQLI-001"
        assert got["report"]["findings"][0]["found_by"] != got["report"]["findings"][0]["verified_by"]


def test_list_orders_most_recent_first():
    with tempfile.TemporaryDirectory() as d:
        with closing(db.connect(os.path.join(d, "e.db"))) as c:
            engagements.save(c, _report("eng-old"), started_at="2026-11-10T08:00:00+00:00")
            engagements.save(c, _report("eng-new"), started_at="2026-11-10T20:00:00+00:00")
            ids = [r["id"] for r in engagements.list_all(c)]
        assert ids == ["eng-new", "eng-old"]


def test_get_unknown_run_is_none():
    with tempfile.TemporaryDirectory() as d:
        with closing(db.connect(os.path.join(d, "e.db"))) as c:
            assert engagements.get(c, "nope") is None


def test_save_is_idempotent_by_id():
    with tempfile.TemporaryDirectory() as d:
        with closing(db.connect(os.path.join(d, "e.db"))) as c:
            engagements.save(c, _report("eng-x", mode="sandboxed"))
            engagements.save(c, _report("eng-x", mode="passive-only"))   # same run, re-saved
            rows = engagements.list_all(c)
        assert len(rows) == 1 and rows[0]["mode"] == "passive-only"


def test_audit_trail_filters_by_run_and_reports_chain_integrity():
    with tempfile.TemporaryDirectory() as d:
        with closing(db.connect(os.path.join(d, "e.db"))) as c:
            audit.record(c, "eng-1", "harness", "sandbox_proof", decision="ok")
            audit.record(c, "eng-1", "dispatcher", "probe", decision="allow")
            audit.record(c, "eng-2", "harness", "sandbox_proof", decision="ok")   # a different run
            trail = engagements.audit(c, "eng-1")
        assert len(trail["rows"]) == 2 and trail["chain_ok"] is True
        assert all(row["engagement_id"] == "eng-1" for row in trail["rows"])


def test_datadir_prefers_override_then_env_then_default():
    with tempfile.TemporaryDirectory() as over, tempfile.TemporaryDirectory() as env:
        assert datadir.base(over) == over                     # explicit override wins
        assert datadir.db_path(over) == os.path.join(over, "engagements.db")
        assert datadir.blob_root(over) == os.path.join(over, "blobs")
        assert os.path.isdir(os.path.join(over, "blobs"))     # created on request

        old = os.environ.get(datadir.ENV_VAR)
        os.environ[datadir.ENV_VAR] = env
        try:
            assert datadir.base() == env                      # env used when no override
        finally:
            if old is None:
                os.environ.pop(datadir.ENV_VAR, None)
            else:
                os.environ[datadir.ENV_VAR] = old


def test_reopening_a_persistent_db_does_not_error_on_existing_tables():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "e.db")
        db.connect(path).close()
        db.connect(path).close()                              # schema is CREATE ... IF NOT EXISTS


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
