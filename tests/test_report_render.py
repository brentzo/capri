#!/usr/bin/env python3
"""Tests for the human-readable report renderer (HC-REPORT-01 §5).

The renderer is a pure function from a validated report (HC-FIND-01 §7) to a self-contained
HTML page, so these drive it with report dicts and assert on the output: findings show impact,
severity, CWE, and the distinct finder and verifier; times render in am/pm, not a 24-hour
clock; every dynamic value is HTML-escaped so model-authored or target text cannot inject
markup; hardening notes render separately with no severity; and a passive-only run shows its
banner and no findings. No store, no server.

Zero-dependency: `python3 tests/test_report_render.py`.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from harness import report_render as rr  # noqa: E402


def _report(mode="sandboxed", findings=None, hardening=None):
    return {
        "engagement_id": "eng-2026-11-10-001",
        "window": {"start": "2026-11-10T20:00:00+00:00", "end": "2026-11-10T21:30:00+00:00"},
        "scope_summary": {"in_scope_hosts": ["t1.sandbox.local"], "max_blast_tier": 2},
        "mode": mode,
        "coverage_summary": {"confirmed": 3, "inconclusive": 1, "not_applicable": 5},
        "findings": findings if findings is not None else [_finding()],
        "hardening_notes": hardening or [],
        "method_summary": "9 pairs evaluated, KB live",
        "generated_at": "2026-11-10T21:30:00+00:00",
    }


def _finding(**over):
    f = {"id": "F-1", "technique_id": "KB-WEB-INJ-SQLI-001", "technique_version": "1.0.0",
         "asset": "t1.sandbox.local/orders?id=", "classification": "vulnerability",
         "cwe": ["CWE-89"], "cvss": {"band": "high", "score": 8.1}, "verdict": "confirmed",
         "found_by": "vk-operator-aaaa", "verified_by": "vk-verifier-bbbb",
         "impact": "reads arbitrary rows from the orders table",
         "remediation": "parameterize the query", "repro": ["baseline GET", "inject payload"]}
    f.update(over)
    return f


def test_a_finding_shows_impact_severity_cwe_and_distinct_actors():
    out = rr.render_html(_report())
    for needle in ("KB-WEB-INJ-SQLI-001", "t1.sandbox.local/orders", "arbitrary rows",
                   "parameterize the query", "high", "8.1", "CWE-89",
                   "vk-operator-aaaa", "vk-verifier-bbbb"):
        assert needle in out, needle
    assert out.strip().startswith("<!doctype html>")


def test_times_render_in_am_pm_not_24_hour():
    out = rr.render_html(_report())
    assert "8:00 PM" in out and "9:30 PM" in out       # 20:00 and 21:30 UTC
    assert "20:00" not in out and "21:30" not in out


def test_am_pm_handles_noon_midnight_and_morning():
    assert "12:30 AM" in rr.am_pm("2026-11-10T00:30:00+00:00")
    assert "12:00 PM" in rr.am_pm("2026-11-10T12:00:00+00:00")
    assert "9:05 AM" in rr.am_pm("2026-11-10T09:05:00+00:00")
    assert rr.am_pm("") == "" and rr.am_pm("not-a-date") == "not-a-date"


def test_untrusted_text_is_escaped_not_rendered_as_markup():
    evil = '<script>alert(1)</script>'
    out = rr.render_html(_report(findings=[_finding(impact=evil)]))
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    assert "<script>alert(1)" not in out                # the raw tag never reaches the page


def test_hardening_notes_render_separately_without_severity():
    note = {"id": "H-1", "technique_id": "KB-WEB-PROTO-HSTS-001", "asset": "t1",
            "classification": "hardening_note", "note": "HSTS header absent"}
    out = rr.render_html(_report(hardening=[note]))
    assert "Hardening notes" in out and "HSTS header absent" in out


def test_passive_only_shows_a_banner_and_no_findings():
    out = rr.render_html(_report(mode="passive-only", findings=[]))
    assert "passive-only" in out and "did not have continuously proven" in out
    assert "No confirmed findings" in out


def test_coverage_counts_render():
    out = rr.render_html(_report())
    assert "confirmed" in out and ">3<" in out


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
