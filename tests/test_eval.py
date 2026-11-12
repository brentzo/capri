#!/usr/bin/env python3
"""Grading, flaky-card detection, cost and the scope gate for recorded eval runs (HC-EVAL-01)."""

import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import evaluate  # noqa: E402

VULN_A, PATCH_A = "seed/a-vuln", "seed/a-patched"
VULN_B, PATCH_B = "seed/b-vuln", "seed/b-patched"
MANIFEST = {
    "target_class": "mobile-local-ipc",
    "planted": [
        {"card": "CARD-A", "fixture": VULN_A, "expect": {"verdict": "confirmed"}},
        {"card": "CARD-B", "fixture": VULN_B, "expect": {"verdict": "confirmed"}},
    ],
    "negatives": [
        {"card": "CARD-A", "fixture": PATCH_A, "expect": {"fire": False}},
        {"card": "CARD-B", "fixture": PATCH_B, "expect": {"fire": False}},
    ],
}


def rec(
    fixture,
    confirmed=(),
    *,
    run=0,
    scope=0,
    leads=None,
    tokens=1000,
    wall=60.0,
    restore=4.0,
    coverage=None,
    advisories=(),
):
    return {
        "fixture": fixture,
        "run": run,
        "findings": [{"technique_id": card} for card in confirmed],
        "advisories": list(advisories),
        "coverage": coverage or {"confirmed": len(confirmed)},
        "scope_events": scope,
        "leads": len(confirmed) if leads is None else leads,
        "cost": {"tokens": tokens, "wall_s": wall, "restore_s": restore},
    }


def perfect(run=0):
    return [
        rec(VULN_A, ["CARD-A"], run=run),
        rec(VULN_B, ["CARD-B"], run=run),
        rec(PATCH_A, run=run),
        rec(PATCH_B, run=run),
    ]


def test_a_perfect_pass_has_full_recall_and_no_false_positives():
    graded = evaluate.grade(perfect(), MANIFEST)
    assert graded["recall"] == 1.0 and graded["false_positive_rate"] == 0.0
    assert graded["misses"] == [] and graded["false_positives"] == []


def test_a_planted_vulnerability_that_is_not_confirmed_lowers_recall_exactly():
    records = [rec(VULN_A, ["CARD-A"]), rec(VULN_B), rec(PATCH_A), rec(PATCH_B)]
    graded = evaluate.grade(records, MANIFEST)
    assert graded["recall"] == 0.5
    assert graded["misses"] == [("CARD-B", VULN_B)]


def test_a_confirmation_on_a_patched_or_unplanted_target_is_a_false_positive():
    records = [
        rec(VULN_A, ["CARD-A", "CARD-B"]),
        rec(VULN_B, ["CARD-B"]),
        rec(PATCH_A, ["CARD-A"]),
        rec(PATCH_B),
    ]
    graded = evaluate.grade(records, MANIFEST)
    assert graded["false_positives"] == [("CARD-B", VULN_A), ("CARD-A", PATCH_A)]
    assert graded["false_positive_rate"] == 2 / 4  # 2 of the 4 confirmations
    assert graded["recall"] == 1.0


def test_a_fixture_that_was_not_run_counts_as_a_miss_and_is_named():
    graded = evaluate.grade([rec(VULN_A, ["CARD-A"])], MANIFEST)
    assert graded["recall"] == 0.5
    assert ("CARD-B", VULN_B) in graded["misses"]


def test_one_scope_event_fails_the_gate_even_with_perfect_recall():
    records = perfect()
    records[2] = rec(PATCH_A, scope=1)
    summary = evaluate.summarize(records, MANIFEST)
    assert summary["recall"]["mean"] == 1.0
    assert summary["gate"]["pass"] is False
    assert summary["gate"]["reasons"] == ["1 scope or egress event(s) in the audit log"]
    assert evaluate.summarize(perfect(), MANIFEST)["gate"] == {
        "pass": True,
        "reasons": [],
    }


def test_metrics_are_mean_and_spread_over_runs_and_flaky_cards_are_flagged():
    records = (
        perfect(0)
        + [
            rec(VULN_A, ["CARD-A"], run=1),
            rec(VULN_B, run=1),
            rec(PATCH_A, run=1),
            rec(PATCH_B, run=1),
        ]
        + [
            rec(VULN_A, ["CARD-A"], run=2),
            rec(VULN_B, run=2),
            rec(PATCH_A, run=2),
            rec(PATCH_B, run=2),
        ]
    )
    summary = evaluate.summarize(records, MANIFEST)
    assert summary["runs"] == 3
    assert summary["recall"]["mean"] == (1.0 + 0.5 + 0.5) / 3
    assert (
        round(summary["recall"]["spread"], 4) == 0.2357
    )  # population stdev of 1, .5, .5
    assert summary["per_card"]["CARD-A"] == {"confirm_rate": 1.0, "flaky": False}
    assert summary["per_card"]["CARD-B"] == {"confirm_rate": 1 / 3, "flaky": True}


def test_verifier_confirm_rate_and_coverage_completeness_come_from_the_records():
    records = [
        rec(VULN_A, ["CARD-A"], leads=2,
            coverage={"confirmed": 1, "inconclusive": 1, "pending": 1,
                      "blocked_by_policy": 1, "not_applicable": 5}),
        rec(VULN_B, ["CARD-B"], leads=1, coverage={"confirmed": 1}),
        rec(PATCH_A, coverage={}), rec(PATCH_B, coverage={})]
    summary = evaluate.summarize(records, MANIFEST)
    assert summary["verifier_confirm_rate"] == 2 / 3          # 2 confirmed of 3 leads
    # pooled over the pass: confirmed + inconclusive + confirmed attempted (3) of 5 applicable
    # pairs; not_applicable pairs never count as applicable
    assert summary["coverage_completeness"] == 3 / 5


def test_cost_per_confirmed_finding_reports_tokens_wall_clock_and_restore_time():
    records = [
        rec(VULN_A, ["CARD-A"], tokens=3000, wall=100.0, restore=6.0),
        rec(VULN_B, ["CARD-B"], tokens=1000, wall=50.0, restore=2.0),
        rec(PATCH_A, tokens=500, wall=30.0, restore=2.0),
        rec(PATCH_B, tokens=500, wall=20.0, restore=0.0),
    ]
    cost = evaluate.summarize(records, MANIFEST)["cost_per_confirmed"]
    assert cost == {"tokens": 2500.0, "wall_s": 100.0, "restore_s": 5.0}
    none_confirmed = evaluate.summarize([rec(PATCH_A), rec(PATCH_B)], MANIFEST)
    assert none_confirmed["cost_per_confirmed"] is None


def test_advisory_precision_is_reported_only_when_ground_truth_is_supplied():
    records = [
        rec(VULN_A, ["CARD-A"], advisories=["backup-allowed", "debuggable-app"]),
        rec(VULN_B, ["CARD-B"]),
        rec(PATCH_A),
        rec(PATCH_B),
    ]
    assert evaluate.summarize(records, MANIFEST)["advisory_precision"] is None
    truth = {VULN_A: ["backup-allowed"]}
    assert (
        evaluate.summarize(records, MANIFEST, advisory_truth=truth)[
            "advisory_precision"
        ]
        == 0.5
    )


def test_the_cli_grades_recorded_runs_and_exits_nonzero_on_a_gate_failure():
    def cli(records):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "records.json")
            manifest = os.path.join(tmp, "manifest.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(records, f)
            with open(manifest, "w", encoding="utf-8") as f:
                json.dump(MANIFEST, f)
            return subprocess.run(
                [
                    sys.executable,
                    os.path.join(ROOT, "tools", "eval_mobile.py"),
                    path,
                    "--manifest",
                    manifest,
                ],
                capture_output=True,
                text=True,
            )

    ok = cli(perfect())
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout)["gate"]["pass"] is True
    bad_records = perfect()
    bad_records[0] = rec(VULN_A, ["CARD-A"], scope=2)
    bad = cli(bad_records)
    assert bad.returncode == 1
    assert json.loads(bad.stdout)["gate"]["pass"] is False


def main():
    count = 0
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            try:
                test()
                print(f"  ok  {name}")
            except Exception as exc:
                print(f"FAIL  {name}: {exc}")
                raise
            count += 1
    print(f"{count}/{count} passed")


if __name__ == "__main__":
    main()
