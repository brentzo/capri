#!/usr/bin/env python3
"""Tests for the deterministic Planner (HC-AGENT-01 §3).

Proves the ordering contract: most-severe-first, then lowest-blast-tier-first
within a band, then a stable (technique, asset) tiebreak so a plan is
reproducible; an unknown card ranks as medium rather than crashing; the plan
returns every candidate and never mutates the input. Zero-dependency:
`python3 tests/test_planner.py`.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.loop import Pair                                  # noqa: E402
from harness.planner import DeterministicPlanner               # noqa: E402


def _card(band, tier):
    return {"severity_rubric": {"base": band}, "blast_tier": tier}


KB = {
    ("T-CRIT", "1.0.0"): _card("critical", 1),
    ("T-HIGH-LOW", "1.0.0"): _card("high", 0),
    ("T-HIGH-HI", "1.0.0"): _card("high", 2),
    ("T-MED", "1.0.0"): _card("medium", 0),
}


def _ids(pairs):
    return [p.technique_id for p in pairs]


def test_orders_by_severity_then_blast_tier():
    cands = [Pair("web", "T-MED", "1.0.0"), Pair("web", "T-HIGH-HI", "1.0.0"),
             Pair("web", "T-CRIT", "1.0.0"), Pair("web", "T-HIGH-LOW", "1.0.0")]
    assert _ids(DeterministicPlanner(KB).plan({}, cands, {})) == \
        ["T-CRIT", "T-HIGH-LOW", "T-HIGH-HI", "T-MED"]


def test_lower_blast_tier_first_within_a_band():
    cands = [Pair("web", "T-HIGH-HI", "1.0.0"), Pair("web", "T-HIGH-LOW", "1.0.0")]
    assert _ids(DeterministicPlanner(KB).plan({}, cands, {})) == ["T-HIGH-LOW", "T-HIGH-HI"]


def test_stable_tiebreak_is_deterministic():
    # same card (equal severity and tier) on two assets -> (technique, asset) tiebreak,
    # and the order does not depend on the input order
    cands = [Pair("web", "T-HIGH-LOW", "1.0.0"), Pair("db", "T-HIGH-LOW", "1.0.0")]
    p = DeterministicPlanner(KB)
    out1 = [(x.technique_id, x.asset) for x in p.plan({}, cands, {})]
    out2 = [(x.technique_id, x.asset) for x in p.plan({}, list(reversed(cands)), {})]
    assert out1 == out2 == [("T-HIGH-LOW", "db"), ("T-HIGH-LOW", "web")]


def test_unknown_card_treated_as_medium():
    cands = [Pair("web", "T-UNKNOWN", "1.0.0"), Pair("web", "T-CRIT", "1.0.0"),
             Pair("web", "T-MED", "1.0.0")]
    out = _ids(DeterministicPlanner(KB).plan({}, cands, {}))
    assert out[0] == "T-CRIT"                           # critical still first
    assert out[1:] == ["T-MED", "T-UNKNOWN"]            # unknown ranks medium, tiebreak by id


def test_plan_returns_all_candidates_without_mutating_input():
    cands = [Pair("web", "T-MED", "1.0.0"), Pair("web", "T-CRIT", "1.0.0")]
    before = _ids(cands)
    plan = DeterministicPlanner(KB).plan({}, cands, {})
    assert len(plan) == len(cands)
    assert {(x.technique_id, x.asset) for x in plan} == {(x.technique_id, x.asset) for x in cands}
    assert _ids(cands) == before                        # sorted() returns a new list


def test_empty_candidates():
    assert DeterministicPlanner(KB).plan({}, [], {}) == []


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
