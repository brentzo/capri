#!/usr/bin/env python3
"""Tests for the run-local world-state blackboard (HC-OBJ-01 §5).

Covers the fact tiers and the invariants that carry finder-is-not-verifier into a
chain: a confirmed fact supersedes its provisional predecessor, a provisional fact
never downgrades a confirmed one, the append-only log keeps the superseded facts,
only confirmed facts appear in the gating view, a fact's scope must be satisfied by
the query context, and the view feeds the predicate evaluator unchanged.

Zero-dependency: `python3 tests/test_blackboard.py`.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import predicates                                 # noqa: E402
from harness.blackboard import CONFIRMED, PROVISIONAL, Blackboard   # noqa: E402

APP = {"host": "app.sandbox.local"}
DB = {"host": "db.sandbox.local"}


def test_put_and_get_a_fact_with_provenance():
    b = Blackboard(clock=lambda: "T0")
    f = b.put("credential", APP, CONFIRMED, produced_by="F-1", event_ids=["pe-1", "pe-2"])
    got = b.get("credential", APP)
    assert got is f and got.tier == CONFIRMED and got.value is True
    assert got.produced_by == "F-1" and got.event_ids == ("pe-1", "pe-2") and got.at == "T0"
    assert b.get("credential", DB) is None                     # a different scope is a different fact


def test_confirmed_supersedes_provisional():
    b = Blackboard()
    b.put("foothold", DB, PROVISIONAL, produced_by="F-lead")
    assert not b.is_confirmed("foothold", DB)
    b.put("foothold", DB, CONFIRMED, produced_by="F-conf")
    assert b.is_confirmed("foothold", DB)
    assert b.get("foothold", DB).produced_by == "F-conf"


def test_provisional_does_not_downgrade_a_confirmed_fact():
    b = Blackboard()
    b.put("foothold", DB, CONFIRMED, produced_by="F-conf")
    b.put("foothold", DB, PROVISIONAL, produced_by="F-late-lead")   # arrives stale
    cur = b.get("foothold", DB)
    assert cur.tier == CONFIRMED and cur.produced_by == "F-conf"


def test_append_only_log_keeps_superseded_facts():
    b = Blackboard()
    b.put("foothold", DB, PROVISIONAL)
    b.put("foothold", DB, CONFIRMED)
    assert len(b.facts()) == 2 and len(b.current()) == 1       # history kept, one current


def test_only_confirmed_facts_appear_in_the_gating_view():
    b = Blackboard()
    b.put("credential", APP, PROVISIONAL)
    assert b.view(APP, tier=CONFIRMED) == {}                    # provisional never gates
    assert b.view(APP, tier=PROVISIONAL) == {"credential": True}   # but informs exploration
    b.put("credential", APP, CONFIRMED)
    assert b.view(APP, tier=CONFIRMED) == {"credential": True}


def test_scope_must_be_satisfied_by_the_context():
    b = Blackboard()
    b.put("foothold", DB, CONFIRMED)
    b.put("recon_done", None, CONFIRMED)                        # globally scoped
    assert b.view(DB) == {"foothold": True, "recon_done": True}
    assert b.view(APP) == {"recon_done": True}                  # db-scoped fact not visible at app


def test_seed_loads_recon_facts_as_confirmed():
    b = Blackboard(seed=[{"name": "asset.type", "scope": APP, "value": "web_api"},
                         {"name": "reachable", "scope": APP}])
    assert b.is_confirmed("asset.type", APP)
    assert b.view(APP, tier=CONFIRMED) == {"asset.type": "web_api", "reachable": True}
    assert b.get("asset.type", APP).produced_by == "recon"


def test_view_feeds_the_predicate_evaluator():
    b = Blackboard()
    b.put("rce_foothold", APP, CONFIRMED)
    app_view = b.view(APP, tier=CONFIRMED)
    db_view = b.view(DB, tier=CONFIRMED)
    assert predicates.evaluate("exists(rce_foothold)", app_view) is True
    assert predicates.evaluate("exists(rce_foothold)", db_view) is False   # not confirmed here


def test_put_many_writes_a_cards_yields():
    b = Blackboard()
    b.put_many([{"name": "credential", "scope": APP}, {"name": "db_read", "scope": DB}],
               tier=CONFIRMED, produced_by="F-7")
    assert b.is_confirmed("credential", APP) and b.is_confirmed("db_read", DB)
    assert b.producer("credential", APP) == "F-7"


def test_unknown_tier_is_rejected():
    b = Blackboard()
    try:
        b.put("x", APP, "verified")
        raise AssertionError("expected a ValueError for an unknown tier")
    except ValueError:
        pass


def test_value_bearing_fact_compares_in_a_predicate():
    b = Blackboard()
    b.put("flag.captured", DB, CONFIRMED)
    b.put("flag.host", DB, CONFIRMED, value="db.sandbox.local")
    view = b.view(DB, tier=CONFIRMED)
    assert predicates.evaluate("exists(flag.captured) && flag.host == 'db.sandbox.local'", view)


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
