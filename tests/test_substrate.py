#!/usr/bin/env python3
"""Adversarial tests for the M0 substrate logic (HC-SUB-01 §4-§7, §12).

Covers contract parsing/validation (fail-closed), the scope guard pre-check
(default-deny, out_of_scope wins, anti-TOCTOU pinning), and the blast-tier gate.
Zero-dependency: `python3 tests/test_substrate.py` (also pytest-discoverable).
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.substrate import contract, scope, blast  # noqa: E402

VALID = """engagement:
  id: eng-2026-11-08-001
  authorized_by: brent / TICKET-1234
  window: { start: 2026-11-08T20:00, end: 2026-11-08T23:59 }
  max_blast_tier: 2
scope:
  in_scope_hosts: [app.sandbox.local]
  in_scope_cidrs: [10.13.0.0/24]
  out_of_scope: [10.13.0.1]
  allowed_ports: { default: [80, 443], "10.13.0.0/24": [22, 80, 443, 5432] }
policy:
  allowed_tactics: [recon, discovery]
  forbidden: [exfil-to-internet]
  rate: { max_rps_per_target: 20, max_actions_per_run: 5000 }
  tier3_techniques: [KB-WEB-INJ-XSS-002]
"""


def eng():
    e, errs = contract.parse(VALID)
    assert not errs, errs
    return e


# --- contract parsing / validation (fail-closed) -------------------------
def test_valid_contract_parses():
    e, errs = contract.parse(VALID)
    assert errs == [] and e is not None
    assert e.max_blast_tier == 2 and e.id == "eng-2026-11-08-001"


def test_missing_scope_fails():
    text = VALID.split("scope:")[0]  # engagement only
    e, errs = contract.parse(text)
    assert e is None and any("scope" in x for x in errs)


def test_bad_blast_tier_fails():
    e, errs = contract.parse(VALID.replace("max_blast_tier: 2", "max_blast_tier: 5"))
    assert e is None and any("max_blast_tier" in x for x in errs)


def test_window_start_after_end_fails():
    bad = VALID.replace("start: 2026-11-08T20:00, end: 2026-11-08T23:59",
                        "start: 2026-11-08T23:59, end: 2026-11-08T20:00")
    e, errs = contract.parse(bad)
    assert e is None and any("before end" in x for x in errs)


def test_invalid_cidr_fails():
    e, errs = contract.parse(VALID.replace("10.13.0.0/24", "10.13.0.0/99"))
    assert e is None and errs


def test_management_overlap_fails():
    e, errs = contract.parse(VALID, management_cidrs=["10.13.0.0/16"])
    assert e is None and any("management" in x for x in errs)


def test_malformed_yaml_fails():
    e, errs = contract.parse("engagement:\n\tid: tabbed")
    assert e is None and errs


# --- scope guard ---------------------------------------------------------
def test_scope_allows_in_scope_ip_and_port():
    assert scope.scope_validate(eng(), "10.13.0.5", 443) == ("allow", None)


def test_scope_out_of_scope_wins():
    v, reason = scope.scope_validate(eng(), "10.13.0.1", 443)
    assert v == "deny" and "out_of_scope" in reason


def test_scope_denies_target_outside_cidr():
    v, reason = scope.scope_validate(eng(), "192.168.0.5", 443)
    assert v == "deny" and "not_in_scope" in reason


def test_scope_denies_disallowed_port():
    v, reason = scope.scope_validate(eng(), "10.13.0.5", 8080)
    assert v == "deny" and "port_not_allowed" in reason


def test_scope_denies_unpinned_host():
    v, reason = scope.scope_validate(eng(), "app.sandbox.local", 443)
    assert v == "deny" and "unpinned_host" in reason


def test_scope_allows_pinned_host():
    e = eng()
    assert e.pin({"app.sandbox.local": "10.13.0.10"}) == []
    assert scope.scope_validate(e, "app.sandbox.local", 443) == ("allow", None)


def test_pin_rejects_ip_outside_cidr():
    e = eng()
    errs = e.pin({"app.sandbox.local": "192.168.1.1"})
    assert errs and "outside in_scope_cidrs" in errs[0]


def test_pin_rejects_out_of_scope_ip():
    e = eng()
    errs = e.pin({"app.sandbox.local": "10.13.0.1"})
    assert errs and "out_of_scope" in errs[0]


# --- blast gate ----------------------------------------------------------
def test_blast_allows_within_cap_with_snapshot():
    assert blast.blast_gate(eng(), 2, has_snapshot=True) == ("allow", None)


def test_blast_denies_over_cap():
    v, reason = blast.blast_gate(eng(), 3, has_snapshot=True,
                                 technique_id="KB-WEB-INJ-XSS-002")
    assert v == "deny" and "blocked_by_policy" in reason   # cap is 2


def test_blast_denies_tier2_without_snapshot():
    v, reason = blast.blast_gate(eng(), 2, has_snapshot=False)
    assert v == "deny" and "snapshot_required" in reason


def test_blast_tier3_requires_named_technique():
    e, _ = contract.parse(VALID.replace("max_blast_tier: 2", "max_blast_tier: 3"))
    v1, r1 = blast.blast_gate(e, 3, has_snapshot=True, technique_id="KB-OTHER-000")
    assert v1 == "deny" and "tier3_not_authorized" in r1
    v2, r2 = blast.blast_gate(e, 3, has_snapshot=True,
                              technique_id="KB-WEB-INJ-XSS-002")
    assert v2 == "allow"


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
