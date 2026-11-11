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


def test_source_root_absent_is_none():
    assert eng().source_root is None       # optional: a contract without it is black-box


def test_source_root_parses_when_present():
    text = VALID.replace("  max_blast_tier: 2",
                         "  max_blast_tier: 2\n  source_root: /srv/app")
    e, errs = contract.parse(text)
    assert errs == [] and e.source_root == "/srv/app"


def test_source_root_must_be_a_nonempty_string():
    text = VALID.replace("  max_blast_tier: 2",
                         '  max_blast_tier: 2\n  source_root: ""')
    e, errs = contract.parse(text)
    assert e is None and any("source_root" in x for x in errs)


# --- engagement.target (app + datastore the range stands up, HC-SUB-01 §4) ----------
def _with_target(block):
    return VALID.replace("  max_blast_tier: 2", "  max_blast_tier: 2\n" + block)


def test_target_absent_is_none():
    assert eng().target is None            # optional: a contract without it runs the bundled listener


def test_target_services_only_parses_and_normalizes_defaults():
    e, errs = contract.parse(_with_target(
        "  target:\n"
        "    services:\n"
        "      - { name: db, engine: postgres, init_sql: ./seed.sql }\n"))
    assert errs == [] and e.target is not None
    svc = e.target["services"][0]
    # defaults fill in: version 16, app/app/app credentials, the alias is the service name
    assert svc == {"name": "db", "engine": "postgres", "version": "16",
                   "init_sql": "./seed.sql", "user": "app", "password": "app", "db": "app"}


def test_target_full_build_and_db_parses():
    e, errs = contract.parse(_with_target(
        "  target:\n"
        "    build: { context: ., dockerfile: Dockerfile }\n"
        "    port: 3000\n"
        '    env: { DATABASE_URL: "postgres://app:app@db:5432/app" }\n'
        "    ready: { path: /healthz, timeout_s: 45 }\n"
        "    services:\n"
        "      - { name: db, engine: postgres, version: \"16\" }\n"))
    assert errs == []
    assert e.target["build"] == {"context": ".", "dockerfile": "Dockerfile"}
    assert e.target["port"] == 3000 and e.target["ready"] == {"path": "/healthz", "timeout_s": 45}
    assert e.target["env"]["DATABASE_URL"] == "postgres://app:app@db:5432/app"


def test_target_image_and_build_are_mutually_exclusive():
    e, errs = contract.parse(_with_target(
        "  target:\n    image: myapp:local\n    build: { context: . }\n    port: 8080\n"))
    assert e is None and any("exactly one" in x for x in errs)


def test_target_app_requires_a_port():
    e, errs = contract.parse(_with_target("  target:\n    image: myapp:local\n"))
    assert e is None and any("port is required" in x for x in errs)


def test_target_rejects_unsupported_keys_rather_than_ignoring_them():
    # A directive that would breach containment (a host volume) must fail loudly, not slip through.
    e, errs = contract.parse(_with_target(
        "  target:\n    image: myapp:local\n    port: 8080\n    volumes: [\"/host:/data\"]\n"))
    assert e is None and any("unsupported key" in x and "volumes" in x for x in errs)


def test_target_rejects_an_unknown_service_engine():
    e, errs = contract.parse(_with_target(
        "  target:\n    services:\n      - { name: cache, engine: redis }\n"))
    assert e is None and any("engine must be one of" in x for x in errs)


def test_target_rejects_a_non_dns_safe_service_alias():
    e, errs = contract.parse(_with_target(
        "  target:\n    services:\n      - { name: DB_1, engine: postgres }\n"))
    assert e is None and any("DNS-safe alias" in x for x in errs)


def test_target_must_declare_something():
    e, errs = contract.parse(_with_target("  target: {}\n"))
    assert e is None and any("must declare an image, a build, or at least one service" in x for x in errs)


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


# --- objective block (HC-OBJ-01 §4, fail-closed) -------------------------
CANARY = """objective:
  id: obj-flag
  description: "Read the planted secret."
  type: canary
  target: app.sandbox.local
  success: "exists(flag.captured) && flag.host == 'app.sandbox.local'"
  proof:
    kind: canary
    location: "/flag.txt"
    sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  on_success: stop
"""


def _with(objective="", extra_policy=""):
    text = VALID
    if extra_policy:
        text = text.rstrip() + "\n  " + extra_policy + "\n"
    if objective:
        text = text.rstrip() + "\n" + objective
    return text


def test_no_objective_runs_as_before():
    e, errs = contract.parse(VALID)
    assert errs == [] and e.objective is None and e.lateral_movement is False


def test_valid_canary_objective_parses():
    e, errs = contract.parse(_with(CANARY))
    assert errs == [], errs
    assert e.objective["id"] == "obj-flag" and e.objective["type"] == "canary"


def test_objective_target_out_of_scope_is_rejected():
    bad = CANARY.replace("target: app.sandbox.local", "target: evil.example.com")
    e, errs = contract.parse(_with(bad))
    assert e is None and any("out-of-scope target aborts" in x for x in errs)


def test_objective_target_may_be_an_in_scope_ip():
    ipobj = CANARY.replace("target: app.sandbox.local", "target: 10.13.0.5")
    e, errs = contract.parse(_with(ipobj))
    assert errs == [], errs


def test_objective_target_in_out_of_scope_ip_is_rejected():
    # 10.13.0.1 is in_scope_cidrs but listed under out_of_scope
    ipobj = CANARY.replace("target: app.sandbox.local", "target: 10.13.0.1")
    e, errs = contract.parse(_with(ipobj))
    assert e is None and errs


def test_canary_inlining_the_plaintext_is_rejected():
    leak = CANARY.replace('sha256: "9f86d0', 'secret: "hunter2"\n    sha256: "9f86d0')
    e, errs = contract.parse(_with(leak))
    assert e is None and any("not the plaintext" in x for x in errs)


def test_canary_requires_a_valid_sha256():
    bad = CANARY.replace("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                         "deadbeef")
    e, errs = contract.parse(_with(bad))
    assert e is None and any("sha256" in x for x in errs)


def test_unparseable_success_predicate_is_rejected():
    bad = CANARY.replace('success: "exists(flag.captured) && flag.host == \'app.sandbox.local\'"',
                         'success: "exists((("')
    e, errs = contract.parse(_with(bad))
    assert e is None and any("predicate DSL" in x for x in errs)


def test_unknown_objective_type_is_rejected():
    bad = CANARY.replace("type: canary", "type: pivot")
    e, errs = contract.parse(_with(bad))
    assert e is None and any("objective.type must be one of" in x for x in errs)


def test_reach_objective_requires_lateral_movement():
    reach = """objective:
  id: obj-reach
  description: "Land on the db host."
  type: reach
  target: app.sandbox.local
  success: "exists(foothold.db)"
  proof: { kind: oob_marker, collaborator: oob-sandbox }
"""
    e, errs = contract.parse(_with(reach))
    assert e is None and any("lateral_movement: true" in x for x in errs)
    e2, errs2 = contract.parse(_with(reach, extra_policy="lateral_movement: true"))
    assert errs2 == [] and e2.lateral_movement is True


def test_reach_objective_rejects_an_external_oob_marker():
    reach = """objective:
  id: obj-reach
  description: "Land on the db host."
  type: reach
  target: app.sandbox.local
  success: "exists(foothold.db)"
  proof: { kind: oob_marker, collaborator: "http://evil.example/cb" }
"""
    e, errs = contract.parse(_with(reach, extra_policy="lateral_movement: true"))
    assert e is None and any("in-sandbox" in x for x in errs)


def test_lateral_movement_must_be_boolean():
    e, errs = contract.parse(_with(extra_policy="lateral_movement: maybe"))
    assert e is None and any("lateral_movement must be a boolean" in x for x in errs)


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
