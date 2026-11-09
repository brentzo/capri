#!/usr/bin/env python3
"""Live guard-proof self-test for the Docker sandbox backend (HC-SUB-01 §8.1).

Provisions a throwaway range on the local Docker host, runs the guard proof from
inside the attacker container, prints each assertion, and tears the range down.
Exits non-zero if any assertion fails. Skips (exit 0) when Docker is unavailable, so
it is safe to invoke anywhere; CI proves the same logic without Docker via
`tests/test_sandbox.py`. Run it on the range host as root (nsenter needs it):

    sudo python3 tools/sandbox_selftest.py

It requires the golden node image to exist (`hc-node:golden`); build it with
`docker build -t hc-node:golden -f infra/sandbox/Dockerfile.node infra/sandbox`.
"""
import os
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.sandbox.docker import DockerSandbox        # noqa: E402
from harness.substrate import contract                  # noqa: E402

CONTRACT = """
engagement:
  id: eng-selftest-001
  authorized_by: selftest
  window: { start: 2026-11-09T00:00, end: 2030-01-01T00:00 }
  max_blast_tier: 1
scope:
  in_scope_hosts: [t1.sandbox.local, t2.sandbox.local]
  in_scope_cidrs: [10.90.0.0/24]
  allowed_ports: { default: [8080] }
"""


def main():
    if shutil.which("docker") is None:
        print("docker not found; skipping live sandbox self-test")
        return 0
    eng, errs = contract.parse(CONTRACT)
    if errs:
        print("contract invalid:", errs)
        return 1
    sb = DockerSandbox()
    try:
        desc = sb.provision(eng)
        print(f"provisioned {desc['range_id']}  pinned={desc['pinned_targets']}")
        guard = sb.guard_proof()
        for a in guard["assertions"]:
            print(f"  [{'ok ' if a['ok'] else 'FAIL'}] {a['name']}: {a['describes']}")
        print("guard proof (G1/G2):", "PASS" if guard["pass"] else "FAIL")
        rt = sb.snapshot_round_trip()
        print(f"  [{'ok ' if rt['pass'] else 'FAIL'}] marker survives restore: "
              f"expected {rt.get('expected')!r}, got {rt.get('got')!r}")
        print("snapshot round-trip (G3):", "PASS" if rt["pass"] else "FAIL")
        esc = sb.escape_attempt()
        for a in esc["assertions"]:
            print(f"  [{'ok ' if a['ok'] else 'FAIL'}] {a['name']}: {a['describes']}")
        print(f"escape attempt (G4): {'PASS' if esc['pass'] else 'FAIL'} "
              f"(runtime: {esc['hardened_runtime']})")
        kd = sb.kill_switch_drill()
        print(f"  [{'ok ' if kd['pass'] else 'FAIL'}] froze in {kd['frozen_ms']}ms "
              f"(budget {kd['budget_ms']}ms) and restored from golden")
        print("kill-switch drill (G5):", "PASS" if kd["pass"] else "FAIL")
        all_ok = all(p["pass"] for p in (guard, rt, esc, kd))
        print("\nALL FIVE GUARANTEES:", "PASS" if all_ok else "FAIL",
              "- the harness may leave passive-only" if all_ok
              else "- the harness stays passive-only")
        return 0 if all_ok else 1
    finally:
        sb.teardown()
        print("range torn down")


if __name__ == "__main__":
    sys.exit(main())
