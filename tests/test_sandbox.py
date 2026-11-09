#!/usr/bin/env python3
"""Tests for the sandbox substrate interface and the Docker backend (HC-SUB-01 §8, §10).

The backend shells every docker/nsenter call through an injected runner, so these
drive the real provisioning and guard-proof logic against a stub with no Docker
present: the commands issued (an internal network, an attacker with no NET_ADMIN, the
host-installed scope guard), the guard ruleset built from the contract, and the four
§8.1 assertions passing only when the range actually enforces scope. The live path is
proven separately by `tools/sandbox_selftest.py` on a real Docker host.

Zero-dependency: `python3 tests/test_sandbox.py`.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.sandbox import PassiveOnlySandbox, guard_proof_result                 # noqa: E402
from harness.sandbox.base import RunResult                                         # noqa: E402
from harness.sandbox.docker import DockerSandbox, guard_ruleset                     # noqa: E402
from harness.substrate import contract                                             # noqa: E402

CONTRACT = """
engagement:
  id: eng-sub-001
  authorized_by: test
  window: { start: 2026-11-09T20:00, end: 2026-11-09T23:59 }
  max_blast_tier: 2
scope:
  in_scope_hosts: [t1.sandbox.local]
  in_scope_cidrs: [10.90.0.0/24]
  allowed_ports: { default: [8080] }
"""


def _eng():
    eng, errs = contract.parse(CONTRACT)
    assert not errs, errs
    return eng


class FakeRunner:
    """Records every command and answers the ones the backend reads back: the attacker
    pid, and the TCP/DNS probes per a configured reachability model."""

    def __init__(self, *, reachable=(), dns_resolves=False, pid=4242):
        self.calls = []
        self.reachable = set(reachable)
        self.dns_resolves = dns_resolves
        self.pid = pid

    def __call__(self, argv, *, input=None, timeout=30):
        self.calls.append(list(argv))
        if argv[:4] == ["docker", "inspect", "-f", "{{.State.Pid}}"]:
            return RunResult(0, str(self.pid), "")
        if "python3" in argv and "-c" in argv:
            src = argv[argv.index("-c") + 1]
            args = argv[argv.index("-c") + 2:]
            if "getaddrinfo" in src:
                return RunResult(0, "RESOLVED" if self.dns_resolves else "REFUSED:gaierror", "")
            ip, port = args[0], int(args[1])
            return RunResult(0, "CONNECTED" if (ip, port) in self.reachable
                             else "BLOCKED:TimeoutError", "")
        return RunResult(0, "", "")

    def ran(self, *needles):
        return any(all(n in call for n in needles) for call in self.calls)


# --- the passive-only default -------------------------------------------
def test_passive_only_sandbox_proves_nothing():
    s = PassiveOnlySandbox()
    assert s.proofs_pass() is False
    assert s.guard_proof()["pass"] is False
    for op in (s.snapshot, lambda: s.restore("x")):
        try:
            op()
            raise AssertionError("passive-only must refuse active-range operations")
        except Exception as e:  # noqa: BLE001
            assert "passive-only" in str(e)
    assert s.kill() is True


# --- the guard-proof assertion model (§8.1) -----------------------------
def test_guard_proof_result_all_four_must_hold():
    ok = dict(internet_reachable=False, public_dns_resolves=False,
              out_of_scope_reachable=False, in_scope_reachable=True)
    assert guard_proof_result(**ok)["pass"] is True
    for flip, bad_assertion in [
            (dict(internet_reachable=True), "internet_tcp_dropped"),
            (dict(public_dns_resolves=True), "public_dns_refused"),
            (dict(out_of_scope_reachable=True), "in_range_out_of_scope_dropped"),
            (dict(in_scope_reachable=False), "in_scope_target_allowed")]:
        res = guard_proof_result(**{**ok, **flip})
        assert res["pass"] is False
        failed = [a["name"] for a in res["assertions"] if not a["ok"]]
        assert failed == [bad_assertion], (flip, failed)


# --- the scope guard ruleset --------------------------------------------
def test_guard_ruleset_default_denies_and_allows_only_pinned_ports():
    rs = guard_ruleset("hc_guard", [("10.90.0.3", [8080, 443])])
    assert "policy drop;" in rs                                 # default-deny egress
    assert 'oifname "lo" accept' in rs
    assert "ct state established,related accept" in rs
    assert "ip daddr 10.90.0.3 tcp dport { 8080, 443 } accept" in rs
    # a target with no allowed ports yields no accept line (fail-closed)
    assert "daddr 10.90.0.9" not in guard_ruleset("hc_guard", [("10.90.0.9", [])])


# --- provisioning -------------------------------------------------------
def test_provision_builds_an_internal_network_and_an_unprivileged_attacker():
    run = FakeRunner()
    sb = DockerSandbox(run=run)
    eng = _eng()
    desc = sb.provision(eng)
    assert desc["range_id"] == "hc-range" and desc["mode"] == "sandboxed"
    assert run.ran("network", "create", "--internal")          # G2 by construction
    assert run.ran("run", "-d", "--name", "hc-range-attacker")
    # the attacker never gets NET_ADMIN, so the agent cannot touch the guard
    attacker_run = next(c for c in run.calls
                        if c[:2] == ["docker", "run"] and "hc-range-attacker" in c)
    assert "NET_ADMIN" not in attacker_run and "--privileged" not in attacker_run
    # the guard is installed by the HOST into the attacker netns, not by the agent
    assert run.ran("nsenter", "-t", "4242", "-n", "nft", "-f", "-")
    assert eng.pinned["t1.sandbox.local"].compressed == "10.90.0.3"   # .1 oos, .2 attacker, .3 target


def test_guard_proof_passes_only_when_the_range_enforces_scope():
    eng = _eng()
    # a correctly enforcing range: only the pinned in-scope target:port connects
    good = FakeRunner(reachable=[("10.90.0.3", 8080)], dns_resolves=False)
    sb = DockerSandbox(run=good)
    sb.provision(eng)
    res = sb.guard_proof()
    assert res["pass"] is True, res

    # a leaky range where the internet canary is reachable fails the matching assertion
    leaky = FakeRunner(reachable=[("10.90.0.3", 8080), ("1.1.1.1", 443)])
    sb2 = DockerSandbox(run=leaky)
    sb2.provision(_eng())
    res2 = sb2.guard_proof()
    assert res2["pass"] is False
    assert any(a["name"] == "internet_tcp_dropped" and not a["ok"] for a in res2["assertions"])


def test_proofs_pass_is_false_until_all_five_guarantees_are_proven():
    # the guard proof (G1/G2) passing is necessary but not sufficient: snapshot (G3),
    # escape (G4), and kill-switch (G5) drills are unbuilt, so the aggregate stays
    # False and the harness stays passive-only (§3).
    run = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=run)
    sb.provision(_eng())
    assert sb.guard_proof()["pass"] is True
    assert sb.proofs_pass() is False


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
