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
    pid, the TCP/DNS probes per a configured reachability model, and a tiny per-
    container filesystem so the snapshot round-trip (commit, overwrite, recreate, read)
    is exercised end to end with no Docker present."""

    def __init__(self, *, reachable=(), dns_resolves=False, pid=4242,
                 runtimes='{"runc":{"path":"runc"}}', host_ip="203.0.113.9"):
        self.calls = []
        self.reachable = set(reachable)
        self.dns_resolves = dns_resolves
        self.pid = pid
        self.runtimes = runtimes
        self.host_ip = host_ip
        self.files = {}       # container -> {path: content}
        self.images = {}      # image tag -> {path: content} (a committed filesystem)

    def __call__(self, argv, *, input=None, timeout=30):
        self.calls.append(list(argv))
        if argv[:4] == ["docker", "inspect", "-f", "{{.State.Pid}}"]:
            return RunResult(0, str(self.pid), "")
        if argv[:2] == ["docker", "info"]:
            return RunResult(0, self.runtimes, "")
        if argv[:3] == ["ip", "route", "get"]:
            return RunResult(0, f"1.1.1.1 via 10.0.0.1 dev eth0 src {self.host_ip} uid 0", "")
        if argv[:2] == ["docker", "commit"]:
            self.images[argv[3]] = dict(self.files.get(argv[2], {}))
            return RunResult(0, "", "")
        if argv[:2] == ["docker", "run"]:
            name, image = argv[argv.index("--name") + 1], argv[-1]
            self.files[name] = dict(self.images.get(image, {}))   # snapshot image -> its files
            return RunResult(0, "", "")
        if argv[:3] == ["docker", "rm", "-f"]:
            self.files.pop(argv[3], None)
            return RunResult(0, "", "")
        if argv[:2] == ["docker", "exec"]:
            i = 2
            while argv[i].startswith("-"):
                i += 1
            name, rest = argv[i], argv[i + 1:]
            if rest[:2] == ["sh", "-c"] and ">" in rest[2]:
                token, path = rest[2].split("echo")[1].split(">")
                self.files.setdefault(name, {})[path.strip()] = token.strip()
                return RunResult(0, "", "")
            if rest[:1] == ["cat"]:
                return RunResult(0, self.files.get(name, {}).get(rest[1], ""), "")
            if rest[0] == "python3" and "-c" in rest:
                src = rest[rest.index("-c") + 1]
                args = rest[rest.index("-c") + 2:]
                if "getaddrinfo" in src:
                    return RunResult(0, "RESOLVED" if self.dns_resolves else "REFUSED", "")
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


# --- snapshot round-trip (§8.2, G3) -------------------------------------
def test_snapshot_round_trip_restores_the_original_marker():
    run = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=run)
    sb.provision(_eng())
    res = sb.snapshot_round_trip()
    assert res["pass"] is True, res
    assert res["got"] == "hc-marker-original"                  # overwrite was undone by restore


def test_restore_recreates_each_target_at_its_pinned_ip():
    run = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=run)
    sb.provision(_eng())
    snap = sb.snapshot()
    assert run.ran("commit", "hc-range-tgt-0")
    run.calls.clear()
    sb.restore(snap)
    assert run.ran("rm", "-f", "hc-range-tgt-0")               # old container discarded
    assert run.ran("run", "-d", "--name", "hc-range-tgt-0", "--ip", "10.90.0.3")
    assert any("hc-snap:" in " ".join(c) for c in run.calls
               if c[:2] == ["docker", "run"])                  # recreated from the snapshot image


def test_restore_unknown_snapshot_raises():
    sb = DockerSandbox(run=FakeRunner())
    sb.provision(_eng())
    try:
        sb.restore("no-such-snap")
        raise AssertionError("expected an unknown snapshot to raise")
    except Exception as e:  # noqa: BLE001
        assert "unknown snapshot" in str(e)


# --- escape attempt (§8.3, G4) and gVisor hardening (§6.2) --------------
def test_escape_attempt_passes_when_the_host_and_other_nets_are_unreachable():
    # only the in-scope target is reachable; the range gateway, host, and an unrelated
    # network are not, so there is no path off the range.
    run = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=run)
    sb.provision(_eng())
    res = sb.escape_attempt()
    assert res["pass"] is True, res
    assert res["hardened_runtime"] == "runc"                   # no gVisor on this stub host
    assert {a["name"] for a in res["assertions"]} == {
        "unreachable:10.90.0.1", "unreachable:203.0.113.9", "unreachable:172.17.0.1"}


def test_escape_attempt_fails_when_the_operator_host_is_reachable():
    # a path to the host's management interface is an escape and must fail the proof
    run = FakeRunner(reachable=[("10.90.0.3", 8080), ("203.0.113.9", 22)])
    sb = DockerSandbox(run=run)
    sb.provision(_eng())
    res = sb.escape_attempt()
    assert res["pass"] is False
    assert any(a["name"] == "unreachable:203.0.113.9" and not a["ok"] for a in res["assertions"])


def test_provision_uses_gvisor_runtime_when_the_host_offers_it():
    hardened = FakeRunner(runtimes='{"runsc":{"path":"/usr/bin/runsc"},"runc":{"path":"runc"}}')
    sb = DockerSandbox(run=hardened)
    sb.provision(_eng())
    assert sb.hardened is True
    assert hardened.ran("run", "--name", "hc-range-attacker", "--runtime", "runsc")
    # without gVisor the range still provisions, just without the hardened runtime
    plain = FakeRunner()
    sb2 = DockerSandbox(run=plain)
    sb2.provision(_eng())
    assert sb2.hardened is False
    attacker_run = next(c for c in plain.calls
                        if c[:2] == ["docker", "run"] and "hc-range-attacker" in c)
    assert "--runtime" not in attacker_run


def test_proofs_pass_is_false_until_all_five_guarantees_are_proven():
    # G1/G2 (guard), G3 (snapshot), and G4 (escape) all pass, but the kill-switch (G5)
    # drill is unbuilt, so the aggregate stays False and the harness stays passive-only
    # (§3).
    run = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=run)
    sb.provision(_eng())
    assert sb.guard_proof()["pass"] is True
    assert sb.snapshot_round_trip()["pass"] is True
    assert sb.escape_attempt()["pass"] is True
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
