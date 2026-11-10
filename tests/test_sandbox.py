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
import json
import os
import sys
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.sandbox import PassiveOnlySandbox, guard_proof_result                 # noqa: E402
from harness.sandbox.base import RunResult                                         # noqa: E402
from harness.sandbox.docker import DockerSandbox, guard_ruleset                     # noqa: E402
from harness.sandbox.probe import DockerProbe                                       # noqa: E402
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
        self.paused = set()   # frozen containers

    def __call__(self, argv, *, input=None, timeout=30):
        self.calls.append(list(argv))
        if argv[:4] == ["docker", "inspect", "-f", "{{.State.Pid}}"]:
            return RunResult(0, str(self.pid), "")
        if argv[:4] == ["docker", "inspect", "-f", "{{.State.Status}}"]:
            return RunResult(0, "paused" if argv[4] in self.paused else "running", "")
        if argv[:2] == ["docker", "pause"]:
            self.paused.update(argv[2:])
            return RunResult(0, "", "")
        if argv[:2] == ["docker", "unpause"]:
            self.paused.difference_update(argv[2:])
            return RunResult(0, "", "")
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
            self.paused.discard(argv[3])
            return RunResult(0, "", "")
        if argv[:2] == ["docker", "exec"]:
            i = 2
            while argv[i].startswith("-"):
                i += 1
            name, rest = argv[i], argv[i + 1:]
            if rest[:2] == ["sh", "-c"]:
                cmd = rest[2]
                if cmd.startswith("echo "):                    # echo <content> > <path>
                    token, path = cmd[len("echo "):].split(">", 1)
                    self.files.setdefault(name, {})[path.strip()] = token.strip()
                    return RunResult(0, "", "")
                if cmd.startswith("cat "):                     # cat <path> 2>/dev/null || true
                    path = cmd[len("cat "):].split()[0]
                    return RunResult(0, self.files.get(name, {}).get(path, ""), "")
                return RunResult(0, "", "")
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
    assert s.kill()["ok"] is True
    assert s.teardown() is True


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


def test_provision_seeds_and_runs_a_custom_listener_app_when_configured():
    run = FakeRunner()
    DockerSandbox(run=run, listener_app="print('vuln app')").provision(_eng())
    # the app is seeded over stdin (never baked into the golden image) and run as the
    # target's listener in place of the plain http.server stand-in
    assert run.ran("exec", "-i", "sh", "-c", "cat > /tmp/app.py")
    assert run.ran("exec", "-d", "python3", "/tmp/app.py")
    assert not run.ran("http.server")                            # replaced, not added


def test_provision_starts_an_in_range_collaborator_when_configured():
    run = FakeRunner()
    sb = DockerSandbox(run=run, collaborator_app="print('collab')")
    eng = _eng()
    sb.provision(eng)
    # the collaborator is created on an in-range address and runs its own seeded app
    assert run.ran("run", "-d", "--name", "hc-range-collaborator")
    assert run.ran("exec", "-i", "sh", "-c", "cat > /tmp/app.py")
    assert sb.collab_addr == "10.90.0.3:8080"                  # .1 oos, .2 attacker, .3 collaborator
    assert eng.pinned["t1.sandbox.local"].compressed == "10.90.0.4"   # target shifted to .4
    # the collaborator is never added to the pinned set, so the scope guard never allows the
    # attacker to reach it; the harness reads its log over docker exec instead
    assert "10.90.0.3" not in {ip.compressed for ip in eng.pinned.values()}


def test_provision_without_a_collaborator_keeps_the_target_at_the_third_address():
    run = FakeRunner()
    eng = _eng()
    DockerSandbox(run=run).provision(eng)
    assert not run.ran("run", "-d", "--name", "hc-range-collaborator")
    assert eng.pinned["t1.sandbox.local"].compressed == "10.90.0.3"


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


# --- kill switch (§8.4, G5) and the full aggregate ----------------------
def test_kill_switch_drill_freezes_within_budget_and_restores_from_golden():
    run = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=run)
    sb.provision(_eng())
    res = sb.kill_switch_drill()
    assert res["pass"] is True, res
    assert res["frozen_ms"] <= res["budget_ms"]
    assert run.ran("pause", "hc-range-attacker")               # one action froze the range
    assert run.ran("commit", "hc-range-attacker")              # frozen state kept for forensics
    assert run.ran("unpause", "hc-range-attacker")             # revived, so the range stays usable


def test_kill_switch_drill_fails_when_the_freeze_misses_its_budget():
    run = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=run, kill_budget_ms=-1)             # no freeze can meet it
    sb.provision(_eng())
    assert sb.kill_switch_drill()["pass"] is False


def test_proofs_pass_is_true_only_when_all_five_guarantees_prove():
    good = FakeRunner(reachable=[("10.90.0.3", 8080)])
    sb = DockerSandbox(run=good)
    sb.provision(_eng())
    assert sb.proofs_pass() is True                            # G1-G5 all hold: may leave passive-only

    # a range with a live escape path to the host never earns full trust
    leaky = FakeRunner(reachable=[("10.90.0.3", 8080), ("203.0.113.9", 22)])
    sb2 = DockerSandbox(run=leaky)
    sb2.provision(_eng())
    assert sb2.proofs_pass() is False


# --- the live probe adapter (HC-AGENT-01) -------------------------------
def test_docker_probe_reports_an_http_response_as_a_hit():
    p = DockerProbe("hc-range-attacker", {}, run=lambda *a, **k: RunResult(0, "STATUS 200", ""))
    res = p.run({"tool": "probe", "target": "10.90.0.3", "port": 8080, "args": {"path": "/"}})
    assert res["deterministic_signals"]["hit"] is True
    assert res["parsed"]["http_status"] == 200 and res["status"] == "ok"


def test_docker_probe_treats_no_response_as_not_a_hit():
    p = DockerProbe("a", {}, run=lambda *a, **k: RunResult(0, "ERR TimeoutError", ""))
    res = p.run({"target": "10.0.0.9", "port": 8080})
    assert res["deterministic_signals"]["hit"] is False and res["status"] == "error"


def test_docker_probe_resolves_a_pinned_host_to_its_guarded_ip():
    import ipaddress
    seen = {}

    def run(argv, *, input=None, timeout=30):
        seen["ip"] = argv[argv.index("-c") + 2]    # the first probe arg after the source
        return RunResult(0, "STATUS 200", "")
    p = DockerProbe("a", {"t1.sandbox.local": ipaddress.ip_address("10.90.0.3")}, run=run)
    p.run({"target": "t1.sandbox.local", "port": 8080})
    assert seen["ip"] == "10.90.0.3"               # aimed at the IP the scope guard enforces on


# --- live reconnaissance (HC-AGENT-01 phase_recon) ----------------------
def _pinned_eng():
    eng = _eng()
    eng.pin({"t1.sandbox.local": "10.90.0.3"})
    return eng


def _recon_runner(*, open_ports=(), http=(), pages=None, headers=None):
    open_ports, http = set(open_ports), set(http)
    pages, headers = (pages or {}), (headers or {})

    def run(argv, *, input=None, timeout=30):
        i = argv.index("-c")
        src, rest = argv[i + 1], argv[i + 2:]
        if "urllib.request" in src:                            # a web-discovery fetch
            path = urlparse(rest[0]).path
            status, body = pages.get(path, (404, ""))
            if "json.dumps(rh)" in src:                        # the header-returning variant
                hdr_json = json.dumps(headers.get(path, {}))
                return RunResult(0, f"STATUS {status}\n{hdr_json}\n---BODY---\n{body}", "")
            return RunResult(0, f"STATUS {status}\n---BODY---\n{body}", "")
        ip, port = rest[0], int(rest[1])
        if "OPEN" in src:                                      # the TCP port probe
            return RunResult(0, "OPEN" if (ip, port) in open_ports else "CLOSED", "")
        return RunResult(0, "STATUS 200" if (ip, port) in http else "ERR", "")  # HTTP status probe
    return run


def test_phase_recon_builds_the_target_model_and_discovers_web_facts():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=... and /item?id=..."),
             "/login": (200, "header.payload.signature"), "/admin": (401, "")}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)], pages=pages)
    model = phase_recon("hc-range-attacker", _pinned_eng(), run=run)
    assert model == {"t1": {"host": "t1.sandbox.local", "addr": "10.90.0.3",
                            "reachable": True, "open_ports": [8080],
                            "asset.type": "http_endpoint", "http_status": 200,
                            "asset.params": ["id", "q"], "asset.auth": "jwt",
                            "asset.login_path": "/login", "authenticated_session": True,
                            "asset.privileged_siblings": ["/admin"]}}


def test_phase_recon_detects_a_cacheable_endpoint():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=..."), "/promo": (200, "<link>")}
    headers = {"/promo": {"Cache-Control": "public, max-age=60", "X-Cache": "MISS"}}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)],
                        pages=pages, headers=headers)
    facts = phase_recon("hc-range-attacker", _pinned_eng(), run=run)["t1"]
    assert facts["asset.cacheable"] is True
    assert facts["cacheable_endpoint"] is True
    assert facts["asset.cache_path"] == "/promo"


def test_phase_recon_detects_a_state_changing_action():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=..."), "/portal/settings": (200, "<form>")}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)], pages=pages)
    facts = phase_recon("hc-range-attacker", _pinned_eng(), run=run)["t1"]
    assert facts["asset.has_state_changing_action"] is True
    assert facts["asset.action_path"] == "/portal/settings"


def test_phase_recon_adds_a_login_endpoint_asset_for_a_session_cookie():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=..."), "/portal": (200, "portal session anonymous")}
    headers = {"/portal": {"Set-Cookie": "sid=abc123; Path=/; HttpOnly"}}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)],
                        pages=pages, headers=headers)
    model = phase_recon("hc-range-attacker", _pinned_eng(), run=run)
    assert "t1-login" in model                               # a distinct asset, same host
    login = model["t1-login"]
    assert login["asset.type"] == "login_endpoint"
    assert login["asset.session_cookie"] == "sid"
    assert login["login_endpoint"] is True and login["reachable"] is True
    assert login["host"] == "t1.sandbox.local"


def test_phase_recon_marks_an_unreachable_target_and_omits_service_type():
    from harness.recon import phase_recon
    model = phase_recon("a", _pinned_eng(), run=_recon_runner())   # nothing open
    assert model["t1"]["reachable"] is False and model["t1"]["open_ports"] == []
    assert "asset.type" not in model["t1"]


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
