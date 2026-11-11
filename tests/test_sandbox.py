#!/usr/bin/env python3
"""Tests for the sandbox substrate interface and the Docker backend (HC-SUB-01 §8, §10).

The backend shells every Docker call through an injected runner, so these
drive the real provisioning and guard-proof logic against a stub with no Docker
present: the commands issued (an internal network, an attacker with no NET_ADMIN, the
helper-installed scope guard), the guard ruleset built from the contract, and the four
§8.1 assertions passing only when the range actually enforces scope. The live path is
proven separately by `tools/sandbox_selftest.py` on a real Docker host.

Zero-dependency: `python3 tests/test_sandbox.py`.
"""
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from unittest.mock import patch
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.sandbox import PassiveOnlySandbox, guard_proof_result, rangelock      # noqa: E402
from harness.sandbox.base import RunResult, SandboxError, default_run                # noqa: E402
from harness.sandbox.docker import DockerSandbox, GOLDEN, _PG_DATA_DIR, guard_ruleset  # noqa: E402
from harness.sandbox.probe import DockerProbe                                       # noqa: E402
from harness.substrate import contract, scope                                      # noqa: E402
from tools.run_engagement import _install_teardown_on_signal                       # noqa: E402

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


def test_default_run_preserves_binary_stdin_bytes():
    script = "import sys; sys.stdout.write(repr(sys.stdin.buffer.read()))"
    result = default_run([sys.executable, "-c", script], input=b"first\nsecond\n")
    assert result.rc == 0, result.err
    assert result.out == "b'first\\nsecond\\n'"


class FakeRunner:
    """Records every command and answers the ones the backend reads back: the attacker
    pid, the TCP/DNS probes per a configured reachability model, and a tiny per-
    container filesystem so the snapshot round-trip (commit, overwrite, recreate, read)
    is exercised end to end with no Docker present."""

    def __init__(self, *, reachable=(), dns_resolves=False, pid=4242,
                 runtimes='{"runc":{"path":"runc"}}', host_ip="203.0.113.9",
                 missing_attacker=False):
        self.calls = []
        self.inputs = {}
        self.reachable = set(reachable)
        self.dns_resolves = dns_resolves
        self.pid = pid
        self.runtimes = runtimes
        self.host_ip = host_ip
        self.missing_attacker = missing_attacker
        self.files = {}       # container -> {path: content}
        self.images = {}      # image tag -> {path: content} (a committed filesystem)
        self.paused = set()   # frozen containers

    def __call__(self, argv, *, input=None, timeout=30):
        self.calls.append(list(argv))
        self.inputs[tuple(argv)] = input
        if argv[:3] == ["docker", "image", "inspect"] and self.missing_attacker:
            return RunResult(1, "", "No such image")
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
            if "--network" in argv and any(arg.startswith("container:") for arg in argv):
                return RunResult(0, "", "")
            name, image = argv[argv.index("--name") + 1], argv[-1]
            self.files[name] = dict(self.images.get(image, {}))   # snapshot image -> its files
            return RunResult(0, "", "")
        if argv[:3] == ["docker", "rm", "-f"]:
            self.files.pop(argv[3], None)
            self.paused.discard(argv[3])
            return RunResult(0, "", "")
        if argv[:2] == ["docker", "cp"]:           # shell-free marker write/read via a tar stream
            src, dst = argv[2], argv[3]
            if src == "-" and ":" in dst:          # tar on stdin -> container dir
                name, dirn = dst.split(":", 1)
                with tarfile.open(fileobj=io.BytesIO(input or b""), mode="r") as tar:
                    for m in tar.getmembers():
                        fh = tar.extractfile(m)
                        content = fh.read().decode("utf-8") if fh else ""
                        key = ("/" + m.name) if dirn == "/" else dirn.rstrip("/") + "/" + m.name
                        self.files.setdefault(name, {})[key] = content
                return RunResult(0, "", "")
            if dst == "-" and ":" in src:          # container file -> tar on stdout
                name, path = src.split(":", 1)
                store = self.files.get(name, {})
                if path not in store:
                    return RunResult(1, "", "no such file or directory in container")
                buf, data = io.BytesIO(), store[path].encode("utf-8")
                with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                    info = tarfile.TarInfo(path.rsplit("/", 1)[-1])
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                return RunResult(0, buf.getvalue().decode("utf-8", "replace"), "")
            return RunResult(0, "", "")
        if argv[:2] == ["docker", "exec"]:
            i = 2
            while argv[i].startswith("-"):
                i += 1
            name, rest = argv[i], argv[i + 1:]
            if rest[:1] == ["timeout"]:            # a probe bounded by the container's timeout
                rest = rest[2:]
            if rest[:2] == ["sh", "-c"]:
                return RunResult(0, "", "")
            if rest[0] == "python3" and "-c" in rest:
                src = rest[rest.index("-c") + 1]
                args = rest[rest.index("-c") + 2:]
                if "getaddrinfo" in src:
                    return RunResult(0, "RESOLVED" if self.dns_resolves else "REFUSED", "")
                if "urlopen" in src:                           # the app health-path readiness probe
                    ip, port = args[0], int(args[1])
                    return RunResult(0, "READY" if (ip, port) in self.reachable
                                     else "NOT:TimeoutError", "")
                ip, port = args[0], int(args[1])
                return RunResult(0, "CONNECTED" if (ip, port) in self.reachable
                                 else "BLOCKED:TimeoutError", "")
        return RunResult(0, "", "")

    def ran(self, *needles):
        return any(all(n in call for n in needles) for call in self.calls)


class FakeHostRoute:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def connect(self, address):
        assert address == ("1.1.1.1", 80)

    def getsockname(self):
        return "203.0.113.9", 54321


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
def test_provision_reports_how_to_build_a_missing_attacker_image():
    sb = DockerSandbox(run=FakeRunner(missing_attacker=True))
    try:
        sb.provision(_eng())
    except SandboxError as error:
        assert "hc-attacker:golden" in str(error)
        assert "docker build -t hc-attacker:golden" in str(error)
    else:
        raise AssertionError("missing attacker image should block provisioning")


def test_provision_builds_an_internal_network_and_an_unprivileged_attacker():
    run = FakeRunner()
    sb = DockerSandbox(run=run)
    eng = _eng()
    with patch("harness.sandbox.docker.socket.socket", return_value=FakeHostRoute()):
        desc = sb.provision(eng)
    assert desc["range_id"] == "hc-range" and desc["mode"] == "sandboxed"
    assert run.ran("network", "create", "--internal")          # G2 by construction
    assert run.ran("run", "-d", "--name", "hc-range-attacker")
    # the attacker never gets NET_ADMIN, so the agent cannot touch the guard
    attacker_run = next(c for c in run.calls
                        if c[:2] == ["docker", "run"] and "hc-range-attacker" in c)
    assert "NET_ADMIN" not in attacker_run and "--privileged" not in attacker_run
    assert "--init" in attacker_run        # reaps the headless browser's orphaned helpers
    # A one-shot helper shares the attacker's netns and receives only NET_ADMIN.
    guard = next(c for c in run.calls if c[:2] == ["docker", "run"]
                 and "container:hc-range-attacker" in c)
    assert "hc-guard:golden" in guard
    assert "--cap-drop=ALL" in guard and "--cap-add=NET_ADMIN" in guard
    assert "--privileged" not in guard
    assert guard[-3:] == ["nft", "-f", "-"]
    ruleset = run.inputs[tuple(guard)]
    assert ruleset == guard_ruleset("hc_guard", [("10.90.0.3", [8080])]).encode("utf-8")
    assert b"\r" not in ruleset
    assert not run.ran("nsenter") and not run.ran("ip", "route", "get")
    escape = sb.escape_attempt()
    assert any(a["name"] == "unreachable:203.0.113.9" for a in escape["assertions"])
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


def _eng_with_target(block):
    text = CONTRACT.replace("  max_blast_tier: 2", "  max_blast_tier: 2\n" + block)
    eng, errs = contract.parse(text)
    assert not errs, errs
    return eng


def test_provision_brings_up_a_declared_postgres_backing_service():
    run = FakeRunner()
    eng = _eng_with_target(
        '  target:\n    services:\n      - { name: db, engine: postgres, version: "16" }\n')
    DockerSandbox(run=run).provision(eng)
    assert run.ran("pull", "postgres:16")                      # host pull, pre-seal (§13)
    # the service runs on its own in-range IP with the alias the app resolves, and the harness
    # waits for it to accept connections before the range is used
    assert run.ran("run", "--ip", "10.90.0.3", "--network-alias", "db", "postgres:16")
    assert run.ran("exec", "pg_isready")
    # the service sits at .3 (before the target at .4) and is never pinned, so the scope guard
    # keeps the attacker off the datastore while the app reaches it over the internal network
    assert eng.pinned["t1.sandbox.local"].compressed == "10.90.0.4"
    assert "10.90.0.3" not in {ip.compressed for ip in eng.pinned.values()}


def test_provision_seeds_postgres_from_init_sql():
    import tempfile
    run = FakeRunner()
    fd, seed_path = tempfile.mkstemp(suffix=".sql")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("CREATE TABLE note (id int);\n")
        eng = _eng_with_target(
            "  target:\n    services:\n      - name: db\n        engine: postgres\n"
            f"        init_sql: {seed_path}\n")
        DockerSandbox(run=run).provision(eng)
    finally:
        os.unlink(seed_path)
    # the declared fixture is piped into the fresh database over `psql`, with ON_ERROR_STOP so a
    # bad fixture aborts provisioning rather than leaving a half-seeded datastore
    psql = [c for c in run.calls if "psql" in c and "ON_ERROR_STOP=1" in c]
    assert psql, "psql was not invoked to seed the database"
    assert run.inputs[tuple(psql[0])] == "CREATE TABLE note (id int);\n"


# --- an arbitrary app image as the target (HC-SUB-01 §4, §6.1) ------------------------
APP_CONTRACT = """
engagement:
  id: eng-app-001
  authorized_by: test
  window: { start: 2026-11-09T20:00, end: 2026-11-09T23:59 }
  max_blast_tier: 2
  target:
    image: myapp:local
    port: 3000
    env: { DATABASE_URL: "postgres://app:app@db:5432/app" }
    ready: { path: /healthz, timeout_s: 30 }
    services:
      - { name: db, engine: postgres }
scope:
  in_scope_hosts: [t1.sandbox.local]
  in_scope_cidrs: [10.90.0.0/24]
"""   # no allowed_ports: the declared app port is auto-added, proving the §5.3 agreement


def _app_eng(text=APP_CONTRACT):
    eng, errs = contract.parse(text)
    assert not errs, errs
    return eng


def test_provision_runs_a_user_app_image_with_its_env_in_place_of_the_listener():
    # .1 oos, .2 attacker, .3 the db service, .4 the app target
    run = FakeRunner(reachable=[("10.90.0.4", 3000)])
    DockerSandbox(run=run).provision(_app_eng())
    assert run.ran("run", "--name", "hc-range-tgt-0", "--ip", "10.90.0.4", "myapp:local")
    assert run.ran("run", "-e", "DATABASE_URL=postgres://app:app@db:5432/app", "myapp:local")
    assert not run.ran("http.server")                          # the image is the app, no stand-in
    assert not run.ran("cat > /tmp/app.py")                    # nothing seeded over stdin
    assert run.ran("python3", "-c", "10.90.0.4", "3000", "/healthz")   # readiness over the real path


def test_provision_builds_a_target_image_from_a_dockerfile():
    build = APP_CONTRACT.replace(
        "    image: myapp:local\n",
        "    build: { context: infra/sandbox/nodepg, dockerfile: Dockerfile }\n")
    run = FakeRunner(reachable=[("10.90.0.4", 3000)])
    DockerSandbox(run=run).provision(_app_eng(build))
    assert run.ran("build", "-t", "hc-target:hc-range", "-f",
                   "infra/sandbox/nodepg/Dockerfile", "infra/sandbox/nodepg")
    assert run.ran("run", "--ip", "10.90.0.4", "hc-target:hc-range")   # the built image is the target


def test_the_declared_app_port_is_allowed_so_the_precheck_and_guard_agree():
    run = FakeRunner(reachable=[("10.90.0.4", 3000)])
    eng = _app_eng()
    DockerSandbox(run=run).provision(eng)
    # the app port joined the allowed ports, so the software pre-check allows exactly the port the
    # guard opened: no §5.3 stop-the-line disagreement between the two layers
    assert scope.scope_validate(eng, "10.90.0.4", 3000) == ("allow", None)


def test_an_app_target_is_recreated_from_its_app_image_on_restore():
    run = FakeRunner(reachable=[("10.90.0.4", 3000)])
    sb = DockerSandbox(run=run)
    sb.provision(_app_eng())
    run.calls.clear()
    sb.restore(GOLDEN)
    assert run.ran("run", "--name", "hc-range-tgt-0", "myapp:local")   # the app image, not node
    assert not run.ran("hc-node:golden")
    assert not run.ran("http.server")


def test_proofs_pass_for_an_app_target_backed_by_a_service():
    # the full five-guarantee path holds with a real app image plus a backing service
    run = FakeRunner(reachable=[("10.90.0.4", 3000)])
    sb = DockerSandbox(run=run)
    sb.provision(_app_eng())
    assert sb.proofs_pass()


# --- the datastore is part of snapshot/restore/kill (HC-SUB-01 §6.3, §6.4; G3, G5) ----
_PG = '  target:\n    services:\n      - { name: db, engine: postgres }\n'


def test_a_backing_service_is_snapshotted_and_restored_with_its_state():
    # G3 must reproduce database state, not only the app's filesystem: a value written to the
    # datastore, snapshotted, then overwritten, comes back on restore of that snapshot.
    run = FakeRunner()
    sb = DockerSandbox(run=run)
    sb.provision(_eng_with_target(_PG))
    sb._write_file("hc-range-svc-db", "/data_marker", "seeded")
    snap = sb.snapshot()
    sb._write_file("hc-range-svc-db", "/data_marker", "mutated")
    sb.restore(snap)
    assert sb._read_file("hc-range-svc-db", "/data_marker") == "seeded"


def test_restore_recreates_the_datastore_before_the_app_target():
    # Dependencies first: the app must come back up against a datastore that is already accepting
    # connections, or its dropped pool connections crash it (caught by the live run, not a mock).
    run = FakeRunner(reachable=[("10.90.0.4", 3000)])
    sb = DockerSandbox(run=run)
    sb.provision(_app_eng())
    run.calls.clear()
    sb.restore(GOLDEN)

    def first_run(image):
        return next(i for i, c in enumerate(run.calls) if "run" in c and image in c)

    assert first_run("hc-golden:hc-range-svc-db") < first_run("myapp:local")


def test_restore_waits_for_a_recreated_app_target_to_become_ready():
    # A recreated app is a fresh process still booting; restore must poll its health path, or
    # recon (and the next probe) races a heavy app that has not finished starting, which is what
    # the first dashboard run hit - the app passed readiness at provision, a proof drill recreated
    # it, and recon then found port 3000 closed. The service re-wait is the datastore's analogue.
    run = FakeRunner(reachable=[("10.90.0.4", 3000)])
    sb = DockerSandbox(run=run)
    sb.provision(_app_eng())
    run.calls.clear()
    sb.restore(GOLDEN)
    assert any("urlopen" in " ".join(c) and "10.90.0.4" in c for c in run.calls)   # health poll ran


def test_restore_golden_recreates_a_service_from_its_seeded_image():
    run = FakeRunner()
    sb = DockerSandbox(run=run)
    sb.provision(_eng_with_target(_PG))
    run.calls.clear()
    sb.restore(GOLDEN)
    # the datastore returns to the golden committed right after seeding (the §4.2 baseline), with
    # its alias so the app still resolves it
    assert run.ran("run", "--network-alias", "db", "hc-golden:hc-range-svc-db")


def test_postgres_data_dir_sits_outside_the_image_volume_so_commit_captures_it():
    # The postgres image declares /var/lib/postgresql/data a VOLUME, and `docker commit` does
    # not capture volume contents: a golden or snapshot committed with the data there comes back
    # empty and silently drops the seed, so the stateful snapshot/restore guarantee only appears
    # to hold. PGDATA must point outside that volume, into the layer commit does capture, both on
    # first bring-up and on every recreate (restore / kill).
    assert not _PG_DATA_DIR.startswith("/var/lib/postgresql/data")   # outside the declared VOLUME
    run = FakeRunner()
    sb = DockerSandbox(run=run)
    sb.provision(_eng_with_target(_PG))
    assert run.ran("run", "postgres:16", f"PGDATA={_PG_DATA_DIR}")    # first bring-up
    run.calls.clear()
    sb.restore(GOLDEN)
    assert run.ran("run", "hc-golden:hc-range-svc-db", f"PGDATA={_PG_DATA_DIR}")   # recreate


def test_the_kill_switch_freezes_and_restores_the_backing_service():
    run = FakeRunner()
    sb = DockerSandbox(run=run)
    sb.provision(_eng_with_target(_PG))
    res = sb.kill()
    assert run.ran("pause", "hc-range-svc-db")                 # frozen with the rest of the range
    assert "db" in res["restored_from_golden"]
    assert run.ran("run", "--network-alias", "db", "hc-golden:hc-range-svc-db")


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


def test_marker_write_and_read_are_shell_free_for_a_distroless_target():
    # A real app image is routinely distroless (no sh, no cat), so the G3 proof must move its
    # marker with docker cp, never docker exec sh -c - otherwise the snapshot round-trip fails on
    # exactly the apps the product exists to test, which is what the first dashboard run hit.
    run = FakeRunner()
    sb = DockerSandbox(run=run)
    sb._write_file("hc-range-tgt-0", "/hc_marker", "hc-marker-original")
    assert sb._read_file("hc-range-tgt-0", "/hc_marker") == "hc-marker-original"
    assert sb._read_file("hc-range-tgt-0", "/absent") == ""    # a missing file reads back empty
    assert run.ran("docker", "cp")
    assert not any(c[:2] == ["docker", "exec"] and "sh" in c for c in run.calls)


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
    with patch("harness.sandbox.docker.socket.socket", return_value=FakeHostRoute()):
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
    with patch("harness.sandbox.docker.socket.socket", return_value=FakeHostRoute()):
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
    guard = next(c for c in hardened.calls if c[:2] == ["docker", "run"]
                 and "container:hc-range-attacker" in c)
    assert "--runtime" in guard and guard[guard.index("--runtime") + 1] == "runsc"
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
    with patch("harness.sandbox.docker.socket.socket", return_value=FakeHostRoute()):
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


def test_phase_recon_marks_an_html_rendering_endpoint():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=...")}
    headers = {"/": {"Content-Type": "text/html; charset=utf-8"}}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)],
                        pages=pages, headers=headers)
    facts = phase_recon("hc-range-attacker", _pinned_eng(), run=run)["t1"]
    assert facts["asset.renders_html"] is True


def test_phase_recon_detects_a_markup_reflecting_endpoint():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=..."), "/clobber": (200, "<div id=out></div>")}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)], pages=pages)
    facts = phase_recon("hc-range-attacker", _pinned_eng(), run=run)["t1"]
    assert facts["asset.allows_named_markup"] is True
    assert facts["asset.clobber_path"] == "/clobber"


def test_phase_recon_detects_a_state_changing_action():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=..."), "/portal/settings": (200, "<form>")}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)], pages=pages)
    facts = phase_recon("hc-range-attacker", _pinned_eng(), run=run)["t1"]
    assert facts["asset.has_state_changing_action"] is True
    assert facts["asset.action_path"] == "/portal/settings"


def test_phase_recon_detects_a_websocket_endpoint():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /search?q=..."), "/ws": (426, "websocket endpoint")}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)], pages=pages)
    facts = phase_recon("hc-range-attacker", _pinned_eng(), run=run)["t1"]
    assert facts["asset.has_websocket"] is True
    assert facts["asset.ws_path"] == "/ws"


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


class _FakeCrawler:
    """Stands in for the in-container black-box crawler: returns a fixed surface map."""

    def __init__(self, surface):
        self.surface = surface
        self.calls = []

    def crawl(self, target, port, **kw):
        self.calls.append((target, port))
        return self.surface


def test_phase_recon_merges_crawler_discovered_endpoints_as_assets():
    from harness.recon import phase_recon
    pages = {"/": (200, "home")}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)], pages=pages)
    crawler = _FakeCrawler({"endpoints": [
        {"path": "/search", "method": "GET", "params": ["q"], "status": 200, "renders_html": True},
        {"path": "/health", "method": "GET", "params": []}]})   # no param: not an injection asset
    model = phase_recon("hc-range-attacker", _pinned_eng(), run=run, crawler=crawler)
    assert "t1" in model                                        # host asset still produced
    assert "t1::/search?q" in model                             # endpoint projected as its own asset
    ep = model["t1::/search?q"]
    assert ep["asset.type"] == "http_endpoint"
    assert ep["asset.path"] == "/search" and ep["asset.param"] == "q"
    assert ep["open_ports"] == [8080]                           # port the Operator probes on
    assert ep["addr"] == "10.90.0.3"
    assert not any(k.startswith("t1::/health") for k in model)  # a no-parameter endpoint is skipped
    assert crawler.calls == [("10.90.0.3", 8080)]               # crawled the pinned ip:port


def test_phase_recon_without_a_crawler_is_unchanged():
    from harness.recon import phase_recon
    pages = {"/": (200, "Try /item?id=...")}
    run = _recon_runner(open_ports=[("10.90.0.3", 8080)], http=[("10.90.0.3", 8080)], pages=pages)
    model = phase_recon("a", _pinned_eng(), run=run)            # no crawler passed
    assert set(model) == {"t1"}                                 # only the host asset, as before


def test_sigterm_handler_raises_keyboardinterrupt_and_is_oneshot():
    # A SIGTERM (what an external `timeout`/supervisor sends) must become a
    # KeyboardInterrupt so the runner's `finally: sb.teardown()` still fires and the
    # range is not leaked. The handler is one-shot: it restores the default disposition
    # before raising, so a second signal hard-kills rather than interrupting teardown.
    import signal
    prev = signal.getsignal(signal.SIGTERM)
    try:
        _install_teardown_on_signal()
        handler = signal.getsignal(signal.SIGTERM)
        assert callable(handler) and handler is not signal.SIG_DFL, "no handler installed"
        raised = False
        try:
            handler(signal.SIGTERM, None)
        except KeyboardInterrupt:
            raised = True
        assert raised, "handler did not raise KeyboardInterrupt"
        assert signal.getsignal(signal.SIGTERM) == signal.SIG_DFL, "handler was not one-shot"
    finally:
        signal.signal(signal.SIGTERM, prev)


def test_install_teardown_on_signal_is_noop_off_main_thread():
    # signal.signal() only works on the main thread; installing from a worker must be a
    # harmless no-op rather than raising, so a threaded caller (e.g. a TUI) stays safe.
    import signal
    import threading
    out = {}

    def worker():
        before = signal.getsignal(signal.SIGTERM)
        _install_teardown_on_signal()
        out["unchanged"] = signal.getsignal(signal.SIGTERM) is before

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert out.get("unchanged") is True, "off-main-thread install changed the disposition"


# --- one engagement per range ---------------------------------------------
def test_a_live_range_refuses_a_second_engagement_until_it_is_released():
    with tempfile.TemporaryDirectory() as lock_dir:
        first = rangelock.RangeLock("hc-range", lock_dir=lock_dir).acquire()
        try:
            try:
                rangelock.RangeLock("hc-range", lock_dir=lock_dir).acquire()
                raise AssertionError("expected the second engagement to be refused")
            except rangelock.RangeBusy as busy:
                assert isinstance(busy, SandboxError)
                assert "already running" in str(busy) and "hc-range" in str(busy), busy
            rangelock.RangeLock("hc-other", lock_dir=lock_dir).acquire().release()
        finally:
            first.release()
        rangelock.RangeLock("hc-range", lock_dir=lock_dir).acquire().release()


def test_a_crashed_engagement_does_not_leave_its_range_locked():
    # The holder dies without releasing, as a crashed run would; the OS drops the lock,
    # so the next run can clean up the leftover range instead of being blocked forever.
    holder = ("import os, sys; sys.path.insert(0, sys.argv[1]); "
              "from harness.sandbox import rangelock; "
              "rangelock.RangeLock('hc-range', lock_dir=sys.argv[2]).acquire(); os._exit(0)")
    with tempfile.TemporaryDirectory() as lock_dir:
        subprocess.run([sys.executable, "-c", holder, ROOT, lock_dir], check=True, timeout=60)
        rangelock.RangeLock("hc-range", lock_dir=lock_dir).acquire().release()


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
