"""Docker-backed sandbox range (HC-SUB-01, first self-hostable backend).

Provisions one egress-denied Docker network (`--internal`, so the range has no route
off the host by construction = G2) holding a target container per in-scope host and
one attacker container where tool adapters run. The scope guard (§5) is an nftables
ruleset a short-lived helper installs into the attacker's network namespace: default-deny egress,
allowing only the pinned in-scope IPs on their allowed ports. The attacker runs with
no NET_ADMIN and no nft binary, so the agent can neither reach an out-of-scope host
nor reconfigure the guard (§2: the agent itself is in the threat model). The guard
proof (§8.1) then proves all of this from inside the attacker container.

No nested virtualization is required, so this runs on any commodity Linux host (and
inside Docker Desktop's Linux VM on macOS/Windows). A separate gateway host and
microVM/gVisor isolation harden G4 further and are selected the same way, behind this
interface; this backend's job is G1 and G2, proven by the guard proof.

Every Docker call goes through an injected `run`, so provisioning and proof
logic is unit-tested against a stub with no Docker present (`tests/test_sandbox.py`);
the live path uses the default subprocess runner and works on Linux and Docker Desktop.
"""
import ipaddress
import os
import socket
import time

from harness.sandbox.base import (
    Sandbox,
    SandboxError,
    default_run,
    guard_proof_result,
)
from harness.store.db import now
from harness.substrate import scope

GOLDEN = "golden"   # the per-run baseline snapshot id the loop restores before verifying (§4.2)

# How long to wait for a backing service (e.g. Postgres) to accept connections before the
# range is declared unprovisionable. A real engine answers in a few seconds on a warm host.
_SERVICE_READY_TIMEOUT_S = 60

# Probes the attacker container runs; stdlib python3 only, so the node image stays tiny.
# The guard runs default-deny DROP, so a connection to a blocked destination never gets a
# refusal, it just goes silent: the probe waits out its bound, and that silence IS the
# "blocked" answer. The guard proof runs before every operator and verifier step, so these
# probes are a hot path, and an unbounded wait on a blocked destination would dominate the
# run. The TCP probe self-bounds with a socket timeout. The DNS probe cannot: getaddrinfo is
# a blocking C call that honours neither the socket timeout nor a Python alarm, so it is
# bounded from outside by `_dns` running it under the container's `timeout`. Either bound is
# generous against a reachable destination, which answers in well under a second, so a probe
# is only cut off when the destination is truly silent, never when egress is in fact open.
_TCP_PROBE = (
    "import socket,sys\n"
    "s=socket.socket(); s.settimeout(1)\n"
    "try:\n"
    "    s.connect((sys.argv[1], int(sys.argv[2]))); print('CONNECTED')\n"
    "except Exception as e: print('BLOCKED:'+type(e).__name__)\n"
)
_DNS_PROBE = (
    "import socket,sys\n"
    "try:\n"
    "    socket.getaddrinfo(sys.argv[1], 443); print('RESOLVED')\n"
    "except Exception as e: print('REFUSED:'+type(e).__name__)\n"
)
# Readiness: a GET to the app's declared health path from the attacker, so "ready" means ready
# as the agent will see it, over the real in-range path and through the scope guard.
_READY_PROBE = (
    "import sys,urllib.request\n"
    "try:\n"
    "    r=urllib.request.urlopen('http://%s:%s%s' % (sys.argv[1], sys.argv[2], sys.argv[3]), timeout=2)\n"
    "    print('READY' if 200 <= r.status < 400 else 'NOT:%d' % r.status)\n"
    "except Exception as e: print('NOT:'+type(e).__name__)\n"
)


def guard_ruleset(table, pinned_ports):
    """The attacker-netns egress guard: default-deny, allow loopback and established,
    then one accept per pinned in-scope IP on its allowed ports. Pure text so it is
    unit-tested directly; `pinned_ports` is a list of (ip_str, [ports])."""
    lines = [f"table inet {table} {{",
             "	chain out {",
             "		type filter hook output priority 0; policy drop;",
             '		oifname "lo" accept',
             "		ct state established,related accept"]
    for ip, ports in pinned_ports:
        ports = [int(p) for p in ports]
        if not ports:
            continue
        portset = ", ".join(str(p) for p in ports)
        lines.append(f"		ip daddr {ip} tcp dport {{ {portset} }} accept")
    lines += ["	}", "}", ""]
    return "\n".join(lines)


class DockerSandbox(Sandbox):
    """A range built from Docker containers plus an nft scope-guard helper.

    `provision` is idempotent-by-teardown: it removes any range of the same name
    first, so a re-driven run starts clean. The backend holds no engagement secrets;
    it shells out to Docker through the injected runner."""

    def __init__(self, *, run=None, node_image="hc-node:golden", network="hc-range",
                 attacker_image="hc-attacker:golden",
                 guard_image="hc-guard:golden",
                 subnet="10.90.0.0/24", internet_canary=("1.1.1.1", 443),
                 public_name="example.com", unrelated_net_ip="172.17.0.1",
                 kill_budget_ms=10000, listener_app=None, collaborator_app=None,
                 clock=now):
        self._run = run or default_run
        self.node_image = node_image              # minimal base for target containers
        # When set, a python source string seeded into each target and run as its
        # listener instead of a bare `http.server`, so a range can carry a real app
        # (e.g. a deliberately vulnerable one) without baking it into the golden image.
        self.listener_app = listener_app
        # When set, a python source string run on a dedicated in-range collaborator
        # container (harness infrastructure, not a target and never in scope): a target can
        # reach it on the internal network, the attacker cannot reach it through the scope
        # guard, and the harness reads its log over docker exec. It is how SSRF is confirmed
        # out of band while egress stays denied. Created once at provision, torn down at the
        # end; snapshot/restore/kill never touch it, so its hit log persists across a run.
        self.collaborator_app = collaborator_app
        self.collaborator = f"{network}-collaborator"
        self.collab_port = 8080
        self.collab_addr = None                    # "ip:port" a target should fetch, set at provision
        # The attacker container carries the pentest toolchain (nmap, ...); it still has
        # no NET_ADMIN and no nft/ip tooling, so the agent can run tools within scope but
        # cannot reach the scope guard helper. Targets stay on the minimal image.
        self.attacker_image = attacker_image
        self.guard_image = guard_image
        self.network = network
        self.subnet = ipaddress.ip_network(subnet)
        self.internet_canary = internet_canary
        self.public_name = public_name
        self.unrelated_net_ip = unrelated_net_ip   # a second host network, for the §8.3 escape test
        self.kill_budget_ms = kill_budget_ms       # the §8.4 network-freeze time budget
        self._clock = clock
        self._forensics = []        # forensics images a kill left behind, cleared on teardown
        self.attacker = f"{network}-attacker"
        self.guard_table = "hc_guard"
        self._runtime = None        # a hardened OCI runtime (gVisor runsc) when the host has one
        self.hardened = False
        self._host_ip = None        # the operator host's own IP, a §8.3 escape target
        self._eng = None
        self._provisioned = False
        self._targets = {}          # host -> (container_name, ip_str)
        self._target_ports = {}     # host -> [ports], to restart listeners after restore
        # Backing services the target app depends on (e.g. a Postgres sidecar), declared by
        # engagement.target.services. They run in-range on their own IPs with a network alias
        # the app resolves, are reachable by the target but never pinned into the scope guard
        # (so the attacker cannot reach the datastore directly), and are torn down with the range.
        self._services = {}         # alias -> (container_name, ip_str)
        # When the engagement declares a target app, the image built/pulled for it (so restore
        # and the kill switch recreate the real app, not the bundled stdlib node image), and the
        # base image each target was created from.
        self._app_image = None
        self._target_image = {}     # host -> base image tag
        self._app_port = None       # the app's listen port, the live port the proofs probe
        self._snapshots = {}        # snapshot_id -> {host: (name, ip, image_tag)}
        self._snap_seq = 0
        self._out_of_scope_ip = None
        self._guard_port = None     # an allowed in-scope port, for the §8.1(d) probe
        self._in_scope_ip = None

    # --- command helpers ------------------------------------------------
    def _docker(self, *args, input=None):
        r = self._run(["docker", *args], input=input)
        if r.rc != 0:
            raise SandboxError(f"docker {' '.join(args[:2])} failed: {r.err.strip() or r.out.strip()}")
        return r.out.strip()

    def _exec_attacker(self, *args, input=None):
        return self._run(["docker", "exec", self.attacker, *args], input=input)

    # --- §10 interface --------------------------------------------------
    def provision(self, engagement):
        """Build the range for `engagement` and install the scope guard. Returns a
        descriptor; the range is not yet trusted until `proofs_pass` succeeds."""
        if not engagement.in_scope_hosts:
            raise SandboxError("cannot provision: the contract declares no in_scope_hosts")
        image = self._run(["docker", "image", "inspect", self.attacker_image])
        if image.rc != 0:
            raise SandboxError(
                f"required attacker image {self.attacker_image} is missing; build it with: "
                "docker build -t hc-attacker:golden -f infra/sandbox/Dockerfile.attacker infra/sandbox")
        self._eng = engagement
        self.teardown()                                        # start from a clean range
        self._runtime = self._detect_runtime()                 # gVisor if the host offers it (§6.2)
        self.hardened = self._runtime == "runsc"
        self._host_ip = self._discover_host_ip()
        # A declared app port is in scope for the app target. Add it to the allowed ports so the
        # software pre-check (scope.validate) and the guard are built from one policy and agree by
        # construction (§5.3), rather than making the operator repeat the port under scope.
        self._app_port = None
        if engagement.target and engagement.target.get("port"):
            self._app_port = int(engagement.target["port"])
            dflt = engagement.allowed_ports.setdefault("default", [])
            if self._app_port not in dflt:
                dflt.append(self._app_port)
        # Build or pull the target app image on the host now, before the range is sealed and while
        # the host still has internet (§13); the sealed range then only runs the already-built image.
        self._app_image = self._prepare_app_image()

        hosts = self.subnet.hosts()
        self._out_of_scope_ip = str(next(hosts))               # .1: in-range, never in scope
        attacker_ip = str(next(hosts))                         # .2
        self._docker("network", "create", "--internal",
                     "--subnet", str(self.subnet), self.network)
        self._docker(*self._run_args(self.attacker, attacker_ip, self.attacker_image, init=True))

        if self.collaborator_app:                              # in-range OOB collaborator (§SSRF)
            collab_ip = str(next(hosts))                       # consumes .3; targets start at .4
            self._docker(*self._run_args(self.collaborator, collab_ip, self.node_image))
            self._start_listeners(self.collaborator, [self.collab_port], app=self.collaborator_app)
            self.collab_addr = f"{collab_ip}:{self.collab_port}"

        # Backing services come up before the targets so the app can reach them the moment it
        # starts. They take in-range IPs but are never added to the guard's pinned allow list,
        # so the attacker cannot reach the datastore while the app can (the app->service flow is
        # target-side, not governed by the attacker-netns guard).
        self._bring_up_services(hosts)

        pinned, pinned_ports = {}, []
        for host in engagement.in_scope_hosts:
            ip = str(next(hosts))
            name = f"{self.network}-tgt-{len(self._targets)}"
            ports = scope.ports_for(engagement, ipaddress.ip_address(ip))
            base = self._app_image or self.node_image
            if self._app_image:                                # run the user's own app image
                self._docker(*self._app_run_args(name, ip, base))
            else:                                              # the bundled stdlib listener
                self._docker(*self._run_args(name, ip, base))
                self._start_listeners(name, ports)             # a listener so §8.1(d) connects
            pinned[host] = ip
            self._targets[host] = (name, ip)
            self._target_image[host] = base
            self._target_ports[host] = ports
            pinned_ports.append((ip, ports))
            if self._in_scope_ip is None and ports:
                # Probe the app's own port for an app target (other declared ports may have no
                # listener); for a bundled target any allowed port has the stdlib listener.
                self._in_scope_ip = ip
                self._guard_port = self._app_port if self._app_image else int(ports[0])

        errs = engagement.pin({h: ip for h, ip in pinned.items()})
        if errs:
            raise SandboxError("pinning failed: " + "; ".join(errs))

        guard_command = ["run", "--rm", "--network", f"container:{self.attacker}"]
        if self._runtime:
            guard_command += ["--runtime", self._runtime]
        guard_command += ["--cap-drop=ALL", "--cap-add=NET_ADMIN", "-i", self.guard_image,
                          "nft", "-f", "-"]
        ruleset = guard_ruleset(self.guard_table, pinned_ports).encode("utf-8")
        self._docker(*guard_command, input=ruleset)
        # With the guard installed, wait for the app to answer its health path over the real
        # in-range path before the range is used, so recon and the proofs never race its startup.
        if self._app_image:
            self._wait_app_targets_ready()
        self._provisioned = True
        return {"range_id": self.network, "attacker": self.attacker, "mode": "sandboxed",
                "pinned_targets": dict(pinned), "provisioned_at": self._clock()}

    def guard_proof(self):
        """Prove G1/G2 from inside the attacker container: internet dropped, public DNS
        refused, in-range out-of-scope dropped, pinned in-scope allowed (§8.1)."""
        if not self._provisioned or self._in_scope_ip is None:
            return {"pass": False, "assertions": [], "reason": "range not provisioned"}
        return guard_proof_result(
            internet_reachable=self._tcp(self.internet_canary[0], self.internet_canary[1]),
            public_dns_resolves=self._dns(self.public_name),
            out_of_scope_reachable=self._tcp(self._out_of_scope_ip, self._guard_port),
            in_scope_reachable=self._tcp(self._in_scope_ip, self._guard_port))

    def proofs_pass(self):
        """Aggregate G1-G5 (§8): the guard proof (G1/G2, §8.1), the snapshot round-trip
        (G3, §8.2), the escape-attempt (G4, §8.3), and the kill-switch drill (G5, §8.4)
        must all hold. Only then may the harness leave passive-only; a single failed
        proof returns False and keeps it passive-only (§3). Each drill leaves the range
        usable, so a passing run hands back a range ready for the engagement."""
        return (self.guard_proof().get("pass", False)
                and self.snapshot_round_trip().get("pass", False)
                and self.escape_attempt().get("pass", False)
                and self.kill_switch_drill().get("pass", False))

    def snapshot(self):
        """Commit every target container to an image and return a snapshot id, so the
        range's state can be restored after a tier>=2 action (§6.3, G3). Filesystem
        state is captured, which is what the §8.2 round-trip and recoverable actions
        need; a separate backend adds memory checkpointing where a target requires it."""
        if not self._provisioned:
            raise SandboxError("no range to snapshot: not provisioned")
        self._snap_seq += 1
        snap_id = f"{self.network}-snap-{self._snap_seq}"
        images = {}
        for host, (name, ip) in self._targets.items():
            image = f"hc-snap:{snap_id}-{len(images)}"
            self._docker("commit", name, image)
            images[host] = (name, ip, image)
        self._snapshots[snap_id] = images
        return snap_id

    def restore(self, snapshot_id):
        """Recreate every target at its pinned IP, so the range returns to a known
        state (§6.3, G3). `GOLDEN` restores the clean golden image (the per-run baseline
        the Verifier reproduces against, §4.2); any other id restores that snapshot. The
        attacker and the scope guard are untouched, since the guard lives in the
        attacker netns and the IPs are preserved."""
        if snapshot_id == GOLDEN:
            targets = {h: (name, ip, self._target_image.get(h, self.node_image))
                       for h, (name, ip) in self._targets.items()}
        else:
            targets = self._snapshots.get(snapshot_id)
            if targets is None:
                raise SandboxError(f"unknown snapshot {snapshot_id}")
        for host, (name, ip, image) in targets.items():
            self._run(["docker", "rm", "-f", name])
            self._recreate_target(host, name, ip, image)
        return True

    def escape_attempt(self):
        """Prove G4 (§8.3): from the attacker container, try to reach the operator
        host's management interface and a second, unrelated host network, and assert
        both are unreachable. The range gateway is the host's own interface on the
        range and is the real escape path, closed only by the scope guard; the
        container runtime is reported so an operator knows whether kernel-escape
        hardening (gVisor) backs the network containment."""
        if not self._provisioned:
            return {"pass": False, "assertions": [], "reason": "range not provisioned"}
        targets = [(self._out_of_scope_ip, "the range gateway (the operator host's interface on the range)")]
        if self._host_ip:
            targets.append((self._host_ip, "the operator host's management interface"))
        targets.append((self.unrelated_net_ip, "a second, unrelated host network"))
        assertions = [{"name": f"unreachable:{ip}", "describes": desc, "ok": not self._tcp(ip, 22)}
                      for ip, desc in targets]
        return {"pass": all(a["ok"] for a in assertions), "assertions": assertions,
                "hardened_runtime": self._runtime or "runc"}

    def snapshot_round_trip(self):
        """Prove G3 (§8.2): write a marker to a target, snapshot, overwrite the marker,
        restore, and assert the original marker is back."""
        if not self._targets:
            return {"pass": False, "reason": "range not provisioned"}
        host = next(iter(self._targets))
        name = self._targets[host][0]
        original, overwrite, path = "hc-marker-original", "hc-marker-overwritten", "/hc_marker"
        self._write_file(name, path, original)
        snap = self.snapshot()
        self._write_file(name, path, overwrite)
        self.restore(snap)
        got = self._read_file(self._targets[host][0], path)
        return {"pass": got == original, "expected": original, "got": got}

    def kill(self):
        """The kill switch (§6.4, G5): one action freezes the whole range at once, so
        the agent and every target stop instantly, commits each frozen container for
        forensics, then restores the targets from the golden image to a clean state.
        The attacker is left frozen (paused), not destroyed, so its state is preserved
        for analysis and the range can be revived. Returns the freeze latency and what
        was restored."""
        if not self._provisioned:
            return {"ok": True, "frozen_ms": 0, "forensics": [], "restored_from_golden": []}
        containers = [self.attacker, *[name for name, _ in self._targets.values()]]
        t0 = time.monotonic()
        self._run(["docker", "pause", *containers])            # instant freeze (cgroup freezer)
        frozen_ms = int((time.monotonic() - t0) * 1000)
        forensics = []
        for c in containers:
            image = f"hc-forensics:{self.network}-{c}"
            self._run(["docker", "commit", c, image])
            forensics.append(image)
        self._forensics.extend(forensics)
        restored = []
        for host, (name, ip) in self._targets.items():         # targets back to golden
            self._run(["docker", "rm", "-f", name])
            self._recreate_target(host, name, ip, self._target_image.get(host, self.node_image))
            restored.append(host)
        return {"ok": True, "frozen_ms": frozen_ms, "forensics": forensics,
                "restored_from_golden": restored}

    def kill_switch_drill(self):
        """Prove G5 (§8.4): in a dry-run, write a marker to a target, invoke the kill
        switch, and assert the freeze lands within the time budget, the target is wiped
        back to golden (the marker is gone), and the attacker is frozen. Then revive the
        attacker so the proven range stays usable."""
        path = "/kill_marker"
        if self._targets:
            host = next(iter(self._targets))
            self._write_file(self._targets[host][0], path, "pre-kill")
        res = self.kill()
        frozen_ok = res["frozen_ms"] <= self.kill_budget_ms
        wiped = (not self._read_file(self._targets[host][0], path)) if self._targets else False
        paused = self._run(["docker", "inspect", "-f", "{{.State.Status}}",
                            self.attacker]).out.strip() == "paused"
        self._run(["docker", "unpause", self.attacker])        # revive; range stays usable
        return {"pass": bool(frozen_ok and wiped and paused), "frozen_ms": res["frozen_ms"],
                "budget_ms": self.kill_budget_ms, "restored_from_golden": res["restored_from_golden"]}

    def teardown(self):
        """Destroy the range entirely: remove the attacker and every target, drop the
        network, and delete the snapshot and forensics images. Best-effort and
        idempotent, so it doubles as pre-provision cleanup."""
        names = [self.attacker, self.collaborator,
                 *[f"{self.network}-tgt-{i}" for i in range(max(len(self._targets), 8))],
                 *[name for name, _ in self._services.values()]]
        for name in names:
            self._run(["docker", "rm", "-f", name])
        # Sweep any backing-service sidecars whose aliases we no longer track (e.g. a prior
        # run with different services), so pre-provision cleanup starts from a clean range.
        stale = self._run(["docker", "ps", "-aq", "--filter", f"name={self.network}-svc-"])
        for cid in stale.out.split():
            self._run(["docker", "rm", "-f", cid])
        self._run(["docker", "network", "rm", self.network])
        images = [img for snap in self._snapshots.values() for _, _, img in snap.values()]
        for image in images + self._forensics:
            self._run(["docker", "rmi", "-f", image])
        self._provisioned = False
        self.collab_addr = None
        self._targets, self._target_ports, self._snapshots, self._forensics = {}, {}, {}, []
        self._services = {}
        self._app_image, self._target_image, self._app_port = None, {}, None
        return True

    # --- helpers --------------------------------------------------------
    def _run_args(self, name, ip, image, *, init=False):
        """`docker run` args for a range container, under the hardened runtime when one
        is present, so a container escape is contained in gVisor's user-space kernel
        rather than the host kernel (§6.2, G4). `init` adds an init process that reaps
        orphaned children, which the attacker needs because the headless browser it runs
        leaves helper processes behind that would otherwise accumulate as zombies."""
        args = ["run", "-d", "--name", name, "--network", self.network, "--ip", ip]
        if init:
            args.append("--init")
        if self._runtime:
            args += ["--runtime", self._runtime]
        return [*args, image]

    def _detect_runtime(self):
        r = self._run(["docker", "info", "--format", "{{json .Runtimes}}"])
        return "runsc" if r.rc == 0 and "runsc" in (r.out or "") else None

    def _discover_host_ip(self):
        # A UDP connect asks the OS to select a route but sends no packet.
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_probe:
                route_probe.connect(("1.1.1.1", 80))
                return route_probe.getsockname()[0]
        except OSError:
            return None

    def _start_listeners(self, name, ports, app=None):
        # A custom app (seeded over stdin so it never touches the golden image), or the
        # plain http.server stand-in. Re-seeded here so restore and kill bring it back.
        # `app` overrides the target listener, so the collaborator runs its own app.
        app = app if app is not None else self.listener_app
        if app:
            self._docker("exec", "-i", name, "sh", "-c", "cat > /tmp/app.py", input=app)
        for port in ports:
            if app:
                self._docker("exec", "-d", name, "python3", "/tmp/app.py", str(port))
            else:
                self._docker("exec", "-d", name, "python3", "-m", "http.server", str(port))

    def _prepare_app_image(self):
        """Build or pull the target app image on the host, before the range is sealed (§13), and
        return its tag; None when the engagement declares no app (the bundled listener runs)."""
        t = (self._eng.target if self._eng else None) or {}
        if t.get("image"):
            img = t["image"]
            if self._run(["docker", "image", "inspect", img]).rc != 0:
                self._docker("pull", img)          # not present locally; fetch it (host has internet)
            return img
        if t.get("build"):
            b = t["build"]
            tag = f"hc-target:{self.network}"
            dockerfile = os.path.join(b["context"], b["dockerfile"])
            self._docker("build", "-t", tag, "-f", dockerfile, b["context"])
            return tag
        return None

    def _app_run_args(self, name, ip, image):
        """`docker run` args for a target running the user's app image: the engagement's env is
        injected so the app finds its datastore by the service alias, and the image's own entry
        point runs (no seeded listener). Under the hardened runtime when the host offers one."""
        args = ["run", "-d", "--name", name, "--network", self.network, "--ip", ip]
        if self._runtime:
            args += ["--runtime", self._runtime]
        for k, v in ((self._eng.target or {}).get("env") or {}).items():
            args += ["-e", f"{k}={v}"]
        return [*args, image]

    def _recreate_target(self, host, name, ip, image):
        """Recreate one target from `image` at its pinned IP. An app target runs the app image
        with its env; a bundled target runs the node image and gets its stdlib listener back."""
        if self._app_image:
            self._docker(*self._app_run_args(name, ip, image))
        else:
            self._docker(*self._run_args(name, ip, image))
            self._start_listeners(name, self._target_ports.get(host, []))

    def _wait_app_targets_ready(self):
        """Poll each app target's health path from the attacker until it answers or the declared
        timeout elapses, so recon and the proofs never race the app's startup (fail-closed)."""
        ready = (self._eng.target or {}).get("ready") or {}
        path, timeout_s = ready.get("path", "/"), ready.get("timeout_s", 60)
        deadline = time.monotonic() + timeout_s
        for host, (name, ip) in self._targets.items():
            port = self._app_port
            while True:
                out = self._exec_attacker("python3", "-c", _READY_PROBE, ip, str(port), path).out
                if "READY" in out:
                    break
                if time.monotonic() >= deadline:
                    raise SandboxError(f"target app at {ip}:{port}{path} was not ready within "
                                       f"{timeout_s}s (last: {out.strip()})")
                time.sleep(0.5)

    def _bring_up_services(self, hosts):
        """Stand up each `engagement.target` backing service as an in-range sidecar.

        Postgres is the first supported engine. The image is pulled on the host, which runs
        before the range is sealed and still has internet (§13); the sealed range then only
        runs it. The container takes an in-range IP and a `--network-alias` the app resolves,
        waits until it accepts connections, and is seeded with the declared init_sql. The IP
        is never added to the guard's pinned allow list, so the datastore is unreachable from
        the attacker while the app reaches it over the internal network."""
        target = (self._eng.target if self._eng else None) or {}
        for svc in target.get("services", []):
            if svc["engine"] != "postgres":
                raise SandboxError(f"unsupported service engine: {svc['engine']}")
            ip = str(next(hosts))
            name = f"{self.network}-svc-{svc['name']}"
            self._bring_up_postgres(name, ip, svc)
            self._services[svc["name"]] = (name, ip)

    def _bring_up_postgres(self, name, ip, svc):
        image = f"postgres:{svc['version']}"
        self._docker("pull", image)                            # host pull, pre-seal (§13)
        args = ["run", "-d", "--name", name, "--network", self.network, "--ip", ip,
                "--network-alias", svc["name"]]
        if self._runtime:
            args += ["--runtime", self._runtime]
        args += ["-e", f"POSTGRES_USER={svc['user']}",
                 "-e", f"POSTGRES_PASSWORD={svc['password']}",
                 "-e", f"POSTGRES_DB={svc['db']}", image]
        self._docker(*args)
        self._wait_pg_ready(name, svc)
        if svc.get("init_sql"):
            self._seed_postgres(name, svc)

    def _wait_pg_ready(self, name, svc):
        """Poll `pg_isready` until the server accepts connections or the budget elapses, so
        the app never starts against a datastore that is not up (fail-closed on timeout)."""
        deadline = time.monotonic() + _SERVICE_READY_TIMEOUT_S
        while True:
            r = self._run(["docker", "exec", name, "pg_isready", "-U", svc["user"], "-d", svc["db"]])
            if r.rc == 0:
                return
            if time.monotonic() >= deadline:
                raise SandboxError(f"service '{svc['name']}' (postgres) did not accept "
                                   f"connections within {_SERVICE_READY_TIMEOUT_S}s")
            time.sleep(0.5)

    def _seed_postgres(self, name, svc):
        """Apply the declared init_sql into the fresh database. ON_ERROR_STOP aborts
        provisioning loudly on a bad fixture rather than leaving a half-seeded datastore."""
        try:
            with open(svc["init_sql"], "r", encoding="utf-8") as fh:
                sql = fh.read()
        except OSError as ex:
            raise SandboxError(f"cannot read init_sql for service '{svc['name']}': {ex}")
        r = self._run(["docker", "exec", "-i", name, "psql", "-v", "ON_ERROR_STOP=1",
                       "-U", svc["user"], "-d", svc["db"]], input=sql)
        if r.rc != 0:
            raise SandboxError(f"seeding service '{svc['name']}' from {svc['init_sql']} failed: "
                               f"{r.err.strip() or r.out.strip()}")

    def _write_file(self, name, path, content):
        self._exec(name, "sh", "-c", f"echo {content} > {path}")

    def _read_file(self, name, path):
        """Read a file from a container, returning empty when it is absent (a missing
        file is a valid state, e.g. a marker wiped by a golden restore), so a read never
        fails the caller the way a bare `cat` on a missing path would."""
        return self._run(["docker", "exec", name, "sh", "-c",
                          f"cat {path} 2>/dev/null || true"]).out.strip()

    def _exec(self, name, *args, input=None):
        r = self._run(["docker", "exec", name, *args], input=input)
        if r.rc != 0:
            raise SandboxError(f"docker exec {name} {args[0]} failed: {r.err.strip()}")
        return r

    # --- probes ---------------------------------------------------------
    def _tcp(self, ip, port):
        out = self._exec_attacker("python3", "-c", _TCP_PROBE, str(ip), str(port)).out
        return "CONNECTED" in out

    def _dns(self, name):
        # getaddrinfo blocks in libc past any in-process timeout, so bound it from outside:
        # `timeout` kills the probe if the lookup has not returned, which reads as "refused".
        out = self._exec_attacker("timeout", "2", "python3", "-c", _DNS_PROBE, str(name)).out
        return "RESOLVED" in out
