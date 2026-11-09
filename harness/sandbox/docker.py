"""Docker-backed sandbox range (HC-SUB-01, first self-hostable backend).

Provisions one egress-denied Docker network (`--internal`, so the range has no route
off the host by construction = G2) holding a target container per in-scope host and
one attacker container where tool adapters run. The scope guard (§5) is an nftables
ruleset the HOST installs into the attacker's network namespace: default-deny egress,
allowing only the pinned in-scope IPs on their allowed ports. The attacker runs with
no NET_ADMIN and no nft binary, so the agent can neither reach an out-of-scope host
nor reconfigure the guard (§2: the agent itself is in the threat model). The guard
proof (§8.1) then proves all of this from inside the attacker container.

No nested virtualization is required, so this runs on any commodity Linux host (and
inside Docker Desktop's Linux VM on macOS/Windows). A separate gateway host and
microVM/gVisor isolation harden G4 further and are selected the same way, behind this
interface; this backend's job is G1 and G2, proven by the guard proof.

Every docker/nsenter call goes through an injected `run`, so provisioning and proof
logic is unit-tested against a stub with no Docker present (`tests/test_sandbox.py`);
the live path uses the default subprocess runner and must execute on the range host
as root (nsenter into the attacker netns needs it).
"""
import ipaddress
import time

from harness.sandbox.base import (
    Sandbox,
    SandboxError,
    default_run,
    guard_proof_result,
)
from harness.store.db import now
from harness.substrate import scope

# Probes the attacker container runs; stdlib python3 only, so the node image stays tiny.
_TCP_PROBE = (
    "import socket,sys\n"
    "s=socket.socket(); s.settimeout(3)\n"
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
    """A range built from Docker containers plus a host-installed nft scope guard.

    `provision` is idempotent-by-teardown: it removes any range of the same name
    first, so a re-driven run starts clean. The backend holds no engagement secrets;
    it only shells out to `docker` and `nsenter` through the injected runner."""

    def __init__(self, *, run=None, node_image="hc-node:golden", network="hc-range",
                 subnet="10.90.0.0/24", internet_canary=("1.1.1.1", 443),
                 public_name="example.com", unrelated_net_ip="172.17.0.1",
                 kill_budget_ms=10000, clock=now):
        self._run = run or default_run
        self.node_image = node_image
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
        self._attacker_pid = None
        self._targets = {}          # host -> (container_name, ip_str)
        self._target_ports = {}     # host -> [ports], to restart listeners after restore
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

    def _attacker_netns(self, *args, input=None):
        if self._attacker_pid is None:
            raise SandboxError("range not provisioned: no attacker netns")
        r = self._run(["nsenter", "-t", str(self._attacker_pid), "-n", *args], input=input)
        if r.rc != 0:
            raise SandboxError(f"nsenter {' '.join(args[:1])} failed: {r.err.strip()}")
        return r.out.strip()

    def _exec_attacker(self, *args, input=None):
        return self._run(["docker", "exec", self.attacker, *args], input=input)

    # --- §10 interface --------------------------------------------------
    def provision(self, engagement):
        """Build the range for `engagement` and install the scope guard. Returns a
        descriptor; the range is not yet trusted until `proofs_pass` succeeds."""
        if not engagement.in_scope_hosts:
            raise SandboxError("cannot provision: the contract declares no in_scope_hosts")
        self._eng = engagement
        self.teardown()                                        # start from a clean range
        self._runtime = self._detect_runtime()                 # gVisor if the host offers it (§6.2)
        self.hardened = self._runtime == "runsc"
        self._host_ip = self._discover_host_ip()

        hosts = self.subnet.hosts()
        self._out_of_scope_ip = str(next(hosts))               # .1: in-range, never in scope
        attacker_ip = str(next(hosts))                         # .2
        self._docker("network", "create", "--internal",
                     "--subnet", str(self.subnet), self.network)
        self._docker(*self._run_args(self.attacker, attacker_ip, self.node_image))

        pinned, pinned_ports = {}, []
        for host in engagement.in_scope_hosts:
            ip = str(next(hosts))
            name = f"{self.network}-tgt-{len(self._targets)}"
            self._docker(*self._run_args(name, ip, self.node_image))
            pinned[host] = ip
            self._targets[host] = (name, ip)
            ports = scope.ports_for(engagement, ipaddress.ip_address(ip))
            self._target_ports[host] = ports
            pinned_ports.append((ip, ports))
            self._start_listeners(name, ports)                 # a listener so §8.1(d) connects
            if self._in_scope_ip is None and ports:
                self._in_scope_ip, self._guard_port = ip, int(ports[0])

        errs = engagement.pin({h: ip for h, ip in pinned.items()})
        if errs:
            raise SandboxError("pinning failed: " + "; ".join(errs))

        self._attacker_pid = int(self._docker("inspect", "-f", "{{.State.Pid}}", self.attacker))
        self._attacker_netns("nft", "-f", "-", input=guard_ruleset(self.guard_table, pinned_ports))
        return {"range_id": self.network, "attacker": self.attacker, "mode": "sandboxed",
                "pinned_targets": dict(pinned), "provisioned_at": self._clock()}

    def guard_proof(self):
        """Prove G1/G2 from inside the attacker container: internet dropped, public DNS
        refused, in-range out-of-scope dropped, pinned in-scope allowed (§8.1)."""
        if self._attacker_pid is None or self._in_scope_ip is None:
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
        if self._attacker_pid is None:
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
        """Recreate every target from its snapshot image at the same pinned IP, so the
        range returns to the captured state (§6.3, G3). The attacker and the scope
        guard are untouched, since the guard lives in the attacker netns and the IPs
        are preserved."""
        images = self._snapshots.get(snapshot_id)
        if images is None:
            raise SandboxError(f"unknown snapshot {snapshot_id}")
        for host, (name, ip, image) in images.items():
            self._run(["docker", "rm", "-f", name])
            self._docker(*self._run_args(name, ip, image))
            self._start_listeners(name, self._target_ports.get(host, []))
        return True

    def escape_attempt(self):
        """Prove G4 (§8.3): from the attacker container, try to reach the operator
        host's management interface and a second, unrelated host network, and assert
        both are unreachable. The range gateway is the host's own interface on the
        range and is the real escape path, closed only by the scope guard; the
        container runtime is reported so an operator knows whether kernel-escape
        hardening (gVisor) backs the network containment."""
        if self._attacker_pid is None:
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
        if self._attacker_pid is None:
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
            self._docker(*self._run_args(name, ip, self.node_image))
            self._start_listeners(name, self._target_ports.get(host, []))
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
        names = [self.attacker, *[f"{self.network}-tgt-{i}"
                                  for i in range(max(len(self._targets), 8))]]
        for name in names:
            self._run(["docker", "rm", "-f", name])
        self._run(["docker", "network", "rm", self.network])
        images = [img for snap in self._snapshots.values() for _, _, img in snap.values()]
        for image in images + self._forensics:
            self._run(["docker", "rmi", "-f", image])
        self._attacker_pid = None
        self._targets, self._target_ports, self._snapshots, self._forensics = {}, {}, {}, []
        return True

    # --- helpers --------------------------------------------------------
    def _run_args(self, name, ip, image):
        """`docker run` args for a range container, under the hardened runtime when one
        is present, so a container escape is contained in gVisor's user-space kernel
        rather than the host kernel (§6.2, G4)."""
        args = ["run", "-d", "--name", name, "--network", self.network, "--ip", ip]
        if self._runtime:
            args += ["--runtime", self._runtime]
        return [*args, image]

    def _detect_runtime(self):
        r = self._run(["docker", "info", "--format", "{{json .Runtimes}}"])
        return "runsc" if r.rc == 0 and "runsc" in (r.out or "") else None

    def _discover_host_ip(self):
        r = self._run(["ip", "route", "get", "1.1.1.1"])
        toks = r.out.split() if r.rc == 0 else []
        return toks[toks.index("src") + 1] if "src" in toks else None

    def _start_listeners(self, name, ports):
        for port in ports:
            self._docker("exec", "-d", name, "python3", "-m", "http.server", str(port))

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
        out = self._exec_attacker("python3", "-c", _DNS_PROBE, str(name)).out
        return "RESOLVED" in out
