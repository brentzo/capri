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
                 public_name="example.com", clock=now):
        self._run = run or default_run
        self.node_image = node_image
        self.network = network
        self.subnet = ipaddress.ip_network(subnet)
        self.internet_canary = internet_canary
        self.public_name = public_name
        self._clock = clock
        self.attacker = f"{network}-attacker"
        self.guard_table = "hc_guard"
        self._eng = None
        self._attacker_pid = None
        self._targets = {}          # host -> ip_str
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
        self.kill()                                             # start from a clean range

        hosts = self.subnet.hosts()
        self._out_of_scope_ip = str(next(hosts))               # .1: in-range, never in scope
        attacker_ip = str(next(hosts))                         # .2
        self._docker("network", "create", "--internal",
                     "--subnet", str(self.subnet), self.network)
        self._docker("run", "-d", "--name", self.attacker, "--network", self.network,
                     "--ip", attacker_ip, self.node_image)     # no NET_ADMIN by design

        pinned, pinned_ports = {}, []
        for host in engagement.in_scope_hosts:
            ip = str(next(hosts))
            name = f"{self.network}-tgt-{len(self._targets)}"
            self._docker("run", "-d", "--name", name, "--network", self.network,
                         "--ip", ip, self.node_image)
            pinned[host] = ip
            self._targets[host] = ip
            ports = scope.ports_for(engagement, ipaddress.ip_address(ip))
            pinned_ports.append((ip, ports))
            for port in ports:                                 # a listener so §8.1(d) connects
                self._docker("exec", "-d", name, "python3", "-m", "http.server", str(port))
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
        """Aggregate G1-G5 (§8). Only the guard proof (G1/G2, §8.1) is implemented; the
        snapshot round-trip (G3), escape-attempt (G4), and kill-switch drill (G5) are
        the next slices, so this stays False and the harness stays passive-only until
        all five are proven (§3: an unproven guarantee is treated as absent)."""
        return False

    def snapshot(self):
        raise SandboxError("snapshot/restore (G3) is not yet implemented in this backend")

    def restore(self, snapshot_id):
        raise SandboxError("snapshot/restore (G3) is not yet implemented in this backend")

    def kill(self):
        """Tear the range down: remove the attacker and every target, then the network.
        Best-effort and idempotent, so it doubles as pre-provision cleanup (§6.4)."""
        names = [self.attacker, *[f"{self.network}-tgt-{i}" for i in range(len(self._targets) or 8)]]
        for name in names:
            self._run(["docker", "rm", "-f", name])
        self._run(["docker", "network", "rm", self.network])
        self._attacker_pid = None
        self._targets = {}
        return True

    # --- probes ---------------------------------------------------------
    def _tcp(self, ip, port):
        out = self._exec_attacker("python3", "-c", _TCP_PROBE, str(ip), str(port)).out
        return "CONNECTED" in out

    def _dns(self, name):
        out = self._exec_attacker("python3", "-c", _DNS_PROBE, str(name)).out
        return "RESOLVED" in out
