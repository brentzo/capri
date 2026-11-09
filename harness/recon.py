"""Live reconnaissance against a provisioned range (HC-AGENT-01, phase_recon).

Produces the target model the threat-model phase consumes, by probing each pinned
in-scope target on its allowed ports from the attacker container. It reads state only
(a TCP connect and, for an open port, one HTTP request), and it stays within scope
because it touches only pinned targets on their allowed ports, which the scope guard
enforces regardless. It reports facts, never conclusions: an open port and an HTTP
status are observations, and the threat-model phase decides which cards apply.
"""
from harness.sandbox.base import default_run
from harness.sandbox.probe import DockerProbe
from harness.substrate import scope

_PORT_PROBE = (
    "import socket,sys\n"
    "try:\n"
    "    s=socket.socket(); s.settimeout(3); s.connect((sys.argv[1], int(sys.argv[2]))); print('OPEN')\n"
    "except Exception: print('CLOSED')\n"
)


def _tcp_open(run, attacker, ip, port):
    r = run(["docker", "exec", attacker, "python3", "-c", _PORT_PROBE, ip, str(port)])
    return "OPEN" in (r.out or "")


def phase_recon(attacker, eng, *, run=None):
    """Probe the pinned in-scope targets and return `{asset: facts}`.

    For each pinned host, scan its allowed ports, record which are open, and on the
    first port that speaks HTTP mark it a web service with its status. `reachable` is
    true when any allowed port is open, so the threat model can gate on a live target."""
    run = run or default_run
    probe = DockerProbe(attacker, eng.pinned, run=run)
    model = {}
    for host, ip_obj in sorted(eng.pinned.items()):
        ip = str(ip_obj)
        open_ports, http_status = [], None
        for port in scope.ports_for(eng, ip_obj):
            if not _tcp_open(run, attacker, ip, port):
                continue
            open_ports.append(port)
            if http_status is None:
                code = probe.run({"target": ip, "port": port})["parsed"]["http_status"]
                if code:
                    http_status = code
        facts = {"host": host, "addr": ip, "reachable": bool(open_ports),
                 "open_ports": open_ports}
        if http_status:
            facts["asset.type"] = "web_service"
            facts["http_status"] = http_status
        model[host.split(".")[0]] = facts
    return model
