"""Live reconnaissance against a provisioned range (HC-AGENT-01, phase_recon).

Produces the target model the threat-model phase consumes, by probing each pinned
in-scope target on its allowed ports from the attacker container. It reads state only
(a TCP connect and HTTP requests), and it stays within scope because it touches only
pinned targets on their allowed ports, which the scope guard enforces regardless. It
reports facts, never conclusions: an open port, an HTTP status, the parameters a page
exposes, an auth scheme, and privileged sibling paths are observations, and the
threat-model phase decides which technique cards apply over them.
"""
import re

from harness.sandbox.adapters import HttpRequestAdapter
from harness.sandbox.base import default_run
from harness.sandbox.probe import DockerProbe
from harness.substrate import scope

_PORT_PROBE = (
    "import socket,sys\n"
    "try:\n"
    "    s=socket.socket(); s.settimeout(3); s.connect((sys.argv[1], int(sys.argv[2]))); print('OPEN')\n"
    "except Exception: print('CLOSED')\n"
)

# Parameter names a landing page exposes in its own links (?name= / &name=).
_PARAM_RE = re.compile(r"[?&]([A-Za-z_]\w*)=")
# A short list of conventional paths recon checks, the way a web probe checks common
# locations: a login endpoint to read the auth scheme from, and privileged areas.
_LOGIN_PATHS = ("/login",)
_ADMIN_PATHS = ("/admin",)


def _tcp_open(run, attacker, ip, port):
    r = run(["docker", "exec", attacker, "python3", "-c", _PORT_PROBE, ip, str(port)])
    return "OPEN" in (r.out or "")


def phase_recon(attacker, eng, *, run=None):
    """Probe the pinned in-scope targets and return `{asset: facts}`.

    For each pinned host, scan its allowed ports, record which are open, and on the
    first port that speaks HTTP mark it an http endpoint with its status and run the
    light web discovery the technique cards gate on. `reachable` is true when any
    allowed port is open, so the threat model can gate on a live target."""
    run = run or default_run
    probe = DockerProbe(attacker, eng.pinned, run=run)
    http = HttpRequestAdapter(attacker, eng.pinned, run=run)
    model = {}
    for host, ip_obj in sorted(eng.pinned.items()):
        ip = str(ip_obj)
        open_ports, http_status, http_port = [], None, None
        for port in scope.ports_for(eng, ip_obj):
            if not _tcp_open(run, attacker, ip, port):
                continue
            open_ports.append(port)
            if http_status is None:
                code = probe.run({"target": ip, "port": port})["parsed"]["http_status"]
                if code:
                    http_status, http_port = code, port
        facts = {"host": host, "addr": ip, "reachable": bool(open_ports),
                 "open_ports": open_ports}
        if http_status:
            facts["asset.type"] = "http_endpoint"
            facts["http_status"] = http_status
            _enrich_web(facts, http, ip, http_port)
        model[host.split(".")[0]] = facts
    return model


def _enrich_web(facts, http, ip, port):
    """Light web discovery, reading state only: the parameters the landing page exposes,
    a JWT auth scheme if a login endpoint hands one back, and privileged sibling paths
    from the conventional-path list. These are exactly the facts the web technique cards
    gate their applicability on, so recon reports them and the cards decide."""
    def fetch(path):
        return http._send_http(f"http://{ip}:{port}{path}")   # (status, body)

    _, home = fetch("/")
    params = sorted(set(_PARAM_RE.findall(home or "")))
    if params:
        facts["asset.params"] = params
    for login in _LOGIN_PATHS:
        status, body = fetch(login + "?user=1")
        if status == 200 and (body or "").strip().count(".") == 2:
            facts["asset.auth"] = "jwt"
            facts["asset.login_path"] = login
            # recon obtained a token, so an authenticated session is available: the
            # precondition the authorization techniques gate on is met.
            facts["authenticated_session"] = True
            break
    siblings = [path for path in _ADMIN_PATHS if fetch(path)[0] in (200, 401, 403)]
    if siblings:
        facts["asset.privileged_siblings"] = siblings
