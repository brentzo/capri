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
# Conventional cacheable endpoints, probed for a cache header so the cache-poisoning card
# has the `asset.cacheable` fact it gates on.
_CACHE_PATHS = ("/promo",)
_CACHE_HEADERS = ("cache-control", "x-cache", "age")
# Conventional cookie-session entry points, probed for a Set-Cookie so the session-fixation
# card (which gates on an `asset.type == "login_endpoint"` asset) has one to apply over.
_SESSION_PATHS = ("/portal",)
# Conventional sensitive-action pages, probed so the CSRF and clickjacking cards (which gate
# on asset.has_state_changing_action) have an action to apply over.
_ACTION_PATHS = ("/portal/settings",)
# Conventional WebSocket paths; a 426 Upgrade Required marks a WS endpoint the WS-hijack card
# (which gates on asset.has_websocket) can apply over.
_WS_PATHS = ("/ws",)
# Conventional pages that reflect caller markup, probed so the DOM-clobbering card (which
# gates on asset.allows_named_markup) has a page to apply over.
_CLOBBER_PATHS = ("/clobber",)


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
        base_key = host.split(".")[0]
        extra = {}
        if http_status:
            facts["asset.type"] = "http_endpoint"
            facts["http_status"] = http_status
            extra = _enrich_web(facts, http, ip, http_port)
        model[base_key] = facts
        for suffix, sub in extra.items():
            model[f"{base_key}-{suffix}"] = sub
    return model


def _enrich_web(facts, http, ip, port):
    """Light web discovery, reading state only: the parameters the landing page exposes,
    a JWT auth scheme if a login endpoint hands one back, privileged sibling paths from the
    conventional-path list, cacheability from a cache header, and a cookie-session login
    endpoint. These are exactly the facts the web technique cards gate their applicability
    on, so recon reports them and the cards decide. Returns extra assets (keyed by a
    suffix) that live on the same host but are a distinct asset type, such as a login
    endpoint, which the session card applies over rather than the http endpoint."""
    def fetch(path):
        return http._send_http(f"http://{ip}:{port}{path}")   # (status, body)

    def fetch_full(path):
        return http._send_http_full(f"http://{ip}:{port}{path}")  # (status, headers, body)

    _, home_headers, home = fetch_full("/")
    ctype = {k.lower(): v for k, v in (home_headers or {}).items()}.get("content-type", "")
    if "text/html" in ctype.lower():
        facts["asset.renders_html"] = True                 # the DOM-based client cards gate on this
    params = sorted(set(_PARAM_RE.findall(home or "")))
    if params:
        facts["asset.params"] = params
    for cpath in _CACHE_PATHS:
        status, headers, _ = fetch_full(cpath)
        low = {k.lower(): v for k, v in (headers or {}).items()}
        if status == 200 and any(h in low for h in _CACHE_HEADERS):
            facts["asset.cacheable"] = True
            facts["cacheable_endpoint"] = True
            facts["asset.cache_path"] = cpath
            break
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
    for apath in _ACTION_PATHS:
        if fetch(apath)[0] == 200:
            facts["asset.has_state_changing_action"] = True
            facts["asset.action_path"] = apath
            break
    for wpath in _WS_PATHS:
        if fetch(wpath)[0] == 426:                 # Upgrade Required: a WebSocket endpoint
            facts["asset.has_websocket"] = True
            facts["asset.ws_path"] = wpath
            break
    for cpath in _CLOBBER_PATHS:
        if fetch(cpath)[0] == 200:
            facts["asset.allows_named_markup"] = True
            facts["asset.clobber_path"] = cpath
            break
    extra = {}
    for spath in _SESSION_PATHS:
        status, headers, _ = fetch_full(spath)
        cookie = _set_cookie_name(headers)
        if status == 200 and cookie:
            extra["login"] = {"host": facts["host"], "addr": ip, "reachable": True,
                              "asset.type": "login_endpoint", "asset.session_cookie": cookie,
                              "login_endpoint": True, "http_status": status,
                              "asset.login_path": spath}
            break
    return extra


def _set_cookie_name(headers):
    """The name of the cookie a Set-Cookie response header issues, or None. A login
    endpoint that hands back a session cookie is what the session-fixation card applies
    over, so recon reports the cookie name and the card gates on it existing."""
    for key, val in (headers or {}).items():
        if key.lower() == "set-cookie":
            name = str(val).split(";", 1)[0].split("=", 1)[0].strip()
            if name:
                return name
    return None
