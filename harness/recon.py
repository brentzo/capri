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


def phase_recon(attacker, eng, *, run=None, crawler=None, source_root=None):
    """Probe the pinned in-scope targets and return `{asset: facts}`.

    For each pinned host, scan its allowed ports, record which are open, and on the
    first port that speaks HTTP mark it an http endpoint with its status and run the
    light web discovery the technique cards gate on. `reachable` is true when any
    allowed port is open, so the threat model can gate on a live target.

    The endpoint surface comes from one of two sources, both projected into the same
    endpoint-as-asset entries (see `project_surface`) so the recon-derived injection
    techniques route at real parameters rather than literals:

    - `source_root` (preferred when given): the target app's own source is read to
      enumerate the complete registered surface, including the auth-gated routes a crawl
      can never reach. Capri is run against its own app, so the operator has the source.
    - `crawler`: a black-box crawl of the running app, the corroboration layer when there
      is no source (or to confirm what the source claims). When both are given, the source
      is authoritative and the crawler is not run, to avoid the blind fan-out.

    With neither, only the host asset and its conventional-path facts are produced."""
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
        if http_status:
            if source_root is not None:
                model.update(phase_source_recon(source_root, host=host, addr=ip,
                                                port=http_port))
            elif crawler is not None:
                surface = crawler.crawl(ip, http_port)
                model.update(project_surface(surface, host, ip, http_port))
    return model


def project_mobile_inventory(inventory):
    """Project manifest facts into one app asset and one asset per supported deep link."""
    package = inventory["package"]
    base = {"host": "mobile-app", "addr": "mobile-app", "reachable": True,
            "asset.type": "mobile_app", "mobile_app": True, "has_deep_link": False,
            "mobile.package": package,
            "mobile.sha256": inventory["sha256"],
            "mobile.components": inventory["components"],
            "mobile.permissions": inventory["permissions"]}
    model = {"mobile-app": base}
    for link in inventory["deep_links"]:
        model[f"mobile-app::{link['id']}"] = {
            **base, "has_deep_link": True, "asset.has_deep_link": True,
            "asset.mobile_link_id": link["id"],
            "mobile.component": link["component"],
            "mobile.link_filter_index": link["filter_index"],
            "mobile.link_scheme": link["scheme"], "mobile.link_host": link["host"],
            "mobile.link_path": link["path"]}
    return model


# A benign value a path parameter is concretized to when it stands in the probe path for
# a *different* injection point (e.g. probing `?search=` on `/api/accounts/:id/transactions`
# needs a value for `:id`). It is deliberately innocuous: recon never attacks the path here.
_PATH_PARAM_DEFAULT = "1"
# Matches a `:name` path parameter or a `*` splat segment produced by the source extractor.
_PATH_HOLE_RE = re.compile(r":[A-Za-z_]\w*|\*")


def _concretize(path):
    """Replace `:param` / `*` holes in a source route with a benign default, so the path is a
    literal one the probe adapters (which append `?param=payload` to a concrete path) can hit."""
    return _PATH_HOLE_RE.sub(_PATH_PARAM_DEFAULT, path)


def project_surface(surface, host, ip, port=None):
    """Project a surface map into endpoint-as-asset target-model entries.

    The map may come from a black-box crawl (the endpoints a crawler reached) or from
    source-aware extraction (`harness.sourcemap.extract_surface`, the complete registered
    surface including auth-gated routes a crawl can never reach). Either way this projects it
    into the `{asset: facts}` shape the threat-model phase consumes: each (endpoint, parameter)
    pair becomes its own asset keyed `<base>::<path>?<param>`, carrying the per-endpoint facts
    the recon-derived injection cards route over (`asset.path`, `asset.param`, `asset.params`),
    so the probe is aimed at a parameter recon discovered rather than one named in the registry.

    Query and form parameters are directly injectable: the adapters append `?param=payload` to
    `asset.path`, so a route's `:id`/`*` holes are concretized to a benign default first (recon
    never attacks the path value here) and `asset.path` is always literal. A path parameter is a
    real injection point too (IDOR / path SQLi on `:id`), but the current adapters inject only in
    the query string, so each path parameter becomes its own asset tagged `asset.inject_in:
    "path"` carrying the `{name}` template in `asset.path_template` and the concretized default in
    `asset.path`, and deliberately *without* `asset.param`; a path-injection card binds it in a
    later slice, while the existing query-injection cards' `{asset.param}` template resolves to
    None and the binder skips them rather than probing the wrong place. An endpoint with neither
    kind of parameter has no injection point and is skipped here; it stays visible to other phases
    on the host asset `phase_recon` builds.

    When the source extractor reports a route as auth-gated, each asset carries
    `asset.auth_required: True`; confirming a probe against such a route needs a session, which a
    later slice supplies, so the flag travels with the asset rather than silently dropping the
    route from the defensive map.

    `open_ports` carries the pinned port the surface was taken against, so the Operator reads the
    same connection fact on an endpoint asset that it reads on the host asset; without it the
    Operator cannot form a probe and the hunt stalls before dispatch."""
    base_key = host.split(".")[0]
    model = {}
    for ep in surface.get("endpoints") or []:
        path = ep.get("path")
        if not path:
            continue
        method = str(ep.get("method") or "GET").upper()
        status = ep.get("status")
        renders_html = bool(ep.get("renders_html"))
        auth_required = bool(ep.get("auth"))
        path_params = [p for p in (ep.get("path_params") or []) if p]
        concrete = _concretize(path)
        sink_analyzed = bool(ep.get("sink_analyzed"))
        sink_risk = list(ep.get("sink_risk") or [])

        def _base_facts():
            facts = {"host": host, "addr": ip, "reachable": True,
                     "asset.type": "http_endpoint", "http_status": status,
                     "asset.path": concrete, "asset.method": method}
            if port is not None:
                facts["open_ports"] = [port]
            if renders_html:
                facts["asset.renders_html"] = True
            if auth_required:
                facts["asset.auth_required"] = True
            if sink_analyzed:
                # Source-aware sink reachability (Slice B): the injection cards gate on these
                # so a probe fires only where a param can reach an unsafe sink. A black-box
                # crawl sets neither fact, and the cards fall back to param presence.
                facts["asset.sink_analyzed"] = True
                facts["asset.sink_risk"] = list(sink_risk)
            return facts

        for param in sorted({p for p in (ep.get("params") or []) if p}):
            facts = _base_facts()
            facts["asset.params"] = [param]
            facts["asset.param"] = param
            model[f"{base_key}::{concrete}?{param}"] = facts
        for param in sorted(set(path_params)):
            facts = _base_facts()
            facts["asset.inject_in"] = "path"
            facts["asset.path_param"] = param
            # The target hole becomes a `{name}` template slot; the other holes concretize to
            # the benign default, so a path-injection card fills one segment and nothing else.
            protected = path.replace(":" + param, "\x00", 1)
            facts["asset.path_template"] = _concretize(protected).replace("\x00", "{%s}" % param)
            model[f"{base_key}::{path}${param}"] = facts
    return model


def phase_source_recon(source_root, *, host, addr, port=None):
    """Source-aware recon: read the app's own source to enumerate its full HTTP surface.

    Capri is run against an app whose source the operator has, so recon reads that source
    rather than crawling a running app blind. `harness.sourcemap.extract_surface` detects the
    framework and returns every registered route, method, parameter and auth flag - including
    the auth-gated routes behind a login a crawl can never reach - and `project_surface` turns
    that into the same endpoint-as-asset model the rest of the pipeline already consumes, so
    the probe-routing spine is unchanged; only the source of the surface differs.

    This reads files on the operator host and executes nothing: no range, no running app, no
    model credits. It returns `{asset: facts}` for the endpoints; the live host facts (open
    ports, server headers) still come from `phase_recon` against the provisioned target, and
    the two models merge when a run both has the source and provisions the app."""
    from harness.sourcemap import extract_surface

    surface = extract_surface(source_root)
    return project_surface(surface, host, addr, port)


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
