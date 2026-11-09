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

    def _send_http(self, url, method="GET"):
        """Issue one HTTP request from the attacker container and return (status, body).
        Shared by the crafted-request and SQL-injection adapters."""
        r = self._exec("python3", "-c", _HTTP_REQUEST, url, method)
        return _parse_http_response(r.out or "")


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
    "import sys,urllib.request,urllib.error\n"
    "url,method=sys.argv[1],sys.argv[2]\n"
    "req=urllib.request.Request(url,method=method)\n"
    "try:\n"
    "    r=urllib.request.urlopen(req,timeout=8); code=r.status; body=r.read(65536)\n"
    "except urllib.error.HTTPError as e:\n"
    "    code=e.code; body=e.read(65536)\n"
    "except Exception as e:\n"
    "    print('ERR',type(e).__name__); sys.exit(0)\n"
    "sys.stdout.write('STATUS %d\\n---BODY---\\n'%code); sys.stdout.flush()\n"
    "sys.stdout.buffer.write(body)\n"
)


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
