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
