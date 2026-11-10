#!/usr/bin/env python3
"""Live pentest-tool adapters (HC-AGENT-01 §5.3).

Adapters run a real tool on the attacker container and return the raw signals the harness
triages. These tests drive them through a fake runner fed the exact XML a real `nmap -sV`
emits (captured from a live scan), so the parsing and the signal shape are pinned with no
Docker and no real tool present - the same no-dependency pattern as the sandbox tests.

Zero-dependency: `python3 tests/test_adapters.py`.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from urllib.parse import parse_qs, urlparse                              # noqa: E402
import base64                                                            # noqa: E402
import re                                                                # noqa: E402
from harness.sandbox.adapters import (                                   # noqa: E402
    BflaAdapter, CacheAdapter, ClickjackAdapter, CmdiAdapter, CorsAdapter, CsrfAdapter,
    HttpRequestAdapter, HttpxAdapter, IdorAdapter, JwtAdapter, NmapAdapter, OpenRedirectAdapter,
    CspAdapter, DomClobberAdapter, PathAdapter, SessAdapter, SqliAdapter, SsrfAdapter,
    SstiAdapter, WsHijackAdapter, _FOREIGN_ORIGIN, _RANGE_CANARY, _parse_http_full,
    _parse_http_response, _parse_httpx, _parse_nmap_services)
from harness.sandbox.base import RunResult                               # noqa: E402

# Real `nmap -sV -Pn -p 8080 -oX -` output (captured live), trimmed to the shape we parse.
NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -sV -Pn -p 8080 -oX - 10.90.0.3" start="1794226837" version="7.95">
<host starttime="1794226837"><status state="up" reason="arp-response"/>
<address addr="10.90.0.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" product="SimpleHTTPServer" version="0.6" extrainfo="Python 3.12.16" method="probed" conf="10"><cpe>cpe:/a:python:simplehttpserver:0.6</cpe></service></port>
</ports>
</host>
</nmaprun>"""

NMAP_XML_CLOSED = """<?xml version="1.0"?>
<nmaprun><host><address addr="10.90.0.9" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="9999"><state state="closed" reason="reset"/></port></ports>
</host></nmaprun>"""

NMAP_XML_NO_SERVICE = """<?xml version="1.0"?>
<nmaprun><host><address addr="10.90.0.3" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port></ports>
</host></nmaprun>"""

# Real `httpx -json ...` output (captured live), one JSON object per line. Base is a bare
# SimpleHTTPServer with no security headers; SECURE carries CSP/XFO/HSTS/CORS; REDIR is a
# 302 that reports its Location without httpx following it. httpx lowercases header names
# and swaps hyphens for underscores, which the adapter normalizes back.
HTTPX_JSON_BASE = ('{"port":"8080","url":"http://10.90.0.3:8080","title":"Directory listing for /",'
                   '"scheme":"http","webserver":"SimpleHTTP/0.6 Python/3.12.13","content_type":"text/html",'
                   '"path":"/","header":{"content_length":"503","content_type":"text/html; charset=utf-8",'
                   '"date":"Mon, 09 Nov 2026 12:50:27 GMT","server":"SimpleHTTP/0.6 Python/3.12.13"},'
                   '"a":["10.90.0.3"],"tech":["Python:3.12.13","SimpleHTTP:0.6"],"status_code":200,'
                   '"content_length":503,"failed":false,"knowledgebase":{"pHash":0}}')

HTTPX_JSON_SECURE = ('{"port":"8080","url":"http://10.90.0.3:8080/secure","title":"Admin","scheme":"http",'
                     '"webserver":"nginx/1.25.3","content_type":"text/html","path":"/secure",'
                     '"header":{"access_control_allow_origin":"*","content_security_policy":"default-src self",'
                     '"content_type":"text/html","date":"Mon, 09 Nov 2026 12:52:40 GMT","server":"nginx/1.25.3",'
                     '"set_cookie":"sid=abc; HttpOnly; Secure; SameSite=Strict",'
                     '"strict_transport_security":"max-age=31536000","x_frame_options":"DENY"},'
                     '"tech":["HSTS","Nginx:1.25.3","Python:3.12.13"],"status_code":200,'
                     '"content_length":22,"failed":false}')

HTTPX_JSON_REDIR = ('{"port":"8080","url":"http://10.90.0.3:8080/redir",'
                    '"location":"http://10.90.0.3:8080/secure","scheme":"http",'
                    '"webserver":"BaseHTTP/0.6 Python/3.12.13","path":"/redir",'
                    '"header":{"date":"Mon, 09 Nov 2026 12:52:42 GMT",'
                    '"location":"http://10.90.0.3:8080/secure","server":"BaseHTTP/0.6 Python/3.12.13"},'
                    '"tech":["Python:3.12.13"],"status_code":302,"content_length":0,"failed":false}')


class FakeRunner:
    def __init__(self, out):
        self.out = out
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        return RunResult(0, self.out, "")


PINNED = {"t1.sandbox.local": "10.90.0.3"}


def test_nmap_extracts_service_product_version_and_cpe():
    fake = FakeRunner(NMAP_XML)
    adapter = NmapAdapter("atk", PINNED, run=fake)
    res = adapter.run({"tool": "nmap", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    assert res["status"] == "ok"
    sig = res["deterministic_signals"]
    assert sig["hit"] is True
    assert sig["open_ports"] == [8080]
    assert sig["service"] == "http"
    assert sig["product"] == "SimpleHTTPServer"
    assert sig["version"] == "0.6"
    assert sig["cpe"] == "cpe:/a:python:simplehttpserver:0.6"
    assert isinstance(res["request_bytes"], bytes) and isinstance(res["response_bytes"], bytes)


def test_nmap_runs_sV_and_resolves_the_pinned_name_to_the_guarded_ip():
    fake = FakeRunner(NMAP_XML)
    NmapAdapter("atk", PINNED, run=fake).run(
        {"tool": "nmap", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    argv = fake.calls[0]
    assert argv[:3] == ["docker", "exec", "atk"]
    assert "-sV" in argv and "-Pn" in argv                     # service detection, no discovery
    assert "10.90.0.3" in argv                                 # resolved to the guarded IP
    assert "t1.sandbox.local" not in argv                      # not the bare name


def test_nmap_no_open_port_is_not_a_hit():
    res = NmapAdapter("atk", PINNED, run=FakeRunner(NMAP_XML_CLOSED)).run(
        {"tool": "nmap", "target": "10.90.0.9", "port": 9999, "args": {}})
    assert res["status"] == "error"
    assert res["deterministic_signals"]["hit"] is False
    assert res["deterministic_signals"]["open_ports"] == []


def test_nmap_open_port_without_a_service_still_registers_the_port():
    svcs = _parse_nmap_services(NMAP_XML_NO_SERVICE)
    assert len(svcs) == 1
    assert svcs[0]["port"] == 22 and svcs[0]["product"] is None


def test_nmap_malformed_output_is_tolerated_not_raised():
    res = NmapAdapter("atk", PINNED, run=FakeRunner("this is not xml")).run(
        {"tool": "nmap", "target": "10.90.0.3", "port": 80, "args": {}})
    assert res["deterministic_signals"]["hit"] is False        # no hit, no exception


def test_httpx_fingerprints_server_tech_title_and_flags_missing_security_headers():
    res = HttpxAdapter("atk", PINNED, run=FakeRunner(HTTPX_JSON_BASE)).run(
        {"tool": "httpx", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    assert res["status"] == "ok"
    sig = res["deterministic_signals"]
    assert sig["hit"] is True
    assert sig["status_code"] == 200
    assert sig["title"] == "Directory listing for /"
    assert sig["webserver"] == "SimpleHTTP/0.6 Python/3.12.13"
    assert "SimpleHTTP:0.6" in sig["tech"]
    # a bare server exposes none of the four, so every one is reported missing
    assert sig["missing_security_headers"] == [
        "content-security-policy", "x-frame-options",
        "strict-transport-security", "x-content-type-options"]


def test_httpx_normalizes_headers_and_reads_present_security_headers_and_cors():
    res = HttpxAdapter("atk", PINNED, run=FakeRunner(HTTPX_JSON_SECURE)).run(
        {"tool": "httpx", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    sig = res["deterministic_signals"]
    # httpx underscore keys are normalized back to canonical hyphenated header names
    assert sig["headers"]["content-security-policy"] == "default-src self"
    assert sig["headers"]["x-frame-options"] == "DENY"
    assert sig["cors_allow_origin"] == "*"
    # three of the four are present; only MIME-sniffing protection is missing
    assert sig["missing_security_headers"] == ["x-content-type-options"]


def test_httpx_reports_redirect_location_without_following_it():
    fake = FakeRunner(HTTPX_JSON_REDIR)
    res = HttpxAdapter("atk", PINNED, run=fake).run(
        {"tool": "httpx", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    sig = res["deterministic_signals"]
    assert sig["hit"] is True and sig["status_code"] == 302
    assert sig["location"] == "http://10.90.0.3:8080/secure"
    argv = fake.calls[0]
    assert not any(a in ("-fr", "-follow-redirects") for a in argv)   # not chased


def test_httpx_targets_the_resolved_ip_not_the_bare_name():
    fake = FakeRunner(HTTPX_JSON_BASE)
    HttpxAdapter("atk", PINNED, run=fake).run(
        {"tool": "httpx", "target": "t1.sandbox.local", "port": 8080, "args": {}})
    argv = fake.calls[0]
    assert argv[:3] == ["docker", "exec", "atk"]
    assert "http://10.90.0.3:8080/" in argv                          # resolved + scheme + path
    assert "t1.sandbox.local" not in " ".join(argv)


def test_httpx_uses_https_scheme_for_a_tls_port():
    fake = FakeRunner(HTTPX_JSON_BASE)
    HttpxAdapter("atk", PINNED, run=fake).run(
        {"tool": "httpx", "target": "10.90.0.3", "port": 443, "args": {}})
    assert "https://10.90.0.3:443/" in fake.calls[0]


def test_httpx_no_output_is_not_a_hit():
    res = HttpxAdapter("atk", PINNED, run=FakeRunner("")).run(
        {"tool": "httpx", "target": "10.90.0.3", "port": 8080, "args": {}})
    assert res["status"] == "error"
    assert res["deterministic_signals"]["hit"] is False


def test_parse_httpx_tolerates_banner_noise_before_the_json_line():
    out = "[INF] Current Version: v1.12.0\n" + HTTPX_JSON_BASE
    obj = _parse_httpx(out)
    assert obj["status_code"] == 200 and obj["webserver"].startswith("SimpleHTTP")


class ReflectingRunner:
    """Simulates the vulnerable target: echoes the request's decoded `q` value into the
    body, optionally HTML-encoded (a safe server) or not at all, so the adapter's own
    random marker flows through exactly as a real reflected-XSS target would echo it."""

    def __init__(self, *, encode=False, reflect=True, status=200):
        self.encode, self.reflect, self.status = encode, reflect, status
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        q = (parse_qs(urlparse(url).query).get("q") or [""])[0]
        if not self.reflect:
            q = ""
        shown = q.replace("<", "&lt;").replace(">", "&gt;") if self.encode else q
        return RunResult(0, f"STATUS {self.status}\n---BODY---\n<p>No results for: {shown}</p>", "")


def test_http_confirms_reflected_xss_when_the_marker_echoes_unencoded():
    fake = ReflectingRunner()
    res = HttpRequestAdapter("atk", PINNED, run=fake).run(
        {"tool": "http", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/search", "reflect_param": "q"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["reflected"] is True
    assert sig["status_code"] == 200
    assert sig["marker"].startswith('"><svg/onload=')        # tag-breaking payload


def test_http_encoded_reflection_is_not_a_hit():
    res = HttpRequestAdapter("atk", PINNED, run=ReflectingRunner(encode=True)).run(
        {"tool": "http", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/search", "reflect_param": "q"}})
    assert res["deterministic_signals"]["reflected"] is False
    assert res["deterministic_signals"]["hit"] is False       # server encodes = safe


def test_http_marker_is_random_per_run_so_a_model_cannot_force_a_match():
    a = HttpRequestAdapter("atk", PINNED, run=ReflectingRunner())
    m1 = a.run({"tool": "http", "target": "10.90.0.3", "port": 8080,
                "args": {"path": "/search", "reflect_param": "q"}})["deterministic_signals"]["marker"]
    m2 = a.run({"tool": "http", "target": "10.90.0.3", "port": 8080,
                "args": {"path": "/search", "reflect_param": "q"}})["deterministic_signals"]["marker"]
    assert m1 != m2                                            # harness-generated nonce


def test_http_plain_request_without_reflection_hits_on_a_response():
    res = HttpRequestAdapter("atk", PINNED, run=ReflectingRunner(reflect=False)).run(
        {"tool": "http", "target": "10.90.0.3", "port": 8080, "args": {"path": "/"}})
    sig = res["deterministic_signals"]
    assert sig["hit"] is True and sig["reflected"] is False and sig["status_code"] == 200


def test_http_targets_the_resolved_ip_and_injects_into_the_named_param():
    fake = ReflectingRunner()
    HttpRequestAdapter("atk", PINNED, run=fake).run(
        {"tool": "http", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/search", "reflect_param": "q"}})
    url = next(a for a in fake.calls[0] if a.startswith("http"))
    assert url.startswith("http://10.90.0.3:8080/search?")     # resolved IP + path
    assert "t1.sandbox.local" not in url
    assert "q=" in url                                          # the injected parameter


def test_http_error_output_is_not_a_hit():
    res = HttpRequestAdapter("atk", PINNED, run=FakeRunner("ERR ConnectionRefusedError")).run(
        {"tool": "http", "target": "10.90.0.3", "port": 8080, "args": {"path": "/"}})
    assert res["deterministic_signals"]["hit"] is False
    assert res["deterministic_signals"]["status_code"] == 0


def test_parse_http_response_splits_status_and_body():
    code, body = _parse_http_response("STATUS 200\n---BODY---\n<html>hi</html>")
    assert code == 200 and body == "<html>hi</html>"
    assert _parse_http_response("ERR Timeout") == (0, "")


class SqlInjectableRunner:
    """Emulates the vulnerable endpoint `SELECT name FROM items WHERE id = <id>` (row 1 is
    'widget'): a true numeric condition returns the row, a false one returns nothing, and a
    broken quote errors - the exact split a boolean-blind SQLi target shows."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        idv = (parse_qs(urlparse(url).query).get("id") or ["1"])[0]
        if "'" in idv:
            inner = "query error"                       # unbalanced quote -> SQL error
        elif idv in ("1", "1 AND 1=1"):
            inner = "<li>widget</li>"                    # baseline / true condition
        else:
            inner = "no item"                            # false condition selects nothing
        return RunResult(0, f"STATUS 200\n---BODY---\n<ul>{inner}</ul>", "")


class SafeSqlRunner:
    """A parametrized-safe endpoint: the id is a literal, so an injected condition never
    acts as SQL - only the exact baseline id returns the row."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        idv = (parse_qs(urlparse(url).query).get("id") or [""])[0]
        inner = "<li>widget</li>" if idv == "1" else "no item"
        return RunResult(0, f"STATUS 200\n---BODY---\n<ul>{inner}</ul>", "")


def test_sqli_confirms_boolean_blind_injection():
    res = SqliAdapter("atk", PINNED, run=SqlInjectableRunner()).run(
        {"tool": "sqli", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/item", "sqli_param": "id"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["sqli"] is True
    assert sig["technique"] == "numeric"                 # the true/false pair split the response


def test_sqli_safe_parametrized_endpoint_is_not_a_hit():
    res = SqliAdapter("atk", PINNED, run=SafeSqlRunner()).run(
        {"tool": "sqli", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/item", "sqli_param": "id"}})
    assert res["deterministic_signals"]["hit"] is False
    assert res["deterministic_signals"]["technique"] is None


def test_sqli_sends_a_harness_generated_true_and_false_condition_to_the_resolved_ip():
    fake = SqlInjectableRunner()
    SqliAdapter("atk", PINNED, run=fake).run(
        {"tool": "sqli", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/item", "sqli_param": "id"}})
    urls = " ".join(a for call in fake.calls for a in call if a.startswith("http"))
    assert "10.90.0.3" in urls and "t1.sandbox.local" not in urls
    assert "1%3D1" in urls and "1%3D2" in urls           # the appended AND 1=1 / AND 1=2


def test_sqli_stops_at_the_first_splitting_template():
    fake = SqlInjectableRunner()
    SqliAdapter("atk", PINNED, run=fake).run(
        {"tool": "sqli", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/item", "sqli_param": "id"}})
    assert len(fake.calls) == 3                           # baseline + the numeric true/false


def test_sqli_without_a_param_probes_once_and_does_not_hit():
    fake = SqlInjectableRunner()
    res = SqliAdapter("atk", PINNED, run=fake).run(
        {"tool": "sqli", "target": "10.90.0.3", "port": 8080, "args": {"path": "/item"}})
    assert res["deterministic_signals"]["hit"] is False
    assert len(fake.calls) == 1                           # no param to inject = baseline only


def _call_url_headers(argv):
    url = next((a for a in argv if a.startswith("http")), "")
    headers = {}
    if argv and argv[-1].startswith("{"):
        try:
            headers = json.loads(argv[-1])
        except ValueError:
            pass
    return url, headers


class JwtAppRunner:
    """Emulates the authenticated target: /login issues a token `h.user<N>.s`, and
    /account returns the requested account to any valid token. With `ownership_check`,
    it returns another user's account only to that user's token (the safe behaviour)."""

    def __init__(self, *, ownership_check=False, issue_token=True,
                 admin_role_check=False, admin_public=False):
        self.ownership_check = ownership_check
        self.issue_token = issue_token
        self.admin_role_check = admin_role_check
        self.admin_public = admin_public
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url, headers = _call_url_headers(argv)
        parts = urlparse(url)
        q = parse_qs(parts.query)
        auth = headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if parts.path == "/login":
            uid = (q.get("user") or ["1"])[0]
            body = f"h.user{uid}.s" if self.issue_token else "login disabled"
            return RunResult(0, f"STATUS 200\n---BODY---\n{body}", "")
        if parts.path == "/account":
            if not token.startswith("h.user"):
                return RunResult(0, "STATUS 401\n---BODY---\nunauthorized", "")
            acct = (q.get("id") or ["1"])[0]
            if self.ownership_check and acct != token.split(".")[1][4:]:
                return RunResult(0, "STATUS 403\n---BODY---\nforbidden", "")
            return RunResult(0, f"STATUS 200\n---BODY---\naccount {acct}: secret-{acct}", "")
        if parts.path == "/admin":
            if self.admin_public:                            # a genuinely public page: not BFLA
                return RunResult(0, "STATUS 200\n---BODY---\nadmin panel", "")
            if not token.startswith("h.user"):
                return RunResult(0, "STATUS 401\n---BODY---\nunauthorized", "")
            if self.admin_role_check:                        # a correct role check refuses a user
                return RunResult(0, "STATUS 403\n---BODY---\nforbidden", "")
            return RunResult(0, "STATUS 200\n---BODY---\nadmin panel: secrets", "")
        return RunResult(0, "STATUS 404\n---BODY---\n", "")


def test_idor_confirms_broken_object_level_authorization():
    res = IdorAdapter("atk", PINNED, run=JwtAppRunner()).run(
        {"tool": "idor", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/account", "id_param": "id", "login_path": "/login", "own_id": "1"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["idor"] is True
    assert sig["authenticated"] is True
    assert sig["own_status"] == 200 and sig["other_status"] == 200


def test_idor_ownership_check_is_not_a_hit():
    res = IdorAdapter("atk", PINNED, run=JwtAppRunner(ownership_check=True)).run(
        {"tool": "idor", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/account", "id_param": "id", "login_path": "/login", "own_id": "1"}})
    sig = res["deterministic_signals"]
    assert sig["hit"] is False
    assert sig["other_status"] == 403                    # the neighbour is refused


def test_idor_sends_the_login_token_as_a_bearer_header():
    fake = JwtAppRunner()
    IdorAdapter("atk", PINNED, run=fake).run(
        {"tool": "idor", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/account", "id_param": "id", "login_path": "/login", "own_id": "1"}})
    paths = [urlparse(_call_url_headers(c)[0]).path for c in fake.calls]
    assert "/login" in paths                             # it authenticates first
    account_calls = [c for c in fake.calls if urlparse(_call_url_headers(c)[0]).path == "/account"]
    assert account_calls and all(
        _call_url_headers(c)[1].get("Authorization") == "Bearer h.user1.s" for c in account_calls)
    # the neighbour it reads is the next id, which it must resolve to the guarded IP
    assert any("id=2" in _call_url_headers(c)[0] and "10.90.0.3" in _call_url_headers(c)[0]
               for c in account_calls)


def test_idor_without_a_usable_login_is_not_a_hit():
    res = IdorAdapter("atk", PINNED, run=JwtAppRunner(issue_token=False)).run(
        {"tool": "idor", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/account", "id_param": "id", "login_path": "/login", "own_id": "1"}})
    assert res["deterministic_signals"]["authenticated"] is False
    assert res["deterministic_signals"]["hit"] is False


def _token_alg(token):
    try:
        head = token.split(".")[0]
        return json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))).get("alg")
    except Exception:
        return None


class JwtVerifierRunner:
    """Simulates a protected endpoint's JWT check: it decodes the presented token's alg.
    When vulnerable it accepts alg 'none' (no signature); it always rejects a token with a
    real (here always bogus) HS256 signature, exactly as the live verifier behaves."""

    def __init__(self, *, accept_alg_none=True):
        self.accept_alg_none = accept_alg_none
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url, headers = _call_url_headers(argv)
        auth = headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        acct = (parse_qs(urlparse(url).query).get("id") or ["1"])[0]
        if _token_alg(token) == "none" and self.accept_alg_none:
            return RunResult(0, f"STATUS 200\n---BODY---\naccount {acct}: secret-{acct}", "")
        return RunResult(0, "STATUS 401\n---BODY---\nunauthorized", "")


def test_jwt_confusion_accepts_an_unsigned_forged_token():
    res = JwtAdapter("atk", PINNED, run=JwtVerifierRunner()).run(
        {"tool": "jwt", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/account", "params": {"id": "1"}}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["jwt_alg_confusion"] is True
    assert sig["alg_none_status"] == 200 and sig["bad_sig_status"] == 401


def test_jwt_strict_verifier_is_not_a_hit():
    res = JwtAdapter("atk", PINNED, run=JwtVerifierRunner(accept_alg_none=False)).run(
        {"tool": "jwt", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/account", "params": {"id": "1"}}})
    assert res["deterministic_signals"]["hit"] is False
    assert res["deterministic_signals"]["alg_none_status"] == 401    # alg:none rejected


def test_jwt_forges_an_alg_none_and_a_bogus_signature_token():
    fake = JwtVerifierRunner()
    JwtAdapter("atk", PINNED, run=fake).run(
        {"tool": "jwt", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/account", "params": {"id": "1"}}})
    algs = {_token_alg(_call_url_headers(c)[1].get("Authorization", "")[7:]) for c in fake.calls}
    assert algs == {"none", "HS256"}                                 # one of each, both harness-forged


def test_bfla_confirms_missing_function_level_authorization():
    res = BflaAdapter("atk", PINNED, run=JwtAppRunner()).run(
        {"tool": "bfla", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/admin", "login_path": "/login", "login_user": "1"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["bfla"] is True
    assert sig["anon_status"] == 401 and sig["user_status"] == 200


def test_bfla_role_check_is_not_a_hit():
    res = BflaAdapter("atk", PINNED, run=JwtAppRunner(admin_role_check=True)).run(
        {"tool": "bfla", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/admin", "login_path": "/login", "login_user": "1"}})
    assert res["deterministic_signals"]["hit"] is False
    assert res["deterministic_signals"]["user_status"] == 403    # the role check refuses


def test_bfla_public_endpoint_is_not_a_hit():
    res = BflaAdapter("atk", PINNED, run=JwtAppRunner(admin_public=True)).run(
        {"tool": "bfla", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/admin", "login_path": "/login", "login_user": "1"}})
    # answers the anonymous call too, so it is public, not a privileged function
    assert res["deterministic_signals"]["anon_status"] == 200
    assert res["deterministic_signals"]["hit"] is False


class SstiRunner:
    """Simulates the endpoint: renders a {{ expression }} the caller injects. With
    `evaluate`, it computes it (template injection); otherwise it reflects it raw."""

    def __init__(self, *, evaluate=True):
        self.evaluate = evaluate
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        name = (parse_qs(urlparse(url).query).get("name") or [""])[0]
        shown = "49" if (self.evaluate and name == "{{7*7}}") else name
        return RunResult(0, f"STATUS 200\n---BODY---\n<p>Hello {shown}</p>", "")


def test_ssti_confirms_template_evaluation():
    res = SstiAdapter("atk", PINNED, run=SstiRunner()).run(
        {"tool": "ssti", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/greet", "param": "name"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["ssti"] is True


def test_ssti_raw_reflection_is_not_a_hit():
    # a page that echoes the expression without evaluating it is not injection
    res = SstiAdapter("atk", PINNED, run=SstiRunner(evaluate=False)).run(
        {"tool": "ssti", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/greet", "param": "name"}})
    assert res["deterministic_signals"]["hit"] is False


class CorsRunner:
    """Simulates the CORS endpoint. When vulnerable it reflects the request Origin into
    Access-Control-Allow-Origin and allows credentials; a safe server does neither."""

    def __init__(self, *, reflect=True, credentials=True):
        self.reflect, self.credentials = reflect, credentials
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        _, req_headers = _call_url_headers(argv)
        origin = req_headers.get("Origin", "")
        headers = {"Content-Type": "application/json"}
        if self.reflect and origin:
            headers["Access-Control-Allow-Origin"] = origin
            if self.credentials:
                headers["Access-Control-Allow-Credentials"] = "true"
        out = "STATUS 200\n" + json.dumps(headers) + '\n---BODY---\n{"data": "ok"}'
        return RunResult(0, out, "")


def test_cors_confirms_reflected_origin_with_credentials():
    res = CorsAdapter("atk", PINNED, run=CorsRunner()).run(
        {"tool": "cors", "target": "t1.sandbox.local", "port": 8080, "args": {"path": "/api/data"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["reflects_origin"] is True and sig["allows_credentials"] is True


def test_cors_reflected_origin_without_credentials_is_not_a_hit():
    res = CorsAdapter("atk", PINNED, run=CorsRunner(credentials=False)).run(
        {"tool": "cors", "target": "t1.sandbox.local", "port": 8080, "args": {"path": "/api/data"}})
    sig = res["deterministic_signals"]
    assert sig["reflects_origin"] is True and sig["allows_credentials"] is False
    assert sig["hit"] is False                               # reading it needs credentials too


def test_cors_strict_origin_is_not_a_hit():
    res = CorsAdapter("atk", PINNED, run=CorsRunner(reflect=False)).run(
        {"tool": "cors", "target": "t1.sandbox.local", "port": 8080, "args": {"path": "/api/data"}})
    assert res["deterministic_signals"]["hit"] is False


class TraversalRunner:
    """Simulates the vulnerable /download endpoint: it joins the `file` parameter to a
    public dir with no containment check, so a `../` payload reads the canary file and its
    marker comes back. A safe server (`contained`) refuses to leave the dir, so the marker
    never appears."""

    def __init__(self, *, contained=False):
        self.contained = contained
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        fname = (parse_qs(urlparse(url).query).get("file") or [""])[0]
        if ".." in fname and not self.contained:
            return RunResult(0, f"STATUS 200\n---BODY---\n{_RANGE_CANARY}\n", "")
        if ".." in fname:                                    # contained: traversal refused
            return RunResult(0, "STATUS 404\n---BODY---\nnot found", "")
        return RunResult(0, "STATUS 200\n---BODY---\nhc-shop public downloads", "")


def test_path_confirms_traversal_when_the_canary_marker_is_read():
    res = PathAdapter("atk", PINNED, run=TraversalRunner()).run(
        {"tool": "path", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/download", "param": "file"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["path_traversal"] is True and sig["file_read"] is True


def test_path_contained_download_is_not_a_hit():
    res = PathAdapter("atk", PINNED, run=TraversalRunner(contained=True)).run(
        {"tool": "path", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/download", "param": "file"}})
    assert res["deterministic_signals"]["hit"] is False      # the app stays inside its dir


def test_path_walks_out_of_the_public_dir_against_the_resolved_ip():
    fake = TraversalRunner()
    PathAdapter("atk", PINNED, run=fake).run(
        {"tool": "path", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/download", "param": "file"}})
    url = next(a for a in fake.calls[0] if a.startswith("http"))
    assert url.startswith("http://10.90.0.3:8080/download?")  # resolved IP + endpoint
    assert "t1.sandbox.local" not in url
    assert "..%2F" in url or "../" in url                     # a traversal payload


class CmdiRunner:
    """Simulates the /ping endpoint: it always answers 200. The timing that distinguishes
    an injectable from a safe server is modelled by the injected clock, not the runner, so
    the adapter's own delta computation is what the test exercises."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        return RunResult(0, "STATUS 200\n---BODY---\npinging 127.0.0.1", "")


def _clock(*ticks):
    return iter(ticks).__next__                               # one value per call, in order


def test_cmdi_confirms_injection_when_the_sleep_dominates_the_round_trip():
    # baseline ~0.01s, injected ~5.01s: the delta clears half the 5s sleep
    fake = CmdiRunner()
    res = CmdiAdapter("atk", PINNED, run=fake, clock=_clock(0.0, 0.01, 0.02, 5.03)).run(
        {"tool": "cmdi", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/ping", "param": "host", "delay_s": 5}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["cmdi"] is True
    assert sig["delta_ms"] >= 2500


def test_cmdi_no_delay_is_not_a_hit():
    # both requests return in the same time: a server that does not shell out
    res = CmdiAdapter("atk", PINNED, run=CmdiRunner(), clock=_clock(0.0, 0.01, 0.02, 0.03)).run(
        {"tool": "cmdi", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/ping", "param": "host", "delay_s": 5}})
    assert res["deterministic_signals"]["hit"] is False


def test_cmdi_appends_a_sleep_to_the_param_against_the_resolved_ip():
    fake = CmdiRunner()
    CmdiAdapter("atk", PINNED, run=fake, clock=_clock(0.0, 0.01, 0.02, 5.03)).run(
        {"tool": "cmdi", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/ping", "param": "host", "delay_s": 5}})
    urls = [next(a for a in c if a.startswith("http")) for c in fake.calls]
    assert len(urls) == 2                                     # baseline, then injected
    assert all("10.90.0.3" in u for u in urls) and all("t1.sandbox.local" not in u for u in urls)
    assert "sleep+5" in urls[1] or "sleep%205" in urls[1]     # the appended shell command


class CachePoisonRunner:
    """Simulates the /promo cache. Vulnerable: it keys the cache on path+query only and
    reflects X-Forwarded-Host, so a value injected on the miss is served to a later clean
    request for the same key. Safe (`keyed_on_header`): the header is part of the key, so a
    clean request is a different key and never gets the poisoned entry."""

    def __init__(self, *, keyed_on_header=False):
        self.keyed_on_header = keyed_on_header
        self.store = {}
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url, headers = _call_url_headers(argv)
        parts = urlparse(url)
        xfh = headers.get("X-Forwarded-Host", "promo.hc-shop")
        key = parts.path + "?" + parts.query + (("|" + xfh) if self.keyed_on_header else "")
        if key not in self.store:
            self.store[key] = f'<link href="http://{xfh}/promo">'    # miss: reflect + cache
        return RunResult(0, f"STATUS 200\n---BODY---\n{self.store[key]}", "")


def test_cache_confirms_poisoning_when_a_clean_request_is_served_the_injected_marker():
    res = CacheAdapter("atk", PINNED, run=CachePoisonRunner()).run(
        {"tool": "cache", "target": "t1.sandbox.local", "port": 8080, "args": {"path": "/promo"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["cache_poison"] is True
    assert sig["reflected"] is True and sig["served_from_cache"] is True


def test_cache_header_keyed_cache_is_not_a_hit():
    res = CacheAdapter("atk", PINNED, run=CachePoisonRunner(keyed_on_header=True)).run(
        {"tool": "cache", "target": "t1.sandbox.local", "port": 8080, "args": {"path": "/promo"}})
    sig = res["deterministic_signals"]
    assert sig["reflected"] is True                          # the miss still reflects
    assert sig["served_from_cache"] is False                 # but the clean request is a clean key
    assert sig["hit"] is False


def test_cache_injects_an_unkeyed_header_only_on_the_first_request():
    fake = CachePoisonRunner()
    CacheAdapter("atk", PINNED, run=fake).run(
        {"tool": "cache", "target": "t1.sandbox.local", "port": 8080, "args": {"path": "/promo"}})
    hdrs = [_call_url_headers(c)[1] for c in fake.calls]
    assert len(hdrs) == 2
    assert "X-Forwarded-Host" in hdrs[0] and "X-Forwarded-Host" not in hdrs[1]
    urls = [_call_url_headers(c)[0] for c in fake.calls]
    assert urls[0] == urls[1] and "10.90.0.3" in urls[0]     # same cache-buster URL, victim's view


class SessionRunner:
    """Simulates the cookie-session portal. Vulnerable: /portal/login authenticates the
    existing session id in place without issuing a new one, so the pre-auth id is valid and
    authenticated afterward. Safe (`rotate_on_login`): login issues a fresh id and leaves
    the pre-auth id anonymous. Emits the header-returning format the session adapter reads."""

    def __init__(self, *, rotate_on_login=False):
        self.rotate_on_login = rotate_on_login
        self.sessions = {}
        self.calls = []
        self._seq = 0

    def _issue(self):
        self._seq += 1
        return f"sid{self._seq}"

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url, headers = _call_url_headers(argv)
        parts = urlparse(url)
        sid = None
        for part in headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                sid = v
        set_cookie = None
        body = ""
        if parts.path == "/portal":
            if not sid or sid not in self.sessions:
                sid = self._issue()
                self.sessions[sid] = None
                set_cookie = f"sid={sid}; Path=/"
            user = self.sessions.get(sid)
            body = "portal session %s: %s" % (sid, ("user %s" % user) if user else "anonymous")
        elif parts.path == "/portal/login":
            uid = (parse_qs(parts.query).get("user") or ["1"])[0]
            if self.rotate_on_login:
                self.sessions.setdefault(sid, None)          # old id stays anonymous
                new = self._issue()
                self.sessions[new] = uid
                set_cookie = f"sid={new}; Path=/"
                body = "logged in as %s (rotated)" % uid
            else:
                self.sessions[sid] = uid                     # authenticate in place, no rotation
                body = "logged in as %s on session %s" % (uid, sid)
        elif parts.path == "/portal/me":
            user = self.sessions.get(sid)
            body = ("me: user %s" % user) if user else "me: anonymous"
        hdr = {"Set-Cookie": set_cookie} if set_cookie else {}
        return RunResult(0, "STATUS 200\n" + json.dumps(hdr) + "\n---BODY---\n" + body, "")


def test_sess_confirms_fixation_when_the_preauth_id_stays_authenticated():
    res = SessAdapter("atk", PINNED, run=SessionRunner()).run(
        {"tool": "sess", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login", "me_path": "/portal/me"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["session_fixation"] is True
    assert sig["pre_auth_id_authenticated"] is True and sig["rotated_on_login"] is False


def test_sess_rotated_id_on_login_is_not_a_hit():
    res = SessAdapter("atk", PINNED, run=SessionRunner(rotate_on_login=True)).run(
        {"tool": "sess", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login", "me_path": "/portal/me"}})
    sig = res["deterministic_signals"]
    assert sig["rotated_on_login"] is True                    # login issued a fresh id
    assert sig["pre_auth_id_authenticated"] is False          # the pre-auth id is anonymous
    assert sig["hit"] is False


def test_sess_reuses_the_preauth_cookie_through_login_and_me():
    fake = SessionRunner()
    SessAdapter("atk", PINNED, run=fake).run(
        {"tool": "sess", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login", "me_path": "/portal/me"}})
    # the first call establishes the session; login and me must carry that same sid cookie
    later = [_call_url_headers(c) for c in fake.calls[1:]]
    cookies = {h.get("Cookie") for _, h in later}
    assert len(cookies) == 1 and next(iter(cookies)) == "sid=sid1"
    assert all("10.90.0.3" in u for u, _ in later)            # resolved to the guarded IP


class SsrfRunner:
    """Simulates the target plus the in-range collaborator. When the target fetches the
    collaborator url (vulnerable), the collaborator records the requested path and the
    target's address; the adapter then reads that log over docker exec. A safe target with
    an allowlist never fetches it, so the log stays empty."""

    def __init__(self, *, vulnerable=True):
        self.vulnerable = vulnerable
        self.hits = []
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        if argv[:2] == ["docker", "exec"] and "cat" in argv and "/tmp/hits.log" in argv:
            return RunResult(0, "\n".join(self.hits) + ("\n" if self.hits else ""), "")
        url = next((a for a in argv if a.startswith("http")), "")
        inner = (parse_qs(urlparse(url).query).get("url") or [""])[0]   # the collaborator url
        if self.vulnerable and inner:
            self.hits.append(f"{urlparse(inner).path} {urlparse(url).hostname}")  # server-side fetch
        return RunResult(0, "STATUS 200\n---BODY---\nfetched", "")


def test_ssrf_confirms_when_the_collaborator_is_hit_from_the_target():
    res = SsrfAdapter("atk", PINNED, run=SsrfRunner(),
                      collaborator="hc-collab", collab_addr="10.90.0.9:8080").run(
        {"tool": "ssrf", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/fetch", "param": "url"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["ssrf"] is True and sig["oob_fired"] is True


def test_ssrf_no_callback_is_not_a_hit():
    res = SsrfAdapter("atk", PINNED, run=SsrfRunner(vulnerable=False),
                      collaborator="hc-collab", collab_addr="10.90.0.9:8080").run(
        {"tool": "ssrf", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/fetch", "param": "url"}})
    assert res["deterministic_signals"]["hit"] is False      # the target never fetched it


def test_ssrf_points_the_target_at_the_collaborator_token_url_and_reads_the_log():
    fake = SsrfRunner()
    SsrfAdapter("atk", PINNED, run=fake,
                collaborator="hc-collab", collab_addr="10.90.0.9:8080").run(
        {"tool": "ssrf", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/fetch", "param": "url"}})
    fetch = next(c for c in fake.calls if any(a.startswith("http") for a in c))
    url = next(a for a in fetch if a.startswith("http"))
    assert "10.90.0.3" in url                                # the target, resolved from the pin
    inner = parse_qs(urlparse(url).query)["url"][0]
    assert inner.startswith("http://10.90.0.9:8080/hcoob")   # collaborator + random token
    assert any(c[:2] == ["docker", "exec"] and "/tmp/hits.log" in c for c in fake.calls)


def test_ssrf_without_a_collaborator_cannot_confirm():
    res = SsrfAdapter("atk", PINNED, run=SsrfRunner()).run(   # no collaborator configured
        {"tool": "ssrf", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/fetch", "param": "url"}})
    assert res["deterministic_signals"]["hit"] is False      # nothing to confirm against


class RedirectRunner:
    """Simulates the /redirect endpoint via the no-follow request script: when vulnerable
    it 302s to whatever `url` it is given (so the foreign origin comes back in Location); a
    safe server confines the destination to its own origin."""

    def __init__(self, *, confine=False):
        self.confine = confine
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        dest = (parse_qs(urlparse(url).query).get("url") or [""])[0]
        loc = "/" if self.confine else dest                  # safe: stays on its own origin
        return RunResult(0, f"STATUS 302\nLOCATION {loc}\n", "")


def test_redirect_confirms_open_redirect_to_a_foreign_origin():
    res = OpenRedirectAdapter("atk", PINNED, run=RedirectRunner()).run(
        {"tool": "redirect", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/redirect", "param": "url"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["open_redirect"] is True
    assert sig["location"] == _FOREIGN_ORIGIN


def test_redirect_confined_to_same_origin_is_not_a_hit():
    res = OpenRedirectAdapter("atk", PINNED, run=RedirectRunner(confine=True)).run(
        {"tool": "redirect", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/redirect", "param": "url"}})
    assert res["deterministic_signals"]["hit"] is False      # destination stayed on-origin


def test_redirect_sends_the_foreign_origin_to_the_resolved_ip_without_following():
    fake = RedirectRunner()
    OpenRedirectAdapter("atk", PINNED, run=fake).run(
        {"tool": "redirect", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/redirect", "param": "url"}})
    argv = fake.calls[0]
    url = next(a for a in argv if a.startswith("http"))
    assert "10.90.0.3" in url and "t1.sandbox.local" not in url
    assert "evil.range.local" in url                         # the harness-chosen foreign origin
    assert "redirect_request" in " ".join(argv)              # the no-follow handler script


class ClickjackRunner:
    """Simulates the sensitive-action page's framing headers. Vulnerable: it returns neither
    X-Frame-Options nor a CSP frame-ancestors directive. The `xfo`/`csp` flags model the two
    safe ways to deny framing."""

    def __init__(self, *, xfo=False, csp_frame_ancestors=False):
        self.xfo, self.csp_frame_ancestors = xfo, csp_frame_ancestors
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        headers = {"Content-Type": "text/html"}
        if self.xfo:
            headers["X-Frame-Options"] = "DENY"
        if self.csp_frame_ancestors:
            headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        return RunResult(0, "STATUS 200\n" + json.dumps(headers) + "\n---BODY---\n<form>", "")


def test_clickjack_confirms_a_framable_sensitive_action():
    res = ClickjackAdapter("atk", PINNED, run=ClickjackRunner()).run(
        {"tool": "clickjack", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal/settings"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["clickjacking"] is True


def test_clickjack_x_frame_options_deny_is_not_a_hit():
    res = ClickjackAdapter("atk", PINNED, run=ClickjackRunner(xfo=True)).run(
        {"tool": "clickjack", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal/settings"}})
    assert res["deterministic_signals"]["hit"] is False      # framing denied by the header


def test_clickjack_csp_frame_ancestors_is_not_a_hit():
    res = ClickjackAdapter("atk", PINNED, run=ClickjackRunner(csp_frame_ancestors=True)).run(
        {"tool": "clickjack", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal/settings"}})
    sig = res["deterministic_signals"]
    assert sig["csp_frame_ancestors"] is True and sig["hit"] is False  # CSP restricts framing


class CsrfRunner:
    """Simulates the cookie-session state change. Vulnerable: `/portal/email?to=` changes
    the session's email with only the cookie and no token, and the sid cookie has no
    SameSite. `require_token` models a safe app that rejects the tokenless change; `samesite`
    models a cookie that is not sent cross-site."""

    def __init__(self, *, require_token=False, samesite=None):
        self.require_token, self.samesite = require_token, samesite
        self.sessions, self.emails, self.calls = {}, {}, []
        self._seq = 0

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url, headers = _call_url_headers(argv)
        parts = urlparse(url)
        q = parse_qs(parts.query)
        sid = None
        for part in headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                sid = v
        set_cookie = None
        body = ""
        if parts.path == "/portal":
            if not sid or sid not in self.sessions:
                self._seq += 1
                sid = f"sid{self._seq}"
                self.sessions[sid] = None
                set_cookie = f"sid={sid}; Path=/" + (f"; SameSite={self.samesite}" if self.samesite else "")
            body = f"portal session {sid}"
        elif parts.path == "/portal/login":
            self.sessions[sid] = (q.get("user") or ["1"])[0]
            body = "logged in"
        elif parts.path == "/portal/email":
            to = (q.get("to") or [""])[0]
            if to and not self.require_token:                    # safe app needs a token
                self.emails[sid] = to
            body = "email: %s" % self.emails.get(sid, "none")
        hdr = {"Set-Cookie": set_cookie} if set_cookie else {}
        return RunResult(0, "STATUS 200\n" + json.dumps(hdr) + "\n---BODY---\n" + body, "")


def test_csrf_confirms_tokenless_state_change_on_a_non_samesite_cookie():
    res = CsrfAdapter("atk", PINNED, run=CsrfRunner()).run(
        {"tool": "csrf", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login",
                  "action_path": "/portal/email", "action_param": "to"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["csrf"] is True
    assert sig["state_changed"] is True and sig["samesite"] is None


def test_csrf_token_required_is_not_a_hit():
    res = CsrfAdapter("atk", PINNED, run=CsrfRunner(require_token=True)).run(
        {"tool": "csrf", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login",
                  "action_path": "/portal/email", "action_param": "to"}})
    sig = res["deterministic_signals"]
    assert sig["state_changed"] is False and sig["hit"] is False  # the tokenless change was refused


def test_csrf_samesite_cookie_is_not_a_hit():
    res = CsrfAdapter("atk", PINNED, run=CsrfRunner(samesite="Strict")).run(
        {"tool": "csrf", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login",
                  "action_path": "/portal/email", "action_param": "to"}})
    sig = res["deterministic_signals"]
    assert sig["samesite"] == "strict" and sig["hit"] is False   # cookie not sent cross-site


class WsHijackRunner:
    """Simulates the cookie-session setup plus the raw WebSocket handshake. Vulnerable: the
    server completes the handshake for any Origin and streams the session's secret. Safe
    (`validate_origin`): a foreign-Origin handshake is rejected."""

    def __init__(self, *, validate_origin=False):
        self.validate_origin = validate_origin
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        src = argv[argv.index("-c") + 1] if "-c" in argv else ""
        if "socket.create_connection" in src:                # the WebSocket handshake probe
            origin = argv[-2]
            if self.validate_origin and origin == _FOREIGN_ORIGIN:
                return RunResult(0, "STATUS 403\nFRAME \n", "")   # origin rejected
            return RunResult(0, "STATUS 101\nFRAME ws-secret-for-user-1\n", "")
        url, _ = _call_url_headers(argv)                     # a _send_http_full call
        hdr = {"Set-Cookie": "sid=sid1; Path=/"} if urlparse(url).path == "/portal" else {}
        return RunResult(0, "STATUS 200\n" + json.dumps(hdr) + "\n---BODY---\nok", "")


def test_wshijack_confirms_foreign_origin_handshake_returns_session_data():
    res = WsHijackAdapter("atk", PINNED, run=WsHijackRunner()).run(
        {"tool": "wshijack", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["ws_hijack"] is True
    assert sig["handshake_status"] == 101 and sig["session_bound"] is True


def test_wshijack_origin_validated_handshake_is_not_a_hit():
    res = WsHijackAdapter("atk", PINNED, run=WsHijackRunner(validate_origin=True)).run(
        {"tool": "wshijack", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login"}})
    sig = res["deterministic_signals"]
    assert sig["handshake_status"] == 403 and sig["hit"] is False  # foreign origin refused


def test_wshijack_opens_the_handshake_with_the_foreign_origin_and_session_cookie():
    fake = WsHijackRunner()
    WsHijackAdapter("atk", PINNED, run=fake).run(
        {"tool": "wshijack", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/portal", "login_path": "/portal/login"}})
    ws = next(c for c in fake.calls if "-c" in c and "socket.create_connection" in c[c.index("-c") + 1])
    assert ws[-4] == "10.90.0.3"                             # resolved target ip
    assert ws[-2] == _FOREIGN_ORIGIN                         # the harness-chosen foreign origin
    assert ws[-1].startswith("sid=")                         # the victim's session cookie


class CspRunner:
    """Simulates headless chromium rendering the /widget page. Vulnerable: the injected
    inline script runs, so document.title becomes the computed marker and appears in the
    serialized DOM. Safe (`csp_blocks`): a restrictive CSP blocks the inline script, so the
    title marker never appears, only the reflected (un-executed) script source."""

    def __init__(self, *, csp_blocks=False):
        self.csp_blocks = csp_blocks
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        html = (parse_qs(urlparse(url).query).get("html") or [""])[0]
        title = ""
        if not self.csp_blocks:
            m = re.search(r"document\.title='([0-9a-f]+)'", html)   # execute title=token+42
            if m:
                title = m.group(1) + "42"
        dom = f"<html><head><title>{title}</title></head><body><div id=out></div>{html}</body></html>"
        return RunResult(0, dom, "")


def test_cspexec_confirms_inline_execution_with_a_weak_csp():
    res = CspAdapter("atk", PINNED, run=CspRunner()).run(
        {"tool": "cspexec", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/widget", "param": "html"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["csp_bypass"] is True and sig["client_exec"] is True


def test_cspexec_restrictive_csp_blocks_execution_is_not_a_hit():
    res = CspAdapter("atk", PINNED, run=CspRunner(csp_blocks=True)).run(
        {"tool": "cspexec", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/widget", "param": "html"}})
    assert res["deterministic_signals"]["hit"] is False      # inline script blocked by CSP


def test_cspexec_renders_in_a_headless_browser_against_the_resolved_ip():
    fake = CspRunner()
    CspAdapter("atk", PINNED, run=fake).run(
        {"tool": "cspexec", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/widget", "param": "html"}})
    argv = fake.calls[0]
    assert "chromium" in argv and "--dump-dom" in argv       # a real browser rendered it
    url = next(a for a in argv if a.startswith("http"))
    assert "10.90.0.3" in url and "t1.sandbox.local" not in url


class DomClobberRunner:
    """Simulates chromium rendering /clobber. Vulnerable: injected `<a id=HCCFG>` clobbers
    the global the gadget reads, so the gadget renders HC-CLOBBERED. Safe: the gadget does
    not trust the clobberable global and renders HC-SAFE."""

    def __init__(self, *, safe=False):
        self.safe = safe
        self.calls = []

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(argv)
        url = next((a for a in argv if a.startswith("http")), "")
        html = (parse_qs(urlparse(url).query).get("html") or [""])[0]
        clobbered = (not self.safe) and bool(re.search(r'id=["\']?HCCFG', html))
        out = "HC-CLOBBERED" if clobbered else "HC-SAFE"
        return RunResult(0, f'<html><body><div id="out">{out}</div>{html}</body></html>', "")


def test_domclobber_confirms_a_clobbered_global():
    res = DomClobberAdapter("atk", PINNED, run=DomClobberRunner()).run(
        {"tool": "domclobber", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/clobber", "param": "html"}})
    sig = res["deterministic_signals"]
    assert res["status"] == "ok"
    assert sig["hit"] is True and sig["dom_clobbering"] is True


def test_domclobber_safe_gadget_is_not_a_hit():
    res = DomClobberAdapter("atk", PINNED, run=DomClobberRunner(safe=True)).run(
        {"tool": "domclobber", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/clobber", "param": "html"}})
    assert res["deterministic_signals"]["hit"] is False      # the gadget does not read the clobbered global


def test_domclobber_injects_named_markup_and_renders_in_a_browser():
    fake = DomClobberRunner()
    DomClobberAdapter("atk", PINNED, run=fake).run(
        {"tool": "domclobber", "target": "t1.sandbox.local", "port": 8080,
         "args": {"path": "/clobber", "param": "html"}})
    argv = fake.calls[0]
    assert "chromium" in argv and "--dump-dom" in argv
    url = next(a for a in argv if a.startswith("http"))
    assert "10.90.0.3" in url and "HCCFG" in url             # the harness-injected named markup


def test_parse_http_full_splits_status_headers_and_body():
    out = 'STATUS 200\n{"Server": "x", "X-A": "b"}\n---BODY---\n<html>hi</html>'
    code, headers, body = _parse_http_full(out)
    assert code == 200 and headers["X-A"] == "b" and body == "<html>hi</html>"
    assert _parse_http_full("ERR Timeout") == (0, {}, "")


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERR  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
