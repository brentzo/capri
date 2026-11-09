#!/usr/bin/env python3
"""Tests for the live Tavily transport (HC-ENRICH-01).

Drives the real standard-library HTTP client against an in-process mock Tavily
(stdlib http.server), so the wire contract is exercised without a live endpoint and
stays CI-green and zero-dependency. Proves:

  - generic web results are mapped into the enricher's shape and categorized
    (cve / advisory / default_cred / writeup);
  - the Tavily key is presented as a bearer token and never placed in the query,
    and the query goes out under a generic User-Agent, never an account identity;
  - an outage, an unreachable endpoint, or a malformed body raises IntelUnavailable;
  - plugged into the real Enricher a lookup is provenance-tagged, and a transient
    failure degrades to intel-unavailable without caching the failure.

Zero-dependency: `python3 tests/test_tavily.py`.
"""
import http.server
import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.enrich import Enricher, IntelUnavailable                      # noqa: E402
from harness.tavily import TavilyTransport                                 # noqa: E402

RESULTS = [
    {"title": "CVE-2021-23017 in nginx", "url": "https://nvd.nist.gov/vuln/detail/x", "content": "resolver bug"},
    {"title": "nginx security advisory", "url": "https://nginx.org/sec", "content": "please upgrade"},
    {"title": "router default password list", "url": "https://w/d", "content": "admin default login admin"},
    {"title": "a write-up on exploitation", "url": "https://blog/p", "content": "how it works"},
]


class _Server(http.server.HTTPServer):
    responder = None
    last = None


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.last = {"auth": self.headers.get("Authorization"),
                            "ua": self.headers.get("User-Agent"), "body": body}
        status, payload = self.server.responder(body)
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def _serve(responder):
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.responder = responder
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/search"


# --- mapping and categorization ------------------------------------------
def test_results_are_mapped_and_categorized():
    srv, ep = _serve(lambda body: (200, {"results": RESULTS}))
    try:
        items = TavilyTransport("tvly-key", endpoint=ep).search("nginx 1.18.0", client_id="hc-enrich/1.0")
        cats = [it["category"] for it in items]
        assert cats == ["cve", "advisory", "default_cred", "writeup"], cats
        assert items[0]["url"].startswith("https://nvd")
    finally:
        srv.shutdown()


# --- opsec of the request (§6) -------------------------------------------
def test_key_is_a_bearer_header_never_in_the_query_and_identity_is_generic():
    srv, ep = _serve(lambda body: (200, {"results": []}))
    try:
        TavilyTransport("tvly-secret", endpoint=ep).search("nginx 1.18.0", client_id="hc-enrich/1.0")
        assert srv.last["auth"] == "Bearer tvly-secret"
        assert srv.last["ua"] == "hc-enrich/1.0" and "@" not in srv.last["ua"]
        assert srv.last["body"]["query"] == "nginx 1.18.0"
        assert "tvly-secret" not in json.dumps(srv.last["body"])     # key never in the payload
        assert "api_key" not in srv.last["body"]
    finally:
        srv.shutdown()


# --- failure maps to IntelUnavailable ------------------------------------
def test_an_outage_is_intel_unavailable():
    srv, ep = _serve(lambda body: (503, {"error": "upstream"}))
    try:
        try:
            TavilyTransport("k", endpoint=ep).search("nginx", client_id="hc-enrich/1.0")
            raise AssertionError("expected IntelUnavailable for a 503")
        except IntelUnavailable:
            pass
    finally:
        srv.shutdown()


def test_an_unreachable_endpoint_is_intel_unavailable():
    srv, ep = _serve(lambda body: (200, {"results": []}))
    srv.shutdown()
    srv.server_close()
    try:
        TavilyTransport("k", endpoint=ep, timeout=2.0).search("nginx", client_id="hc-enrich/1.0")
        raise AssertionError("expected IntelUnavailable for an unreachable endpoint")
    except IntelUnavailable:
        pass


def test_a_malformed_response_is_intel_unavailable():
    srv, ep = _serve(lambda body: (200, {"no": "results key"}))
    try:
        try:
            TavilyTransport("k", endpoint=ep).search("nginx", client_id="hc-enrich/1.0")
            raise AssertionError("expected IntelUnavailable for a malformed body")
        except IntelUnavailable:
            pass
    finally:
        srv.shutdown()


# --- end to end through the enricher -------------------------------------
def test_enricher_lookup_is_provenance_tagged_end_to_end():
    srv, ep = _serve(lambda body: (200, {"results": RESULTS}))
    try:
        enr = Enricher(TavilyTransport("k", endpoint=ep))
        res = enr.lookup({"product": "nginx", "version": "1.18.0"})
        assert res["mode"] == "active"
        assert res["cves"] and res["advisories"] and res["default_creds"] and res["writeups"]
        for item in res["cves"]:
            assert item["source"] == "tavily" and item["trust"] == "low" and item["fetched_at"]
    finally:
        srv.shutdown()


def test_enricher_degrades_and_does_not_cache_a_transient_failure():
    state = {"n": 0}

    def responder(body):
        state["n"] += 1
        if state["n"] == 1:
            return 503, {"error": "upstream"}        # first call fails
        return 200, {"results": RESULTS}             # then recovers

    srv, ep = _serve(responder)
    try:
        enr = Enricher(TavilyTransport("k", endpoint=ep))
        first = enr.lookup("nginx 1.18.0")
        assert first["mode"] == "intel-unavailable" and first["cves"] == []
        second = enr.lookup("nginx 1.18.0")          # retried, not served from a cached failure
        assert second["mode"] == "active" and second["cves"]
    finally:
        srv.shutdown()


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
