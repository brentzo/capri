"""Live Tavily transport (HC-ENRICH-01), the HTTP client behind the enricher.

The enrichment service (`harness/enrich.py`) is policy over an injected search
`transport`; this is the real one, a thin standard-library HTTP client to the
Tavily search API. It is the only holder of the Tavily key: it presents the key as
a bearer token and never puts it, or any account identity, in the query. Queries
reach it already sanitized by the enricher (public product/version or CPE only) and
carry only a generic client identity as the User-Agent (§6).

Everything here is `urllib`, no third-party dependency; the live Tavily endpoint is
out of repo, and `tests/test_tavily.py` drives this client against an in-process
stdlib mock so the wire contract stays CI-green. Tavily returns generic web
results, so the client maps each into the enricher's shape and infers a category
(cve / advisory / default_cred / writeup) from the result. Enrichment is optional
and advisory, so any failure (an outage or a bad key) raises `IntelUnavailable` and
the enricher degrades rather than letting a lookup break a run.
"""
import json
import re
import time
import urllib.error
import urllib.request

from harness.enrich import IntelUnavailable

_ENDPOINT = "https://api.tavily.com/search"
_CVE = re.compile(r"CVE-\d{4}-\d{3,}", re.IGNORECASE)
_CVE_HOSTS = ("nvd.nist.gov", "cve.org", "cve.mitre.org")


def _categorize(title, url, content):
    """Infer the enricher bucket from a generic web result; order matters so a CVE
    advisory is a cve, not an advisory. Anything unrecognized is a write-up."""
    hay = f"{title} {url} {content}".lower()
    if _CVE.search(f"{title} {content}") or any(h in url for h in _CVE_HOSTS):
        return "cve"
    if "advisory" in hay or "ghsa-" in hay or "security bulletin" in hay:
        return "advisory"
    if "default password" in hay or "default credential" in hay or "default login" in hay:
        return "default_cred"
    return "writeup"


class TavilyTransport:
    def __init__(self, api_key, *, endpoint=_ENDPOINT, timeout=15.0, max_results=5,
                 clock=time.monotonic):
        self.api_key = api_key           # the Tavily key, held here only
        self.endpoint = endpoint
        self.timeout = timeout
        self.max_results = max_results
        self._clock = clock

    def search(self, query, *, client_id):
        """Run one Tavily search and return the results mapped into the enricher's
        shape, or raise IntelUnavailable so the enricher can degrade."""
        body = json.dumps({"query": query, "search_depth": "basic",
                           "max_results": self.max_results}).encode("utf-8")
        headers = {"Authorization": f"Bearer {self.api_key}",   # key in the header, not the query
                   "Content-Type": "application/json",
                   "User-Agent": str(client_id)}                # generic identity, never an email
        req = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise IntelUnavailable(f"tavily returned status {e.code}")
        except (urllib.error.URLError, TimeoutError):
            raise IntelUnavailable("tavily unreachable")
        try:
            results = json.loads(raw)["results"]
        except (ValueError, KeyError, TypeError):
            raise IntelUnavailable("malformed tavily response")
        return [self._map(item or {}) for item in (results or [])]

    @staticmethod
    def _map(item):
        title, url, content = item.get("title"), item.get("url"), item.get("content")
        return {"category": _categorize(title or "", url or "", content or ""),
                "title": title, "url": url, "content": content}
