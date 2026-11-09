"""Tavily enrichment service and untrusted-data handling (HC-ENRICH-01).

Enrichment is optional and advisory: a detected stack becomes a lookup of public
vulnerability intelligence (CVEs, advisories, default credentials, write-ups) that
can raise the priority of matching cards, and it never decides, acts, or touches
the sandbox. The actual Tavily client egresses from the trusted host and is
infrastructure, injected here as a `transport`, the same pattern as the Bifrost
model transport and the tool adapters; tests drive the service with a stub.

What this module enforces, the HC-ENRICH-01 §10 criteria that are code:

- Opsec of the queries (§6): a query carries only a public technology identifier
  (product and version, or a CPE) under a generic client identity, never target
  data, a credential, or the user's account. `assert_public_identifier` refuses a
  query that carries an IP, an address, or a URL before any egress.
- Untrusted-data posture (§4): every result is provenance-tagged (`source: tavily`,
  `url`, `fetched_at`, `trust: low`) and `frame` renders it as a clearly delimited
  untrusted block (HC-AGENT-01 §7) for the enrichment role only, never the
  Operator; it is advisory, never a success signal, ground truth, or a label.
- Degradation (§7): with no Tavily transport the service runs `passive-intel-off`
  and the loop proceeds on the knowledge base alone.
- Reach (§3, HC-MODEL-01 §8): the tool is brokered only to `vk-enrich`, which the
  model plane enforces at config; nothing here hands enrichment to the Operator.

The offline KB-freshness pass (§8) is `research`: it only ever produces drafts for
human review and never an active card or a live-run path.
"""
import re
import time

from harness import roleio
from harness.store.db import now

CLIENT_ID = "hc-enrich/1.0"      # generic client identity (§6), never the user's email
SOURCE = "tavily"
TRUST = "low"
_BUCKETS = ("cves", "advisories", "default_creds", "writeups")
_CATEGORY_TO_BUCKET = {"cve": "cves", "advisory": "advisories",
                       "default_cred": "default_creds", "writeup": "writeups"}
# A public identifier is a product/version string or a CPE: a bounded, conservative
# character set, no addresses or URLs.
_ALLOWED = re.compile(r"^[A-Za-z0-9 ._:/*+-]{1,120}$")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class OpsecError(Exception):
    """A query that would leak target data or a secret; refused before egress (§6)."""


def normalize_query(stack_or_cpe):
    """A product/version string, a CPE string, or a {product, version} / {cpe} dict
    becomes one normalized query string built only from those public fields."""
    if isinstance(stack_or_cpe, dict):
        if stack_or_cpe.get("cpe"):
            return str(stack_or_cpe["cpe"]).strip()
        return " ".join(str(stack_or_cpe[k]).strip()
                        for k in ("product", "version") if stack_or_cpe.get(k)).strip()
    return str(stack_or_cpe).strip()


def assert_public_identifier(query):
    """Raise OpsecError unless `query` is a bare public technology identifier (§6)."""
    if not query:
        raise OpsecError("empty enrichment query")
    if not _ALLOWED.match(query):
        raise OpsecError("query is not a bare product/version or CPE identifier")
    if query.lower().startswith("cpe:"):
        return query                     # a CPE is a public identifier by construction
    if "@" in query or "://" in query:
        raise OpsecError("query carries an address or URL, not a public identifier")
    if _IP.search(query):
        raise OpsecError("query carries an IP address; enrichment carries no target data")
    return query


class Enricher:
    def __init__(self, transport, *, ttl=86400.0, clock=time.monotonic, client_id=CLIENT_ID):
        self.transport = transport       # Tavily client; None => passive-intel-off
        self.ttl = ttl
        self._clock = clock
        self.client_id = client_id
        self._cache = {}                 # normalized query -> (t, result)

    def available(self):
        return self.transport is not None

    def lookup(self, stack_or_cpe):
        """Public-intel lookup for a detected stack (§2). Returns a provenance-tagged,
        advisory result, or a passive-intel-off result when no transport is wired."""
        query = normalize_query(stack_or_cpe)
        if not self.available():
            return self._passive(query)
        assert_public_identifier(query)                  # refuse to egress target data
        cached = self._cache.get(query)
        if cached is not None and (self._clock() - cached[0]) < self.ttl:
            return cached[1]
        raw = self.transport.search(query, client_id=self.client_id) or []
        result = self._assemble(query, raw)
        self._cache[query] = (self._clock(), result)
        return result

    def frame(self, result):
        """Render enrichment as untrusted, provenance-tagged reference data for the
        enrichment role's context (§4, HC-AGENT-01 §7). Advisory only, never the
        Operator's context, never a success signal or a label."""
        header = (f"enrichment for {result.get('query')!r} (mode={result.get('mode')}, "
                  f"source={SOURCE}, trust={TRUST}); advisory only, not a success signal "
                  f"or a label.")
        lines = [header]
        for bucket in _BUCKETS:
            for item in result.get(bucket, []):
                lines.append(f"- [{bucket}] {item.get('title')} ({item.get('url')}): "
                             f"{item.get('content')}")
        return roleio.frame_untrusted("\n".join(lines), label="enrichment")

    def research(self, topic):
        """Offline KB-freshness pass (§8): candidate card drafts for HUMAN review.
        Never autonomous, never an active card, never a live-run path."""
        query = normalize_query(topic)
        assert_public_identifier(query)
        if not self.available():
            return []
        fetched = now()
        return [{"status": "draft", "review": "human-required", "topic": query,
                 "title": (it or {}).get("title"), "url": (it or {}).get("url"),
                 "source": SOURCE, "fetched_at": fetched, "trust": TRUST}
                for it in (self.transport.search(query, client_id=self.client_id) or [])]

    # --- helpers --------------------------------------------------------
    def _passive(self, query):
        return {"query": query, "mode": "passive-intel-off",
                **{b: [] for b in _BUCKETS}}

    def _assemble(self, query, raw):
        out = {"query": query, "mode": "active", **{b: [] for b in _BUCKETS}}
        fetched = now()
        for item in raw:
            item = item or {}
            bucket = _CATEGORY_TO_BUCKET.get(item.get("category"), "writeups")
            out[bucket].append({"title": item.get("title"), "content": item.get("content"),
                                "source": SOURCE, "url": item.get("url"),
                                "fetched_at": fetched, "trust": TRUST})
        return out
