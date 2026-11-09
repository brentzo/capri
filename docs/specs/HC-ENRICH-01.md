---
tag: HC-ENRICH-01
title: Tavily enrichment service and untrusted-data handling
status: draft
parent: SPEC.md#5.3
depends_on: [HC-SUB-01, HC-MODEL-01, HC-KB-01]
depended_on_by: [HC-AGENT-01, HC-SAFE-01]
updated: 2026-11-08
---

# HC-ENRICH-01 - Tavily enrichment service and untrusted-data handling

## 1. Purpose

This spec defines the enrichment plane: how external vulnerability intelligence (CVEs, advisories, default credentials, public write-ups) is pulled via Tavily to sharpen threat modeling and keep the knowledge base current, where it runs, and how its output is handled as untrusted data.

Enrichment is optional and advisory.
It makes the agent better informed, it never decides or acts, and it never touches the sandbox.

## 2. What it does

- Recon enrichment: a detected stack and version (for example nginx 1.18.0 or a specific CMS) becomes a lookup of known CVEs, advisories, default credentials, and public write-ups, which raises the applicability and priority of matching cards and can surface candidate techniques (feeds HC-AGENT-01 threat modeling).
- KB freshness: a periodic research pass surfaces new TTPs and advisories as proposed card drafts for HC-KB-01 (section 8).

## 3. Placement (the hard boundary)

- The enrichment service runs on the trusted host, outside the egress-denied range, and egresses to Tavily from the control plane like Bifrost's provider traffic.
- It is never called from inside the range; the sandbox has no internet and enrichment does not change that (HC-SUB-01 G2).
- It is brokered as an MCP tool through Bifrost, exposed only to `vk-enrich` (the recon/enrichment role), never to the Operator (HC-MODEL-01 §8).

```
recon detects: nginx 1.18.0, CMS 6.2
  -> enrich.lookup(stack)  via Tavily        [trusted host, control plane only]
  -> { cves, advisories, default_creds, writeups }   [untrusted, provenance-tagged, low-trust]
  -> threat model raises priority of matching cards; proposes candidate cards
  -> any resulting technique still runs through the normal loop and all dispatch() guards
```

## 4. Untrusted-data posture

Fetched web content is a prompt-injection surface, so every Tavily result is treated as untrusted data.

- It enters the recon/enrichment role's context as clearly delimited reference data, never as instructions (HC-AGENT-01 §7).
- Whatever the content says, it cannot widen scope, raise tier, or reach a new target: the Operator never sees it, and any action it inspires still passes `dispatch()` validation and the scope guard.
- Enrichment output is advisory only: it can suggest candidate cards or priorities, but it never directly authorizes an action.
- Every enrichment fact is provenance-tagged (`source: tavily`, `url`, `fetched_at`, `trust: low`); it informs, it does not become ground truth, and it is never written as a corpus label (HC-DATA-01 labels come only from the Verifier and audits).

## 5. What it must not do

- Fetch or proxy anything into the sandbox.
- Let fetched content trigger a tool call directly.
- Become ground truth, a success signal, or a training label.
- Run from inside the range during exploitation.

## 6. Opsec of the queries

- Enrichment queries carry only public technology identifiers (product and version, or a CPE), never target data, credentials, evidence, or internal detail.
- They use a generic client identity and never the user's email or any account identifier.
- Rationale: an enrichment query is a lookup of public information about public software; it must not leak anything about the specific target or the operator, and sensitive data stays inside the trust boundary.

## 7. Caching, cost, and degradation

- Tavily is usage-priced, so lookups are cached on the trusted host, keyed by normalized query (stack plus version) with a TTL, because advisories change.
- Enrichment is optional: with no Tavily key the harness runs in `passive-intel-off` and the loop proceeds on the knowledge base alone (SPEC.md#5.3).
- Structured CVE feeds (NVD, OSV) are a candidate complement to Tavily search for more precise version-to-CVE mapping (section 11).

## 8. KB-freshness workflow (offline, human-reviewed)

- A periodic, human-triggered research pass uses Tavily to surface new TTPs and advisories and drafts candidate cards against the HC-KB-01 schema.
- A human reviews and approves a draft before it becomes an `active` card.
- This is not an autonomous live-run path: web intelligence never autonomously adds an active card or drives a live engagement, which keeps real-world intel flowing into the KB without letting live web content steer exploitation.

## 9. Interfaces

```
enrich.lookup(stack_or_cpe)  -> { cves, advisories, default_creds, writeups }   # untrusted, provenance-tagged
enrich.research(topic)       -> candidate_card_drafts[]                         # offline, human-reviewed
```

Both are exposed only to `vk-enrich` via the Bifrost MCP broker, and all results carry the low-trust provenance tag.

The service is implemented as pure-standard-library policy in `harness/enrich.py` (`Enricher`, `lookup`, `research`).
The Tavily client egresses from the trusted host and is infrastructure, injected as a `transport`, the same pattern as the Bifrost model transport and the tool adapters, so tests drive the service with a stub.
`assert_public_identifier` refuses a query that is not a bare product/version or CPE identifier (an IP, an address, or a URL is rejected before any egress), and every query goes out under a generic client identity (`CLIENT_ID`), never the user's email.
Results are bucketed into cves / advisories / default_creds / writeups, each provenance-tagged (`source: tavily`, `url`, `fetched_at`, `trust: low`), and `frame` renders them through `harness/roleio.py:frame_untrusted` as a delimited untrusted block for the enrichment role only; nothing here hands enrichment to the Operator, and the model plane (HC-MODEL-01 §8) refuses to broker the tool to any vkey but `vk-enrich`.
Lookups are cached by normalized query with a TTL, and with no transport the service returns `passive-intel-off` so the loop proceeds on the KB alone; `research` only ever yields human-review-required drafts, never an active card.
The §10 criteria are covered by `tests/test_enrich.py` in CI.

The live transport behind the injected seam is `harness/tavily.py:TavilyTransport`, a thin standard-library HTTP client to the Tavily search API.
It is the only holder of the Tavily key: it presents the key as a bearer token and never puts it, or any account identity, in the query, which carries only a generic client identity as the User-Agent (§6).
Tavily returns generic web results, so the client maps each into the enricher's shape and infers a bucket (cve / advisory / default_cred / writeup) from the result.
Because enrichment is optional and advisory, any failure (an outage, an unreachable endpoint, a bad key, or a malformed body) raises `IntelUnavailable` and the enricher degrades to an `intel-unavailable` result without caching the failure, rather than letting a lookup break a run.
`tests/test_tavily.py` drives it against an in-process stdlib mock Tavily so the wire contract stays CI-green and zero-dependency; what remains is pointing it at the real API with a real key and wiring enrichment into live recon and threat modeling.

## 10. Acceptance criteria

- Tavily is never reachable from the range; an enrichment call originates only from the trusted host.
- Enrichment output reaches only the recon/enrichment role, never the Operator, and never as instructions.
- An injected instruction inside a Tavily result cannot cause a tool call or widen scope, confirmed by the scope guard and `dispatch()` still gating everything and by the Operator never seeing the content.
- Enrichment facts are provenance-tagged and never written as corpus labels or treated as ground truth.
- With no Tavily key, the harness runs in `passive-intel-off` and the loop still runs on the KB.
- Enrichment queries contain only public technology identifiers and a generic client identity, carrying no target data or secrets.

## 11. Open questions

- Add structured CVE feeds (NVD, OSV) alongside Tavily search for precise version-to-CVE mapping; leaning yes, as web search is noisier for that mapping.
- Whether to use Tavily extract or crawl for deeper advisory text, or keep strictly to search.
- Cache TTL tuning for advisories versus cost.
- Whether matching an enrichment CVE to an existing card can be automated while new-card creation stays human-reviewed.
