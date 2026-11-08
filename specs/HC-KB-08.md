---
tag: HC-KB-08
title: Resource-exhaustion technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-08 - Resource-exhaustion technique-card starter set

## 1. Purpose

Ten cards for the `resource-exhaustion` class, authored against the HC-KB-01 schema.
It covers availability and resource limits: algorithmic complexity, memory amplification, missing caps, and connection exhaustion.

Each card ships as its own YAML file under `kb/resource-exhaustion/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. The safety rule for this class (read first)

Availability testing is the one class whose naive proof is an outage, so these cards never cause one:

- A card proves the absence of a limit with a single bounded probe, not by exhausting the service. The signal is a `timing_oracle` crossing a threshold on one crafted request, or a `differential` showing an unreasonable size or rate is accepted where it should be rejected.
- Every probe is capped (`cap_s`, `cap_bytes`, `cap_conn`) and bounded further by the `dispatch()` per-target rate limit (HC-AGENT-01 §5.2), the HC-MODEL-01 budget, the engagement window, and the watchdog (HC-SAFE-01 §4).
- Resource-consuming cards are tier 2 and snapshot first, so availability is restored after the proof.
- These cards run only when the engagement contract authorizes availability testing (`policy.allowed_tactics`, HC-SUB-01 §4.1); absent that, they are `blocked_by_policy`, exactly like any tier it does not permit.

The point is a confirmed finding that says "no limit exists here," proven safely, not a demonstrated denial of service.

## 3. Coverage map

| Card | Family | CWE | ATT&CK | Tier | Signal | Yields |
|------|--------|-----|--------|------|--------|--------|
| KB-DOS-COMPUTE-REDOS-001 | Compute complexity | CWE-1333 | T1499.003 # verify | 2 | timing_oracle | resource_exhaustion |
| KB-DOS-COMPUTE-HASHDOS-001 | Compute complexity | CWE-407 | T1499.003 # verify | 2 | timing_oracle | resource_exhaustion |
| KB-DOS-COMPUTE-AMPLIFY-001 | Compute complexity | CWE-405 | T1499.003 # verify | 2 | timing_oracle | resource_exhaustion |
| KB-DOS-MEM-XMLEXPAND-001 | Memory amplification | CWE-776 | T1499.004 # verify | 2 | timing_oracle | resource_exhaustion |
| KB-DOS-MEM-DECOMPRESS-001 | Memory amplification | CWE-409 | T1499.004 # verify | 2 | timing_oracle | resource_exhaustion |
| KB-DOS-MEM-ALLOC-001 | Memory amplification | CWE-789 | T1499.004 # verify | 2 | timing_oracle | resource_exhaustion |
| KB-DOS-MEM-UPLOAD-001 | Memory amplification | CWE-400 | T1499.003 # verify | 2 | differential | resource_exhaustion |
| KB-DOS-LIMIT-PAGINATION-001 | Missing limit | CWE-770 | T1499.003 # verify | 1 | differential | resource_exhaustion |
| KB-DOS-LIMIT-RATE-001 | Missing limit | CWE-770 | T1499.003 # verify | 1 | differential | rate_unbounded |
| KB-DOS-CONN-EXHAUST-001 | Connection | CWE-400 | T1499.001 # verify | 2 | timing_oracle | resource_exhaustion |

Tier distribution: two tier-1 (bounded detection of a missing cap) and eight tier-2 (resource-consuming proof, snapshot required).

## 4. Cards

### 4.1 Compute-complexity family

```yaml
id: KB-DOS-COMPUTE-REDOS-001
title: Regular-expression denial of service (catastrophic backtracking)
taxonomy: { attack: {technique: T1499.003}, cwe: [CWE-1333, CWE-400] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.params)' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: redos_payload, args: { cap_s: 10, trials: 3 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "superlinear_time(payload_vs_baseline, p<0.01) within cap_s, no input-length cap" }
severity_rubric: { base: medium, raise_if: [ { when: "asset.unauthenticated", to: high } ] }
false_positive_notes: [ "Require a statistically significant superlinear curve across trials, not one slow response; the probe stays under cap_s." ]
```

```yaml
id: KB-DOS-COMPUTE-HASHDOS-001
title: Hash-collision algorithmic complexity
taxonomy: { attack: {technique: T1499.003}, cwe: [CWE-407] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.parses_structured_keys == true' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: colliding_keys_payload, args: { cap_s: 10, trials: 3 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "colliding-key input is superlinear versus random-key input within cap_s" }
severity_rubric: { base: medium }
```

```yaml
id: KB-DOS-COMPUTE-AMPLIFY-001
title: Asymmetric request amplification (fan-out)
taxonomy: { attack: {technique: T1499.003}, cwe: [CWE-405] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.triggers_downstream_work == true' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: single_request_high_fanout, args: { cap_s: 10 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "one bounded request causes downstream work disproportionate to its size, within cap_s" }
severity_rubric: { base: medium }
```

### 4.2 Memory-amplification family

```yaml
id: KB-DOS-MEM-XMLEXPAND-001
title: XML entity expansion (billion laughs)
taxonomy: { attack: {technique: T1499.004}, cwe: [CWE-776] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.parses_xml == true' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: bounded_entity_expansion, args: { cap_s: 10, cap_bytes: 5000000 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "a bounded nested-entity document expands without a parser entity-limit, within cap_s" }
severity_rubric: { base: high }
```

```yaml
id: KB-DOS-MEM-DECOMPRESS-001
title: Decompression bomb
taxonomy: { attack: {technique: T1499.004}, cwe: [CWE-409] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.accepts_compressed_input == true' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: bounded_compression_bomb, args: { cap_s: 10, cap_ratio: 1000 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "a highly compressed payload is inflated without a decompressed-size cap, within cap_s" }
severity_rubric: { base: high }
```

```yaml
id: KB-DOS-MEM-ALLOC-001
title: Unbounded allocation from a size field
taxonomy: { attack: {technique: T1499.004}, cwe: [CWE-789] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.reads_size_field == true' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: large_size_field_small_body, args: { cap_s: 10 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "a declared-large size drives allocation disproportionate to the actual body, within cap_s" }
severity_rubric: { base: medium }
```

```yaml
id: KB-DOS-MEM-UPLOAD-001
title: Missing upload-size cap
taxonomy: { attack: {technique: T1499.003}, cwe: [CWE-400] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.accepts_upload == true' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: oversize_upload_probe, args: { cap_bytes: 50000000 } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "an upload above a reasonable limit is accepted where a size cap should reject it" }
severity_rubric: { base: medium }
```

### 4.3 Missing-limit family

```yaml
id: KB-DOS-LIMIT-PAGINATION-001
title: Unbounded pagination or result size
taxonomy: { attack: {technique: T1499.003}, cwe: [CWE-770] }
applicability: [ 'asset.type == "http_endpoint"', 'matches(asset.params, /limit|page_size|count|per_page/)' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 1                      # bounded detection: is an unreasonable limit rejected
cleanup: none
probe_steps:
  - { tool: custom.dos_probe, intent: request_unreasonable_limit, args: { limit: 1000000, materialize: false } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "an unreasonable page size is accepted (no server-side maximum) without fetching the full set" }
severity_rubric: { base: low, raise_if: [ { when: "asset.unauthenticated", to: medium } ] }
```

```yaml
id: KB-DOS-LIMIT-RATE-001
title: Missing rate limit on an expensive endpoint
taxonomy: { attack: {technique: T1499.003}, cwe: [CWE-770] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.is_expensive == true' ]
preconditions: [ reachable ]
yields_on_success: [ rate_unbounded ]
blast_tier: 1                      # bounded burst within the dispatch rate cap
cleanup: none
probe_steps:
  - { tool: custom.dos_probe, intent: bounded_burst, args: { attempts: 50, window_s: 10 } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "no throttle, 429, or backoff appears after a bounded burst on an expensive route" }
severity_rubric: { base: low, raise_if: [ { when: "asset.is_expensive", to: medium } ] }
```

### 4.4 Connection family

```yaml
id: KB-DOS-CONN-EXHAUST-001
title: No connection cap or idle timeout (slow-connection exhaustion)
taxonomy: { attack: {technique: T1499.001}, cwe: [CWE-400] }
applicability: [ 'asset.type == "network_service"' ]
preconditions: [ reachable ]
yields_on_success: [ resource_exhaustion ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.dos_probe, intent: bounded_slow_connections, args: { cap_conn: 50, cap_s: 20 } }
success_signal: { type: timing_oracle, evaluator: deterministic,
                  assert: "slow/partial connections are held open past a reasonable idle timeout, within cap_conn" }
severity_rubric: { base: medium }
false_positive_notes: [ "The probe holds a bounded number of connections for a bounded time; it measures the absence of a timeout, not an outage." ]
```

## 5. Chaining in this set

- `KB-DOS-LIMIT-RATE-001` yields `rate_unbounded`, the same missing-control that lets `KB-WEB-AUTH-BRUTE-001` (HC-KB-02) attempt credential stuffing, so a rate finding here strengthens the auth chain there.
- The `resource_exhaustion` yield is an availability fact rather than an access primitive, so these cards mostly compound the impact of a chain rather than extend it; a confirmed `resource_exhaustion` raises the availability dimension of any co-located finding.
- `KB-DOS-MEM-XMLEXPAND-001` and the HC-KB-07 XXE card share an XML-parser fixture, so the same target exercises both confidentiality (XXE file read) and availability (entity expansion).

## 6. Seed targets and fixtures

v1 stands up self-hosted targets on the range (no internet) with the limits deliberately removed: an endpoint with a backtracking regex, a structured-key parser vulnerable to hash collisions, a high-fan-out route, an XML parser with entity limits off, a decompressor with no size cap, a handler that allocates from a declared size, an upload with no maximum, a paginated API with no server-side cap, an expensive unthrottled route, and a network service with no connection cap or idle timeout.
Each `does_not_fire` fixture applies the control: linear-time matching or input caps, randomized hashing, fan-out limits, parser entity and size limits, upload caps, a server-side pagination maximum, rate limiting, and connection caps with timeouts.
Every probe is bounded by its `cap_*` argument and by the dispatch rate limit; the eval harness runs this class only with a contract that authorizes availability testing.
Probing uses `custom.dos_probe`, a reviewed allowlist adapter (HC-AGENT-01 §5.3).

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including ATT&CK and CWE resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01, within its `cap_*` bounds.
- The eight tier-2 cards refuse to run without a live snapshot and restore the service cleanly; without contract authorization for availability testing, all ten are `blocked_by_policy`.
- No probe exceeds its cap or the dispatch rate limit, and no run degrades a shared eval target beyond its snapshot restore, confirmed by the audit log and the watchdog.
- The chain in section 5 holds: a missing rate limit strengthens the HC-KB-02 brute-force finding.
- Timing and cap-acceptance signals are evaluated deterministically by the harness, with the timing tests using the shared statistical helper (HC-KB-01 open question).

## 8. Open questions

- Threshold calibration: the superlinear and timeout thresholds must separate a real complexity bug from range noise; this needs the shared statistical helper and per-target baselines.
- Whether availability findings need a distinct severity model, since CVSS availability impact understates control-plane or shared-service blast.
- How to bound amplification safely when the downstream work is asynchronous and not observable within `cap_s`; likely an inconclusive verdict with a flagged follow-up.
- Whether to model distributed or multi-source floods at all, or keep strictly to single-probe limit-absence proofs (leaning strictly single-probe for v1).

## 9. Backlog (deferred from this set)

- Protocol-specific floods (TCP SYN, UDP amplification) that are infrastructure DoS rather than application limits.
- GraphQL query-cost and nesting limits, sequenced with the HC-KB-07 GraphQL card.
- Cache-stampede and thundering-herd behavior under coordinated expiry.
- Financial or cost denial (metered-resource exhaustion), overlapping the HC-KB-03 unbounded-consumption card.
- Memory-leak accretion over a long run, which needs a soak-test harness rather than a single bounded probe.
