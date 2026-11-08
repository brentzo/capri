---
tag: HC-KB-09
title: Data-isolation technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-09 - Data-isolation technique-card starter set

## 1. Purpose

Ten cards for the `data-isolation` class, authored against the HC-KB-01 schema.
It covers tenant isolation, data at rest, and data lifecycle: cross-tenant access, shared-cache leakage, exposed backups and exports, plaintext storage, logs, incomplete deletion, and residual data.

Each card ships as its own YAML file under `kb/data-isolation/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Determinism for a data-isolation target

This is a confidentiality class, and every card proves a boundary crossing with a planted canary rather than a judgment that data "looks sensitive":

- A tenant-B canary record, field, or document read as tenant A is a deterministic `content_match` that something crossed the isolation boundary.
- A "deleted" canary still retrievable, or a residual canary on a reused resource, is a deterministic `content_match` that the lifecycle control failed.
- Predictable identifiers and shared caches are proven by a deterministic `differential`: sequential ids return foreign records, or the same cache key serves another tenant's canary.

Because the proof is a specific planted marker, these findings are cleanly verifiable (HC-FIND-01) with no fuzzy judgment and no `laya:` evaluator in the class.

## 3. Coverage map

| Card | Family | CWE | OWASP / ATT&CK | Tier | Signal | Yields |
|------|--------|-----|----------------|------|--------|--------|
| KB-DATA-TENANT-READ-001 | Isolation | CWE-639 | API1:2023 (BOLA) | 1 | content_match | cross_object_read |
| KB-DATA-TENANT-WRITE-001 | Isolation | CWE-639 | API1:2023 # verify | 2 | state_change | cross_tenant_write |
| KB-DATA-CACHE-LEAK-001 | Isolation | CWE-524 | T1213 # verify | 1 | differential | cross_object_read |
| KB-DATA-IDOR-ENUM-001 | Isolation | CWE-340 | API1:2023 # verify | 1 | differential | cross_object_read |
| KB-DATA-BACKUP-EXPOSED-001 | Data at rest | CWE-530 | T1530 | 1 | content_match | data_exposure |
| KB-DATA-ENCRYPTION-ATREST-001 | Data at rest | CWE-311 | T1530 # verify | 1 | content_match | data_exposure |
| KB-DATA-LOG-PII-001 | Data at rest | CWE-532 | T1552 # verify | 1 | content_match | data_exposure |
| KB-DATA-EXPORT-OVERSHARE-001 | Data at rest | CWE-213 | API3:2023 # verify | 1 | content_match | data_exposure |
| KB-DATA-DELETE-INCOMPLETE-001 | Lifecycle | CWE-212 | T1485 # verify | 1 | content_match | data_recovery |
| KB-DATA-RESIDUAL-001 | Lifecycle | CWE-226 | T1530 # verify | 1 | content_match | data_recovery |

Tier distribution: nine tier-1 (read-only confidentiality probing) and one tier-2, cross-tenant write, which changes another tenant's state and so snapshots first.

## 4. Cards

### 4.1 Isolation family

```yaml
id: KB-DATA-TENANT-READ-001
title: Cross-tenant data read (isolation bypass)
taxonomy: { owasp: [API1:2023], cwe: [CWE-639, CWE-284] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.multi_tenant == true' ]
preconditions: [ reachable, authenticated_session, multi_tenant ]     # session scoped to tenant A
yields_on_success: [ cross_object_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: read_foreign_tenant_record, args: { from: tenant_a, canary: tenant_b_canary } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "tenant A reads the tenant_b_canary record" }
severity_rubric: { base: high }
```

```yaml
id: KB-DATA-TENANT-WRITE-001
title: Cross-tenant write (isolation bypass on mutation)
taxonomy: { owasp: [API1:2023], cwe: [CWE-639] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.multi_tenant == true' ]
preconditions: [ reachable, authenticated_session, multi_tenant ]
yields_on_success: [ cross_tenant_write ]
blast_tier: 2                      # mutates another tenant's record
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.data_probe, intent: write_foreign_tenant_record, args: { from: tenant_a, target: tenant_b, marker: cross_write_canary } }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "tenant A sets cross_write_canary on a tenant B record" }
severity_rubric: { base: critical }
```

```yaml
id: KB-DATA-CACHE-LEAK-001
title: Shared cache serves another tenant's data
taxonomy: { cwe: [CWE-524, CWE-488] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.multi_tenant == true', 'asset.cacheable == true' ]
preconditions: [ reachable, multi_tenant ]
yields_on_success: [ cross_object_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: warm_cache_as_tenant_b }
  - { tool: custom.data_probe, intent: read_same_key_as_tenant_a, args: { canary: tenant_b_canary } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "tenant A is served tenant_b_canary from cache because the key omits the tenant" }
severity_rubric: { base: high }
```

```yaml
id: KB-DATA-IDOR-ENUM-001
title: Predictable identifiers enable bulk extraction
taxonomy: { owasp: [API1:2023], cwe: [CWE-340, CWE-639] }
applicability: [ 'asset.type == "http_endpoint"', 'matches(asset.params, /id|seq|num/)' ]
preconditions: [ reachable, authenticated_session ]
yields_on_success: [ cross_object_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: walk_sequential_ids, args: { bounded: 20, canary: foreign_owner_canary } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "sequential identifiers return records owned by other principals (foreign_owner_canary)" }
severity_rubric: { base: high }
false_positive_notes: [ "Enumeration is bounded; one foreign record proves the weakness without extracting the dataset." ]
```

### 4.2 Data-at-rest family

```yaml
id: KB-DATA-BACKUP-EXPOSED-001
title: Backup or export reachable without authorization
taxonomy: { attack: {technique: T1530}, cwe: [CWE-530, CWE-200] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_backup_surface == true' ]
preconditions: [ reachable ]
yields_on_success: [ data_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: fetch_reachable_backup }     # e.g., an exposed .bak/.sql/export path
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "an unauthenticated backup or export returns the backup_canary" }
severity_rubric: { base: high }
```

```yaml
id: KB-DATA-ENCRYPTION-ATREST-001
title: Sensitive data stored in plaintext at rest
taxonomy: { attack: {technique: T1530}, cwe: [CWE-311] }
applicability: [ 'asset.type == "data_store"' ]
preconditions: [ reachable ]
yields_on_success: [ data_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: read_store_for_plaintext_canary }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a reachable store returns the atrest_canary in plaintext (not a hash or ciphertext)" }
severity_rubric: { base: high }
```

```yaml
id: KB-DATA-LOG-PII-001
title: PII or secrets written to accessible logs
taxonomy: { cwe: [CWE-532, CWE-200] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_log_surface == true' ]
preconditions: [ reachable ]
yields_on_success: [ data_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: read_reachable_application_log }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a reachable log exposes the log_pii_canary (token or PII)" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.cloud_credential", to: high } ] }
```

```yaml
id: KB-DATA-EXPORT-OVERSHARE-001
title: Export or report returns forbidden fields or foreign rows
taxonomy: { owasp: [API3:2023], cwe: [CWE-213] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_export == true' ]
preconditions: [ reachable, authenticated_session ]
yields_on_success: [ data_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: request_export_and_inspect_fields }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "an export includes a forbidden field or foreign row carrying the export_canary" }
severity_rubric: { base: high }
```

### 4.3 Lifecycle family

```yaml
id: KB-DATA-DELETE-INCOMPLETE-001
title: Deleted data remains retrievable
taxonomy: { attack: {technique: T1485}, cwe: [CWE-212] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.supports_delete == true' ]
preconditions: [ reachable, authenticated_session ]
yields_on_success: [ data_recovery ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: delete_then_retrieve, args: { canary: delete_canary } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a record reported deleted still returns delete_canary via an alternate path or id" }
severity_rubric: { base: medium }
```

```yaml
id: KB-DATA-RESIDUAL-001
title: Residual data on a reused or deprovisioned resource
taxonomy: { attack: {technique: T1530}, cwe: [CWE-226] }
applicability: [ 'asset.type == "data_store"', 'asset.reuses_resources == true' ]
preconditions: [ reachable ]
yields_on_success: [ data_recovery ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.data_probe, intent: allocate_reused_resource_and_read }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a freshly allocated resource still carries a prior tenant's residual_canary" }
severity_rubric: { base: medium }
```

## 5. Chaining in this set

- `KB-DATA-TENANT-READ-001`, `KB-DATA-CACHE-LEAK-001`, and `KB-DATA-IDOR-ENUM-001` yield `cross_object_read`, the same fact the HC-KB-02 IDOR card and the HC-KB-03 RAG-exfil card produce, so a data-layer isolation break and an application-layer one reinforce each other on the same tenant fixture.
- `KB-DATA-BACKUP-EXPOSED-001`, `KB-DATA-ENCRYPTION-ATREST-001`, and `KB-DATA-LOG-PII-001` yield `data_exposure`, which often contains credentials and so feeds the HC-KB-05 cloud chain and the HC-KB-02 auth chain (a leaked secret becomes `cloud_credential` or seeds a session).
- `KB-DATA-TENANT-WRITE-001` yields `cross_tenant_write`, an integrity break that pairs with `privilege_escalation` from the mass-assignment and IAM cards.

## 6. Seed targets and fixtures

v1 stands up a self-hosted multi-tenant application and data store on the range (no internet), reusing the two seeded accounts (HC-KB-02 §5) as tenant A and tenant B.
The vulnerable variant plants a `tenant_b_canary` record and field readable by tenant A, a tenant-blind shared cache, sequential record ids with a `foreign_owner_canary`, a reachable backup carrying a `backup_canary`, a plaintext `atrest_canary` in the store, an application log with a `log_pii_canary`, an export that overshares an `export_canary`, a soft-delete that leaves `delete_canary` retrievable, and a reused resource with a `residual_canary`.
Each `does_not_fire` fixture applies the control: row-level tenant scoping, tenant-keyed caches, unpredictable ids with authorization checks, authenticated backups, encryption at rest, log redaction, field-scoped exports, hard deletion, and resource zeroing on reuse.
Probing uses `custom.data_probe`, a reviewed allowlist adapter (HC-AGENT-01 §5.3); all reads stay within declared scope.

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including taxonomy resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01.
- The cross-tenant write card refuses to run without a live snapshot and restores the affected tenant cleanly.
- No card causes a scope or egress violation; enumeration stays bounded and all reads are in-scope, confirmed by the audit log.
- The chain in section 5 executes: a data-layer isolation break and the application-layer IDOR confirm on the same tenant fixture, and an exposed backup yields a credential that feeds the cloud chain.
- All signals are deterministic canary or differential checks; the class uses no `laya:` evaluator.

## 8. Open questions

- Canary strategy for stores: how to seed canaries across caches, backups, and reused resources without the seeding itself becoming the leak path the card then detects.
- Whether tenant isolation deserves a dedicated multi-tenant fixture distinct from the two-account authz fixture, given both reuse tenant A and tenant B.
- Residual-data detection depends on the substrate's resource reuse model; align with the HC-SUB-01 snapshot and cloning behavior so "reuse" is observable.
- How to bound enumeration proofs so one foreign record suffices and the agent never extracts a dataset, even on a confirmed weakness.

## 9. Backlog (deferred from this set)

- Backup restoration and point-in-time recovery abuse (reading historical data a current ACL would deny).
- Cross-region replication lag used to read stale, since-revoked data.
- Search-index and analytics-store isolation separate from the primary store.
- Deterministic-encryption and tokenization inference (equality and ordering leaks).
- Right-to-be-forgotten and retention-policy verification as a compliance-oriented card set.
