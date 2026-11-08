---
tag: HC-KB-05
title: Cloud and deployment technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-05 - Cloud and deployment technique-card starter set

## 1. Purpose

Ten cards for the `cloud-deployment` class, authored against the HC-KB-01 schema.
It covers the control-plane and deployment surface: instance metadata, IAM, object storage, infrastructure-as-code secrets, container and orchestration escape, serverless event injection, and network exposure.
These targets are modeled on the range as self-hosted equivalents (a mock metadata endpoint, a mock cloud API, an S3-style object store, a local Kubernetes-style API), never a real cloud account, so the egress-denied guarantee holds.

Each card ships as its own YAML file under `kb/cloud-deployment/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Determinism and containment for a cloud target

- Credentials and secrets are planted canaries (a canary IAM role name, a canary secret string, a canary object), so retrieval is a deterministic `content_match` rather than a judgment that "this looks like a key."
- Escalation and write actions are proven by a deterministic `state_change`: the probe performs the action against a mock control plane and the harness observes the resulting canary resource or marker, not the model's claim.
- Container and orchestration escape is bounded by HC-SUB-01 G4: the "host" an escape reaches is the range node, and the escape-attempt self-test (HC-SUB-01 §8.3) proves the operator host and other networks stay unreachable regardless.
- Serverless and SSRF-style reach is proven by an out-of-band callback to the in-sandbox collaborator (`range-oob`), never an internet host.

## 3. Coverage map

| Card | Family | CWE | ATT&CK | Tier | Signal | Yields |
|------|--------|-----|--------|------|--------|--------|
| KB-CLOUD-META-SSRF-001 | Metadata | CWE-918 | T1552.005 | 1 | content_match | cloud_credential |
| KB-CLOUD-IAM-PRIVESC-001 | IAM | CWE-269 | T1098 # verify | 2 | state_change | cloud_admin |
| KB-CLOUD-STORAGE-READ-001 | Object storage | CWE-284 | T1530 | 1 | content_match | data_exposure |
| KB-CLOUD-STORAGE-WRITE-001 | Object storage | CWE-284 | T1530 # verify | 2 | state_change | storage_write |
| KB-CLOUD-IAC-SECRET-001 | IaC / config | CWE-798 | T1552.001 | 1 | content_match | cloud_credential |
| KB-CLOUD-SECRETS-ENDPOINT-001 | Secrets exposure | CWE-200 | T1552 # verify | 1 | content_match | cloud_credential |
| KB-CLOUD-CONTAINER-ESCAPE-001 | Container | CWE-269 | T1611 | 2 | state_change | node_foothold |
| KB-CLOUD-K8S-ANON-001 | Orchestration | CWE-306 | T1610 # verify | 1 | status_match | cluster_read |
| KB-CLOUD-SERVERLESS-INJECT-001 | Serverless | CWE-74 | T1059 # verify | 1 | oob_callback | rce_foothold |
| KB-CLOUD-NET-SG-001 | Network exposure | CWE-284 | T1021 # verify | 1 | status_match | lateral_reach |

Tier distribution: seven tier-1 (read-only probing) and three tier-2 (state-changing, snapshot required): IAM escalation, unauthenticated storage write, and container escape.

## 4. Cards

### 4.1 Metadata and IAM family

```yaml
id: KB-CLOUD-META-SSRF-001
title: Instance metadata service reachable, credential theft
taxonomy: { attack: {technique: T1552.005}, cwe: [CWE-918, CWE-200] }
applicability: [ 'asset.type == "cloud_instance" || asset.has_fetch_surface == true' ]
preconditions: [ reachable, internal_reach ]        # reached via an SSRF primitive (HC-KB-02/03)
yields_on_success: [ cloud_credential ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.cloud_probe, intent: fetch_metadata_credentials, args: { endpoint: mock-imds } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "response_contains(metadata_role_canary) OR response_contains(temp_credential_canary)" }
severity_rubric: { base: high, raise_if: [ { when: "yields.cloud_admin", to: critical } ] }
false_positive_notes: [ "The metadata endpoint must require no app credentials; a hop that itself authenticates is not this weakness." ]
```

```yaml
id: KB-CLOUD-IAM-PRIVESC-001
title: Over-permissioned role enables privilege escalation
taxonomy: { attack: {technique: T1098}, cwe: [CWE-269] }
applicability: [ 'asset.type == "cloud_control_plane"' ]
preconditions: [ reachable, cloud_credential ]
yields_on_success: [ cloud_admin ]
blast_tier: 2                      # mutates IAM state on the mock control plane
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.cloud_probe, intent: enumerate_permissions }
  - { tool: custom.cloud_probe, intent: escalate_via_passrole_or_attach, args: { marker: admin_canary }}
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "an action the role should be denied succeeds and creates admin_canary" }
severity_rubric: { base: critical }
```

### 4.2 Object storage family

```yaml
id: KB-CLOUD-STORAGE-READ-001
title: Public object storage exposes data
taxonomy: { attack: {technique: T1530}, cwe: [CWE-284, CWE-200] }
applicability: [ 'asset.type == "object_store"' ]
preconditions: [ reachable ]
yields_on_success: [ data_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.cloud_probe, intent: anonymous_get, args: { object: canary_object } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "an unauthenticated request returns the canary object's contents" }
severity_rubric: { base: high }
```

```yaml
id: KB-CLOUD-STORAGE-WRITE-001
title: Unauthenticated or world-writable object storage
taxonomy: { attack: {technique: T1530}, cwe: [CWE-284] }
applicability: [ 'asset.type == "object_store"' ]
preconditions: [ reachable ]
yields_on_success: [ storage_write ]
blast_tier: 2                      # writes an object to a shared store
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.cloud_probe, intent: anonymous_put, args: { object: write_marker } }
  - { tool: custom.cloud_probe, intent: read_back_marker }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "an unauthenticated PUT persists and the marker reads back" }
severity_rubric: { base: high, raise_if: [ { when: "asset.serves_content", to: critical } ] }
```

### 4.3 Secrets and configuration family

```yaml
id: KB-CLOUD-IAC-SECRET-001
title: Secret committed in infrastructure-as-code or build config
taxonomy: { attack: {technique: T1552.001}, cwe: [CWE-798] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.serves_config == true' ]
preconditions: [ reachable ]
yields_on_success: [ cloud_credential ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.cloud_probe, intent: fetch_reachable_iac_or_env }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a reachable template/env/config exposes the secret_canary" }
severity_rubric: { base: high }
```

```yaml
id: KB-CLOUD-SECRETS-ENDPOINT-001
title: Unauthenticated secrets or diagnostics endpoint
taxonomy: { cwe: [CWE-200, CWE-306] }
applicability: [ 'asset.type == "http_endpoint"', 'asset.has_admin_surface == true' ]
preconditions: [ reachable ]
yields_on_success: [ cloud_credential ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: httpx, intent: probe_diagnostics_paths }    # e.g., exposed env/actuator/secrets routes
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "an unauthenticated diagnostics or secrets route returns the secret_canary" }
severity_rubric: { base: high }
```

### 4.4 Container and orchestration family

```yaml
id: KB-CLOUD-CONTAINER-ESCAPE-001
title: Container escape via misconfiguration
taxonomy: { attack: {technique: T1611}, cwe: [CWE-269] }
applicability: [ 'asset.type == "container_workload"' ]
preconditions: [ reachable, rce_foothold ]            # a foothold inside a container first
yields_on_success: [ node_foothold ]
blast_tier: 2                      # touches node state; still contained by HC-SUB-01 G4
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.cloud_probe, intent: probe_escape_surface, args: { checks: [privileged, host_mount, docker_sock] } }
  - { tool: custom.cloud_probe, intent: touch_node_canary }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "a node-scoped canary reachable only after escape is read or written" }
severity_rubric: { base: critical }
false_positive_notes: [ "The node here is the range node; the operator host stays unreachable by HC-SUB-01 §8.3, which bounds blast regardless of confirmation." ]
```

```yaml
id: KB-CLOUD-K8S-ANON-001
title: Anonymous or over-exposed orchestration API
taxonomy: { attack: {technique: T1610}, cwe: [CWE-306] }
applicability: [ 'asset.type == "orchestrator_api"' ]
preconditions: [ reachable ]
yields_on_success: [ cluster_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.cloud_probe, intent: anonymous_api_list, args: { resource: canary_namespace } }
success_signal: { type: status_match, evaluator: deterministic,
                  assert: "an unauthenticated API call returns 2xx and lists the canary namespace/secret" }
severity_rubric: { base: high }
```

### 4.5 Serverless and network family

```yaml
id: KB-CLOUD-SERVERLESS-INJECT-001
title: Event-data injection into a serverless function
taxonomy: { attack: {technique: T1059}, cwe: [CWE-74] }
applicability: [ 'asset.type == "serverless_function"' ]
preconditions: [ reachable ]
yields_on_success: [ rce_foothold ]
blast_tier: 1                      # read-only proof: OOB callback, no destructive command
cleanup: none
probe_steps:
  - { tool: custom.cloud_probe, intent: inject_event_payload, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=function)" }
severity_rubric: { base: critical }
# collaborator MUST be the in-sandbox listener; external would fail HC-KB-01 validation
```

```yaml
id: KB-CLOUD-NET-SG-001
title: Overly permissive security group exposes an internal service
taxonomy: { attack: {technique: T1021}, cwe: [CWE-284] }
applicability: [ 'asset.type == "network_service"', 'asset.intended_internal == true' ]
preconditions: [ reachable ]
yields_on_success: [ lateral_reach ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: nmap, intent: reachability_from_peer_segment, args: { service_marker: internal_canary } }
success_signal: { type: status_match, evaluator: deterministic,
                  assert: "a service marked internal-only is reachable from an in-scope peer segment" }
severity_rubric: { base: medium, raise_if: [ { when: "yields.cluster_read", to: high } ] }
false_positive_notes: [ "Reachability is tested only within declared scope; the scope guard still forbids anything out of scope (HC-SUB-01)." ]
```

## 5. Chaining in this set

- `KB-CLOUD-META-SSRF-001` consumes `internal_reach` from a web or agent SSRF (HC-KB-02 SSRF-001, HC-KB-03 AGENCY-SSRF-001) and yields `cloud_credential`, turning a reach primitive into cloud access.
- `KB-CLOUD-IAC-SECRET-001` and `KB-CLOUD-SECRETS-ENDPOINT-001` also yield `cloud_credential`, so three independent paths feed `KB-CLOUD-IAM-PRIVESC-001`, which yields `cloud_admin`.
- `KB-CLOUD-SERVERLESS-INJECT-001` yields `rce_foothold`, the precondition for `KB-CLOUD-CONTAINER-ESCAPE-001`, which yields `node_foothold`; `rce_foothold` is also produced by the web CMDI/SSTI cards, so the chain is cross-class.
- `KB-CLOUD-K8S-ANON-001` yields `cluster_read`, which raises the severity of `KB-CLOUD-NET-SG-001`.

## 6. Seed targets and fixtures

v1 stands up self-hosted cloud equivalents on the range (no internet): a mock instance-metadata endpoint serving a `metadata_role_canary`, a mock cloud control plane with an over-permissioned role and an `admin_canary` resource, an S3-style object store with a public `canary_object` and a writable bucket, a config server exposing a `secret_canary`, a privileged container with a host mount and a node-scoped canary, a Kubernetes-style API that lists a `canary_namespace` anonymously, a serverless function that calls `range-oob` on injected input, and an internal-only service tagged with `internal_canary`.
Each `does_not_fire` fixture applies the control: IMDSv2-style hop limits, least-privilege roles, private buckets, secret references instead of literals, an unprivileged container, authenticated orchestration, event validation, and a tight security group.
Probing uses `custom.cloud_probe` and `nmap`, both reviewed allowlist adapters (HC-AGENT-01 §5.3); the mock control plane and metadata endpoints live on the range and never egress.

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including ATT&CK and CWE resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01.
- The three tier-2 cards (IAM escalation, storage write, container escape) refuse to run without a live snapshot and restore cleanly.
- No card causes a scope or egress violation; the container escape never reaches the operator host (HC-SUB-01 §8.3) and the serverless OOB terminates only at `range-oob`, confirmed by the audit log.
- The chain in section 5 executes: an SSRF or leaked secret yields a cloud credential that escalates to cloud admin; a serverless foothold escapes to the node.
- Credential, secret, and canary-resource signals are evaluated deterministically by the harness.

## 8. Open questions

- Fidelity of the mock control plane: how closely to model a specific provider's IAM semantics versus a provider-neutral permission model, given the cards must stay portable.
- Whether container-escape testing needs a dedicated nested-container fixture distinct from the attacker VM, to keep G4 containment unambiguous.
- Mapping cloud findings to CVSS cleanly, since control-plane impact (cloud_admin) often exceeds what a single-host vector expresses.
- Whether to add a lightweight CIS-benchmark cross-reference to the taxonomy for config-hardening findings.

## 9. Backlog (deferred from this set)

- Cross-account trust and role-assumption chains (needs a multi-account mock).
- Supply-chain of deployment (CI/CD) overlaps the HC-KB supply-chain class; keep IaC-secret here and build the CI pipeline attacks there.
- Serverless cold-start and concurrency abuse for cost and availability (overlaps the resource-exhaustion class).
- Cloud logging/trail tampering and detection evasion, deferred as out of scope for an authorized-finding agent.
- Managed-database and queue exposure, sequenced with the data-isolation and rpc-messaging classes.
