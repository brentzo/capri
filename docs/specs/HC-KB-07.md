---
tag: HC-KB-07
title: RPC and messaging technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-08
---

# HC-KB-07 - RPC and messaging technique-card starter set

## 1. Purpose

Ten cards for the `rpc-messaging` class, authored against the HC-KB-01 schema.
It covers the non-browser request surface: serialization, RPC method authorization, object binding, webhooks, and message queues.
It also lands three weaknesses HC-KB-02 deferred because they are serialization- and RPC-shaped rather than classic web injection: XXE, GraphQL abuse, and mass assignment.

Each card ships as its own YAML file under `kb/rpc-messaging/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Determinism for an RPC and messaging target

- Code execution and server-side fetch are proven by an out-of-band callback to `range-oob` (deserialization gadget, webhook SSRF, poison queue message), a deterministic `oob_callback`.
- File and schema disclosure are proven by a planted canary (a canary file via XXE, a cross-tenant canary field via GraphQL), a deterministic `content_match`.
- Authorization and binding weaknesses are proven by a deterministic `status_match`, `differential`, or `state_change`: a privileged method answers a low-privilege caller, a type-juggled comparison is accepted, or a forbidden field is set and reads back as a canary marker.
- Every card that changes state (mass assignment, webhook-forged action, queue publish consumed downstream) is tier 2 and snapshots first.

## 3. Coverage map

| Card | Family | CWE | OWASP / ATT&CK | Tier | Signal | Yields |
|------|--------|-----|----------------|------|--------|--------|
| KB-RPC-SERIAL-DESER-001 | Serialization | CWE-502 | T1190 | 1 | oob_callback | rce_foothold |
| KB-RPC-SERIAL-XXE-001 | Serialization | CWE-611 | WSTG-INPV-07 | 1 | content_match | file_read |
| KB-RPC-SERIAL-TYPE-001 | Serialization | CWE-843 | WSTG-INPV-??  # verify | 1 | differential | authn_bypass |
| KB-RPC-METHOD-AUTHZ-001 | Method authz | CWE-862 | API5:2023 (BFLA) | 1 | status_match | priv_function_access |
| KB-RPC-GRAPHQL-ABUSE-001 | Method authz | CWE-639 | API3:2023 # verify | 1 | content_match | cross_object_read |
| KB-RPC-BIND-MASSASSIGN-001 | Object binding | CWE-915 | API6:2023 # verify | 2 | state_change | privilege_escalation |
| KB-RPC-WEBHOOK-SSRF-001 | Webhook | CWE-918 | T1190 # verify | 1 | oob_callback | internal_reach |
| KB-RPC-WEBHOOK-FORGERY-001 | Webhook | CWE-345 | T1190 # verify | 2 | state_change | forged_event |
| KB-RPC-QUEUE-INJECT-001 | Messaging | CWE-74 | T1190 # verify | 2 | oob_callback | queue_inject |
| KB-RPC-QUEUE-ANON-001 | Messaging | CWE-306 | T1190 # verify | 1 | content_match | data_exposure |

Tier distribution: seven tier-1 (read-only probing) and three tier-2 (state-changing, snapshot required): mass assignment, webhook-forged action, and queue injection.

## 4. Cards

### 4.1 Serialization family

```yaml
id: KB-RPC-SERIAL-DESER-001
title: Insecure deserialization reaches code execution
taxonomy: { attack: {technique: T1190}, cwe: [CWE-502] }
applicability: [ 'asset.type == "rpc_endpoint"', 'asset.deserializes_input == true' ]
preconditions: [ reachable, deserializes_input ]
yields_on_success: [ rce_foothold ]
blast_tier: 1                      # read-only proof: a gadget triggers an OOB callback
cleanup: none
probe_steps:
  - { tool: custom.rpc_probe, intent: send_deser_gadget, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=target)" }
severity_rubric: { base: critical }
# collaborator MUST be the in-sandbox listener; external would fail HC-KB-01 validation
```

```yaml
id: KB-RPC-SERIAL-XXE-001
title: XML external entity injection
taxonomy: { owasp: [WSTG-INPV-07], cwe: [CWE-611] }
applicability: [ 'asset.type == "rpc_endpoint"', 'asset.parses_xml == true' ]
preconditions: [ reachable, rpc_endpoint ]
yields_on_success: [ file_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.rpc_probe, intent: xxe_file_entity, args: { target: range_canary_file } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "response_contains(range_canary_marker)" }
severity_rubric: { base: high, raise_if: [ { when: "yields.internal_reach", to: critical } ] }
```

```yaml
id: KB-RPC-SERIAL-TYPE-001
title: Type confusion or type juggling bypasses a check
taxonomy: { cwe: [CWE-843] }
applicability: [ 'asset.type == "rpc_endpoint"' ]
preconditions: [ reachable, rpc_endpoint ]
yields_on_success: [ authn_bypass ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.rpc_probe, intent: send_type_juggled_payload }   # e.g., array/bool where a string is compared
success_signal: { type: differential, evaluator: deterministic,
                  assert: "a type-coerced value is accepted where the typed value is rejected" }
severity_rubric: { base: high }
```

### 4.2 Method authorization family

```yaml
id: KB-RPC-METHOD-AUTHZ-001
title: Missing authorization on an RPC method
taxonomy: { owasp: [API5:2023], cwe: [CWE-862] }
applicability: [ 'asset.type == "rpc_endpoint"', 'exists(asset.privileged_methods)' ]
preconditions: [ reachable, authenticated_session ]     # low-privilege caller
yields_on_success: [ priv_function_access ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.rpc_probe, intent: low_priv_calls_privileged_method }
success_signal: { type: status_match, evaluator: deterministic,
                  assert: "a privileged method returns a success status for a low-privilege session" }
severity_rubric: { base: high }
```

```yaml
id: KB-RPC-GRAPHQL-ABUSE-001
title: GraphQL introspection and broken field authorization
taxonomy: { owasp: [API3:2023], cwe: [CWE-639, CWE-200] }
applicability: [ 'asset.type == "graphql_endpoint"' ]
preconditions: [ reachable, authenticated_session ]
yields_on_success: [ cross_object_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.graphql_probe, intent: introspect_schema }
  - { tool: custom.graphql_probe, intent: query_foreign_tenant_field, args: { canary: tenant_b_canary } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "introspection is enabled AND a field returns tenant_b_canary to tenant A" }
severity_rubric: { base: high }
false_positive_notes: [ "Introspection alone is a hardening note; it becomes a finding only when a field returns data across an authorization boundary." ]
```

### 4.3 Object binding family

```yaml
id: KB-RPC-BIND-MASSASSIGN-001
title: Mass assignment sets a protected field
taxonomy: { owasp: [API6:2023], cwe: [CWE-915] }
applicability: [ 'asset.type == "rpc_endpoint"', 'asset.binds_object == true' ]
preconditions: [ reachable, authenticated_session ]
yields_on_success: [ privilege_escalation ]
blast_tier: 2                      # sets a protected attribute (state change)
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.rpc_probe, intent: overpost_protected_field, args: { field: role, value: admin_canary } }
  - { tool: custom.rpc_probe, intent: confirm_field_applied }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "a protected field is set to admin_canary and persists" }
severity_rubric: { base: critical }
```

### 4.4 Webhook family

```yaml
id: KB-RPC-WEBHOOK-SSRF-001
title: Webhook callback URL drives server-side request forgery
taxonomy: { attack: {technique: T1190}, cwe: [CWE-918] }
applicability: [ 'asset.type == "rpc_endpoint"', 'asset.accepts_callback_url == true' ]
preconditions: [ reachable, rpc_endpoint ]
yields_on_success: [ internal_reach ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.rpc_probe, intent: register_callback, args: { url: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=target)" }
severity_rubric: { base: high, raise_if: [ { when: "yields.cloud_credential", to: critical } ] }
```

```yaml
id: KB-RPC-WEBHOOK-FORGERY-001
title: Webhook receiver accepts unsigned or forged events
taxonomy: { attack: {technique: T1190}, cwe: [CWE-345] }
applicability: [ 'asset.type == "rpc_endpoint"', 'asset.is_webhook_receiver == true' ]
preconditions: [ reachable ]
yields_on_success: [ forged_event ]
blast_tier: 2                      # a forged event drives a state change
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.rpc_probe, intent: deliver_forged_event, args: { marker: forged_canary } }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "an event with no valid signature is processed and produces forged_canary state" }
severity_rubric: { base: high }
```

### 4.5 Messaging family

```yaml
id: KB-RPC-QUEUE-INJECT-001
title: Message queue accepts a poison message
taxonomy: { attack: {technique: T1190}, cwe: [CWE-74] }
applicability: [ 'asset.type == "message_queue"' ]
preconditions: [ reachable, has_message_queue ]
yields_on_success: [ queue_inject ]
blast_tier: 2                      # publishes a message a consumer will process
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.rpc_probe, intent: publish_poison_message, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=consumer)" }
severity_rubric: { base: high }
```

```yaml
id: KB-RPC-QUEUE-ANON-001
title: Unauthenticated queue subscription exposes messages
taxonomy: { attack: {technique: T1190}, cwe: [CWE-306, CWE-200] }
applicability: [ 'asset.type == "message_queue"' ]
preconditions: [ reachable, has_message_queue ]
yields_on_success: [ data_exposure ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.rpc_probe, intent: anonymous_subscribe, args: { topic: canary_topic } }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "an unauthenticated subscriber receives canary_topic messages" }
severity_rubric: { base: high }
```

## 5. Chaining in this set

- `KB-RPC-SERIAL-TYPE-001` yields `authn_bypass`, which an authenticated login turns into `authenticated_session`, unlocking the method-authz, GraphQL, and mass-assignment cards the way the HC-KB-02 auth chain does.
- `KB-RPC-SERIAL-DESER-001` and `KB-RPC-QUEUE-INJECT-001` reach `rce_foothold`-class execution, feeding the HC-KB-05 container-escape chain.
- `KB-RPC-WEBHOOK-SSRF-001` yields `internal_reach`, the precondition for the HC-KB-05 metadata-SSRF card, and raises to critical when it reaches cloud credentials.
- `KB-RPC-BIND-MASSASSIGN-001` yields `privilege_escalation`, consumed by later cloud and data-isolation cards.

## 6. Seed targets and fixtures

v1 stands up self-hosted RPC and messaging targets on the range (no internet): a deserializing RPC endpoint, an XML parser with external entities enabled and a seeded `range_canary_file`, a type-juggling auth check, a gRPC-style service with an unguarded privileged method, a GraphQL endpoint with introspection on and a cross-tenant `tenant_b_canary` field, an object-binding endpoint that over-posts a `role` field, a webhook sender that fetches arbitrary callback URLs, a webhook receiver that skips signature checks, and a message broker allowing anonymous publish and subscribe with a `canary_topic`.
Each `does_not_fire` fixture applies the control: safe deserialization, XXE-hardened parsing, strict typing, per-method authorization, field-level authorization, binding allowlists, callback-URL allowlists, signed webhooks, and authenticated queues.
Deserialization, webhook, and queue proofs terminate at `range-oob`; probing uses `custom.rpc_probe` and `custom.graphql_probe`, reviewed allowlist adapters (HC-AGENT-01 §5.3).

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including taxonomy resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01.
- The three tier-2 cards refuse to run without a live snapshot and restore cleanly.
- No card causes a scope or egress violation; every deserialization, webhook, and queue proof terminates only at `range-oob`, confirmed by the audit log.
- The chain in section 5 executes: a type-juggling bypass yields a session that unlocks mass assignment; a webhook SSRF reaches the cloud metadata card.
- OOB, canary, and authorization signals are evaluated deterministically by the harness.

## 8. Open questions

- Protocol breadth: how many concrete RPC framings (gRPC, JSON-RPC, SOAP, Thrift) to model before the probe adapter becomes a maintenance burden; leaning on a small set with a generic request shape.
- Whether GraphQL deserves its own class as API-specific surfaces grow, or stays a family here.
- Deserialization gadget libraries: keep per-language gadgets inline or factor a shared, version-pinned gadget set (parallels the HC-KB-01 payload-library open question).
- Queue-consumer timing: how long to wait for the downstream consumer to process a poison message before a verdict is inconclusive.

## 9. Backlog (deferred from this set)

- HTTP request smuggling (CL.TE / TE.CL), still owned by the HC-KB-02 web-protocol backlog, sequenced after this set since smuggling and queue/webhook timing interact.
- gRPC server reflection enumeration as a dedicated card once the method-authz fixture is stable.
- Protobuf and Avro schema-evolution confusion.
- SOAP action spoofing and WS-Security misuse.
- Event-sourcing and saga-replay abuse in message-driven systems.
