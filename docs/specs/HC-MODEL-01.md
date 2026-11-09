---
tag: HC-MODEL-01
title: Bifrost topology - roles, keys, budgets, MCP boundary
status: draft
parent: SPEC.md#5.1
depends_on: [HC-AGENT-01, HC-SUB-01]
depended_on_by: [HC-AGENT-01, HC-MODEL-02, HC-ENRICH-01, HC-SAFE-01]
updated: 2026-11-08
---

# HC-MODEL-01 - Bifrost topology: roles, keys, budgets, MCP boundary

## 1. Purpose

This spec defines the model and governance plane: how the four roles map to Bifrost virtual keys, the budget and rate hierarchy, provider routing and the Verifier pinning, the semantic-cache policy, the MCP boundary, and how model-call observability feeds the audit log.

All generative LLM traffic goes through Bifrost; no role holds a provider key.
Bifrost governs model access, the harness governs what executes against the target, and those two responsibilities never merge.
The decision models (Laya) are not on this plane; they are a local sidecar (HC-MODEL-02) because their classify-not-chat I/O does not fit the chat-completions abstraction.

## 2. Placement (control plane, not the range)

- Bifrost runs on the trusted host alongside the orchestrator, as a control-plane component.
- It reaches LLM providers over normal outbound from the trusted host; that egress is the host's, not the range's.
- It is never reachable from the sandbox range, and model traffic never traverses the egress-denied data plane (HC-SUB-01 §6.1).
- This is why the sandbox can be fully egress-denied while the agent still thinks: the reasoning lives on the control plane, the exploitation lives on the data plane, and the two are separated.

```
  trusted host (control plane)
    orchestrator + roles  ->  Bifrost  ->  LLM providers (internet)
            |  control RPC
            v
  [ attacker VM ] --data plane, egress-denied--> [ target VMs ]   (no path to Bifrost or internet)
```

## 3. Deployment

- Self-hosted via Docker or Helm on the trusted host (or the embedded Go SDK), exposing the OpenAI-compatible `/v1/chat/completions`.
- Configuration is file-based (`config.json`) under version control, with provider secrets supplied by environment, never committed.
- Native Prometheus metrics, tracing, and request logging are enabled and wired to the audit log (section 8).

## 4. Virtual-key topology

One virtual key per role, each binding a provider set, a budget, a rate limit, a cache policy, and a fallback policy.

| vkey | Role | Providers | Budget | Cache | Fallback |
|------|------|-----------|--------|-------|----------|
| `vk-planner`  | Planner  | cheaper reasoning model | low | on | free |
| `vk-operator` | Operator | strong model, provider A | high | off | within A's set only |
| `vk-verifier` | Verifier | strong model, provider B | medium | off | none (pinned) |
| `vk-reporter` | Reporter | cheap model | low | on | free |
| `vk-enrich`   | Enrichment (HC-ENRICH-01) | cheap model + the Tavily MCP tool | low | on | free |

Provider-diversity invariant: `vk-operator.providers` and `vk-verifier.providers` are disjoint, asserted at startup, and a violation fails closed before any run.
This is finder-is-not-verifier enforced at the model plane, complementing the session-level rule in HC-AGENT-01 and the DB-level check in HC-DATA-01.

## 5. Budgets

- Budgets are hierarchical (Bifrost supports keys, teams, customers): the engagement is the parent budget and each role vkey is a child, so the engagement caps the sum.
- A budget breach fails closed: the vkey stops serving, the role stops, and the orchestrator either abandons the current pair or halts the run.
- A breach consistent with a runaway loop can trip the HC-SUB-01 watchdog and kill switch.
- Fall-through is structurally impossible: because roles hold no provider keys of their own, a breached budget has nothing to fall through to, which is the whole reason traffic is routed through Bifrost rather than straight to a provider.

## 6. Rate limiting

- Per-vkey request and token rate limits at Bifrost, protecting the model APIs and the budget.
- This is independent of the per-target network rate limit in `dispatch()` (HC-AGENT-01 §5.2), which protects the target.
- Two limiters for two resources: do not conflate the model-API rate with the target-network rate.

## 7. Semantic cache

- Enabled for `vk-planner` and `vk-reporter`, whose output is stable prose.
- Disabled for `vk-operator` and `vk-verifier`, so a cached response can never drive a live action or a verification.
- The cache is namespaced per engagement, so one target's context cannot leak into another engagement's planning or report.

## 8. The MCP boundary

Bifrost is also an MCP and agent gateway that can broker tools (filesystem, web search, database) to models, including "MCP Code Mode."
This is deliberately fenced off:

- Forbidden: pentest tool execution never flows through Bifrost's MCP brokering. The propose-and-dispose chokepoint (HC-AGENT-01 §5) is the only path to the sandbox, and scope, blast-tier, and rate validation live in the harness, not the gateway.
- Allowed: the read-only Tavily enrichment tool (HC-ENRICH-01), brokered only to `vk-enrich`, never to the Operator, and its output treated as untrusted data.
- Rationale: safety-critical validation stays in the harness and unbypassable, so a bug in the gateway's convenience layer cannot reach a target.

## 9. Observability into the audit log

- Every model call is logged with its vkey (hence role), provider and model, token counts, latency, cache hit or miss, and a timestamp.
- The orchestrator passes a correlation id (engagement, phase, pair, and the related probe_event where applicable) as request metadata, so a model turn ties back to the action it drove.
- These records are part of the append-only audit log specified in HC-SAFE-01.

## 10. Failure modes

| Condition | Response |
|-----------|----------|
| Provider outage for Planner/Reporter | Bifrost fallback serves from another provider transparently |
| Provider outage for Operator | Fallback within its own provider set only, never onto the Verifier's provider |
| Provider outage for Verifier | No fallback; the lead stays `needs_validation` rather than verify on a shared model |
| Provider-diversity invariant violated in config | Refuse to start |
| Budget breach on a vkey | Role stops, fail closed, possible watchdog/kill |
| Bifrost unreachable | Reasoning roles are down, so the run halts gracefully; this is a hard stop, distinct from the sandbox-down passive-only mode |

## 11. Config sketch

```json
{
  "virtual_keys": {
    "vk-operator": { "providers": ["providerA/strong-model"], "cache": false, "fallback": "within_set" },
    "vk-verifier": { "providers": ["providerB/strong-model"], "cache": false, "fallback": "none" },
    "vk-planner":  { "providers": ["providerA/mid-model"],    "cache": true },
    "vk-reporter": { "providers": ["providerA/cheap-model"],  "cache": true },
    "vk-enrich":   { "providers": ["providerA/cheap-model"],  "cache": true, "mcp_tools": ["tavily"] }
  },
  "budgets": {
    "engagement": { "limit": "<per-run cap>", "children": ["vk-operator","vk-verifier","vk-planner","vk-reporter","vk-enrich"] }
  }
}
```

Provider and model names are illustrative; the only hard constraint is that `vk-operator` and `vk-verifier` providers are disjoint.
Model selection per role is a bake-off (section 13).

## 12. Interfaces

```
model.call(role, messages, metadata) -> completion     # thin wrapper over Bifrost with the role's vkey
model.assert_provider_diversity()    -> ok | fail       # startup invariant (operator ∩ verifier = ∅)
```

Budget and rate enforcement are Bifrost's; the orchestrator observes stop signals and reacts per section 10.

The plane is implemented as pure-standard-library policy in `harness/modelplane.py` (`ModelPlane`, `VirtualKey`), with `call(role, messages, metadata)` and `assert_provider_diversity()` as in the sketch above.
The actual Bifrost HTTP client is infrastructure and is injected as a `transport` (the only holder of provider credentials), the same way tool adapters and the sandbox are injected into `dispatch()` and the loop, so a role names a role and never a provider or a key.
The plane enforces the §4 diversity invariant and the §8 MCP boundary at construction (fail closed before any run), routes through the role's vkey with the §10 fallback policy (free, within-set, or the Verifier's pin), applies the §5 hierarchical budget and the §6 per-vkey rate as fail-closed `PlaneStop` signals, serves the §7 per-engagement cache only for the prose roles, and writes a §9 audit row for every call and every stop through `harness/store/audit.py`.
`from_config` builds a plane from the §11 config shape and fails startup on a diversity or MCP violation.
The stub transport in `tests/test_modelplane.py` drives the §13 criteria in CI; the real Bifrost-backed role sessions that call this plane assemble prompts from `role_context` and emit the text `parse_request` reads (`harness/roles.py`).

The live transport behind the injected seam is `harness/bifrost.py:BifrostTransport`, a thin standard-library HTTP client to a running Bifrost gateway (the OpenAI chat-completions shape).
It is the only holder of credentials: the plane passes the role's virtual key name, and the client resolves it to the Bifrost secret and presents it as the bearer token, so no role holds a provider key.
The plane owns the provider route and its fallback order (so the Verifier's pin is enforced in the harness, not left to the gateway), and the client maps a provider outage (a 502/503/504 or an unreachable gateway) to `ProviderDown` for fallback, while a 4xx or a malformed body is a hard `BifrostError`.
`tests/test_bifrost.py` drives it against an in-process stdlib mock Bifrost so the wire contract stays CI-green and zero-dependency; what remains is pointing it at a real gateway with real virtual-key secrets.

The gateway itself is stood up with one command by `tools/modelplane.py`, so a self-hosting developer needs no cloud account and no hand-assembled config.
`up` generates the Bifrost config and a per-role virtual key, seeds a Docker-managed volume with the config over stdin and makes it group-0 writable so the gateway can write its stores, runs the container bound to localhost only, and waits for health; `keys` reads the provider keys with no echo, `env` prints the handles the runner reads, `status` reports health and whether keys are set, and `down`/`destroy` stop or wipe it.
The generated config encodes the §4 diversity invariant structurally (operator on DeepSeek, verifier on OpenAI, one provider per virtual key, the two disjoint) and carries only `env.VAR` references, never a literal secret, with the provider keys and virtual keys held in an `.env` outside the repo so no secret reaches a working tree.
`tools/run_engagement.py` builds the plane from those handles and runs the Operator and Verifier on their disjoint providers through it, falling back to deterministic stand-ins when no gateway is configured.
The config and virtual-key logic is unit-tested with no Docker present (`tests/test_modelplane_setup.py`); the Docker bring-up is proven on a real host, and the one step left to the operator is pasting their own provider API keys, which are read straight into the gateway's env and never committed, printed, or passed as process arguments.

## 13. Acceptance criteria

- No role possesses a provider key; every model call carries a role vkey.
- `vk-operator` and `vk-verifier` resolve to disjoint providers, and a config that violates this fails startup.
- A budget breach stops the role and cannot reach a provider directly.
- Operator and Verifier turns are never served from cache; Planner and Reporter may be, scoped to the engagement.
- No pentest tool call reaches the sandbox via Bifrost MCP; only Tavily is brokered, and only to `vk-enrich`.
- Every model call appears in the audit log correlated to its engagement and action.
- Bifrost on the trusted host is unreachable from the range (verified by an HC-SUB-01 escape-style probe).

## 14. Open questions

- Model and provider selection per role, pending a cost-versus-capability bake-off; the diversity constraint is the only fixed requirement.
- Whether the enrichment role needs an LLM at all or is mostly tool-plus-harness with minimal reasoning.
- Semantic-cache similarity threshold for Planner and Reporter.
- Team-level budgets if multiple engagements run concurrently on one host.
