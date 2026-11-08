---
tag: HC-SAFE-01
title: Safety and guardrails
status: draft
parent: SPEC.md#11
depends_on: [HC-SUB-01, HC-AGENT-01, HC-MODEL-01, HC-DATA-01, HC-ENRICH-01]
depended_on_by: []
updated: 2026-11-08
---

# HC-SAFE-01 - Safety and guardrails

## 1. Purpose

This is the capstone: the single place that names every guardrail, where it is enforced, how it fails, and how it is tested, plus the authoritative audit-log schema and the watchdog and kill-switch orchestration that HC-DATA-01 and HC-MODEL-01 defer here.

The governing principles, consolidated:

- Every guardrail is code in the harness, enforced at a layer the agent and target cannot reconfigure, and each has a test.
- Every guardrail fails closed: under any safety uncertainty the system stops, denies, or drops to passive-only, never proceeds.
- Defense in depth: each core guarantee is enforced at more than one independent layer, so no single bug defeats it.

## 2. Guardrail inventory

The single pane of safety; each row cites the spec that owns the mechanism.

| Guardrail | Enforced where | Trigger | Response (fail-closed) | Test |
|-----------|----------------|---------|------------------------|------|
| Scope guard | HC-SUB-01 §5 (gateway) + HC-AGENT-01 §5.2 (pre-check) | Out-of-scope target/port | Drop at gateway; deny at dispatch | Guard proof (HC-SUB-01 §8.1) |
| Egress-denied topology | HC-SUB-01 §5.2 | Any egress from the range | No route exists | Guard proof + escape test |
| Blast-tier gate | HC-SUB-01 §7 | tier > cap, or no snapshot for tier >= 2 | Deny the action | Blast-gate unit + snapshot test |
| Target rate limit | HC-AGENT-01 §5.2 | RPS over cap per target | Deny/queue; may trip watchdog | Rate-limit test |
| Model budget + rate | HC-MODEL-01 §5-6 | vkey budget or rate breach | Stop the role; no fall-through | Budget-breach test |
| Provider diversity | HC-MODEL-01 §4 | operator ∩ verifier providers != empty | Refuse to start | Startup invariant test |
| No raw shell | HC-AGENT-01 §5 | Any non-structured action | Only validated tool calls execute | Dispatch contract test |
| Finder != verifier | HC-AGENT-01 (session) + HC-MODEL-01 (provider) + HC-DATA-01 (DB check) | found_by == verified_by | Reject at three layers | Finding-integrity test |
| Evidence immutability | HC-DATA-01 §9 | UPDATE/DELETE on probe_event/label | Trigger rejects | Append-only test |
| Untrusted-data handling | HC-AGENT-01 §7 + HC-ENRICH-01 §4 | Target/web content as instruction | Delimited data only; still gated | Injection test (HC-AGENT-01 §11) |
| Kill switch | HC-SUB-01 §6.4 | Operator/watchdog/out-of-band | Freeze segment, snapshot-freeze, restore | Kill-switch drill (HC-SUB-01 §8.4) |
| Window enforcement | HC-SUB-01 §4.2 | Run reaches window end | Abort in-flight, restore, finalize | Window test |
| Passive-only fallback | HC-SUB-01 §9 | Sandbox/guard not proven | No active calls; leads stay needs_validation | Sandbox-down test |

## 3. The audit log

Authoritative here, append-only and tamper-evident, inside the trust boundary.

```sql
create table audit_log (
  seq            bigserial primary key,
  ts             timestamptz not null,           -- stored UTC/ISO; rendered am/pm for humans
  engagement_id  text not null,
  actor          text not null,                  -- role/session | harness | watchdog
  category       text not null,                  -- tool_request|guard_decision|model_call|snapshot|
                                                  -- kill|budget|scope|window|enrich|...
  decision       text,                           -- allow|deny|exec|stop
  reason         text,
  correlation_id text,                            -- ties to pair / probe_event / model call
  detail         jsonb not null default '{}',
  prev_hash      text not null,                   -- hash of the previous row
  row_hash       text not null                    -- hash of this row incl. prev_hash
);
-- append-only trigger rejects UPDATE/DELETE
```

- Every guard decision, tool request and execution, model call (vkey, model, tokens, from HC-MODEL-01 §9), snapshot and restore, kill, budget and rate event, scope decision, window event, and enrichment call is recorded.
- `prev_hash`/`row_hash` form a hash chain, so the log is tamper-evident, not merely immutable; `audit.verify_chain()` detects any altered or removed row.
- Correlation ids tie a model call to the action it drove and to the probe_event it produced, so a run is reconstructable end to end.
- Human-rendered audit and report timestamps display in am/pm per house style; storage stays ISO/UTC.

## 4. The watchdog

- A harness component that monitors invariants live: budget and rate breaches, repeated denials, anomalous action counts, guard health, and the engagement window.
- On a breach consistent with a runaway loop or a compromise, it triggers the kill switch (HC-SUB-01 G5) and a snapshot-freeze for forensics.
- Thresholds are configurable and the watchdog itself fails closed: if it cannot confirm invariants hold, it stops the run.

## 5. Fail-closed, enumerated

What "closed" means per guardrail, so the default under uncertainty is never "proceed":

- Scope or egress uncertain: drop to passive-only, no active calls.
- Blast gate uncertain or snapshot missing: deny the action.
- Budget or rate breached: stop the role; nothing to fall through to.
- Provider diversity unmet: refuse to start.
- Sandbox or guard unproven: passive-only, leads stay needs_validation.
- Watchdog cannot verify invariants: kill and restore.

## 6. Defense in depth

The same guarantee is held at independent layers, so no single failure defeats it:

- Scope: a no-route gateway topology, a dispatch pre-check, and the guard-proof self-test.
- finder != verifier: separate sessions, disjoint providers, and a database check constraint.
- Egress: no route from the range, plus the guard proof that actively tries and fails to reach out.
- Evidence integrity: append-only triggers, per-event content hashes, and the hash-chained audit log.

## 7. Operator-facing failures

The operator is not served raw internal detail when a run aborts.

- Every operator-facing failure states what happened, why, and what to do next, and renders the recovery path as an affordance rather than prose.
- Examples: a budget abort offers resume-from-ledger or raise-the-budget; a window abort offers extend-and-resume; a scope-validation abort names the offending target and offers to correct the contract; a sandbox-down run says so plainly and points at the passive-only report.
- Raw exceptions, transport strings, and provider wording are logged server-side where the operator can act on them, never surfaced as the message.
- This applies the house standard for user-facing errors to the operator surface: name the specific expected failures and write real copy for each, and give whatever remains a plain sentence, never a stack trace.

## 8. Testing

- Every row in the section-2 inventory has a passing test, and those tests run in the HC-EVAL-01 safety regression suite.
- The scope-violation gate (HC-EVAL-01 §7) fails the build on any out-of-scope or egress event, which is the CI expression of the scope and egress guardrails.
- A simulated runaway (rapid denials or a budget spike) must trip the watchdog and the kill switch within the time budget.

## 9. Interfaces

```
audit.record(event)              # called by every guardrail and by model/tool paths
audit.verify_chain(engagement)   -> ok | tamper(seq)
watchdog.check()                 # periodic; may invoke sandbox.kill()
safety.fail_closed(context)      # the single helper every guard calls on uncertainty
```

The tamper-evident audit log (`audit.record`, `audit.verify_chain`) is implemented in `harness/store/audit.py` over the append-only `audit_log` table (HC-DATA-01): each row carries `prev_hash` and a `row_hash` over its content plus `prev_hash`, so an altered or removed row is detected even though the triggers already forbid UPDATE/DELETE.
Adversarial tests in `tests/test_store.py` cover both the clean-chain and tampered cases.
The watchdog, the kill switch, and the guard inventory remain to be built.

## 10. Acceptance criteria

- Every guardrail in the inventory has a passing test, and the safety suite runs in CI.
- The audit log is append-only and its hash chain verifies; an altered or deleted row is detected.
- A simulated runaway trips the watchdog and kill switch within the time budget.
- On any guard failure the system fails closed as enumerated in section 5.
- Operator-facing abort messages state what, why, and next, with a recovery affordance and no raw internal detail.
- Human-rendered audit and report timestamps display in am/pm.

## 11. Open questions

- Watchdog threshold tuning: false-positive kills versus missed runaways.
- Whether to externally anchor the audit-log hash chain (periodic notarization) for stronger tamper evidence.
- Secrets handling for provider and Tavily keys (vaulting, rotation); an ops concern to spec separately if it grows.
- Audit-log export format for a SIEM, if the system ever reports outside its own boundary.
