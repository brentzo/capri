---
tag: HC-OBJ-01
title: Objective-driven engagements, attack-path chaining, and lateral movement
status: draft
parent: SPEC.md#4, SPEC.md#6
depends_on: [HC-SUB-01, HC-AGENT-01, HC-KB-01, HC-FIND-01, HC-DATA-01]
depended_on_by: [HC-EVAL-01]
updated: 2026-11-09
---

# HC-OBJ-01 - Objective-driven engagements, attack-path chaining, and lateral movement

## 1. Purpose

This spec defines how a run pursues an assigned objective rather than only enumerating coverage.
It adds three things that the current system specifies in part but does not yet realize: an objective the harness can evaluate, a live blackboard that lets cards chain, and a report that states whether the objective was met and by what path.
It also resolves the HC-SUB-01 open thread on lateral movement, because "movement between lab machines" is exactly a chain whose intermediate fact is a foothold on a second in-scope host.

The governing rule is unchanged and constrains every decision below: the harness owns truth, the model only proposes.
An objective is achieved only when deterministic harness code says so, never when a role claims it.

## 2. The gap this closes

The system today is coverage-driven.
`Loop.run` (HC-AGENT-01 §4) computes the candidate `(asset, technique)` set once from static recon facts, hunts every pair, verifies the leads, and reports findings plus a coverage summary.
Three things are missing for objective completion.

- There is no objective.
  The engagement contract (HC-SUB-01 §4) has `engagement`, `scope`, and `policy`, but no goal, so there is nothing to work toward, detect, or report against.
- Chaining is specified but inert.
  HC-KB-01 §6 defines `preconditions` and `yields_on_success` over a shared blackboard, yet the loop evaluates applicability once against frozen recon facts and never writes a yield back.
  A card whose precondition is only satisfiable by another card's yield is therefore always `not_applicable`, so a multi-step objective cannot be reached even in principle.
- Lateral movement is undecided.
  HC-SUB-01 §13 leaves multi-host movement open; the scope guard already carries multi-host CIDRs, but no capability-level notion of a foothold on one in-scope host unlocking work against another exists.

This spec supplies the objective, makes the blackboard live, and gates movement, while preserving every substrate and finder-is-not-verifier guarantee.

## 3. Design principles

- Objective success is harness-evaluated and deterministic.
  The success test is a predicate over confirmed blackboard facts plus a deterministic proof (a planted-canary hash match or an in-sandbox out-of-band marker), evaluated in code, mirroring the deterministic-first success-signal rule of HC-KB-01 §5.
  A role never asserts completion.
- Only confirmed facts escalate.
  A yield written by a lead is `provisional` and may guide exploration, but a fact that unlocks a higher-impact or lateral card, and every fact the objective predicate reads, must be `confirmed` by the independent Verifier.
  This carries finder-is-not-verifier into every hop of a chain, not just the final finding.
- A foothold unlocks techniques, never targets.
  Reaching a host never widens scope.
  Every target in a chain is already in `in_scope_cidrs` and pinned; a foothold only makes new techniques against already-in-scope hosts applicable, and the HC-SUB-01 gateway still default-denies everything else.
- Objective-pursuit is additive and optional.
  An engagement with no objective runs exactly as today (pure coverage), so this change is backward compatible with every existing contract, card, and test.

## 4. The objective (engagement-contract extension)

### 4.1 Schema

An optional top-level `objective` block in the HC-SUB-01 engagement contract.
The organizer may supply it as a separate file merged into the contract at load time; validation treats the merged document as one contract.

```yaml
objective:
  id:          obj-flag-on-db
  description: "Read the planted secret at /flag.txt on the database host."
  type:        canary                       # capability | canary | reach
  target:      db.sandbox.local             # must be an in_scope_host (pinned)
  success:     "exists(flag.captured) && flag.host == 'db.sandbox.local'"   # §4 DSL over confirmed facts
  proof:                                     # deterministic completion evidence
    kind:      canary                        # canary | oob_marker
    location:  "/flag.txt"
    sha256:    "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  on_success:  stop                          # stop | continue-for-coverage
```

### 4.2 Objective types

| Type | Meaning | Deterministic proof |
|------|---------|---------------------|
| `capability` | A named capability is held on a target, e.g. `rce_foothold`, `db_read` | The confirmed fact exists on the blackboard, backed by the card's own in-sandbox success signal (oob callback or canary) |
| `canary` | A planted secret at a known location is retrieved | The retrieved content's SHA-256 equals the pre-registered `proof.sha256`; the harness compares hashes, never the plaintext, and the contract never carries the plaintext |
| `reach` | A foothold or session is established on a specific in-scope host reachable only via a chain | An in-sandbox oob marker fired for that host (HC-KB-01 §5, in-range collaborator only) is received |

### 4.3 Success predicate and proof

`success` is a predicate in the HC-KB-01 §4 DSL, evaluated by `harness/predicates.py` over the confirmed-tier view of the blackboard (§5), so completion reuses the same audited expression language as applicability.
`proof` binds completion to a deterministic artifact: a canary hash the harness computes and compares, or an in-sandbox marker the harness observes.
The predicate and the proof must both hold; the predicate expresses what state is required, the proof makes that state impossible to fake from model output.

### 4.4 Validation rules (fail-closed, extends HC-SUB-01 §4.2)

- `objective.target` must be an `in_scope_host` and resolve under pinning (§4.3 of HC-SUB-01); an objective naming an out-of-scope or unpinned host aborts the run before provisioning.
- `proof.kind: oob_marker` must terminate at an in-sandbox collaborator, never an external host, exactly as HC-KB-01 §5 requires of `oob_callback`.
- `success` must parse under the §4 DSL and reference only declared fact names; an unparseable or free-variable predicate aborts.
- `type: reach` requires `policy.lateral_movement: true` (§8); otherwise the contract is rejected as internally contradictory.
- A `canary` objective carries a hash, never the secret; a contract that inlines the plaintext is rejected.

### 4.5 Status

The objective block and `policy.lateral_movement` are implemented in `harness/substrate/contract.py`.
`parse` reads them onto the `Engagement` (`objective`, `lateral_movement`), and `validate` enforces the §4.4 rules fail-closed, so a bad objective aborts before provisioning and a contract with no objective is unchanged (acceptance §11 first criterion).
`objective.target` is checked against the declared in-scope hosts and in-scope CIDRs, so an out-of-scope or undeclared target is rejected; `success` is parse-checked against the HC-KB-01 §4 predicate DSL (`harness/predicates.py`); a `reach` objective requires `policy.lateral_movement: true`; and a `canary` proof must carry a 64-hex `sha256` and no inlined plaintext.
The runtime half of §4.4 (host pinning, and an `oob_marker` terminating at the in-sandbox collaborator) is enforced at provisioning by the existing scope guard and the sandbox, and cross-referencing `success` fact names against the live KB happens at threat-model load.
The blackboard (§5), the capability-frontier loop (§6), the planner delta (§7), and the report delta (§9) remain to be built against this.
Covered by the objective cases in `tests/test_substrate.py`.

## 5. The blackboard (world-state realization)

The blackboard makes HC-KB-01 §6 real: the run-local, append-only store of facts that cards read as preconditions and write as yields.

### 5.1 Fact shape and trust tier

```json
{
  "name": "credential",                  // the fact name a card yields / requires
  "scope": { "host": "app.sandbox.local" },
  "tier": "confirmed",                   // provisional | confirmed
  "produced_by": "F-3a91c2e40b17",       // the finding that yielded it
  "event_ids": ["pe-...", "pe-..."],     // provenance into HC-DATA-01
  "at": "2026-11-09T20:14:03Z"
}
```

- `provisional` is written when a lead is emitted; it may inform planning and the Operator's exploration.
- `confirmed` is written only when the Verifier confirms the producing finding, and only `confirmed` facts satisfy a precondition that gates escalation or lateral movement, or are read by the objective predicate.

### 5.2 Ownership and integrity

- The blackboard is append-only and provenance-tagged, consistent with the HC-DATA-01 evidence posture; a fact is never mutated, only superseded by a higher-tier fact of the same name and scope.
- Only the harness writes facts, at lead emission (provisional) and at confirmation (confirmed); a role never writes a fact, it only produces the probe evidence from which the harness derives one.
- Facts are keyed by `(name, scope)` so a confirmed fact supersedes its provisional predecessor without losing the audit trail.

### 5.3 Yield-and-re-evaluate

On confirmation of a finding, the harness writes the card's `yields_on_success` facts at `confirmed` tier, then re-evaluates applicability and preconditions for the whole candidate set against the updated blackboard, which may open new candidates (§6).

### 5.4 Status

The blackboard is implemented in `harness/blackboard.py` (`Blackboard`, `Fact`).
`put` writes a fact and `put_many` writes a card's yields; both append to an immutable log and update a current view only when the new fact does not downgrade a higher-tier predecessor, so a `confirmed` fact supersedes its `provisional` predecessor of the same `(name, scope)` while the superseded fact stays in the log for the attack-path trace (§9).
`view(context, tier)` returns the flat `{name: value}` the HC-KB-01 §4 predicate evaluator consumes: `tier=confirmed` is the gating view that only confirmed facts enter (§3), and a fact's scope must be satisfied by the query context, so a host-scoped fact is visible only against that host.
`is_confirmed` and `producer` support the §6 escalation gate and the §9 trace.
This slice is the store itself; seeding it from recon, writing yields at lead emission and confirmation, and re-evaluating applicability over it are the capability-frontier loop (§6), and durable resume replays the confirmed findings rather than persisting the board.
Covered by `tests/test_blackboard.py`.

## 6. The capability-frontier loop (revision to HC-AGENT-01 §4)

Chaining requires that a confirmed fact be available before the next card is planned, so the batch shape of HC-AGENT-01 §4 (hunt all, then verify all) is revised to interleave verification into the hunt.
This is the §12 "re-plan after each phase" direction made concrete.

### 6.1 Loop shape

```
run(engagement):
    passive = not sandbox.proofs_pass()           # HC-SUB-01 §8; passive => no confirm, no escalation
    board   = Blackboard(seed = recon_facts)
    while True:
        candidates = phase_threat_model(target_model, kb, board)   # applicability over live board
        plan       = planner.plan(target_model, candidates, board, objective)  # §7
        pair       = next_pending(plan)
        if pair is None: break                     # frontier exhausted
        lead = hunt(pair, board)                   # §4.1 Operator inner loop, unchanged
        if lead:
            board.put(lead.yields, tier=provisional)
            verdict = verify(lead)                 # §4.2 Verifier, immediately, on a disjoint session
            if verdict == confirmed:
                board.put(lead.yields, tier=confirmed)
                if objective and objective_met(objective, board):   # §4.3, deterministic
                    record_objective(achieved, attack_path(board, objective))
                    if objective.on_success == stop: break
        if window_elapsed() or budget_exhausted(): break
    if objective and not achieved:
        record_objective(not_achieved, reached_facts(board, objective))
    report = reporter.render(...)                  # §9
```

### 6.2 Why interleave

Interleaving is what keeps escalation honest.
Because a yield is written at `confirmed` tier only after the independent Verifier reproduces it, a card that unlocks a higher-impact or lateral step is gated on a verified fact, so finder-is-not-verifier holds at every hop, not only at the leaf finding.
The cost is more snapshot churn (a verify runs mid-hunt rather than in a final batch), which is acceptable and arguably more correct because the state is still fresh; the batch-verify alternative is rejected because it cannot chain within a run without letting unverified yields drive escalation.

### 6.3 Termination

The loop ends on the first of: the objective predicate holding on confirmed facts with `on_success: stop`, the candidate frontier exhausting (no pending pair opens new facts), or the HC-SUB-01 window or the action budget ending.
With no objective, termination is frontier exhaustion, which reproduces today's coverage run.
In passive-only mode nothing is confirmed, so no fact reaches `confirmed`, no chain escalates, and an objective is reported `not_achieved` with its provisional progress, consistent with HC-SUB-01 §9.

### 6.4 Status

The capability-frontier loop is implemented in `harness/loop.py`.
`run` branches on the objective: with none it runs `_run_coverage`, the unchanged HC-AGENT-01 §4 batch run, so every existing contract and test behaves exactly as before (§3); with an objective it runs `_run_objective`, the frontier loop.
The frontier loop seeds a `Blackboard` (§5) from recon as confirmed ground truth, then repeatedly computes the pending set (`_frontier_pending`: cards whose applicability and preconditions both hold over the confirmed board at the asset's host, and that the ledger has not processed), hunts the Planner's first pick, writes its yields provisional, verifies it at once on a disjoint session, and on confirmation writes its yields confirmed, so only a verified fact can open the next card.
A provisional yield never gates, which carries finder-is-not-verifier into every hop; in passive-only no fact is confirmed, so nothing chains.
This slice drives the chain and terminates on frontier exhaustion or a step cap; objective completion (the §4.3 success predicate plus the deterministic proof), the `achieved`/`not_achieved` outcome, the `attack_path`, and objective-met termination are the following slice, as is the §8 lateral gate.
Covered by `tests/test_frontier.py` (a confirmed yield opens the next card, a provisional one does not, passive chains nothing, and the same cards with no objective take the coverage path).

## 7. Objective-aware planning (delta to the Planner)

The Planner (HC-AGENT-01 §3) gains the objective and the live blackboard and keeps its deterministic, reproducible contract.

### 7.1 Goal relevance

Relevance is a bounded, static backward reachability over declared card edges, computed once from the KB: starting from the facts the objective requires, walk `precondition <- yields_on_success` edges to the set of facts that can transitively contribute to the objective.
A card is objective-advancing when any of its `yields_on_success` is in that set.
This stays within the HC-KB-01 §6 rule of "declared yields and preconditions only, no automatic deep attack-path search": it is a precomputed relevance set over declared edges, not a live search, and it is fully auditable.

### 7.2 Priority

The ordering becomes: objective-advancing first, then the existing most-severe-first, then lowest-blast-tier-first, then the stable `(technique, asset)` tiebreak, so a plan stays byte-for-byte reproducible.
With no objective the first key is constant and the ordering is exactly today's.
The reasoning-model Planner may later replace the static relevance set with richer path reasoning behind the same `plan(...)` seam, with the deterministic planner remaining the fallback.

## 8. Lateral movement (resolves HC-SUB-01 §13)

Lateral movement is a chain whose intermediate confirmed fact is a foothold, credential, or session scoped to a second in-scope host.

### 8.1 Permission

`policy.lateral_movement: true | false`, default `false`.
When false, a card whose applicability or precondition references a foothold-scoped fact on a different host than the pair's asset is marked `blocked_by_policy` with sub-reason `blocked_lateral`, surfaced in the coverage summary so a negative result stays meaningful.

### 8.2 The no-scope-widening invariant

A foothold never expands scope.
The pivot host must already be in `in_scope_cidrs` and pinned, every probe still passes `scope.validate` and `blast.gate`, and the gateway still default-denies, so a confirmed foothold changes only which techniques are applicable, never which targets are reachable.
This is the sentence that answers a judge: movement between machines is authorized in advance by the scope file, and the foothold only decides when a permitted technique becomes relevant.

### 8.3 Foothold as capability, not shell

A foothold is modeled as a capability fact (a credential, token, or network-position the attacker VM may now use), not as the agent obtaining a shell on the target.
Subsequent probes are still issued by the attacker VM's allow-listed adapters, now authorized by the acquired credential or aimed at a host recon places behind the first, which preserves containment (HC-SUB-01 G4): no role ever holds a shell on a compromised host.
Executing tooling from inside a compromised host (a true on-host pivot) is a separately gated, deferred capability with its own containment analysis, the same stance HC-KB-10 takes on weaponized memory exploitation.

## 9. Reporting the objective (delta to HC-FIND-01 §7)

### 9.1 The objective_outcome section

The report gains an `objective_outcome` block.

```json
"objective_outcome": {
  "id": "obj-flag-on-db",
  "status": "achieved",                    // achieved | not_achieved | not_applicable (no objective)
  "proof": { "kind": "canary", "sha256_matched": true },
  "attack_path": [                         // ordered confirmed findings whose yields reached the goal
    { "step": 1, "finding_id": "F-...", "technique_id": "KB-WEB-AUTH-...", "yielded": "credential@app" },
    { "step": 2, "finding_id": "F-...", "technique_id": "KB-DATA-...",     "yielded": "foothold@db" },
    { "step": 3, "finding_id": "F-...", "technique_id": "KB-DATA-CANARY-...", "yielded": "flag.captured@db" }
  ],
  "reached_facts": ["credential@app", "foothold@db"]   // present when not_achieved, to show how far it got
}
```

The `attack_path` is reconstructed by tracing the objective's required facts back through `yields_on_success <- preconditions` edges over the confirmed blackboard, so it is the kill chain of verified findings, in order, with the fact each one contributed.

### 9.2 Validator additions (extends HC-FIND-01 §7.2)

- `status: achieved` requires every finding in `attack_path` to be `confirmed` with `found_by != verified_by`, and the chain to resolve from recon facts to the objective proof with no provisional link.
- `status: achieved` requires `proof.sha256_matched: true` for a canary objective, or a recorded in-sandbox marker for a reach objective.
- `status: achieved` cannot appear in `mode: passive-only`; an objective in passive-only is `not_achieved`.
- `not_achieved` must list `reached_facts`, so the report states how far the chain got, which keeps a negative objective result as meaningful as a negative coverage result (HC-FIND-01 §7.3).

## 10. Deltas to existing specs and code (applied at implementation time)

This spec is the design; the following are the edits a build slice would make, listed so the implementation pointer is unambiguous and nothing is hand-waved.

- HC-SUB-01 §4: add the optional `objective` block and `policy.lateral_movement`, and the §4.4 validation rules; `harness/substrate/contract.py` parses and fail-closed-validates both.
- HC-AGENT-01 §4: replace the batch hunt-then-verify with the §6 capability-frontier loop in `harness/loop.py`; add the blackboard (`harness/blackboard.py`), fact tiers, and yield-on-confirm.
- HC-AGENT-01 §3: extend `harness/planner.py` with the §7 goal-relevance key, keeping the deterministic order.
- HC-KB-01 §6: no schema change; `yields_on_success` and `preconditions` become live rather than declarative-only.
- HC-FIND-01 §7: add `objective_outcome` to `harness/report.py:build_report` and the §9.2 checks to `validate_report`.
- Tests: a chaining end-to-end test (credential -> foothold -> canary) and a lateral-denied test, wired into `tests/` and CI per the project test convention; the objective proof, blackboard tiers, and no-scope-widening invariant each get an adversarial case.

## 11. Acceptance criteria

- A contract with no objective runs exactly as today and the report's `objective_outcome.status` is `not_applicable`.
- A multi-step objective is reached only through a chain of `confirmed` findings; forcing a provisional yield to satisfy a precondition does not advance the objective and does not appear in `attack_path`.
- An objective is reported `achieved` only when the deterministic proof holds (canary hash match or in-sandbox marker); a role claiming success without the proof does not flip the status.
- An objective naming an out-of-scope host is rejected before provisioning, and a confirmed foothold never makes an out-of-scope host reachable (the guard-proof still denies it).
- With `lateral_movement: false`, a lateral card is `blocked_by_policy / blocked_lateral` and never runs; with it true, the same card runs only after the foothold fact is `confirmed`.
- In passive-only mode an objective is `not_achieved`, no fact reaches `confirmed`, and the report says `mode: passive-only`.
- A killed run resumes from the ledger and blackboard and reaches the same objective status and the same `attack_path` as an uninterrupted run.

## 12. Open questions

- Multiple objectives per engagement: v1 is one objective; whether to support an ordered or any-of set is deferred, and the schema leaves room for it.
- Re-plan cost: whether re-evaluating the whole candidate set after every confirmation needs incremental evaluation (only cards whose preconditions reference the new fact) once the KB is large; leaning incremental.
- Provisional-fact exploration budget: how much Operator effort to spend chasing a chain whose earlier link is only provisional, before the Verifier has confirmed it; leaning on a small per-chain cap.
- True on-host pivot: the containment analysis and gating for executing tooling from a compromised host, if a later milestone needs movement the capability-fact model cannot express.
