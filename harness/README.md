# harness

The running system (as opposed to `tools/`, which is KB build tooling). Pure
Python standard library, zero third-party dependencies.

## What's here (M0 substrate, the buildable slice)

The safety-critical logic of HC-SUB-01, as testable code. The sandbox itself
(Firecracker microVMs, the nftables/eBPF no-route gateway, snapshot/restore) is
infrastructure, not in this repo; what lives here is the decision logic the
harness runs on top of it:

- `yamlmini.py` - a small, strict YAML-subset loader (block + flow), so the
  contract parser has no third-party dependency.
- `substrate/contract.py` - parse and validate the engagement contract
  (HC-SUB-01 §4). Fail-closed: `parse()` returns `(engagement, errors)` and
  yields no Engagement on any error, so nothing is provisioned from a bad
  contract. Runnable: `python3 -m harness.substrate.contract <file>`.
- `substrate/scope.py` - `scope_validate(eng, target, port)`, the default-deny
  scope pre-check (§5.3); out_of_scope wins and unpinned hosts are denied
  (anti-TOCTOU, §4.3).
- `substrate/blast.py` - `blast_gate(eng, tier, has_snapshot, technique_id)`,
  the blast-tier gate (§7): tier cap, snapshot-required for tier >= 2, and
  per-technique authorization for tier 3.

## What's here (M1 store, the data backbone)

The evidence/findings/ledger/audit store of HC-DATA-01 and HC-SAFE-01, as a
SQLite realization of the production target (Postgres plus a content-addressed
blob store). The three guarantees
the specs insist on are enforced in the database itself, not only the app:

- `store/schema.sql` - the schema. `finder_not_verifier` is a `finding` CHECK
  constraint; `probe_event`, `finding_status`, and `label` carry append-only
  BEFORE UPDATE/DELETE triggers; `audit_log` rows chain on `prev_hash`.
- `store/db.py` - `connect(path=':memory:')` applies the schema and returns a
  connection; `now()` is the ISO-8601 UTC stored timestamp.
- `store/findings.py` - `insert_lead` then `confirm`/`reject`/`mark_inconclusive`;
  each verdict change appends a `finding_status` row and updates `finding.verdict`
  atomically, and confirming with `verified_by == found_by` is rejected by the DB.
- `store/ledger.py` - the coverage ledger: `mark`, `done`, `summary`, so a
  resumed run skips `(asset, technique_id)` pairs it already processed.
- `store/audit.py` - the tamper-evident audit log: `record` appends a hash-chained
  row; `verify_chain` recomputes the chain and returns the first broken row.
- `store/blobstore.py` - the content-addressed blob store (the HC-DATA-01 §3
  default backend): `put` dedups by sha256 and is write-once, `get`/`verify`
  read back and check integrity. `blob://<sha256>` URIs embed the hash.
- `store/evidence.py` - `record_probe_event` writes raw request/response to the
  blob store and inserts one immutable `probe_event`; `verify_integrity` catches
  a swapped URI or a corrupted blob.

## What's here (dispatch, the propose-and-dispose chokepoint)

The single gate every proposed action passes through (HC-AGENT-01 §5.2), wiring
the M0 guards to the M1 store. The real tool adapters and the sandbox are
infrastructure (injected), so this is the decision logic, not the tools.

- `dispatch.py` - `Dispatcher.dispatch(req, ctx)` runs the four guards in order
  (unknown_tool, out_of_scope, blast_denied, rate/budget), short-circuits with a
  structured denial, and on pass runs the adapter, records exactly one
  `probe_event`, writes an audit row, and returns the normalized result. A denial
  is data, not an error; an adapter error is recorded as an observation and never
  surfaced as internal detail.
- `ratelimit.py` - the fourth guard: a per-target token bucket plus a run-action
  budget, both from the contract's `policy.rate`, with an injectable clock.

## What's here (finding/report layer)

The verdict-to-report path of HC-FIND-01, as pure-stdlib code.

- `predicates.py` - the blackboard predicate evaluator (HC-KB-01 §4 DSL:
  identifiers, == != < > <= >= / in, exists()/matches(), ! && ||) over a facts
  dict. Evaluates every applicability and severity `when` clause in the KB.
- `severity.py` - scores a card's `severity_rubric` (base band adjusted by
  raise_if / lower_if, evaluated with `predicates`) to a band + CVSS vector +
  representative score. A raise clause only raises, a lower clause only lowers.
- `kb.py` - loads the materialized card tree into a `(id, version) -> card`
  index so a finding's technique resolves to a known card.
- `store/findings.py` - `emit_lead` (severity + cwe from the card), the verdict
  transitions, `classify_hardening`, the verifier `label` on confirm/reject, and
  `to_record` building the §3 finding record from the store.
- `report.py` - `build_report` assembles the §7.1 report from the store;
  `validate_report` is the ship gate (finder != verifier, confirmed-backed-by-a-
  verifier-event-and-repro, vuln-has-cvss+cwe / hardening-has-neither, technique
  resolves, no raw internal error text, passive-only ships nothing confirmed).

## What's here (the outer control loop)

The engine of HC-AGENT-01 §4: the deterministic loop that drives a run through
plan -> hunt -> verify -> report. The four roles, the sandbox, and the model
plane (Bifrost) are infrastructure, injected here; this is the orchestration and
the signal triage the harness owns on top of them.

- `loop.py` - `Loop.run(target_model)` runs `phase_threat_model` (assets x
  applicable KB cards, via the applicability DSL), lets the injected Planner
  order the pairs, then for each pair runs the Operator inner loop through
  `dispatch()` until a deterministic success signal fires and a lead is emitted,
  and reproduces each lead on a disjoint Verifier session (finder != verifier,
  asserted here over the DB CHECK). Signal triage stays in harness code: the loop
  reads the probe_event's recorded `deterministic_signals` (`evidence.get_signals`)
  and applies the card's success-signal rule, so the Operator never sees the raw
  signal and an injected instruction cannot forge a lead. `signal_evaluator` is
  the seam where Laya (HC-MODEL-02) replaces the deterministic default. With the
  sandbox down the loop runs passive-only: every lead is held `needs_validation`
  and the report ships nothing confirmed. The report ships only if
  `validate_report` passes.

## What's here (the Planner)

The first of the four roles with a real (non-stub) implementation, slotted into
the loop's role seam.

- `planner.py` - `DeterministicPlanner(kb_index)` ranks the candidate pairs the
  loop hunts: most-severe-first by the card's base band, then
  lowest-blast-tier-first within a band, then a stable (technique, asset)
  tiebreak so a plan is reproducible. Read-only and model-free; it is the v1
  stand-in the reasoning-model planner swaps behind later, same `plan` interface.

## Run

```sh
make test                                                   # harness + KB tests
python3 tests/test_substrate.py                             # M0 substrate
python3 tests/test_store.py                                 # M1 store invariants
python3 tests/test_dispatch.py                              # propose-and-dispose chokepoint
python3 tests/test_findings_report.py                       # finding/report layer
python3 tests/test_loop.py                                  # outer control loop + roles
python3 tests/test_planner.py                               # deterministic planner
python3 -m harness.substrate.contract harness/substrate/examples/engagement.example.yaml
```

## Not here yet

Provisioning, snapshot/restore, the gateway, the guard-proof self-tests as live
probes, and the kill switch (infrastructure). On the model plane: the
Bifrost-backed role sessions that implement the loop's role seam (the Operator,
Verifier, and Reporter prompts and their virtual keys, plus the reasoning-model
planner that would replace the deterministic one) and the live `phase_recon`
that produces the target model. This slice is the policy core and the
orchestration those plug into.
