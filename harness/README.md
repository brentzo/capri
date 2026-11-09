# harness

The running system (as opposed to `tools/`, which is KB build tooling). Pure
Python standard library, zero third-party dependencies.

## What's here (M0 substrate, the buildable slice)

The safety-critical logic of HC-SUB-01, as testable code. The decision logic the
harness runs on top of the sandbox (a self-hostable Docker backend now lives in
`harness/sandbox/`, below):

- `yamlmini.py` - a small, strict YAML-subset loader (block + flow), so the
  contract parser has no third-party dependency.
- `substrate/contract.py` - parse and validate the engagement contract
  (HC-SUB-01 §4). Fail-closed: `parse()` returns `(engagement, errors)` and
  yields no Engagement on any error, so nothing is provisioned from a bad
  contract. It also validates the optional `objective` block and
  `policy.lateral_movement` (HC-OBJ-01 §4): an out-of-scope objective target, an
  unparseable `success` predicate, a `reach` objective without lateral movement,
  or a canary that inlines the plaintext each abort, while a contract with no
  objective runs exactly as before. Runnable:
  `python3 -m harness.substrate.contract <file>`.
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
- `loop.py` (objective mode, HC-OBJ-01 §6) - when the contract carries an
  objective, `run` takes the capability-frontier path instead: it seeds a
  `Blackboard` from recon, then hunts a pair, verifies it at once on a disjoint
  session, writes its `yields_on_success` to the board (provisional at lead,
  confirmed on confirm), and re-evaluates applicability and preconditions over the
  live confirmed board, so a verified fact opens the next card and cards chain.
  Only confirmed facts gate a new card, so finder-is-not-verifier holds at every
  hop. With no objective the loop runs the unchanged coverage path. The objective
  is completed deterministically: the success predicate over the confirmed board
  plus a proof the harness observes (the retrieved canary's hash matching the
  contract, or an in-sandbox marker), so a role cannot claim success; the outcome
  (achieved / not_achieved / not_applicable, with the attack path) is on the run
  result, `on_success: stop` ends the run, and passive-only is never achieved.

## What's here (the Planner)

The first of the four roles with a real (non-stub) implementation, slotted into
the loop's role seam.

- `planner.py` - `DeterministicPlanner(kb_index)` ranks the candidate pairs the
  loop hunts: most-severe-first by the card's base band, then
  lowest-blast-tier-first within a band, then a stable (technique, asset)
  tiebreak so a plan is reproducible. Read-only and model-free; it is the v1
  stand-in the reasoning-model planner swaps behind later, same `plan` interface.

## What's here (the role I/O boundary)

The trust boundary between a model role and the harness (HC-AGENT-01 §5.1, §7,
§9). A role emits raw text and the harness, never the role, decides what it
means. This is the emit-time half of the prompt-injection posture; `dispatch()`
re-validates every request on the dispose side, so the two are defense in depth.

- `roleio.py` - `parse_request` turns a role's raw output into a validated
  `{tool, intent, target, port, args}` request or rejects the turn: free text, a
  shell string, surrounding prose, a smuggled extra field, a bad port, or a
  malformed object are not actionable. The loop re-prompts a rejected turn with
  the schema for bounded retries, then marks the pair inconclusive. On the other
  side, `frame_untrusted` wraps target responses and enrichment as a delimited
  data block whose unguessable per-call nonce a hostile response cannot forge, so
  an injected close-delimiter cannot break back into the instruction channel, and
  `role_context` is the harness-owned probe-history view a role sees: untrusted
  output framed, a denial or a rejected turn rendered as a trusted directive.

## What's here (the Bifrost model plane)

The policy around every model call (HC-MODEL-01). One virtual key per role and no
role holds a provider key; the real Bifrost HTTP client is infrastructure and is
injected as a `transport` (the only holder of credentials), the same pattern as
the tool adapters and the sandbox.

- `modelplane.py` - `ModelPlane` routes a `call(role, messages, metadata)` through
  the role's `VirtualKey`. It asserts the operator/verifier provider-diversity
  invariant and the MCP-tool boundary at construction (fail closed before any
  run), applies the fallback policy (Planner and Reporter fall back freely, the
  Operator only within its own set, the Verifier not at all so it never verifies
  on the Operator's model), enforces the hierarchical per-vkey and engagement
  budget and the per-vkey rate as fail-closed stops, serves the semantic cache
  only for the prose roles and only within an engagement, and writes an audit row
  for every call and every stop. `from_config` builds one from the §11 config
  shape.

## What's here (the Bifrost-backed role sessions)

The Operator and Verifier as model sessions that run on the plane (HC-AGENT-01
§4.1, §4.2), the first consumers of the plane, the role I/O boundary, and the
loop together. The actual Bifrost HTTP transport and the prompt bake-off are
still out of repo; what lives here is the wiring and the propose-only contract.

- `roles.py` - `ModelOperator` / `ModelVerifier` assemble a prompt from the
  harness-owned `role_context` (the framed, untrusted probe history) plus the
  trusted task, call `plane.call` through the role's virtual key, and return the
  model's raw text, which the loop parses or rejects with `roleio`. No role holds
  a provider key, and because the plane keeps the Operator and Verifier on
  disjoint providers, finder is not verifier at the model plane as well. A plane
  stop (budget, rate, a down provider) or a stop sentinel makes a role give up,
  so the loop ends the pair or holds the lead. The prompts here are a starting
  point; the reasoning-model choice and few-shot are the HC-MODEL-01 bake-off and
  iterate behind this same seam.

## What's here (the Tavily enrichment service)

Optional, advisory vulnerability intelligence (HC-ENRICH-01). It sharpens threat
modeling and never decides, acts, or touches the sandbox. The Tavily client
egresses from the trusted host and is infrastructure, injected as a `transport`.

- `enrich.py` - `Enricher.lookup(stack_or_cpe)` refuses a query that is not a bare
  product/version or CPE identifier (an IP, address, or URL is rejected before any
  egress, under a generic client identity, never the user's email), then returns
  the public intel bucketed into cves / advisories / default_creds / writeups,
  each provenance-tagged (`source: tavily`, `url`, `fetched_at`, `trust: low`).
  `frame` wraps a result as a delimited untrusted block (via `roleio`) for the
  enrichment role only; it is advisory, never a success signal or a label, and the
  model plane brokers the tool to `vk-enrich` alone, never the Operator. Lookups
  are TTL-cached, and with no transport the service runs `passive-intel-off` so the
  loop proceeds on the KB. `research` yields only human-review-required card
  drafts, never an active card.

## What's here (the live Bifrost transport)

The first live transport: the real HTTP client behind the model plane's injected
seam (HC-MODEL-01). Still pure standard library (`urllib`); the running Bifrost
gateway is out of repo.

- `bifrost.py` - `BifrostTransport` POSTs a turn to a Bifrost gateway in the
  OpenAI chat-completions shape. It is the only holder of credentials: the plane
  hands it the role's virtual key name, and the client resolves it to the Bifrost
  secret and presents it as the bearer token, so no role holds a provider key. A
  provider outage (a 502/503/504 or an unreachable gateway) maps to `ProviderDown`
  so the plane falls back; a 4xx or a malformed body is a hard `BifrostError`. It
  is exercised against an in-process stdlib mock Bifrost in CI, so the wire
  contract is tested without a live gateway; pointing it at a real one is config.

## What's here (the live Tavily transport)

The second live transport: the real HTTP client behind the enrichment service's
injected seam (HC-ENRICH-01). Still pure standard library (`urllib`); the live
Tavily endpoint is out of repo.

- `tavily.py` - `TavilyTransport` POSTs a search to the Tavily API and is the only
  holder of the Tavily key: it presents the key as a bearer token and never puts
  it, or any account identity, in the query, which goes out under a generic
  User-Agent. Tavily returns generic web results, so the client maps each into the
  enricher's shape and infers a bucket (cve / advisory / default_cred / writeup).
  Because enrichment is optional and advisory, any failure raises
  `IntelUnavailable` and the enricher degrades to `intel-unavailable` without
  caching the failure. It is contract-tested against an in-process stdlib mock
  Tavily in CI; pointing it at the real API with a key is config.

## What's here (the blackboard)

The run-local world-state store that makes the KB's preconditions and yields live
(HC-OBJ-01 §5), the first piece of objective-driven chaining.

- `blackboard.py` - `Blackboard` holds facts a card reads as preconditions and the
  harness writes as yields. Two tiers carry finder-is-not-verifier into every hop:
  a `provisional` fact (written at lead emission) informs exploration but gates
  nothing, and a `confirmed` fact (written only when the Verifier confirms the
  producing finding) is the only tier that satisfies an escalation or
  lateral-movement precondition or the objective predicate. Facts are immutable
  and append-only; a confirmed fact supersedes its provisional predecessor of the
  same `(name, scope)` without losing the log, so the attack path reconstructs.
  `view(context, tier)` is the flat `{name: value}` the predicate evaluator reads,
  scoped so a host-scoped fact is visible only against that host. The loop that
  seeds, writes, and re-evaluates over it is the next slice.

## What's here (the objective in the report)

The report delta of HC-OBJ-01 §9: a shipped report states whether the declared
objective was met and by what verified attack path, and the ship gate proves that
claim rather than trusting it.

- `report.py` - `build_report` now embeds an `objective_outcome` block (id, status,
  proof summary, kill chain, and the facts the chain reached), defaulting to
  `not_applicable` so every report carries the field. `validate_report` gains the
  §9.2 checks: an `achieved` outcome must carry a non-empty `attack_path` whose
  every step is a confirmed, independently verified finding in the report, a matched
  canary hash or a fired in-sandbox marker for its proof kind, and never the
  `passive-only` mode; a `not_achieved` outcome must list `reached_facts`.
- `loop.py` - `_attack_path` reconstructs the kill chain rather than dumping every
  confirmed finding: it traces the objective's required facts (the `success`
  predicate's identifiers, plus the recorded proof facts) back through
  `yields_on_success <- preconditions` over the confirmed board, keeps only the
  findings that transitively contributed, and orders them by precondition depth, so
  the path reads recon-to-goal and an off-path confirmed finding is pruned.
- `predicates.py` - adds `identifiers(expr)`, the fact names a predicate depends on,
  which is how the trace learns what the objective requires.

## What's here (the lateral-movement gate)

HC-OBJ-01 §8: a chain may cross from one in-scope host to another only when the
contract permits it, and a foothold never widens scope.

- `loop.py` - in the frontier, a card is evaluated first over the confirmed facts at
  the pair's own host. If it does not hold there, `_lateral_facts` gathers the
  confirmed facts the card references that live on a *different* in-scope host and
  that this host lacks - the foothold a lateral chain pivots on (host-local recon
  facts are present everywhere, so only a capability gained elsewhere registers).
  When such a foothold would make the card applicable, `lateral_movement: true`
  admits the pair and `_effective_facts` merges the foothold into the hunt view;
  `false` marks the pair `blocked_by_policy` with ledger detail `blocked_lateral` and
  never runs it. A merely provisional foothold never counts, so finder-is-not-verifier
  holds across the host boundary too. The probe target stays the pair's own in-scope
  asset, so a foothold changes which techniques apply, never which hosts are reachable.
- `store/ledger.py` - `mark` takes an optional `detail` sub-reason (a new nullable
  column) and `detail()` reads it back, so a negative result names *why* a pair was
  blocked without multiplying the status vocabulary; `summary` is unchanged.

## What's here (the sandbox substrate backend)

HC-SUB-01 §10: the interface the control loop drives to get an isolated range, plus
the first self-hostable backend. No nested virtualization needed, so it runs on any
commodity Linux host (and inside Docker Desktop's Linux VM on macOS/Windows).

- `sandbox/base.py` - `Sandbox`, the backend-agnostic interface (`provision /
  snapshot / restore / guard_proof / proofs_pass / kill`), and `PassiveOnlySandbox`,
  the safe default whose proofs all fail so a harness with no range stays
  passive-only. `guard_proof_result` evaluates the four §8.1 assertions.
- `sandbox/docker.py` - `DockerSandbox`, the Docker backend. `provision` builds one
  `--internal` network (no egress by construction = G2) with a target container per
  in-scope host and one attacker container (no `NET_ADMIN`, no network tooling, so the
  agent can neither leave scope nor touch the guard). The scope guard is an nftables
  ruleset the host installs into the attacker's netns - default-deny egress, allowing
  only the pinned in-scope IPs on their allowed ports (`scope.ports_for`). `guard_proof`
  runs the four §8.1 probes from inside the attacker container. `snapshot`/`restore`
  give reproducibility (G3): `snapshot` commits each target container to an image and
  `restore` recreates it from that image at the same pinned IP (the attacker and guard
  are untouched), and `snapshot_round_trip` proves it per §8.2 (marker survives an
  overwrite-then-restore). `escape_attempt` proves containment (G4, §8.3): from the
  attacker it probes the operator host, the range gateway (the host's interface on the
  range, closed only by the guard), and an unrelated network, asserting all
  unreachable; `provision` runs the containers under gVisor's `runsc` runtime when the
  host offers it (auto-detected, no KVM needed), so an escape is contained in a
  user-space kernel. `kill` is the kill switch (G5): one action freezes the whole range
  at once, commits it for forensics, and restores the targets from golden;
  `kill_switch_drill` proves it per §8.4 (freeze within a budget, target wiped to
  golden), then revives the range. `kill` is distinct from `teardown`, which destroys
  the range. `proofs_pass` runs all five drills and returns `True` only when every
  guarantee holds, so the harness may leave passive-only; any failed proof keeps it
  passive-only.
- `sandbox/probe.py` - `DockerProbe`, the live tool adapter. After the dispatcher
  passes scope/blast/rate, it runs an HTTP probe on the attacker container against a
  pinned in-scope target (resolving a pinned name to the IP the guard enforces on) and
  reports the raw signals the harness triages. `recon.py:phase_recon` is the live
  recon phase: it probes each pinned in-scope target on its allowed ports from the
  attacker container and returns the `{asset: facts}` target model the threat-model
  phase consumes (reachable, open ports, service type), reading state only and within
  scope. `tools/run_engagement.py` wires it all: parse a contract, provision the real
  range, gate on `proofs_pass`, recon the targets, and drive the control loop, so a
  live run confirms a finding (finder and verifier disjoint) and produces a validated
  report under sandbox enforcement.
  Every docker/nsenter call goes through an injected runner, so the logic is
  unit-tested with no Docker present (`tests/test_sandbox.py`); the live path is proven
  by `tools/sandbox_selftest.py` (golden image and notes in `infra/sandbox/`).

## What's here (the model-plane gateway bring-up)

HC-MODEL-01: the one-command way to stand up the Bifrost gateway the model plane talks
to, so a new developer runs two commands instead of ten and needs no cloud account. The
gateway is infrastructure, the way Docker is for the sandbox; the harness itself stays
dependency-free and is handed a gateway URL.

- `tools/modelplane.py` - stdlib-only and cross-platform. `up` generates the Bifrost
  config and an `.env`, mints a per-role virtual key (`sk-bf-...`), seeds a
  Docker-managed volume with the config over stdin (no host bind mount, so it survives
  Docker Desktop file sharing and odd `/tmp` setups) and makes it group-0 writable so
  the gateway can write its stores, runs the container bound to `127.0.0.1` only, and
  waits for health. `keys` reads the two provider API keys with no echo and restarts;
  `env` prints the `HC_BIFROST_URL` / `HC_VK_OPERATOR` / `HC_VK_VERIFIER` exports the
  runner reads; `status` shows health, routes, and whether keys are set; `down` and
  `destroy` stop or wipe it. The generated config encodes the §4 diversity invariant
  structurally - operator on DeepSeek, verifier on OpenAI, one provider per virtual key,
  the two disjoint - and carries only `env.VAR` references, never a literal secret, so
  it is safe to generate into a file. State (the config and the `.env` holding the keys
  and virtual keys) lives under `~/.hackculture/modelplane`, outside the repo, so
  secrets never reach a working tree, and the gateway binds to localhost so the provider
  keys it holds are never on the network.
- `tools/run_engagement.py` now builds the model plane from those env vars and runs the
  Operator on DeepSeek and the Verifier on OpenAI through it, falling back to the
  deterministic stand-ins when no gateway is configured, so finder-is-not-verifier holds
  at the model plane as well as at the loop and the DB.
  The config, `.env`, and virtual-key logic is unit-tested with no Docker present
  (`tests/test_modelplane_setup.py`); the live bring-up is proven on a real Docker host,
  and the one step left to the operator is pasting their own provider keys (dev notes in
  `infra/modelplane/`).

## Run

```sh
make test                                                   # harness + KB tests
python3 tests/test_substrate.py                             # M0 substrate
python3 tests/test_store.py                                 # M1 store invariants
python3 tests/test_dispatch.py                              # propose-and-dispose chokepoint
python3 tests/test_findings_report.py                       # finding/report layer
python3 tests/test_loop.py                                  # outer control loop + roles
python3 tests/test_planner.py                               # deterministic planner
python3 tests/test_roleio.py                                # role I/O boundary (parse-or-reject, framing)
python3 tests/test_modelplane.py                            # Bifrost model plane (vkeys, budgets, diversity)
python3 tests/test_roles.py                                 # model-backed Operator/Verifier end to end
python3 tests/test_enrich.py                                # Tavily enrichment (opsec, provenance, framing)
python3 tests/test_bifrost.py                               # live Bifrost transport (mock-server contract)
python3 tests/test_tavily.py                                # live Tavily transport (mock-server contract)
python3 tests/test_blackboard.py                            # world-state blackboard (fact tiers, chaining)
python3 tests/test_frontier.py                              # capability-frontier loop (live card chaining)
python3 tests/test_sandbox.py                               # sandbox substrate: interface + Docker guard proof
python3 tests/test_modelplane_setup.py                      # model-plane gateway bring-up (config, vkeys, .env)
python3 -m harness.substrate.contract harness/substrate/examples/engagement.example.yaml
```

## Not here yet

Provisioning, snapshot/restore, the gateway, the guard-proof self-tests as live
probes, and the kill switch (infrastructure). The Bifrost and Tavily transports
(`bifrost.py`, `tavily.py`) are here and contract-tested against mocks, but
pointing them at a running gateway and the real Tavily API with real secrets is
deployment, and wiring enrichment into live recon and threat modeling remains. On
the model plane, a Reporter LLM over the deterministic reporter and the
reasoning-model planner that would replace the deterministic one remain, as does
the live `phase_recon` that produces the target model. What is here is the policy
core, the orchestration, and the transport clients those plug into.
