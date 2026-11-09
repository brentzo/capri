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
  the seam where Laya (HC-MODEL-02) replaces the deterministic default. If
  sandbox proofs fail or raise, the loop skips or halts active hunting and
  verification, records the failure, and holds outstanding leads at
  `needs_validation`. The passive-only report explains containment was not
  proven throughout the run and omits previously confirmed findings without
  changing stored records. The report ships only if
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
loop together. The live Bifrost transport is in repo (`bifrost.py`) and the whole
path is proven end to end against a real gateway (see below); what lives here is
the wiring and the propose-only contract, and the prompt bake-off continues.

- `roles.py` - `ModelOperator` / `ModelVerifier` assemble a prompt from the
  harness-owned `role_context` (the framed, untrusted probe history) plus the
  trusted task, call `plane.call` through the role's virtual key, and return the
  model's raw text, which the loop parses or rejects with `roleio`. No role holds
  a provider key, and because the plane keeps the Operator and Verifier on
  disjoint providers, finder is not verifier at the model plane as well. The
  Operator's task names the tool the harness will run and tells the model to aim
  at the asset's `recon.addr`, so a real model emits a probe the dispatcher
  accepts instead of inventing a tool name. A plane stop (budget, rate, a down
  provider) or a stop sentinel makes a role give up, so the loop ends the pair or
  holds the lead. The prompts are a starting point; the reasoning-model choice and
  few-shot are the HC-MODEL-01 bake-off and iterate behind this same seam.
  Proven live: pointed at a Bifrost gateway with the Operator on DeepSeek and the
  Verifier on OpenAI, a run confirmed an exposed-service finding end to end, finder
  and verifier on disjoint providers.

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
  agent can neither leave scope nor touch the guard). A target's listener is the plain
  `http.server` stand-in, or, when `listener_app` is set, a python app seeded in over
  stdin (never baked into the golden image); the live runner seeds `infra/sandbox/vulnweb.py`,
  a deliberately vulnerable app (it reflects one query parameter unencoded, concatenates
  another into a SQL query, and exposes a toy JWT login whose /account skips the ownership
  check and whose /admin skips the role check), so the XSS, SQLi, IDOR, and BFLA
  techniques have a real hole to confirm.
  The scope guard is an nftables
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
- `sandbox/adapters.py` - the live tool adapters that give the §5.3 allowlist real
  tools beyond the baseline probe. `NmapAdapter`, registered in `dispatch()` as the
  `nmap` tool, runs `nmap -sV -Pn` on one in-scope port against a pinned target and
  parses the XML into per-port service, product, version, and CPE signals (the shape
  version-based cards match on). `HttpxAdapter`, the `httpx` tool, fingerprints a web
  surface with ProjectDiscovery httpx: status, title, server and technology, the
  normalized response headers, which of the four baseline security headers are missing,
  any CORS allow-origin, and any redirect target (reported, not followed, since a
  redirect can leave the asset) - the signals the web-protocol-auth and client-side
  cards become applicable on. `HttpRequestAdapter`, the `http` tool, is the crafted-HTTP
  request primitive the web and auth techniques drive: it sends the request a card
  parametrizes (method, path, query) and, for a reflected-XSS technique, injects a
  random tag-breaking marker into a named parameter and reports whether that exact marker
  reflects unencoded in the body - a deterministic signal the harness owns, since the
  marker is generated here, so a model can neither pre-pick a match nor forge the echo.
  `SqliAdapter`, the `sqli` tool, is the blind-injection counterpart: it sends a baseline
  plus a harness-generated true and false condition on a named parameter and confirms
  boolean-blind SQL injection only when the true one reproduces the baseline response and
  the false one changes it, so a safely parametrized parameter never splits and the
  verdict stays harness-owned. `IdorAdapter`, the `idor` tool, carries identity: it logs
  in as one user, then reads that user's own object and a neighbour's with the same token,
  and reports broken object-level authorization (IDOR/BOLA) only when the neighbour comes
  back 200 with distinct data, which an ownership check would refuse with a 401/403.
  `BflaAdapter`, the `bfla` tool, is the function-level counterpart: it calls a privileged
  function with no token and then with an ordinary user's token, reporting broken
  function-level authorization only when the anonymous call is refused but the user's
  executes - a public endpoint that answers both is not flagged.
  The attacker container runs the toolchain image (`infra/sandbox/Dockerfile.attacker`,
  built for amd64 and arm64, httpx checksum-pinned) while targets stay the minimal node
  image, and the attacker still holds no `NET_ADMIN`, so the host-owned scope guard
  bounds every request. Each adapter's parse and signal shape are pinned against captured
  real tool output (or, for the crafted probes, a runner that simulates the vulnerable
  server) with no Docker and no tool present (`tests/test_adapters.py`); a live
  model-driven run confirmed service-disclosure, web-fingerprint, reflected-XSS,
  boolean-blind-SQLi, broken-object-level-authorization, and broken-function-level-
  authorization findings alongside the baseline probe, the Operator proposing each probe
  and the Verifier reproducing on a disjoint provider.

## What's here (the capri CLI and model-plane setup)

HC-MODEL-01: `capri`, the one command a self-hoster runs, and the terminal UI behind
`capri setup` that picks the models and starts the gateway on their own machine - no
cloud account, no browser. The gateway (Bifrost) is infrastructure, the way Docker is
for the sandbox; the harness itself stays dependency-free and is handed a gateway URL.

- `capri` (repo root) - the entry point: `capri setup`, `capri run`, `capri gateway
  <status|env|down|destroy|…>`, `capri help` (with a banner). `make install` symlinks it
  onto the PATH. `capri run` loads the gateway handles into its own env (resolving the
  invoking user's home under sudo), so there is no manual export step.
- `tools/catalog.py` - the provider catalog Capri owns: the single-API-key providers
  Bifrost supports (OpenAI, Anthropic, Gemini, DeepSeek, Mistral, Cohere, Groq, Cerebras,
  xAI, Perplexity, OpenRouter, Nebius, Hugging Face, Replicate), each with its Bifrost
  identifier, key env var, and suggested models. One place to edit to add a provider;
  `validate_pairing` enforces the one rule - operator and verifier on different providers.
- `tools/setup.py` - the setup TUI (standard-library `curses`, with a plain-prompt
  fallback where curses is absent or output is not a terminal). It shows the catalog as
  one list of models grouped by provider, takes a model for each role (the Verifier list
  excludes the Operator's provider), reads keys with no echo, and calls the gateway
  bring-up with a live progress display. It requires both selected provider keys before
  starting Docker or writing state. Esc steps back, q quits.
- `tools/modelplane.py` - the gateway mechanics the TUI and CLI share. `bring_up`
  generates the Bifrost config from the chosen pairing, seeds a Docker-managed volume
  with it over stdin (surviving Docker Desktop file sharing and odd `/tmp` setups) and
  makes it group-0 writable so the gateway can write its stores, runs the container bound
  to `127.0.0.1` only, and waits for health. The config carries only `env.VAR` references,
  never a literal secret, and encodes the diversity invariant (one provider per virtual
  key, the two disjoint). State (config, the chosen pairing, and the `.env` holding keys
  and virtual keys) lives under `~/.hackculture/modelplane`, outside the repo. `runtime_env`
  hands the runner its handles; `status` / `down` / `destroy` manage the lifecycle.
- `tools/run_engagement.py` builds the model plane from those handles and runs the two
  roles on whichever providers were picked, falling back to the deterministic stand-ins
  when no gateway is configured, so finder-is-not-verifier holds at the model plane too.
  The catalog and the config / virtual-key logic are unit-tested with no Docker present
  (`tests/test_catalog.py`, `tests/test_modelplane_setup.py`); the live bring-up and a
  confirmed finding from real models are proven on a real Docker host (dev notes in
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
python3 tests/test_adapters.py                              # live tool adapters (nmap service/version scan)
python3 tests/test_catalog.py                               # the provider catalog we own
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
