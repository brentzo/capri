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
the M0 guards to the M1 store. The tool adapters and the sandbox are injected
through a seam (their real backends now live in `sandbox/`, below), so this file
is the decision logic, not the tools themselves.

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
plane are injected through seams, with their backends in this package (`roles.py`,
`sandbox/`, `modelplane.py`) and in `infra/`; this is the orchestration and the
signal triage the harness owns on top of them.

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
  so the plane falls back. A 402 maps to `ProviderDown` flagged `out_of_credit`, so a
  role whose providers are all out of credit stops with `provider_out_of_credit` and
  the run summary says so; any other 4xx or a malformed body is a hard `BifrostError`. A
  role's per-call output cap rides on its virtual key and goes out as Bifrost's
  `max_completion_tokens`, so a provider never reserves its own large default. It
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
the first self-hostable backend. It runs on Linux and on Windows/macOS through Docker
Desktop without requiring host `nsenter` or root.

- `sandbox/base.py` - `Sandbox`, the backend-agnostic interface (`provision /
  snapshot / restore / guard_proof / proofs_pass / kill`), and `PassiveOnlySandbox`,
  the safe default whose proofs all fail so a harness with no range stays
  passive-only. `guard_proof_result` evaluates the four §8.1 assertions.
- `sandbox/docker.py` - `DockerSandbox`, the Docker backend. `provision` builds one
  `--internal` network (no egress by construction = G2) with a target container per
  in-scope host and one attacker container (no `NET_ADMIN`, no network tooling, so the
  agent can neither leave scope nor touch the guard). A short-lived `hc-guard:golden`
  helper joins the attacker's network namespace with only `NET_ADMIN`, installs the
  default-deny nftables rules from stdin, then exits. A target's listener is the plain
  `http.server` stand-in, or, when `listener_app` is set, a python app seeded in over
  stdin (never baked into the golden image); the live runner seeds `infra/sandbox/vulnweb.py`,
  a deliberately vulnerable app (it reflects one query parameter unencoded, concatenates
  another into a SQL query, evaluates a third through a template engine, reflects any
  Origin with credentials, and exposes a toy JWT login whose verifier honors alg:none,
  whose /account skips the ownership check, and whose /admin skips the role check), so the
  XSS, SQLi, SSTI, CORS, IDOR, BFLA, and JWT-confusion techniques have a real hole.
  The scope guard is an nftables
  ruleset a short-lived helper installs into the attacker's netns - default-deny egress,
  allowing only the pinned in-scope IPs on their allowed ports (`scope.ports_for`). `guard_proof`
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
  the range. `sandbox/rangelock.py` keeps one engagement per range: the live callers
  hold its OS file lock from before `provision` (which first clears any same-named
  range) until after `teardown`, so a second run is refused instead of destroying a
  live range, and a crashed holder releases it on exit. `proofs_pass` runs all five drills and returns `True` only when every
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
  Every Docker call goes through an injected runner, so the logic is
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
  `SqliAdapter`, the `sqli` tool, is the injection counterpart with two harness-owned
  differentials on a named parameter: error-based, where a value that unbalances the SQL
  quoting provokes a database error the benign value did not, and boolean-blind, where two
  different always-true conditions answer alike but an always-false one differs. It assumes
  no baseline value that matches a row, so a real app's injectable parameter confirms, while
  a safely parametrized one neither errors nor splits and the verdict stays harness-owned. `IdorAdapter`, the `idor` tool, carries identity: it logs
  in as one user, then reads that user's own object and a neighbour's with the same token,
  and reports broken object-level authorization (IDOR/BOLA) only when the neighbour comes
  back 200 with distinct data, which an ownership check would refuse with a 401/403.
  `BflaAdapter`, the `bfla` tool, is the function-level counterpart: it calls a privileged
  function with no token and then with an ordinary user's token, reporting broken
  function-level authorization only when the anonymous call is refused but the user's
  executes - a public endpoint that answers both is not flagged. `JwtAdapter`, the `jwt`
  tool, attacks the token: it forges an unsigned (alg:none) token and a bogus-signature
  one and reports JWT algorithm confusion only when the server accepts the unsigned token
  but rejects the bogus-signature one, proving it honors alg:none rather than ignoring
  verification entirely. `SstiAdapter` (`ssti`) injects an arithmetic template
  expression in each major dialect syntax in turn and confirms server-side template
  injection on the first whose response has the computed value and not the raw expression; `CorsAdapter` (`cors`) sends a crafted Origin and confirms a
  CORS misconfiguration only when the response reflects that origin with credentials (it
  reads a response header, so the in-container request grew a header-returning variant).
  `PathAdapter` (`path`) requests a file parameter with a traversal ladder and confirms a
  path traversal only when the response carries the range canary marker the target writes
  outside its public dir, proving the read escaped it; the marker never travels in the
  request, so a contained server never echoes it. `CmdiAdapter` (`cmdi`) proves OS command
  injection by a timing oracle: it appends a shell `sleep` to the parameter through each
  common framing (separator, pipe, logical-and, substitution, backticks, newline) and fires
  on the first whose request runs at least the sleep longer than the baseline, which the
  harness times itself (the clock is injected so tests need no real sleep). `CacheAdapter`
  (`cache`) proves web cache poisoning: it injects a random marker through an unkeyed
  header on a cache-busting request, then makes a clean request for the same URL, and fires
  only when that clean request is served the marker from cache. `SessAdapter` (`sess`)
  proves session fixation: it obtains a pre-auth session id, logs in reusing it, and fires
  only when the login issues no fresh id and the pre-auth id is authenticated afterward;
  recon emits the login endpoint as a second asset so this card has a login-typed asset to
  apply over. `SsrfAdapter` (`ssrf`) proves server-side request forgery with a denied-egress
  range: the range runs an in-range out-of-band collaborator (never in scope), the adapter
  points the target's fetch parameter at a collaborator URL carrying a random token, and it
  fires only when the collaborator was hit for that token from the target, read out of band
  over docker exec rather than through the scope guard. `OpenRedirectAdapter` (`redirect`),
  the first client-side card, sets the redirect parameter to a harness-chosen attacker
  origin and fires only when the response is a 3xx whose Location points at that exact
  foreign origin (a dedicated in-container opener disables redirect-following so the probe
  reads the 3xx instead of chasing it off the range). `ClickjackAdapter` (`clickjack`)
  fetches a sensitive-action page and fires when it carries neither X-Frame-Options nor a
  CSP frame-ancestors directive, the two headers that stop cross-origin framing (recon marks
  `asset.has_state_changing_action` from a conventional action page so the card applies).
  `CsrfAdapter` (`csrf`) logs into a cookie session, drives the state change with only the
  cookie and no anti-CSRF token, and fires only when the change takes effect and the session
  cookie has no SameSite protection (the pair that lets a cross-origin page forge it).
  `WsHijackAdapter` (`wshijack`) opens a raw WebSocket handshake (a stdlib socket client) from
  a foreign Origin carrying the session cookie and fires only when the handshake is accepted
  and the socket returns the session's own data, proving the server did not validate the
  handshake Origin (recon marks `asset.has_websocket` from a 426 on a conventional ws path).
  Those four are the browserless client-side cards. The DOM-only ones need a real browser,
  so the attacker image now carries chromium (a tool, run one-shot with `--dump-dom`, not a
  harness dependency) and a shared `_render_dom` loads a URL headless, runs its JS, and
  returns the serialized DOM. `CspAdapter` (`cspexec`) injects an inline script that writes a
  computed marker into the title and fires only when that marker appears in the rendered DOM,
  proving the inline script executed (a restrictive CSP blocks it). `DomClobberAdapter`
  (`domclobber`) injects named markup whose id matches a global the page gadget reads and
  fires when the gadget's output shows the global resolved to the injected element.
  `ProtoPolluteAdapter` (`protopollute`) sends a parameter that walks into Object.prototype
  with a random marker and fires when a gadget reads that marker off a plain object. So seven
  of the ten client-side cards confirm live; web-storage token (needs JS evaluation),
  postMessage (needs a second origin), and DOM-based XSS (needs Laya) stay out of reach.
  The attacker container runs the toolchain image (`infra/sandbox/Dockerfile.attacker`,
  built for amd64 and arm64, httpx checksum-pinned) while targets stay the minimal node
  image, and the attacker still holds no `NET_ADMIN`, so the namespace scope guard
  bounds every request. Each adapter's parse and signal shape are pinned against captured
  real tool output (or, for the crafted probes, a runner that simulates the vulnerable
  server) with no Docker and no tool present (`tests/test_adapters.py`); a live
  model-driven run confirmed service-disclosure, web-fingerprint, reflected-XSS,
  boolean-blind-SQLi, broken-object-level-authorization, broken-function-level-
  authorization, and JWT-algorithm-confusion findings alongside the baseline probe, the
  Operator proposing each probe and the Verifier reproducing on a disjoint provider.
- Two hot-path waits are bounded so a full run finishes instead of stalling. A headless
  render that wedges never returns, and killing its `docker exec` would leave chromium
  holding the captured pipe open past the subprocess timeout and hang the whole run, so the
  render runs under an in-container `timeout`, kills its helpers by name, and the attacker
  runs with an init that reaps them. The scope-guard proof runs before every step, and its
  probes to blocked destinations each waited out a full timeout; the TCP probe self-bounds
  with a one-second socket timeout and the DNS probe is bounded by the container's `timeout`
  (getaddrinfo honours neither the socket timeout nor an alarm), so the per-step containment
  check no longer dominates a long run. A full deterministic engagement runs to completion
  and confirms seventeen of the eighteen web and client-side cards on the sandbox range.

## What's here (the capri CLI and model-plane setup)

HC-MODEL-01: `capri`, the one command a self-hoster runs, and the terminal UI behind
`capri setup` that picks the models and starts the gateway on their own machine - no
cloud account, no browser. The gateway (Bifrost) is infrastructure, the way Docker is
for the sandbox; the harness itself stays dependency-free and is handed a gateway URL.

- `capri` (repo root) - the entry point: `capri setup`, `capri run`, `capri source --project <path>`, `capri gateway
  <status|env|down|destroy|…>`, `capri help` (with a banner). `make install` symlinks it
  onto the PATH. `capri run` loads the gateway handles into its own env (resolving the
  invoking user's home under sudo), so there is no manual export step.
- `tools/catalog.py` - the provider catalog Capri owns: the single-API-key providers
  Bifrost supports (OpenAI, Anthropic, Gemini, DeepSeek, Mistral, Cohere, Groq, Cerebras,
  xAI, Perplexity, OpenRouter, Nebius, Hugging Face, Replicate), each with its Bifrost
  identifier, key env var, and suggested models. One place to edit to add a provider;
  `validate_pairing` enforces the one rule - operator and verifier on different providers.
- `cli/setup.py` - the setup flow, with a Textual TUI on interactive terminals and
  plain prompts for non-interactive runs or `--plain`. It shows the catalog as
  one list of models grouped by provider, takes a model for each role (the Verifier list
  excludes the Operator's provider), reads keys with no echo, and calls the gateway
  bring-up with a live progress display. It requires both selected provider keys before
  starting Docker or writing state. The TUI uses Back/Next and masks key entry.
  Searching updates a visible result list immediately; Down focuses the first result,
  arrows move the highlighted provider/model, and Down from the final result focuses Next.
  Enter selects without opening a dropdown, and Tab moves through the footer buttons.
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

## What's here (local source assessment)

HC-PROJ-01 and HC-PROJ-02: `capri source --project <path>` scans a temporary snapshot for source rules and dependency hygiene, and optionally matches dependencies against a local Trivy database.
The snapshot omits project scanner settings, symlinks and installed dependency folders, stays outside the project, and is removed even when a scanner fails.
Semgrep and Trivy metrics, version checks, project configuration and network access are disabled for assessments; the tools never run project code or package managers.
The report is written outside the project under `~/.capri/reports/` by default, contains no complete dependency inventory or source snippets, and keeps source, dependency and runtime areas separate.
Without Trivy or its database, source rules and hygiene still run while vulnerable-dependency coverage is `not_run` with a warning.

Run `capri source update-db` to explicitly download the public Trivy database into `~/.capri/trivy/`.
On an air-gapped host, copy `trivy.db` and `metadata.json` into `~/.capri/trivy/db/`.
The database is never refreshed during an assessment.

## What's here (the real KB in the live run)

The live engagement runs the real materialized knowledge base, not hand-written demo
cards, bridged to the concrete tool adapters.

- `capabilities.py` - the reviewed bridge from a KB technique card to the adapter that
  runs it. A card names its probe at a conceptual level (`custom.authz_probe`), while the
  dispatcher runs concrete adapters (`idor`, `sqli`, ...), and one conceptual tool can
  map to two adapters (object-level vs function-level authz), so the registry is keyed by
  card id. `runnable_index(kb_index)` projects the KB into just the techniques the harness
  implements, each with a concrete probe step attached, keeping the genuine card's id,
  applicability, preconditions, success signal, and real CVSS. A card with no entry (or a
  model-evaluated `laya:` signal) still loads into the full KB but is not hunted, so the
  harness degrades rather than proposing a tool the dispatcher would deny. `tests/
  test_capabilities.py` pins the registry against the real KB: no capability names a
  missing card, each targets a known adapter, and each maps a deterministically
  confirmable technique.
- `recon.py` now does light web discovery (reading state only) so the real cards' facts
  are there to gate on: the parameters a landing page exposes, a JWT auth scheme and an
  available authenticated session from a login probe, privileged sibling paths from a short
  conventional-path list, a cache header on a conventional cacheable path, and a
  cookie-session login endpoint emitted as a second asset. `tools/run_engagement.py` loads
  the KB with `kb.load`, projects it with `capabilities.runnable_index`, and drives it; a
  live run confirms all eleven genuine web-protocol-auth cards end to end (JWT algorithm
  confusion, server-side template injection, and OS command injection at the cards' own
  critical severity, object- and function-level authorization, boolean-blind SQL injection,
  path traversal, server-side request forgery, web cache poisoning, session fixation, and
  CORS misconfiguration), found_by distinct from verified_by on each. Under the disjoint
  model plane ten of the eleven confirm; the lightweight Verifier model does not reproduce
  the session-fixation probe, so the harness holds that one inconclusive rather than confirm
  it (the finder-is-not-verifier guarantee refusing an unreproduced lead). A stronger
  Verifier is the HC-MODEL-01 bake-off.

## What's here (durable runs, the dashboard store)

HC-REPORT-01 begins with persistence, since a live run used to open an in-memory database
and a throwaway blob directory, so nothing survived the process and there was nothing for an
operator to browse later. A run now persists under a per-user data directory,
`~/.capri/` by default and overridable with `HC_DATA_DIR` (`harness/store/datadir.py`): the
SQLite store at `engagements.db` and the content-addressed evidence at `blobs/`. The schema
gains one `engagement` summary row per run, carrying the run's identity, window, scope, mode,
and its validated report (HC-FIND-01), while the evidence, finding, and audit tables are
unchanged. `harness/store/engagements.py` is the single writer and the read API the dashboard
will use: `save` persists a finished run and commits, and `list_all`, `get`, and `audit` read
runs back, the last returning a run's audit rows with the global hash-chain verification
result so integrity is shown, not assumed. `tools/run_engagement.py` now writes to this store
instead of a temp dir. `tests/test_engagements_store.py` drives a real on-disk file, reopening
it between write and read, so a run provably survives the process that produced it.

The report renderer is the next piece built: `harness/report_render.py` turns a validated
report (HC-FIND-01) into one self-contained HTML page, a pure function with no store and no
server so it is unit-tested directly (`tests/test_report_render.py`). It renders each finding
with its impact, severity, CWE, and distinct finder and verifier, keeps hardening notes in
their own section with no severity, shows a passive-only banner when containment was not
proven, and renders times in am/pm (the stored form is ISO, so the am/pm form is a render
concern, closing the BR-08 gap). Every dynamic value is HTML-escaped, so target strings and
any model-authored text render as inert text, never active markup. The same output is what
the dashboard serves per run and what a static export would carry.

`capri dashboard` serves the whole thing locally: a standard-library `http.server`
(`cli/dashboard.py`) bound to `127.0.0.1` only, read-only, running no tool, that lists the
runs under `~/.capri/`, serves each run's rendered report, and shows its audit timeline with
the hash-chain verification result so tampering is visible rather than assumed. The routing
and rendering are split into a pure `route` function tested with no socket bound
(`tests/test_dashboard.py`).

The reasoning record captures what the agent actually proposed. The control loop used to take
each Operator and Verifier turn's raw text, parse it into an action, and drop the text; it now
persists that text first, as a `role_turn` row written through `harness/store/reasoning.py`,
so an operator can read step by step what the agent said and why it acted. The capture covers
every proposal, whether it dispatched a probe, was denied, or was unparseable, and links the
probe it produced. The record is write-only from the loop and read-only from the dashboard,
which keeps the finder-is-not-verifier guarantee intact: capturing the Operator's words for
later display never places them in front of the Verifier. It is untrusted, display-only data,
rendered escaped at `GET /run/{id}/reasoning` with the two roles shown as the distinct sessions
they are, never merged into one voice. The `role_turn` table is append-only, so a captured turn
is never rewritten. `tests/test_reasoning_store.py` proves the roundtrip and immutability,
`tests/test_loop.py` proves a confirmed run records both roles, and `tests/test_dashboard.py`
proves model-authored markup renders inert. The per-finding raw-evidence view follows.

## What's here (source-aware recon)

Capri is run against an app whose source the operator has, so recon reads that source to
enumerate the full HTTP surface rather than crawling a running app blind. Blind crawling is
the wrong model: the real target gates its whole surface behind a login, so a link-crawler
reaches almost none of it, and it then sprays every technique across every endpoint it does
reach. Source analysis reaches all of it, including the auth-gated, admin-only and
interaction-gated routes where the dangerous bugs live, and it reaches them precisely.

- `sourcemap/` - the deterministic surface extractor. `extract_surface(source_root)` detects
  the framework (`detect.py`) and dispatches to an adapter; the React Router file-based
  (`flatRoutes`) adapter (`react_router.py`) ships first. Route paths and path parameters
  decode from the filename convention purely (`api.accounts.$id.transactions.tsx` ->
  `/api/accounts/:id/transactions`, path param `id`), and a comment-stripped scan of each
  handler reads the exports (`loader` -> GET, `action` -> a mutation, `default` -> page vs
  resource), the input taps (`searchParams.get`, `formData`/`formText`, a JSON body), and the
  auth gate (a `requireSession`-style call, or membership in the `_dashboard` subtree). It
  executes nothing, so the same source always yields the same surface and a construct it
  cannot resolve is an explicit gap, not a guess. A new stack is a new adapter, never a change
  to the spine.
- `recon.py:project_surface` turns that surface into the same endpoint-as-asset entries the
  probe-routing spine already consumes, so `bind.py` and the templated injection cards are
  unchanged. Each query or form parameter becomes a directly injectable asset over a path
  whose `:id`/`*` holes are concretized to a benign literal (the adapters append
  `?param=payload` to a concrete path). Each path parameter becomes its own path-injection
  asset carrying the `{name}` template in `asset.path_template`, and deliberately no
  `asset.param`, so the current query-injection cards skip it rather than probe the wrong
  place; a path-aware card binds it in a later slice. A route's auth requirement rides along
  as `asset.auth_required` instead of dropping the route from the map.
- `recon.py:phase_source_recon` is the static entry point (reads files, runs no range and
  spends no credits); `phase_recon` takes an optional `source_root` and, when the contract
  carries one, builds the surface from the source and demotes the black-box crawler
  (`sandbox/crawler.py`) to the corroboration path it uses only when there is no source. The
  contract's optional `source_root` (`substrate/contract.py`) is the seam. On the real
  dashboard's source this recovers the complete route, parameter and auth inventory a crawl
  cannot. `tests/test_sourcemap.py` covers the filename decode, the handler scan, and the
  projection over a fixture route tree, with no network and no models; confirming a candidate
  on an auth-gated route still needs a session and the app provisioned, a later slice.

## What's here (sink tracing)

The full surface is large (168 routes became 633 endpoint-assets), and probing every technique
against every parameter is the fan-out that times a run out. Sink tracing decides which
parameters are worth probing by reading how each handler reaches its sinks, so a probe fires
only where a parameter can reach a dangerous one.

- `sourcemap/sinks.py` - the per-handler sink analyzer. `build_import_graph` scans the app's
  source once and resolves its imports (relative, plus project path aliases read from
  `tsconfig.json`/`jsconfig.json` rather than a hardcoded convention) into a graph of the
  project's own files; `reachable_files` takes each handler's transitive closure over it, since a route's
  taps and its sinks usually sit in different files (route -> facade -> provider). Each file is
  classified on its own text into four sink classes - SQL injection, path traversal, OS command
  injection, server-side template injection - and a class is risky for the handler when any
  reachable file is risky for it. A value reaches SQL safely as a `$N` parameter (`push(...)`,
  `$${...}`); a statement is risky only when a value is inlined into a string literal
  (`'${x}'`) or a request-derived expression reaches it, so a well-parameterized layer stays
  clean without a whitelist of safe idioms. The other classes key on a request value reaching a
  filesystem path, a `child_process` call, or `eval`/a template engine. It runs no code.
- `recon.py:project_surface` attaches `asset.sink_risk` (the risky classes) and
  `asset.sink_analyzed` to every parameter of the handler. The four injection cards
  (`kb/web-protocol-auth/KB-WEB-INJ-{SQLI,CMDI,SSTI,PATH}-001`, authored in the HC-KB-02 spec)
  gain one applicability clause each: the card applies only when the parameter reached the
  matching sink, or when the asset was never analyzed, so a source-aware run probes the few
  real candidates while a black-box crawl (which sets neither fact) keeps its param-presence
  behavior. Over the real dashboard's source the injectable candidates collapse from 572 to
  zero - an honest clean bill for a uniformly-parameterized app.
- It is precision-favoring, not exhaustive: it flags where the source shows a value reaching a
  sink unsafely and can miss one laundered through several indirections (a sink helper that
  raw-interpolates its own parameter is the known gap). `tests/test_sinks.py` covers the
  classifier, the cross-file closure, the projection and the gate over a fixture app, with no
  network and no models.

## What's here (caller session threading and the spend cap)

An auth-gated app refuses an unauthenticated probe, and recon surfaces those routes but cannot
confirm a finding on them without a session. This threads a caller-supplied session onto every
probe, and caps what a run can spend.

- `substrate/contract.py` - the engagement gains an optional `session` (`bearer` ->
  `Authorization: Bearer`, `cookie` -> `Cookie`, and verbatim `headers`), normalized to
  `eng.session_headers`, plus `model_budget` (total model tokens a run may spend, with a
  conservative default so every run is bounded). The session is a credential, so it lives only
  on `eng.session_headers` and never on the `{asset: facts}` model - it stays out of the recon
  log, the report and the persisted run.
- `sandbox/adapters.py` - `_Adapter` takes `session_headers` and merges them as base headers in
  `_send_http`/`_send_http_full`, under any per-call header. So the injection adapters now reach
  an auth-gated route, while an adapter that forges its own `Authorization` still wins. The
  generic "attach to every probe" seam the per-adapter auth code lacked.
- `tools/run_engagement.py` - hands `eng.session_headers` to every HTTP adapter, and wires
  `eng.model_budget` into `build_roles` as the plane's engagement budget and each role's child
  budget, so a run stops cleanly at the cap. The budget machinery already lived in
  `modelplane.py`; it was simply never wired, so earlier runs were open-ended.
- `infra/sandbox/noteapp.py` - a `/vault/notes` route that is 401 without the demo bearer and the
  same boolean-blind SQLi with it, so a confirmed finding there proves the session reached the
  probe. `tests/test_session.py` covers all of the above (no Docker, no models); the plane's
  budget enforcement stays in `tests/test_modelplane.py`.
- Out of scope here: standing the real React Router + Postgres dashboard up in the range (the
  sandbox provisions only single-process targets today) and two-session IDOR confirmation.

## What's here (the target contract and a Postgres backing service)

The range could only run a bundled single-process stdlib listener, so it could not host anyone
else's app - which is the point of the product, since others run it against their own apps. This
is the first increment toward standing an arbitrary app and its datastore up in the range: the
contract to declare one, and the backing-service machinery that runs its database.

- `substrate/contract.py` - an optional `engagement.target` block, parsed and validated
  fail-closed into `eng.target`. It declares a real app by exactly one of `image` or `build`, its
  `port`, `env`, a `ready` probe, and a closed set of backing `services` by known `engine` (only
  `postgres` today), each with optional `init_sql`, `version`, and credentials. We own this
  surface on purpose: it cannot express a host volume, a published port, or an external network,
  and an unsupported key is rejected rather than ignored, so a containment-breaking directive
  fails loudly instead of slipping through.
- `sandbox/docker.py` - `provision` brings each declared service up before the targets:
  `_bring_up_services` pulls the engine image on the host (before the range is sealed, where it
  still has internet), runs it in-range on its own IP with a `--network-alias` the app resolves,
  waits on `pg_isready`, and applies `init_sql` with `psql -v ON_ERROR_STOP=1`. The sidecar is
  never added to the pinned allow list, so the scope guard keeps the attacker off the datastore
  while the app reaches it over the internal network; teardown sweeps it.
- `sandbox/docker.py` - when the engagement declares an app, `_prepare_app_image` builds its
  `build` context or pulls its `image` on the host before the range is sealed, and the target runs
  that image with the engagement `env` injected in place of the bundled listener. The declared
  `port` is added to the allowed ports so the pre-check and the guard agree (§5.3); after the guard
  is up the harness polls the app's `ready` health path from the attacker over the real in-range
  path, and restore and the kill switch recreate the app from its own image.
- `infra/sandbox/nodepg/` - a bundled, deliberately vulnerable Node + Postgres practice target
  (Dockerfile, `server.js`, `seed.sql`), so the app-image path is proven on a genuine app image and
  datastore, not a stdlib stand-in. It is the Node+Postgres analogue of `vulnweb.py`/`noteapp.py`.
- `tests/test_substrate.py` and `tests/test_sandbox.py` cover the target contract and, through the
  injected runner (no Docker, no network), the Postgres bring-up and seed, the app image running
  with its env, the Dockerfile build, the port agreement, and the five guarantees holding for an
  app-plus-service target.
- `sandbox/docker.py` - the datastore is part of snapshot/restore/kill, so G3 and G5 reproduce a
  mutating action's database state, not only the app's filesystem. `snapshot` commits each service
  container (a `CHECKPOINT` first), `restore` recreates it from the snapshot or from a per-service
  golden committed right after seeding, and the kill switch freezes and restores it with the range.
  Postgres is crash-safe, so a committed data directory recovers on restart.

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
python3 tests/test_adapters.py                              # live tool adapters (nmap, httpx, injection, auth)
python3 tests/test_capabilities.py                          # KB technique -> adapter capability registry
python3 tests/test_catalog.py                               # the provider catalog we own
python3 tests/test_modelplane_setup.py                      # model-plane gateway bring-up (config, vkeys, .env)
python3 -m harness.substrate.contract harness/substrate/examples/engagement.example.yaml
```

## Not here yet

The sandbox substrate (provisioning, snapshot/restore, the five guard proofs, and
the kill switch) and the model gateway now ship as self-hostable backends
(`sandbox/`, `infra/`, and `capri setup`), and live `phase_recon` produces the
target model, so these are no longer stubs. What remains:

- Coverage: the live run drives the whole web-protocol-auth class (all eleven
  cards), several client-side cards, and the first mobile deep-link card; wiring
  the other KB classes (ai-llm, cloud, supply-chain, rpc, dos, data, memory-binary,
  the other mobile cards, and the DOM-only
  client-side cards) to concrete adapters is the next work, and the DOM-based and
  fuzzy-judgment cards wait on the Laya decision layer (HC-MODEL-02).
- Model plane: the Planner and Reporter are still the deterministic stand-ins; a
  reasoning-model Planner and an LLM Reporter swap in behind the same seams, and a
  stronger Verifier is the HC-MODEL-01 bake-off.
- Enrichment: Tavily is built and contract-tested against a mock but not yet wired
  into live recon and threat modeling, and pointing it at the real Tavily API with
  a key is deployment.

What stays out of repo is your own provider and Tavily API keys and the host you
run the backends on.

## Android mobile assessment (HC-MOB-01)

The first runnable mobile capability accepts an authorized APK in
`engagement.android_app.apk`, inventories the decoded manifest with the pinned
Android SDK tools, and adds one coverage item per supported `VIEW` plus
`BROWSABLE` deep-link filter.
Mobile-specific APK and deep-link behavior lives in `harness/mobile/`; the range,
dispatch, and recon layers stay shared with web engagements.
The manifest-derived probe invokes a fixed Android intent with a harness-created
callback URL; only a matching nonce observed from the emulator at the in-range
collaborator can produce a finding.
The existing Bifrost roles, dispatcher, audit and evidence stores, coverage
ledger, and independent Verifier remain in the path.

The runtime is a digest-pinned Google API 30 emulator container with an
ADB-only private control path, guest egress guard, and ephemeral APK copy.
APK analysis uses Android SDK Command-line Tools `15859902`, and device control
uses Platform-Tools `37.0.1`; exact checksums and the probe flow are recorded in
`docs/specs/HC-MOB-01.md`.
Active runtime assessment requires Linux Docker with KVM.
The vulnerable and patched canary app sources are under
`tests/fixtures/mobile/canary/`; `tools/build_mobile_canaries.sh` builds them
with SDK Platform `android-30`, Build-Tools `30.0.3`, and JDK 17.
The APKs are generated locally and are not checked in.
The other mobile technique cards remain unrunnable in the current slice.
