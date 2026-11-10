---
tag: HC-AGENT-01
title: Agent loop and role orchestration
status: draft
parent: SPEC.md#4, SPEC.md#6
depends_on: [HC-SUB-01, HC-MODEL-01, HC-KB-01, HC-FIND-01, HC-DATA-01, HC-MODEL-02, HC-ENRICH-01]
depended_on_by: [HC-MODEL-01, HC-FIND-01, HC-SAFE-01, HC-EVAL-01]
updated: 2026-11-08
---

# HC-AGENT-01 - Agent loop and role orchestration

## 1. Purpose

This spec defines the engine: the deterministic control loop that drives a run through the phases, the four isolated agent roles, the propose-and-dispose contract by which the model requests actions and the harness decides what executes, and how all of it is wired through Bifrost.

The governing rule, restated for this layer: the orchestrator is code and owns the loop; the roles are prompted LLM sessions that only ever propose.
No role holds a shell, a network socket, or a provider credential.
A role emits a structured request; the harness validates it against the HC-SUB-01 guards and either executes it through a tool adapter or returns a structured denial.

## 2. Loop principles

- The harness owns control flow; the model never decides what runs, only what to try.
- Roles are isolated sessions with separate contexts and separate Bifrost virtual keys, so one role cannot see another's reasoning.
- Finder is not verifier, enforced at the model level: the Verifier runs on a provider disjoint from the Operator's and sees only repro steps and evidence.
- Every executed action becomes an append-only `probe_event` (HC-DATA-01), so a run is fully reconstructable and resumable from state, never from chat memory.
- Untrusted input (target responses, enrichment data) enters a context as delimited data, never as instructions, and cannot widen what the harness will execute.

## 3. The four roles

| Role | Inputs | Outputs | Tool access | Model tier | Bifrost vkey |
|------|--------|---------|-------------|-----------|--------------|
| Planner | Target model, KB candidate set, coverage ledger summary | Prioritized list of (asset, technique) pairs with rationale | None (read-only) | Mid reasoning | `vk-planner` |
| Operator | One assigned (asset, technique) pair, its card, running observations | Proposed tool calls; a `lead` with repro and evidence, or a negative result | Active, via `dispatch()` only | Strong reasoning | `vk-operator` |
| Verifier | A lead's repro steps and evidence pointers, nothing else | A reproduce/again attempt; confirm or cannot-reproduce | Active, via `dispatch()` only | Strong, different provider than Operator | `vk-verifier` |
| Reporter | The findings store (confirmed findings and hardening notes) | A target-neutral report that passes the HC-FIND-01 schema | None | Cheap | `vk-reporter` |

Role isolation is a hard requirement, not a convenience:

- The Planner gets a ledger summary, not the full action history, to keep it cheap and unbiased.
- The Operator's context is scoped to its one assigned pair, which bounds both token cost and blast radius.
- The Verifier gets only `{repro_steps, evidence_pointers}` and has no access to how the Operator reached the lead, which is what makes its reproduction independent.
- The orchestrator asserts `verifier_session_id != operator_session_id` and records both on the finding (HC-FIND-01 rejects them equal).

## 4. The control loop

```
run(engagement):
    if not sandbox.proofs_pass():            # HC-SUB-01 §8
        mode = passive-only                    # leads stay needs_validation
    target_model = phase_recon(engagement)
    candidates   = phase_threat_model(target_model)     # assets -> applicable KB cards
    plan         = planner.plan(target_model, candidates, ledger.summary())

    for pair in plan.ordered_pairs:            # (asset, technique)
        if ledger.done(pair): continue
        hunt(pair)

    for lead in findings.leads():
        verify(lead)

    report = reporter.render(findings.confirmed(), findings.hardening_notes())
    schema.validate(report)                    # HC-FIND-01; report does not ship otherwise
```

### 4.1 Operator inner loop

```
hunt(pair):
    card = kb.get(pair.technique)                        # HC-KB-01
    if not preconditions_met(card, pair.asset):
        ledger.mark(pair, not_applicable); return
    if card.blast_tier > engagement.max_blast_tier:
        ledger.mark(pair, blocked_by_policy); return
    snap = sandbox.snapshot() if card.blast_tier >= 2 else None

    ctx = operator.session(vkey=vk-operator, scope=pair)  # isolated
    observations = []
    for _ in bounded(card.probe_steps, budget, max_denied=N):
        req = operator.propose_next(ctx, card, observations)   # structured request
        obs = dispatch(req, pair, card.blast_tier)
        observations.append(obs)
        if signal_hit(card, observations):                     # deterministic, or Laya (HC-MODEL-02)
            findings.emit_lead(pair, repro=observations, evidence=obs.evidence)
            break
    ledger.mark(pair, outcome_of(observations))
    if snap: sandbox.restore(snap)
```

### 4.2 Verification

```
verify(lead):
    sandbox.restore(golden_snapshot); fresh = sandbox.snapshot()
    vctx = verifier.session(vkey=vk-verifier)              # provider disjoint from Operator
    input = { steps: lead.repro, evidence: lead.evidence }  # ONLY this crosses over
    result = verifier.reproduce(vctx, input)                # proposes via same dispatch()
    if result.signal_reproduced and vctx.id != lead.found_by:
        findings.confirm(lead, verified_by=vctx.id)
    elif result.actively_disproved or known_false_positive(lead):
        findings.reject(lead, reason=result.reason)
    else:
        findings.mark_inconclusive(lead, reason=result.reason)   # env/time, not a rejection
```

## 5. The propose-and-dispose contract

This is the single chokepoint through which every action reaches the sandbox.

### 5.1 Request (what a role emits)

```json
{
  "tool": "httpx",
  "intent": "inject_error_payloads",
  "target": "api.sandbox.local",
  "port": 443,
  "args": { "path": "/orders", "param": "id", "payloads": ["'", "1 OR 1=1"] }
}
```

The role emits only this structured object.
It never emits a shell command, and free-text "do X" is not actionable; the orchestrator parses a request or rejects the turn.

### 5.2 Dispose (what the harness does with it)

```
dispatch(req, pair, tier):
    if req.tool not in ADAPTERS:                 return denial("unknown_tool")
    if scope.validate(req.target, req.port) != allow:  return denial("out_of_scope")   # HC-SUB-01 §5.3
    if blast.gate(tier, have_snapshot(pair)) != allow: return denial("blast_denied")    # HC-SUB-01 §7
    if not rate.allow(req.target):               return denial("rate_limited")          # may trip watchdog -> kill
    result = ADAPTERS[req.tool].run(req)         # executes on the attacker VM
    evt = evidence.record_probe_event(pair, req, result)   # HC-DATA-01, raw I/O retained
    return normalize(result, evt)                # { status, parsed, evidence_uri, probe_event_id }
```

- The four guard checks run in this order and short-circuit; the first failure returns a structured denial the role must handle.
- A denial is data, not an error: the role sees `denial(reason)` and must adapt, and a role that keeps proposing denied calls is capped by `max_denied` and the pair is abandoned.
- Validation here is defense in depth; the HC-SUB-01 gateway remains the real enforcement, so even a dispatch bug cannot send out-of-scope traffic.

### 5.3 Tool adapters

- Adapters are an allowlist (`nmap`, `httpx`, `ffuf`, `sqlmap`, `nuclei`, a Playwright browser driver, plus custom probe scripts); an unknown tool is denied.
- Each adapter wraps a real tool behind the normalized `{tool, intent, target, port, args} -> {status, parsed, evidence_uri, raw_uri}` shape.
- Every adapter run produces exactly one `probe_event` with raw request and response retained (HC-DATA-01), which is both the evidence trail and the training corpus.
- A new capability is a new reviewed adapter, never a general exec primitive handed to the model.

## 6. Bifrost wiring (model plane)

All generative traffic goes through Bifrost (HC-MODEL-01); no role holds a provider key.

| Concern | How it is wired |
|---------|-----------------|
| Per-role isolation | One virtual key per role; the Operator and Verifier keys resolve to disjoint providers so finder and verifier do not share a failure mode |
| Budget | Hierarchical budgets per vkey; a breach fails closed (the role stops) and can trip the HC-SUB-01 watchdog, never falls through to a direct provider call |
| Rate | Per-vkey rate limits, independent of the per-target network rate limit in `dispatch()` |
| Fallback | Bifrost handles provider fallback transparently, except the Verifier, which must not silently fall back onto the Operator's provider (pin it) |
| Caching | Semantic cache is allowed for Planner and Reporter prose, and disabled for Operator and Verifier turns so a cached decision never drives a live action |
| Observability | Bifrost request logs and traces feed the audit log: which vkey asked which model what, and when |

The decision models (Laya) are not on this plane; they are called directly by the harness as a local sidecar (HC-MODEL-02), because their classify-not-chat I/O does not fit the chat-completions abstraction.

## 7. Context management and prompt-injection posture

- Target responses and Tavily enrichment enter a role's context wrapped as clearly delimited untrusted data, never merged into the instruction channel.
- Whatever that data says, the role's output is still only a structured request that `dispatch()` re-validates, so injected instructions cannot widen scope, raise tier, or reach a new target; the scope guard would drop the traffic regardless.
- Where practical, a non-generative classifier (Laya) sits on the raw-target-output boundary for success-signal triage, shrinking the prompt-injection surface because a classifier emits a label, not an action.
- Handoff between roles and phases is through the coverage ledger and findings store, not shared conversation memory, which keeps role isolation intact and keeps context windows small.

## 8. Resumability and concurrency

- The loop is driven by the coverage ledger: each (asset, technique) pair carries a status, and a killed run resumes by re-provisioning from golden and continuing from the first pending pair.
- Actions are idempotent at the pair level: re-running a `done` pair is a no-op unless explicitly forced, and because every pair starts from a known snapshot, replays are deterministic.
- Concurrency for v1: one Operator at a time per target to preserve reproducibility, with parallelism only across independent targets on separate clones; the per-target network rate limit is shared across all workers hitting that target.

## 9. Failure modes

| Condition | Response |
|-----------|----------|
| Role emits an unparseable or schema-invalid request | Reject the turn, re-prompt with the schema, bounded retries, then mark the pair `inconclusive` and move on |
| Role repeatedly proposes denied calls | Cap at `max_denied`, abandon the pair, log the denials |
| Tool adapter times out or errors | Record the probe_event with an error status, surface it as an observation, let the role adapt |
| Budget or rate breach on a vkey | Role stops; watchdog may trigger the HC-SUB-01 kill switch |
| Verifier would fall back onto the Operator's provider | Refuse; hold the lead as `needs_validation` rather than verify on a shared model |
| Engagement window ends mid-run | Abort in-flight work, restore from snapshot, run the Reporter on whatever is confirmed |

## 10. Interfaces

Consumes:

- HC-SUB-01: `sandbox.*`, `scope.validate`, `blast.gate`, the watchdog/kill switch.
- HC-MODEL-01: Bifrost endpoint and per-role virtual keys.
- HC-KB-01: technique cards, preconditions, probe steps, success signals.

Produces:

- HC-DATA-01: one `probe_event` per adapter run, with raw I/O.
- HC-FIND-01: `lead`, `confirm`, `reject` / `mark_inconclusive`, and the final report.

The `dispatch()` chokepoint (§5.2) is implemented as pure-standard-library code in `harness/dispatch.py` (`Dispatcher`, `ProbeContext`): it runs the four guards in order, records one `probe_event` with raw I/O through `harness/store/evidence.py` into the content-addressed `harness/store/blobstore.py`, and writes an audit row through `harness/store/audit.py`.
The fourth guard (per-target rate and run-action budget) is `harness/ratelimit.py`.
Tool adapters and the sandbox are injected (the real tools are infrastructure, like the gateway), so tests drive the chokepoint with stub adapters; adversarial tests in `tests/test_dispatch.py` run in CI.

The outer control loop (§4, §4.1, §4.2) is implemented as pure-standard-library code in `harness/loop.py` (`Loop`, `Pair`, `phase_threat_model`).
`Loop.run(target_model)` drives plan -> hunt -> verify -> report: `phase_threat_model` turns the recon target model into candidate pairs by evaluating each card's applicability DSL (`harness/predicates.py`), the injected Planner orders them, `_hunt` runs the Operator inner loop through `dispatch()` until a success signal fires, and `_verify` runs the Verifier on a disjoint session.
Signal triage is in harness code, not the Operator's context: the loop reads the probe_event's recorded `deterministic_signals` through `harness/store/evidence.py:get_signals` and applies the card's success-signal rule (`signal_evaluator`, the seam where Laya replaces the deterministic default), so an injected instruction in a target response cannot forge a lead (§7).
finder != verifier is asserted at the loop before any confirm, over the DB CHECK; if sandbox proofs fail or raise, the loop stops active work, holds outstanding leads at `needs_validation`, and records the failure; the report ships only if `validate_report` passes.
The four roles, the sandbox, and the Reporter are injected (the real roles are Bifrost-backed LLM sessions and the sandbox is infrastructure), so `tests/test_loop.py` drives the loop with deterministic stub roles and a stub sandbox, proving the §11 criteria (confirmed-ships-valid, finder!=verifier refused, resume-from-ledger, injected-target-denied, passive-only); these run in CI.
The Planner (§3) is implemented against this seam as `harness/planner.py:DeterministicPlanner`, the first role with a real rather than stub implementation: it ranks the candidate pairs most-severe-first, then lowest-blast-tier-first, then by a stable (technique, asset) tiebreak, read-only and model-free, with `tests/test_planner.py` in CI.
The role I/O boundary (§5.1, §7, §9) is `harness/roleio.py`: `parse_request` turns a role's raw model text into a validated `{tool, intent, target, port, args}` request or rejects the turn (a smuggled field, surrounding prose, a bad port, or a malformed object), and `frame_untrusted` / `role_context` wrap target output as a nonce-delimited data block a hostile response cannot break out of, so untrusted data never reaches the instruction channel.
The loop now calls `roleio` on both sides: the Operator and Verifier emit text that the harness parses or rejects (re-prompting with the schema for bounded retries, then marking the pair inconclusive), and each role sees the probe history through `role_context`; this is the emit-time half of the prompt-injection posture, and `dispatch()` re-validates every request regardless, so the two layers are defense in depth.
`tests/test_roleio.py` covers the parse-or-reject and framing cases, with loop-level tests in `tests/test_loop.py` proving an unparseable turn is rejected before dispatch and an injected close-delimiter stays inside the data block; these run in CI.
The Bifrost-backed Operator and Verifier sessions (§4.1, §4.2, §6) are `harness/roles.py:ModelOperator` / `ModelVerifier`: each turn assembles a prompt from `role_context` and the trusted task, calls `plane.call` through the role's virtual key (HC-MODEL-01), and returns the model's raw text for the harness to parse, so no role holds a provider key and the plane keeps the Operator and Verifier on disjoint providers (finder != verifier at the model plane too). A `PlaneStop` (budget, rate, or a down provider) or a stop sentinel makes a role give up cleanly. The loop now passes the Operator session the asset's recon facts, and records each lead's full requests as its repro so the Verifier can reproduce from the steps alone. `tests/test_roles.py` runs the whole loop over a deterministic fake model, confirming a finding across disjoint providers and exercising the budget, sentinel, and down-provider stops; it runs in CI.
The Operator's task also carries the tool the harness will run (from the card's probe step) and instructs the model to aim at the asset's `recon.addr`, so a real model emits a probe the dispatcher accepts instead of inventing a tool name or targeting a bare hostname, with a regression test asserting the prompt names both.
Pointed at a live Bifrost gateway with the Operator on DeepSeek and the Verifier on OpenAI, the loop confirmed an exposed-service finding end to end, the finder and verifier on disjoint providers, which is the first confirmed finding from real models rather than the deterministic stand-ins.
Live reconnaissance (§4) is `harness/recon.py:phase_recon`: against a provisioned range it probes each pinned in-scope target on its allowed ports from the attacker container, records which are open and the HTTP status of a web port, and returns the `{asset: facts}` target model the threat-model phase consumes, reading state only and staying within scope (it touches only pinned targets on allowed ports, which the scope guard enforces regardless).
With it, the Docker sandbox backend (HC-SUB-01), the live HTTP probe adapter (`harness/sandbox/probe.py:DockerProbe`), and the deterministic Planner, Operator, and Verifier, `tools/run_engagement.py` drives a full engagement against a real self-hosted range end to end: provision, gate on the five guarantees, recon the targets, hunt, verify on a disjoint identity, and ship a validated report, all under sandbox enforcement.
The §5.3 tool allowlist now begins to run real tools rather than only the baseline probe: `harness/sandbox/adapters.py:NmapAdapter`, registered in `dispatch()` as the `nmap` tool, runs `nmap -sV -Pn` on one in-scope port against a pinned target and parses the XML into per-port service, product, version, and CPE signals, which is exactly what version-based cards match on.
The attacker container is built from `infra/sandbox/Dockerfile.attacker` (it carries the toolchain) while targets stay the minimal node image, and the attacker still holds no `NET_ADMIN`, so the host-owned scope guard bounds every scan regardless of what the model proposes.
The second real tool is `harness/sandbox/adapters.py:HttpxAdapter`, registered as `httpx`, the web-recon layer the web and auth techniques build on: it issues one request with ProjectDiscovery httpx and returns the status, title, server and technology fingerprint, the normalized response headers, which of the four baseline security headers are missing, any CORS allow-origin, and any redirect target, which it reports rather than follows, since a redirect can leave the asset.
These are the signals the web-protocol-auth and client-side cards become applicable on, so the fingerprint is what turns a bare open port into a web asset the web techniques can plan against.
The attacker image builds on amd64 and arm64 so it runs on an Apple Silicon host's Docker Desktop as well as a Linux range, and the httpx binary is pinned by version and checksum, so a tampered download fails the build.
The third tool is the crafted-HTTP request primitive `harness/sandbox/adapters.py:HttpRequestAdapter`, registered as `http`, which the web and auth techniques drive with the request a card parametrizes (method, path, query parameters).
For a reflected-cross-site-scripting technique it injects a random, tag-breaking marker into a named parameter and reports whether that exact marker reflects unencoded in the response body, which is a deterministic signal the harness owns rather than the model: the marker is generated in the adapter, so a model can neither pre-pick one that always matches nor forge the server's echo, and a server that encodes its output never reflects the raw marker.
The same shape extends to blind injection in `harness/sandbox/adapters.py:SqliAdapter`, registered as `sqli`: for a named parameter the harness sends three requests, the baseline value and the value with an appended condition that is always true and one that is always false, and reports boolean-blind SQL injection only when the true condition reproduces the baseline response while the false one changes it.
The conditions are generated in the adapter, not by the model, and a parameter the query parametrizes safely treats all three as literal data, so its responses never split that way, which keeps the signal deterministic and harness-owned; the Verifier reruns the differential, so a confirm is two independent splits.
Authorization techniques carry an identity, so `harness/sandbox/adapters.py:IdorAdapter`, registered as `idor`, authenticates as one identity through the target's login, then requests that identity's own object and a neighbouring object it should not own, both with the same token, and reports broken object-level authorization (IDOR / BOLA) only when the neighbour comes back 200 with distinct data, which an app that checks ownership refuses with a 401 or 403.
The identity and the neighbour id are chosen by the harness, so the model cannot force the verdict, and the Verifier repeats the pair, so a confirm is two independent reads.
`harness/sandbox/adapters.py:BflaAdapter`, registered as `bfla`, is the function-level counterpart: it calls a privileged function first with no token and then with an ordinary user's token, and reports broken function-level authorization only when the anonymous call is refused (401 or 403) yet the ordinary user's executes (200), so a merely public endpoint, which answers the anonymous call too, is not reported.
`harness/sandbox/adapters.py:JwtAdapter`, registered as `jwt`, attacks the token itself: it forges two tokens it could not legitimately sign, one with alg "none" and no signature and one with a bogus HS256 signature, and presents each to a protected endpoint, reporting JWT algorithm confusion only when the unsigned token is accepted (200) while the bogus-signature one is refused, which proves the server honors alg "none" rather than skipping verification on everything.
Two more web techniques follow the same harness-owned pattern: `SstiAdapter` (`ssti`) injects a fixed arithmetic template expression and reports server-side template injection only when the response carries the computed value and not the raw expression, which proves the engine evaluated harness input rather than reflecting it; `CorsAdapter` (`cors`) sends a crafted attacker Origin and reports a CORS misconfiguration only when the response reflects that exact origin in Access-Control-Allow-Origin and allows credentials, the pair that lets a malicious site read an authenticated response (it reads a response header, so the in-container request grew a variant that returns headers as well as the body).
`PathAdapter` (`path`) reads the same way from disk: it requests the named file parameter with a traversal ladder that walks out of the app's public directory toward a range canary the target writes outside it, and reports a path traversal only when the response carries the canary marker, which proves the read escaped the public directory rather than serving an in-directory file; the marker is the harness's and never travels in the request, so a server that contains the path never echoes it.
`CmdiAdapter` (`cmdi`) proves OS command injection by a timing oracle: it sends a baseline request and one that appends a shell `sleep` to the parameter, and reports injection only when the injected request takes at least the sleep duration longer than the baseline, which proves the server executed the injected command rather than treating it as data; the harness measures the round-trip itself and the delay is the harness's, so a model cannot forge it, and the clock is injected so the timing logic is tested without real sleeps while the live path measures the real wall clock.
`CacheAdapter` (`cache`) proves web cache poisoning: it sends a cache-busting request that injects a random marker through an unkeyed header (X-Forwarded-Host), then a clean request for the same URL, and reports poisoning only when the clean request is served the injected marker, which proves the marker was cached under a key that ignored the header and handed to a victim who never sent it; the marker travels only in the first request's header, so a cache that keys on the header, or does not reflect it, never serves it on the clean request.
`SessAdapter` (`sess`) proves session fixation: it obtains a pre-auth session id, authenticates reusing that exact id, and reports the flaw only when the login issues no fresh id and the pre-auth id is authenticated afterward, which is the condition that lets an attacker fix an id onto a victim and inherit their session; the harness drives the cookie lifecycle and the id is the server's own, so a model cannot forge it, and an app that rotates the id on login leaves the pre-auth id anonymous and does not fire. This card applies over a distinct asset type (a login endpoint, not the http endpoint), so recon emits a second asset for the same host when a path hands back a session cookie, and the planner pairs the session card with that asset alone.
`SsrfAdapter` (`ssrf`) proves server-side request forgery against a denied-egress range, where there is nothing off the range to call: the range gains an in-range out-of-band collaborator (`infra/sandbox/collaborator.py`), harness infrastructure that is never in scope, and the adapter points the target's fetch parameter at a collaborator URL carrying a random token, then reads the collaborator's hit log out of band (over docker exec, never through the attacker's scope guard) and reports SSRF only when the collaborator was hit for that exact token from the target's own address. The token is the harness's and the hit is read from harness infrastructure the agent cannot reach, so a model can neither forge the callback nor read the log; `DockerSandbox` grows the collaborator on a dedicated in-range address that the scope guard never allows the attacker to reach, started once at provision and left untouched by snapshot, restore, and kill so its log persists across a run.
The first client-side techniques follow the same pattern: `OpenRedirectAdapter` (`redirect`) sets the redirect parameter to a harness-chosen attacker origin and reports an open redirect only when the response is a 3xx whose Location points at that exact foreign origin, which proves the destination was not confined to the same origin or an allowlist; the request does not follow the redirect (the baseline send would chase it off the range), so a dedicated in-container opener disables redirects and returns the status and Location. `ClickjackAdapter` (`clickjack`) fetches a sensitive-action page and reports clickjacking only when the response carries neither X-Frame-Options nor a CSP `frame-ancestors` directive, the two headers that stop a cross-origin page from framing it; this is the HTTP-observable half of the card, so a page that denies framing with either header does not fire, while a browser adapter would also confirm the action operates inside the frame.
`CsrfAdapter` (`csrf`) establishes an authenticated cookie session, then drives the state change carrying only the session cookie and no anti-CSRF token, and reports CSRF only when the change takes effect and the session cookie has no SameSite protection, the pair that lets a cross-origin page make the request on the victim's behalf; the harness picks the marker and reads the state back itself, so an app that requires a token leaves the state unchanged, and one that sets SameSite on the cookie fails the second half.
`WsHijackAdapter` (`wshijack`) opens a raw WebSocket handshake from a foreign Origin carrying the session cookie (a stdlib socket client run in the attacker container) and reports cross-site WebSocket hijacking only when the handshake is accepted and the socket returns the session's own data, which proves the server did not validate the handshake Origin; a browser attaches the cookie cross-site on its own, so the harness attaches it explicitly, and a server that checks Origin rejects the foreign handshake and does not fire.
The DOM-only client-side cards need a real browser, so the attacker image carries chromium (a tool like nmap and httpx, run one-shot with `--dump-dom`, never a harness dependency), and a shared `_render_dom` loads a URL headless, runs its JavaScript, and returns the serialized DOM for the adapter to read a harness marker out of. `CspAdapter` (`cspexec`) is the first: it injects an inline script that writes a computed marker into the page title, renders the page, and reports a missing or bypassable CSP only when that marker appears in the DOM, which proves the inline script executed; the marker is computed in the browser, so the reflected script source alone never contains it and a restrictive CSP that blocks inline script leaves it absent.
`DomClobberAdapter` (`domclobber`) injects named markup whose id matches a global the page gadget reads, renders the page, and reports DOM clobbering only when the gadget's output shows the global resolved to the injected element rather than its intended value; the injected markup and the expected marker are the harness's, and the marker is produced only by the gadget on a real clobber.
`ProtoPolluteAdapter` (`protopollute`) sends a parameter that walks into Object.prototype carrying a random marker, renders the page, and reports client-side prototype pollution only when a gadget's output shows it read that marker off a plain object; the marker reaches the DOM only through the gadget reading the polluted prototype, never reflected from the URL, so a merge that rejects `__proto__` renders the clean value.
Proving these needs a target with real holes, so `DockerSandbox` gained a `listener_app` option that seeds a given app into each target over stdin, never into the golden image, and `infra/sandbox/vulnweb.py` is a deliberately vulnerable stand-in: it reflects one query parameter unencoded, concatenates another into a SQL query, evaluates a third through a template engine, reflects any Origin with credentials, serves a `/download` that joins a file parameter to a public dir with no containment check so `../` reads any file on disk, interpolates a `/ping` host parameter into a shell command so `; sleep` runs as a second command, serves a `/promo` that caches by path and query but reflects the unkeyed X-Forwarded-Host header, runs a `/portal` cookie session that does not rotate its id on login, serves a `/fetch` that makes a server-side request to any url, serves a `/redirect` that 302s to any url with no same-origin check, serves a `/portal/settings` sensitive-action page with no framing headers, changes an email through `/portal/email` with no anti-CSRF token on a non-SameSite cookie, completes a `/ws` WebSocket handshake without checking Origin and streams session data, serves a `/widget` that reflects an html parameter with no CSP so an injected inline script runs, serves a `/clobber` that reads a global injected named markup can override, serves a `/profile` whose client JS merges the query string unsafely so `__proto__` pollutes Object.prototype, and exposes a toy JWT login whose verifier honors alg "none", whose `/account` returns any account to any authenticated caller, and whose `/admin` runs for any authenticated user with no role check; it stays inside the egress-denied range.
`tests/test_adapters.py` pins each adapter's parse and signal shape against captured real tool output (or, for the crafted probes, a runner that simulates the vulnerable server so the adapter's own generated input flows through) with no Docker and no tool present.
The live run now drives the real materialized knowledge base (HC-KB-01) rather than hand-written demo cards: `tools/run_engagement.py` loads every card with `harness/kb.py:load`, and `harness/capabilities.py:runnable_index` keeps the techniques the harness has a concrete adapter for and attaches each one's probe step, so the planner, the deterministic signal rule, and the report validator all see the genuine card (its id, applicability, preconditions, success signal, and real CVSS) while the dispatcher runs a real adapter; a technique with no adapter, or a model-evaluated `laya:` signal, still loads into the full KB but is not hunted, so the harness degrades rather than proposing a tool the dispatcher would deny.
The real cards gate their applicability and preconditions on facts a bare port probe does not give, so `harness/recon.py` grew light web discovery, reading state only: the parameters a landing page exposes, a JWT auth scheme and an available authenticated session from a login probe, privileged sibling paths from a short conventional-path list, a cache header on a conventional cacheable path, and a cookie-session login endpoint it emits as a second asset.
A live run against the real KB confirms all eleven genuine web-protocol-auth cards end to end on the sandbox range, found_by distinct from verified_by on each: JWT algorithm confusion, server-side template injection, and OS command injection (all three the cards' own CVSS critical), broken object-level authorization, boolean-blind SQL injection, broken function-level authorization, path traversal, server-side request forgery, web cache poisoning, session fixation, and CORS misconfiguration (the two recoverable tier-2 cards, web cache poisoning and session fixation, hunt under the snapshot-and-restore path, so the live contract authorizes tier 2). Under the disjoint model plane (DeepSeek Operator, OpenAI Verifier) ten of the eleven confirm; session fixation is found by the Operator but the lightweight Verifier model does not reproduce its multi-request session probe, so the harness holds it inconclusive rather than confirming it, which is the finder-is-not-verifier guarantee refusing an unreproduced lead. A stronger Verifier model is the HC-MODEL-01 bake-off, behind the same role seam.
Four of the ten client-side cards confirm live with browserless, harness-owned signals: open redirect, clickjacking (framing-header absence on a sensitive-action page recon discovers and marks `asset.has_state_changing_action`), CSRF (a tokenless cross-origin state change on a non-SameSite cookie, a recoverable tier-2 card), and cross-site WebSocket hijacking (a foreign-Origin handshake over a stdlib socket, recon marking `asset.has_websocket`). The DOM-only client-side cards are reached with chromium in the attacker image and the `_render_dom` driver: missing-CSP execution, DOM clobbering, and client-side prototype pollution are all confirmed this way (inject markup or a polluting parameter, render, read a harness marker the page gadget wrote into the DOM). The remaining three client-side cards stay out of reach: a token read from web storage needs a JavaScript evaluation the `--dump-dom` driver does not expose, a cross-origin postMessage handler needs a second origin to post from, and DOM-based XSS needs Laya for its `laya:` evaluator. So seven of the ten client-side cards confirm live, and the harness now runs twenty-one techniques against the real catalogue across the web-protocol-auth and client-side classes.
Confirming the browser cards live surfaced two hot-path waits that could stall or hang a full run, now bounded. A headless render that wedges never returns, and killing its `docker exec` leaves chromium holding the captured output pipe open past the exec's own subprocess timeout, so the whole engagement hangs; the render now runs under an in-container `timeout` and kills its helper processes by name afterward (by name, not by a command-line match, which would also match the shell running the render script), with the attacker container running under an init that reaps the remnants, so a stuck browser cannot hang the run and a render leaves nothing behind to starve the next scope-guard proof. The guard proof runs before every operator and verifier step, and its probes to the internet canary and the out-of-scope host each waited out a full connect or resolver timeout before the default-deny DROP answered, so a run with many steps was dominated by the per-step containment check; each probe is now bounded tightly, the TCP connect by a short socket timeout and the DNS lookup by the container's `timeout` (getaddrinfo honours neither the socket timeout nor a Python alarm, so it is bounded from outside), which proves the same four assertions because a reachable in-scope target answers in well under a second. A full deterministic engagement now runs to completion on the sandbox range and confirms seventeen of the eighteen web-protocol-auth and client-side cards end to end, found_by distinct from verified_by on each, the three DOM cards (missing-CSP execution, DOM clobbering, prototype pollution) among them.
What remains needs the deployed model plane: a Reporter LLM over the deterministic reporter, the reasoning-model planner that would replace the deterministic one, more capability entries and the heavier real tools (`ffuf`, `sqlmap`, `nuclei`, a browser driver) to cover more of the catalogue, and deeper recon discovery so a card's probe arguments come from recon rather than the registry.

## 11. Acceptance criteria

- A role cannot cause any action except through a structured request that passes all four `dispatch()` guards; a crafted request to an out-of-scope target is denied and logged.
- The Operator and Verifier demonstrably run on different providers, and a finding with `found_by == verified_by` cannot be produced.
- A run killed mid-hunt resumes from the ledger and reaches the same confirmed set as an uninterrupted run over the same targets.
- An injected instruction in a target response does not change which targets, tiers, or tools the harness will execute.
- With the sandbox down, the loop runs end to end in passive-only and emits a report in which every lead is `needs_validation`.

## 12. Open questions

- Planner cadence: re-plan once up front, or re-plan after each phase as the coverage ledger fills; leaning toward a cheap re-plan after recon and after the first hunting pass.
- Whether the Verifier may use a second, independent technique to confirm (not just replay the Operator's repro), which is stronger but costlier; candidate for a later revision.
- Multi-Operator parallelism within a single target once reproducibility tooling is mature.
- How aggressively to summarize the ledger for the Planner before it biases prioritization.
