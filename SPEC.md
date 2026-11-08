# HackCulture - Autonomous Authorized Pentest Agent

**Status:** Living design spec (exploration / pre-build)
**Last updated:** 2026-11-08
**Scope of this document:** architecture and methodology for an agent that performs authorized penetration testing against its own disposable sandbox targets. This is a build-from spec, not an implementation.

## How to read this doc

This is a living spec.
When a decision changes, update the relevant section and add a line to the Decision log at the bottom.
Sections are ordered foundation-first: the substrate (authorization and sandbox) comes before the agent, because every safety property depends on it.

The one sentence that governs everything else: **the harness is code, the agent is prompted.**
Anything that must be reliable, auditable, or safety-critical lives in deterministic code and is never left to model judgment.
The agent decides what to try and why; the harness decides what is allowed to actually execute.

---

## 1. Thesis

Build a deterministic harness (orchestration, state, safety, scope) that drives an LLM agent (reasoning, hypothesis, adaptation) through a multi-phase pentest against a disposable sandbox target, grounded in a versioned knowledge base of real attacker techniques (MITRE ATT&CK + OWASP + CWE), producing independently reproduced findings.

How this differs from the Cloudflare `security-audit-skill` that inspired it: that skill is a static code auditor that reads a repository.
HackCulture is a dynamic pentest agent that runs attacks against a live running target inside a sandbox.
We borrow its good structural ideas (phased workflow, finder-is-not-verifier, coverage ledger, schema-validated findings) and build an original architecture around the dynamic case.

---

## 2. Design principles

- Scope is enforced in the network layer, not the prompt: a model instruction is a suggestion, a dropped packet is a guarantee.
- Finder is never verifier: a finding is a hypothesis until a second, independent agent reproduces its success signal from the repro steps alone, in a fresh snapshot.
- Coverage is a first-class artifact: track a target-by-technique matrix, because "we did not find SQLi" is meaningless without "we attempted 14 injection techniques across 9 endpoints."
- Techniques are structured data, not prose: each attacker pattern is a machine-readable card with preconditions, probe steps, and a success signal.
- Blast radius is tiered and gated: every technique is tagged by destructiveness, and destructive tiers require a snapshot and explicit authorization before they run.
- Idempotent, resumable, append-only: every run restores from a known snapshot, every action is logged append-only, and a run can be killed and resumed from its ledger.
- Put non-generative models on untrusted boundaries: a classifier that only emits a typed label cannot be prompt-injected by target output the way an LLM can.

---

## 3. Authorization and sandbox substrate

This is the load-bearing wall.
An autonomous agent firing exploits is only "authorized pentesting" because the substrate makes it impossible to be anything else.
Nail this first (milestone M0) and never compromise it.

### 3.1 Engagement contract

A signed, declarative input parsed before anything runs.
The harness refuses to start if the target resolves outside `in_scope_cidrs`.

```yaml
scope:
  in_scope_cidrs:  [10.13.0.0/24]
  in_scope_hosts:  [app.sandbox.local, api.sandbox.local]
  out_of_scope:    [10.13.0.1]        # e.g. the gateway, always excluded
  max_blast_tier:  2                   # 0=passive .. 3=destructive
  allowed_tactics: [recon, initial-access, discovery, cred-access]
  forbidden:       [exfil-to-internet, persistence-survive-reset]
  window:          { start, end }      # time-boxed
  authorized_by:   <name/ticket>
```

### 3.2 Sandbox runtime

- Disposable, snapshot-restorable VMs or containers (Firecracker microVMs or a dedicated hypervisor pool), cloned per run.
- Egress-denied by default: the scope guard is an outbound firewall (nftables or eBPF) that allows traffic only to in-scope targets and drops everything else, including internet egress.
- This single control enforces scope and simultaneously prevents an exploited box from phoning home.
- Snapshot before each destructive-tier action, and restore on completion or abort.
- A host-level kill switch the harness can hit to freeze the whole network segment.

### 3.3 The non-negotiable fallback

If no OS-enforced sandbox is confirmed live, the harness runs in `passive-only` mode and every lead stays `needs_validation`.
It never executes exploit code without the sandbox confirmed up.

---

## 4. System architecture

Two trust zones: the harness (code, our trust boundary) and the sandbox (egress-denied target network).
Only normalized, gated tool calls cross from the harness into the sandbox.

```
            +---------------------- HARNESS (code, trust boundary) ----------------------+
            |                                                                            |
 roles ---> |   Planner / Operator / Verifier / Reporter   (generative reasoning)        |
            |        |                                                                   |
            |        v                                                                   |
            |   +----------+   per-role virtual keys, budgets, rate limits, fallback,    |
            |   | BIFROST  |   semantic cache, Prometheus/tracing  -> audit log          |
            |   +----+-----+   (Verifier pinned to a different provider than Operator)   |
            |        v                                                                   |
            |   23+ providers / many models                                             |
            |                                                                            |
            |   +--------------+   typed decisions + calibrated confidence (hot paths):   |
            |   | LAYA sidecar |   success-signal triage, verdict gate, applicability,    |
            |   | (self-hosted)|   prioritization, CWE/severity bucket                    |
            |   +--------------+   <- sits on the raw-target-output boundary              |
            |                                                                            |
            |   +------------------+  CVE / exploit intel + KB freshness (recon role)     |
            |   | ENRICHMENT svc   |--> TAVILY (via Bifrost MCP)   [untrusted data in]    |
            |   | (OUTSIDE sandbox)|                                                      |
            |   +------------------+                                                      |
            |                                                                            |
            |   State: Coverage Ledger | Findings Store | Evidence Store | Audit Log     |
            |   Controls: Scope Guard | Snapshot Mgr | Blast-tier Gate | Rate/Kill       |
            +--------|-------------------------------------------------------------------+
                     |  only normalized, gated tool calls cross into v
            +--------v------------------ SANDBOX (egress-denied) ------------------------+
            |   target VMs, scope-guard firewall, snapshot/restore, tool adapters         |
            +----------------------------------------------------------------------------+
```

### 4.1 Components

- **Orchestrator:** a phase state machine (section 6). It is the only thing that advances phases, and it owns the loop.
- **Agent roles:** Planner, Operator, Verifier, Reporter, run as separate prompted sessions so the Verifier has no memory of how the Operator convinced itself a bug was real.
- **Tool adapters:** wrap real tools behind a normalized `{tool, args, target, tier} -> {stdout, parsed, artifacts}` interface.
- Every adapter call passes through the scope guard and blast-tier gate before execution; the agent requests a call, the harness decides whether it runs, and the agent never gets a raw shell.
- **State stores:** coverage ledger, findings store, evidence store, and audit log, all append-only.
- **Model plane:** Bifrost, Laya, and the Tavily enrichment service, detailed in section 5.

---

## 5. The model plane

Three distinct planes, each with a different job and a different I/O shape.

### 5.1 Bifrost: the model and governance plane (required)

Bifrost is an Apache-2.0 Go AI gateway: one OpenAI-compatible endpoint in front of many providers, with fallback, load balancing, semantic caching, Prometheus and tracing, and hierarchical budgets, virtual keys, and rate limits.

All generative LLM traffic routes through it; no agent role talks to a provider directly.

- One virtual key per role, each with its own budget and rate limit.
- The Operator can be capped hard, the Reporter can use a cheap model, and the Verifier can be pinned to a different provider or model than the Operator so finder and verifier do not share a failure mode.
- Bifrost budgets and rate limiting become the concrete implementation of the section-11 budget guardrail.
- Bifrost request logging and tracing feed the audit log: which role asked which model what, and when.

The bright line: Bifrost is also an MCP and agent gateway that can broker tools to models.
Do not let that become how pentest tools reach the model.
Scope-guard and blast-tier validation must stay in the harness and be unbypassable; if tool adapters are exposed over MCP at all, they still call back through the harness gate.
Bifrost governs model access, the harness governs what executes against the target.

Route only generative traffic through Bifrost.
The decision models have a different I/O shape and belong on their own path.

### 5.2 Laya: the in-loop decision layer

Laya (Convai Innovations, open-weights, Apache 2.0) is a non-generative "System One" decision model that emits typed answers (choice, score, yes/no with calibrated confidence), fast and cheap, and by construction it cannot hallucinate free text.
It complements the LLM, it does not replace it: the LLM defines the decision, the decision model executes the repeated structured part.

It runs as a local sidecar inside the trust boundary, called directly by the harness (not through Bifrost's chat-completions shape).
Use the English ModernBERT-large checkpoint, whose pretraining covers code and technical text, which matches our input distribution of HTTP headers, stack traces, and DB errors.

Where it slots in (the high-frequency hot paths):

- Success-signal triage in the hunting loop: "does this response indicate a SQL error," "is this reflected input executing versus merely echoed," "is this a real auth bypass or just a 200."
- The verdict gate: its calibrated confidence becomes a deterministic threshold in the harness, e.g. `confidence < 0.9 -> stays needs_validation -> independent Verifier`.
- Applicability predicates (which technique cards fit an asset) and lead prioritization (which pair to try next).
- Evidence-to-CWE and severity bucketing.

Why Laya over Jev (TypeSafe AI) for this system specifically: Jev is hosted, so in-loop use would ship sensitive probe evidence to a third party and require internet from the boundary that is supposed to have none.
Laya is open-weights and self-hostable, so it runs air-gapped with zero egress, and it can be fine-tuned locally on sensitive evidence (section 10), which hosted Jev cannot.
Reserve Jev, if used at all, for non-sensitive meta-tasks, never for target-touching decisions.

Security bonus: a non-generative classifier on the boundary that ingests raw target output cannot be prompt-injected by attacker-influenced content the way an LLM could, so Laya there shrinks the prompt-injection blast radius.

### 5.3 Tavily: the enrichment plane (optional, outside the sandbox)

Tavily is a search, extract, and crawl API built for agents, usage-priced.
It is genuinely useful here, with one non-negotiable boundary: the sandbox has no internet egress, so Tavily is never called from inside it.
It lives in a harness-side enrichment service that runs outside the target network and feeds results in as data.

- Recon enrichment: a detected stack and version (nginx 1.18.0, a specific library, a CMS) becomes a lookup of known CVEs, advisories, default creds, and public write-ups, which informs which technique cards apply.
- KB freshness: research new TTPs and advisories to keep technique cards current.

Rules:

- Tavily may be brokered as an MCP tool through Bifrost, but exposed only to the recon/enrichment role, not the sandbox Operator.
- Treat every Tavily result as untrusted external data, the same as target responses: fetched web content enters as reference context for a decision or planning step, never as instructions the Operator executes.
- The harness degrades to `passive-intel-off` cleanly if there is no Tavily key.

---

## 6. Multi-phase methodology

Grounded in PTES and NIST SP 800-115, with ATT&CK tactics as the spine.
Each phase has an entry gate, an exit criterion, and writes to the coverage ledger.

| Phase | ATT&CK / PTES mapping | Agent does | Harness enforces | Exit criterion |
|---|---|---|---|---|
| 0. Pre-engagement | PTES pre-engagement | Parse scope, build target model | Scope validation, sandbox liveness | Contract valid, sandbox up |
| 1. Recon | Recon + Discovery | Passive and active enumeration (hosts, ports, services, routes, stack, auth surfaces) | Tier <= 1, rate-limited | Asset inventory complete |
| 2. Threat modeling | PTES threat modeling | Map assets to technique cards via applicability predicates | - | Candidate technique set per asset |
| 3. Coverage-led hunting | Initial Access, Execution, etc. | For each (asset, technique): run probe steps, check success signal | Blast-tier gate, snapshot before destructive | Matrix filled, leads logged |
| 4. Validation | - | Verifier reproduces each lead in a fresh snapshot from repro steps only | Fresh snapshot per verification | Every lead resolved to a verdict |
| 5. Post-exploitation (optional, gated) | Priv-esc, lateral, persistence, exfil | Only if the contract allows; demonstrate impact, do not maximize damage | Hard tier cap, egress-denied | Impact chain documented |
| 6. Reporting | PTES reporting | Reporter writes a target-neutral report from the findings store | Schema validation | Report passes the validator |

### 6.1 The hunting loop (phase 3), per technique card

1. Check preconditions against current target state; skip if unmet (log `not_applicable`).
2. If `tier > contract.max_blast_tier`: log `blocked_by_policy` and skip.
3. If destructive: request a snapshot.
4. Execute probe steps through tool adapters.
5. Evaluate the success signal (deterministic where possible, Laya for the fuzzy calls).
6. Write the outcome to the ledger; if the signal is hit, emit a `lead` to the findings store.
7. Restore the snapshot if one was taken.

Empirical note carried over from the Cloudflare skill: one pass finds roughly half of what repeated passes find in total.
Make runs repeatable and cheap so coverage accretes across runs rather than betting on one perfect run.

---

## 7. The attacker-pattern knowledge base

This is the "grounded on actual attacker patterns" core.
Do not write freeform prose; make each technique a structured card so the agent is driven by data.

### 7.1 Grounding sources (public, authoritative, real-adversary-derived)

- MITRE ATT&CK: the catalog of TTPs actually observed in the wild, the spine for tactics (the why) and techniques (the how).
- OWASP WSTG (web testing), ASVS (verification requirements), Top 10, and LLM Top 10 for AI targets.
- MITRE CWE: the weakness taxonomy findings are tagged with.
- CVSS v4: severity scoring.

### 7.2 Technique card schema

```yaml
id: KB-WEB-INJ-SQLI-001
title: Error-based SQL injection in query parameter
attack:   { tactic: TA0001-initial-access, technique: T1190 }
owasp:    [WSTG-INPV-05]
cwe:      CWE-89
applicability:            # predicate over the target model
  - asset.type == http_endpoint
  - asset.params.length > 0
preconditions: [ reachable, accepts_user_input ]
blast_tier: 1             # read-only probing; data modification would be higher
probe_steps:              # ordered, each a normalized tool-adapter request
  - { tool: httpx, intent: baseline_response }
  - { tool: custom.sqli_probe, intent: inject_error_payloads }
success_signal:
  type: response_diff
  assert: "db_error_fingerprint present OR boolean_oracle divergence"
severity_rubric: { base: high, raise_if: [writable, authn_bypass] }
cleanup: none
references: [owasp-wstg-url, attack-url]
```

### 7.3 KB structure and versioning

Group cards by target class, each card kept as data:
`web-protocol-auth`, `client-side`, `ai-llm`, `cloud-deployment`, `supply-chain`, `rpc-messaging`, `resource-exhaustion`, `data-isolation`, `memory-binary`, `mobile-local-ipc`.

Version the KB in git.
A new real-world TTP becomes a new or revised card, which improves coverage for every future run without touching harness code.
That separation (stable harness, evolving KB) is what lets the system grow the way Cloudflare's did.

---

## 8. Findings and independent verification

### 8.1 Verdict lifecycle

`lead -> needs_validation -> confirmed | rejected`.

### 8.2 Finding schema

Validated by a zero-dependency checker, runnable in CI.
The report does not ship unless it validates.

```json
{
  "id": "F-2026-0007",
  "technique_id": "KB-WEB-INJ-SQLI-001",
  "asset": "api.sandbox.local/orders?id=",
  "cwe": "CWE-89",
  "cvss": { "vector": "...", "score": 8.1 },
  "verdict": "confirmed",
  "found_by": "operator-session-A",
  "verified_by": "verifier-session-B",
  "repro": ["step 1 ...", "step 2 ...", "observed signal ..."],
  "evidence": ["artifact://pcap/...", "artifact://resp/..."],
  "impact": "read arbitrary rows from orders table",
  "remediation": "parameterize query; see CWE-89",
  "blast_tier_used": 1
}
```

### 8.3 Verification protocol (the hard rule)

- A lead carries only its repro steps and evidence pointers into a fresh Verifier session against a fresh snapshot.
- The Verifier gets no access to the Operator's reasoning.
- It either reproduces the success signal (confirmed) or cannot (stays needs_validation, or rejected with a reason).
- `found_by == verified_by` is a schema violation; the validator rejects the report.
- A defense-in-depth gap with no demonstrated impact is a `hardening_note`, not a finding, which keeps severity honest.

---

## 9. Evidence store and self-labeling corpus

Decision (2026-11-08): the harness logs the Verifier-labeled corpus from day one, and the evidence store retains raw probe I/O, not just the final finding.
The raw probe I/O is the atomic, immutable record; findings and labels both hang off it as references.
Parsed features can always be recomputed, raw request and response cannot be reconstructed after the fact, so the raw I/O is what we persist.

### 9.1 The three records

`probe_event` (atomic, append-only, the training substrate):

```
probe_event
  id, engagement_id, ts
  provenance:    eval_seed | live_engagement   # quarantines seeded vulns from training
  split_bucket:  train | test                  # deterministic = hash(engagement|asset), set at write
  phase, role                                  # hunting/validation ; operator/verifier
  target_asset, snapshot_id                    # snapshot_id makes the event replayable
  technique_id + technique_version             # pinned to the exact KB card version
  tool, tool_args
  request_raw_uri, response_raw_uri            # full I/O (and pcap) as blobs in object store
  parsed                                       # derived: status, headers, timing, fingerprints
  deterministic_signals                        # what the regex/code gate already concluded
```

`finding` (references events, never duplicates them):

```
finding
  id, technique_id, asset, cwe, cvss
  verdict:            lead | needs_validation | confirmed | rejected
  found_by_event_ids, verified_by_event_ids    # the actual probe_events on both sides
  found_by_session, verified_by_session         # schema rejects if equal
  repro, impact, remediation
```

`label` (the training signal; one raw event can yield several):

```
label
  id, probe_event_id, ts
  decision_point:  success_signal | applicability | severity_bucket | ...   # which classifier it trains
  value            # the typed class
  confidence       # if model-produced
  source:          verifier | human_audit | strong_llm_audit | deterministic
  tier:            gold | silver            # audited vs auto
  labeler_id, model_version                 # provenance (LLM labels via Bifrost, versioned)
  supersedes:      label_id?                # re-audit appends, never mutates
```

### 9.2 The corpus view

The fine-tuning corpus is a view: join `probe_event` to `label` on a given `decision_point`, filter `split_bucket = train`, exclude `provenance = eval_seed`, prefer `tier = gold` where present.
Out comes `(raw text + parsed features, typed label, confidence, tier)`, LoRA-ready, with eval targets structurally impossible to leak into training.

### 9.3 Five rules that keep the corpus honest

- Split is a property of the event, set at write time and deterministic, so a given asset lands in the same bucket forever and never straddles train and test across runs.
- `eval_seed` is quarantined by construction, not by a filter someone has to remember to apply.
- Labels are append-only: a re-audit writes a new row that supersedes the old, and gold overrides silver at training time.
- The corpus is a sensitive asset because it holds raw target data, so it lives inside the trust boundary, encrypted at rest and access-controlled, which is also the hard reason the fine-tune runs locally on Laya and never on hosted Jev.
- Add a PII-tagging pass on the raw blobs if targets ever mirror realistic data.

### 9.4 Storage tiers

- Metadata, parsed features, and labels in Postgres.
- Raw request, response, and pcap as content-addressed, compressed blobs in object storage, which deduplicates near-identical responses.
- Retention policy keyed per engagement.

---

## 10. Laya decision layer and fine-tuning strategy

The sequence is: start zero-shot, fine-tune only where a measured baseline shows a gap, and lean on the fact that this system produces labeled training data for free.

### 10.1 Start zero-shot (M3-M4)

Decision models do zero-shot typed classification against a defined label schema per decision point.
Stand that up first and measure it against the seeded-vuln harness, because you cannot know whether fine-tuning is worth the maintenance burden without that baseline.

Pull the cheaper levers before touching weights:

- Curate the label definitions and a few exemplars in each decision schema (the decision-model equivalent of prompt engineering).
- Keep deterministic signals as plain code, not ML: a known DB-error fingerprint or an exact boolean-oracle divergence is a regex, so Laya only ever sees the genuinely fuzzy calls.

### 10.2 The self-labeling flywheel

The independent Verifier produces ground-truth labels for every lead as a byproduct of the confirm/reject lifecycle.
Every run appends `(probe output -> verdict)` pairs at zero extra labeling cost.
This is also the thing hosted Jev structurally cannot do, because fine-tuning on sensitive evidence requires the evidence to stay inside the trust boundary.

### 10.3 Targeted fine-tuning, if the baseline underperforms

Small per-decision LoRA adapters on a 300-400M base, trivial on a single GPU, not one mega-model.
Three hygiene rules make or break this:

- Never train on the seeded-vuln eval targets, enforced by the `provenance`/`split_bucket` design in section 9.
- Calibration is the deliverable, not accuracy, because the verdict gate thresholds on confidence; re-check calibration (reliability diagram / ECE) after every fine-tune, and if it degrades, apply post-hoc recalibration (temperature or Platt scaling) or keep the gate deterministic and demote Laya to an advisory ranker.
- Do not let the model gate its own training data unaudited; keep a held-out stream that a human or a stronger LLM audits periodically so the flywheel cannot drift.

---

## 11. Safety and guardrails (engineered, not prompted)

These live in harness code, and each has a test:

- Scope guard: outbound firewall allows only in-scope targets, the DNS resolver refuses out-of-scope names, and there is a pre-flight re-check before every tool call.
- Blast-tier gate: rejects any action above `contract.max_blast_tier`, and destructive tiers require a live snapshot handle.
- Rate limiter and budget: caps requests per second per target and total actions and tokens per run (implemented via Bifrost virtual keys and budgets), failing closed so a blown budget stops the agent rather than falling through to a direct provider call.
- Kill switch: a single call freezes the segment and restores snapshots.
- Append-only audit log: every requested action, allow/deny decision, and outcome, timestamped (am/pm) with the responsible agent role.
- No raw shell, ever: the agent only emits normalized tool-adapter requests, and a new capability is a new reviewed adapter, not a model that can type arbitrary commands.

---

## 12. Technology stack

- Harness and orchestrator: Go for a single static safety-critical binary, or Python (async) for faster iteration and a closer security-tool ecosystem.
- Agent loop: a tool-use loop over the Claude API with role-separated sessions, where the harness owns the loop and validates every proposed call.
- Model gateway: Bifrost (`npx @maximhq/bifrost` or Docker on 8080, or embedded Go SDK), with per-role virtual keys.
- Decision model: Laya self-hosted as a local sidecar (English ModernBERT-large checkpoint).
- Enrichment: Tavily via the harness-side enrichment service, outside the sandbox.
- Sandbox: Firecracker microVMs or a hypervisor pool with snapshot and restore, nftables or eBPF for the scope guard.
- Tool adapters: nmap, httpx, ffuf, sqlmap, nuclei, a headless browser (Playwright) for client-side, plus custom probe scripts, all with normalized I/O.
- State: findings, coverage ledger, labels, and audit log in Postgres; evidence blobs in object storage referenced by URI.
- Validators and schema: zero-dependency, runnable in CI.

---

## 13. Build roadmap

1. M0 - Substrate: sandbox with snapshot/restore, scope-guard firewall, engagement-contract parser; prove you cannot reach an out-of-scope host even when you try. Nothing else starts until this is solid.
2. M1 - Harness skeleton: phase state machine, coverage ledger, findings store, evidence store (raw I/O plus the label table from the first commit, per section 9), audit log, blast-tier gate; drive it with scripted actions, no agent yet.
3. M2 - KB v0: 15-20 technique cards across web and auth, with schema and validator.
4. M3 - Single-role agent: Operator only, runs phases 1-3 against one deliberately vulnerable sandbox target; leads only, all needs_validation; Laya zero-shot on success-signal triage.
5. M4 - Verification: add the independent Verifier and the confirm/reject lifecycle; the self-labeling corpus starts filling automatically from here.
6. M5 - Reporter and schema-gated output: target-neutral reports that pass the validator.
7. M6 - Scale coverage: grow the KB, add target classes, run repeated passes, and fine-tune Laya per-decision only where the M3-M4 baseline shows a gap.

---

## 14. Evaluation

- Seeded-vuln recall: stand up sandbox targets with a known set of planted vulns and measure the fraction the agent confirms. This is the primary metric.
- False-positive rate: fraction of confirmed findings that are not actually exploitable; the finder-is-not-verifier rule should keep this near zero.
- Coverage completeness: of applicable (asset, technique) pairs, what fraction were actually attempted.
- Scope violations: must be exactly zero, enforced by the guard and confirmed by the audit log; any nonzero value is a stop-the-line bug.
- Cost per confirmed finding: tokens plus wall-clock, to keep repeated-pass economics sane.
- Decision-model quality (once Laya is in the gate): success-signal accuracy and, critically, whether confidence is calibrated on our own probe outputs.

---

## 15. Open threads (next up)

- Technique-card starter set: the full web-plus-auth class, around 15 cards, with applicability predicates and success signals.
- Agent loop wired through Bifrost: role sessions, per-role virtual keys and budgets, and the "harness validates every proposed call" pattern against the Claude API tool-runner.

---

## 16. Decision log

- 2026-11-08: Harness-is-code / agent-is-prompted adopted as the governing principle.
- 2026-11-08: Dynamic pentest agent, not a static code auditor; Cloudflare skill used for structural ideas only.
- 2026-11-08: Bifrost adopted as the required model and governance plane; only generative traffic routes through it, tool execution stays behind the harness gate.
- 2026-11-08: Laya chosen over Jev for the in-loop decision layer, on air-gap and data-control grounds (open-weights, self-hosted, locally fine-tunable).
- 2026-11-08: Tavily adopted as optional enrichment, strictly outside the sandbox, output treated as untrusted.
- 2026-11-08: Log the Verifier-labeled corpus from day one; evidence store retains raw probe I/O; fine-tune later and only on a measured gap.
- 2026-11-08 (HC-SUB-01): Scope guard is a no-route topology, not only firewall rules; the sandbox has no path to the internet or operator LAN to misconfigure around.
- 2026-11-08 (HC-SUB-01): Tool adapters run on an attacker VM inside the isolated range, driven over a separate narrow authenticated control plane, so a target pivot stays contained.
- 2026-11-08 (HC-SUB-01): In-scope hostnames are pinned to IPs at provisioning via a sandbox-only resolver, closing the DNS-rebinding TOCTOU; the guard enforces on pinned IPs.
- 2026-11-08 (HC-SUB-01): The agent itself is in the threat model; the substrate contains our own autonomous agent as if it were hostile, not only the simulated attacker.
- 2026-11-08 (HC-AGENT-01): A denied tool call returns a structured reason the role must adapt to (capped by max_denied), not an exception, so the agent reasons rather than crashes.
- 2026-11-08 (HC-AGENT-01): The Verifier is pinned and never falls back onto the Operator's provider, because a shared model would silently break finder-is-not-verifier.
- 2026-11-08 (HC-AGENT-01): Semantic cache is disabled for Operator and Verifier turns and allowed only for Planner/Reporter prose, so a cached response can never drive a live action.
- 2026-11-08 (HC-AGENT-01): v1 concurrency is one Operator per target, parallel only across independent target clones, to keep snapshot reproducibility.
- 2026-11-08 (HC-KB-01): Applicability is a small safe expression DSL, not arbitrary code, so cards stay auditable and a bad card cannot execute logic.
- 2026-11-08 (HC-KB-01): Success signals are deterministic-first; Laya is named only for inherently fuzzy judgments and its confidence feeds the needs_validation gate.
- 2026-11-08 (HC-KB-01): Out-of-band callbacks must terminate at an in-sandbox collaborator, never the internet; an external collaborator fails card validation.
- 2026-11-08 (HC-KB-01): Every probe_event pins card id and version, so a finding stays interpretable against the exact card that produced it.
- 2026-11-08 (HC-FIND-01): Independent verification is universal; finder-is-not-verifier reproduction is always required to reach confirmed, and signal confidence only gates whether a lead is emitted, never substitutes for verification.
- 2026-11-08 (HC-FIND-01): rejected and inconclusive are distinct verdicts; only active disproof or a known false positive is rejected, while an unestablished verdict is inconclusive and never ships as confirmed.
- 2026-11-08 (HC-FIND-01): The harness, not the Verifier model, renders the final deterministic verdict; the Verifier role exists to drive and adapt repro, so a model cannot talk itself into a confirmation.
- 2026-11-08 (HC-FIND-01): Hardening notes carry no CVSS and are reported separately from vulnerabilities, keeping severity tied to demonstrated impact.
- 2026-11-08 (HC-DATA-01): finder-is-not-verifier is enforced at the database layer (a check constraint), not only in application code.
- 2026-11-08 (HC-DATA-01): Laya's own predictions are never written as training labels; only Verifier verdicts (silver) and audits (gold) become corpus labels, which prevents a self-training feedback loop.
- 2026-11-08 (HC-DATA-01): The evidence store is self-hosted inside the trust boundary (Postgres + MinIO, no external managed service), with content-addressed blobs and per-event content hashes forming an append-only integrity chain.
- 2026-11-08 (HC-EVAL-01): False positives are measured against complete ground truth; on an eval target every real vuln is known, so any confirmed finding absent from the manifest is a false positive.
- 2026-11-08 (HC-EVAL-01): Metrics are distributions, reported as mean and spread over K eval runs, because LLM nondeterminism makes a single-number score misleading; recall is reported at both one pass and N passes.
- 2026-11-08 (HC-EVAL-01): Scope violations are a build-failing CI gate pinned at zero, not a metric to optimize; a single out-of-scope or egress event in the audit log fails the suite.
- 2026-11-08 (HC-EVAL-01): A card promotes to active only by passing its positive fixture and staying silent on its negative fixture in the standing eval suite.
- 2026-11-08 (HC-MODEL-01): Bifrost is a control-plane component on the trusted host, never reachable from the sandbox range; model traffic egresses to providers from the host and never traverses the egress-denied range.
- 2026-11-08 (HC-MODEL-01): A provider-diversity invariant is asserted at startup (fail-closed): the Operator and Verifier virtual keys must resolve to disjoint provider sets, enforcing finder-is-not-verifier at the model plane.
- 2026-11-08 (HC-MODEL-01): Budget fall-through is structurally impossible because roles hold no provider keys of their own; a breached budget stops the role and cannot reach a provider directly.
- 2026-11-08 (HC-MODEL-01): Bifrost MCP tool-brokering is forbidden as a path to the target; only read-only enrichment (Tavily) is brokered, and only to the enrichment virtual key, never the Operator.
- 2026-11-08 (HC-MODEL-02): Laya is a per-decision family of LoRA heads on one self-hosted base, called directly by the harness off the Bifrost plane, because its classify-not-chat I/O does not fit chat-completions.
- 2026-11-08 (HC-MODEL-02): Calibration, not accuracy, is the promotion criterion for a fine-tuned decision head; a calibration regression blocks promotion even when accuracy improves.
- 2026-11-08 (HC-MODEL-02): Graceful degradation when Laya is unavailable: deterministic evaluators run, and a laya-only signal keeps its lead at needs_validation rather than ever silently confirming.
- 2026-11-08 (HC-MODEL-02): If the bake-off shows poor calibration, the emission/confirm gate stays deterministic and Laya is demoted to an advisory ranker only.
- 2026-11-08 (HC-ENRICH-01): Enrichment runs only on the control plane (trusted host) and is never reachable from the range; Tavily is never called from inside the sandbox.
- 2026-11-08 (HC-ENRICH-01): Enrichment output is advisory and low-trust: provenance-tagged, delivered only to the recon/enrichment role, never as instructions, and never ground truth or corpus labels.
- 2026-11-08 (HC-ENRICH-01): Enrichment queries carry only public technology identifiers (product and version), never target data, secrets, or the user's identity, and use a generic client name.
- 2026-11-08 (HC-ENRICH-01): New cards from KB-freshness research are human-reviewed before activation; web intel never autonomously adds an active card or drives a live engagement.

---

## 17. References

- Cloudflare security-audit-skill: https://github.com/cloudflare/security-audit-skill
- Bifrost: https://github.com/maximhq/bifrost
- Laya: https://systemonemodels.org/models/laya/
- TypeSafe AI / Jev: https://typesafe.ai/blog/introducing-system-one-models-and-jev
- Tavily: https://www.tavily.com
- MITRE ATT&CK: https://attack.mitre.org
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- MITRE CWE: https://cwe.mitre.org
- NIST SP 800-115: https://csrc.nist.gov/pubs/sp/800/115/final
