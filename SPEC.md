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
- Blast radius is tiered and gated: every technique is tagged by destructiveness, state-changing tiers require a snapshot, and destructive tiers additionally require explicit authorization, before they run.
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
  allowed_tactics: [recon, initial-access, discovery, credential-access]
  forbidden:       [exfil-to-internet, persistence-survive-reset]
  window:          { start, end }      # time-boxed
  authorized_by:   <name/ticket>
```

### 3.2 Sandbox runtime

- Disposable, snapshot-restorable VMs or containers (Firecracker microVMs or a dedicated hypervisor pool), cloned per run.
- Egress-denied by default: the scope guard is an outbound firewall (nftables or eBPF) that allows traffic only to in-scope targets and drops everything else, including internet egress.
- This single control enforces scope and simultaneously prevents an exploited box from phoning home.
- Snapshot before each state-changing action (tier >= 2), and restore on completion or abort.
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
- The Operator can be capped hard, the Reporter can use a cheap model, and the Verifier can be pinned to a different (disjoint) provider than the Operator so finder and verifier do not share a failure mode.
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
3. If `tier >= 2` (state-changing or destructive): request a snapshot.
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
- MITRE ATLAS: the adversarial-ML threat matrix, the spine for AI and LLM targets where ATT&CK has no equivalent.
- OWASP WSTG (web testing), ASVS (verification requirements), Top 10, and LLM Top 10 for AI targets.
- MITRE CWE: the weakness taxonomy findings are tagged with.
- CVSS v4: severity scoring.

### 7.2 Technique card schema

```yaml
id: KB-WEB-INJ-SQLI-001
title: Error-based SQL injection in query parameter
attack:   { tactic: TA0001, technique: T1190 }
owasp:    [WSTG-INPV-05]
cwe:      [CWE-89]
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
severity_rubric: { base: high, raise_if: [ { when: "yields.writable", to: critical } ] }
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

`lead -> needs_validation -> confirmed | rejected | inconclusive`.
A lead with no demonstrated impact is split off at triage as a `hardening_note`, which is never verified (HC-FIND-01 §2).

### 8.2 Finding schema

Validated by a zero-dependency checker, runnable in CI.
The report does not ship unless it validates.

```json
{
  "id": "F-2026-0007",
  "technique_id": "KB-WEB-INJ-SQLI-001",
  "asset": "api.sandbox.local/orders?id=",
  "cwe": ["CWE-89"],
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
  verdict:            lead | needs_validation | confirmed | rejected | inconclusive
  found_by_event_ids, verified_by_event_ids    # the actual probe_events on both sides
  found_by, verified_by                        # session identities; schema rejects if equal
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
- Blast-tier gate: rejects any action above `contract.max_blast_tier`, and tier >= 2 (state-changing or destructive) requires a live snapshot handle.
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
- 2026-11-08 (HC-DATA-01): The evidence store is self-hosted inside the trust boundary (Postgres plus a content-addressed blob store, no external managed service), with content-addressed blobs and per-event content hashes forming an append-only integrity chain.
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
- 2026-11-08 (HC-SAFE-01): The audit log is append-only and hash-chained (a prev_hash per row), making it tamper-evident, not merely immutable.
- 2026-11-08 (HC-SAFE-01): Every guardrail fails closed; under any safety uncertainty the default is to stop, deny, or drop to passive-only, never to proceed.
- 2026-11-08 (HC-SAFE-01): Defense-in-depth is explicit: scope, finder-is-not-verifier, and egress are each enforced at multiple independent layers so no single bug defeats a guarantee.
- 2026-11-08 (HC-SAFE-01): Operator-facing failures state what happened, why, and what to do next with a recovery affordance, never a raw internal error; human-rendered timestamps use am/pm.
- 2026-11-08 (consistency pass): Standardized cross-spec vocabulary - finder-is-not-verifier means disjoint providers everywhere (dropped "or model"), `passive-only` is the single mode token, `cwe` is always an array, and `raise_if`/`lower_if` are always `[{when, to}]` objects; made the spec `depends_on`/`depended_on_by` frontmatter reciprocal, with the HC-AGENT-01/HC-MODEL-01, HC-AGENT-01/HC-FIND-01, and HC-FIND-01/HC-DATA-01 co-design cycles noted as intended.
- 2026-11-08 (HC-KB-03): Added the AI/LLM technique-card starter set (twelve cards across prompt injection, output handling, disclosure, excessive agency, RAG exfiltration, unbounded consumption, and guardrail bypass), grounded on the OWASP LLM Top 10 and MITRE ATLAS; the design prefers planted-canary, OOB, and tool-observation determinism over judging model text, reaching for laya:success_signal only where compliance is irreducibly fuzzy, and extends the HC-KB-01 taxonomy with an optional atlas field for classes ATT&CK does not model.
- 2026-11-08 (HC-KB-04): Added the client-side technique-card starter set (ten cards: DOM XSS, DOM clobbering, client-side prototype pollution, postMessage origin abuse, clickjacking, open redirect, CSRF, sensitive web-storage exposure, cross-site WebSocket hijacking, and weak CSP), grounded on OWASP WSTG-CLNT and CWE; signals are deterministic via headless-DOM assertions, header parsing, and controlled untrusted-origin frames, with laya reserved for the execution judgment.
- 2026-11-08 (HC-KB-05): Added the cloud-deployment technique-card starter set (ten cards: instance-metadata SSRF, IAM privilege escalation, public and writable object storage, IaC secret exposure, unauthenticated secrets endpoint, container escape, anonymous orchestration API, serverless event injection, and permissive security group), grounded on the ATT&CK cloud matrix and CWE; cloud equivalents are self-hosted on the range so the egress-denied guarantee holds, credentials and secrets are planted canaries for deterministic proof, and container escape stays bounded by HC-SUB-01 G4.
- 2026-11-08 (HC-KB-06): Added the supply-chain technique-card starter set (ten cards: anonymous registry publish, dependency confusion, typosquatting, lockfile tampering, lifecycle-script execution, CI build injection, CI secret exposure, unsigned artifact acceptance, update integrity failure, and untrusted plugin load), grounded on ATT&CK T1195 and CWE; the build and registry stack is self-hosted on the range, code-execution weaknesses prove out via range-oob callbacks, and integrity weaknesses prove out via deterministic differentials.
- 2026-11-08 (HC-KB-07): Added the rpc-messaging technique-card starter set (ten cards: insecure deserialization, XXE, type confusion, RPC method authorization, GraphQL abuse, mass assignment, webhook SSRF, webhook forgery, queue injection, and anonymous queue subscription), grounded on CWE, the OWASP API Top 10, and ATT&CK; this set also lands the XXE, GraphQL, and mass-assignment weaknesses HC-KB-02 deferred, and proves code execution via range-oob callbacks and disclosure via planted canaries.
- 2026-11-08 (HC-KB-08): Added the resource-exhaustion technique-card starter set (ten cards: ReDoS, hash-collision complexity, request amplification, XML entity expansion, decompression bomb, unbounded allocation, missing upload cap, unbounded pagination, missing rate limit, and connection exhaustion), grounded on ATT&CK T1499 and CWE; every card proves the absence of a limit with a single bounded probe rather than causing an outage, runs only when the contract authorizes availability testing, and is bounded by the dispatch rate limit, the budget, the window, and the watchdog.
- 2026-11-08 (HC-KB-09): Added the data-isolation technique-card starter set (ten cards: cross-tenant read and write, shared-cache leakage, predictable-id enumeration, exposed backups, plaintext data at rest, PII in logs, export oversharing, incomplete deletion, and residual data), grounded on CWE, the OWASP API Top 10, and ATT&CK; every card proves a boundary crossing with a planted canary, so the class is fully deterministic with no laya evaluator, and it reuses the two-account tenant fixture from HC-KB-02.
- 2026-11-08 (HC-KB-10): Added the memory-binary technique-card starter set (ten cards: stack, heap, and integer overflow, use-after-free, type confusion, out-of-bounds read, format-string leak, null dereference, TOCTOU race, and argument injection), grounded on CWE and ATT&CK T1203; the class is scoped to confirming a memory-safety defect via sanitizer diagnostics, crashes, or canary leaks on sanitizer-built range services, not to weaponized exploitation, which is a separately gated deferred capability.
- 2026-11-08 (HC-KB-11): Added the mobile-local-ipc technique-card starter set (ten cards: deep-link abuse, intent redirection, exported-component invocation, content-provider SQLi, unauthenticated local IPC socket, WebView bridge exposure, insecure local storage, extractable backup, cleartext traffic, and tapjacking), grounded on the OWASP Mobile Top 10 and CWE; this completes the ten-class knowledge base, proves out via range-oob callbacks and planted canaries, and chains local-storage plus cleartext interception into the HC-KB-02 auth chain.
- 2026-11-08 (tooling): Implemented the HC-KB-01 card validator (`tools/validate_kb.py`, pure standard library) with its bundled taxonomy reference (`tools/taxonomy.py`), adversarial self-tests (`tests/test_validator.py`), and CI (`.github/workflows/validate.yml`); it checks schema, the applicability DSL, success-signal and severity shapes, blast-tier and cleanup, in-sandbox oob, and taxonomy resolution. The validator first surfaced two ATLAS ids (AML.T0053, AML.T0057) as UNRESOLVED; both were confirmed against ATLAS v4.9.0 and added to the reference, so all 107 authored cards now pass, including --strict.
- 2026-11-08 (M2 materialization): Materialized all 107 technique cards from the condensed specs into the full `kb/<class>/*.yaml` tree (`tools/materialize_kb.py`), filling the template shipping fields (version, status, inputs, confidence_floor, a band-derived CVSS v4 base vector, convention-based test fixtures, and canonical taxonomy reference URLs), and generated `kb/_index/index.md` plus per-class `eval/manifests/*.yaml` ground-truth files (HC-EVAL-01 §4). The specs stay the source of truth; the validator now checks the full-card tree with the shipping-field, filename, and manifest-coverage gates and passes `--strict`, and CI fails if the tree drifts from the specs.
- 2026-11-08 (M0 substrate core): Implemented the buildable, safety-critical slice of HC-SUB-01 as pure-stdlib code in `harness/`: a strict YAML-subset loader (`yamlmini.py`), the fail-closed engagement-contract parser and validator (`substrate/contract.py`, runnable via `python3 -m harness.substrate.contract`), the default-deny scope pre-check with anti-TOCTOU pinning (`substrate/scope.py`), and the blast-tier gate with snapshot and tier-3 rules (`substrate/blast.py`), with 19 adversarial tests (`tests/test_substrate.py`) wired into CI. The sandbox infrastructure (microVMs, the no-route gateway, snapshot/restore, guard-proof probes, the kill switch) remains out of this repo.
- 2026-11-08 (business requirements): Added a business-requirements workstream in `docs/requirements/`: ten end-to-end requirement specs (BR-01..BR-10) stated as user stories with user-centric Gherkin acceptance scenarios, each mapped to the HC-* specs that implement it. The executable Gherkin is generated into `docs/requirements/features/*.feature` by `tools/gen_features.py` (`make features`), validated and kept in sync by CI (37 scenarios).
- 2026-11-08 (M1 data store): Implemented the evidence/findings/ledger/audit store from HC-DATA-01 and HC-SAFE-01 as pure-stdlib code in `harness/store/` (`schema.sql`, `db.py`, `ledger.py`, `findings.py`, `audit.py`), a SQLite realization of the production target (Postgres plus a content-addressed blob store) that enforces the three guarantees in the database itself: finder-is-not-verifier is a `finding` CHECK constraint (confirming with `verified_by == found_by` is rejected at the DB), evidence is append-only via BEFORE UPDATE/DELETE triggers on `probe_event`, `finding_status`, and `label`, and the audit log is hash-chained (`row_hash` over content plus `prev_hash`, excluding the autoincrement seq) so `verify_chain` detects any altered or removed row. Verdict transitions append a `finding_status` row and update the denormalized `finding.verdict` atomically. Covered by 9 adversarial tests (`tests/test_store.py`) wired into CI and `make test`.
- 2026-11-08 (HC-DATA-01, blob backend): Chose a content-addressed filesystem store as the default blob backend over running an object-storage server. The `blob://<sha256>` scheme maps directly to a path, so deduplication and write-once immutability are intrinsic, nothing extra runs on the range, and it fits the zero-dependency, egress-denied posture. A lightweight S3-compatible server (Garage, or SeaweedFS for file-level access) stays a drop-in behind the same interface if an external S3-only tool or multi-node scale-out ever requires it. MinIO is excluded: its community edition was gutted through 2025 (web console removed, prebuilt binaries and images stopped) and the `minio/minio` repository was archived in April 2026.
- 2026-11-08 (docs layout): Folded the `specs/` and `requirements/` trees into a single `docs/` directory (`docs/specs/`, `docs/requirements/`) with a short `docs/README.md` index; `SPEC.md` stays at the repo root as the overview and decision log. The three tools (`validate_kb.py`, `materialize_kb.py`, `gen_features.py`), the CI sync check, and the cross-doc links were updated to the new paths; `kb/` and `eval/` are unchanged.
- 2026-11-08 (dispatch chokepoint): Implemented the propose-and-dispose chokepoint of HC-AGENT-01 §5.2 as pure-stdlib code, wiring the M0 guards to the M1 store. `harness/dispatch.py` (`Dispatcher`, `ProbeContext`) runs the four guards in order (unknown_tool, out_of_scope via `scope_validate`, blast_denied via `blast_gate`, then per-target rate / run budget), short-circuits each with a structured denial the role must handle, and on pass runs the adapter, records exactly one `probe_event`, writes an audit row, and returns the normalized result. Added the content-addressed blob store `harness/store/blobstore.py` (the HC-DATA-01 §3 default backend: sha256-keyed, write-once, dedup, integrity-verifiable), the probe-event recorder `harness/store/evidence.py`, and the rate/budget guard `harness/ratelimit.py` (injectable clock). A denial records no `probe_event`; an adapter error is kept server-side as an observation and never surfaced as internal detail; the audit chain stays valid across denials and execs. Tool adapters and the sandbox are injected (real tools are infrastructure), exercised by stub adapters in 17 adversarial tests (`tests/test_dispatch.py`) wired into CI and `make test`. The planner, role sessions, Bifrost wiring, and the outer control loop remain to be built.
- 2026-11-08 (finding/report layer): Implemented the verdict-to-report path of HC-FIND-01 as pure-stdlib code. `harness/predicates.py` evaluates the HC-KB-01 §4 blackboard DSL (identifiers, comparisons, `in`, `exists`/`matches`, `! && ||`) over a facts dict and handles all 99 distinct real card predicates. `harness/severity.py` scores a card's `severity_rubric` (base band adjusted by raise_if/lower_if via the evaluator; a raise clause only raises, a lower only lowers) to a band, CVSS vector, and a band-representative score, with exact CVSS v4 vector scoring left as a deferred refinement rather than hand-rolled. `harness/kb.py` loads the materialized card tree into a `(id, version)` index for technique resolution. `harness/store/findings.py` gains `emit_lead` (cwe from the card taxonomy, cvss from the rubric), `classify_hardening`, the verifier `label` on confirm/reject (`source: verifier`, `tier: silver`), evidence linkage, and `to_record` building the §3 record; a `repro` column was added to the finding schema. `harness/report.py` assembles the §7.1 report from the store and `validate_report` is the ship gate implementing every §7.2 check, including that user-facing text carries no raw internal error detail (a stack trace or exception string is rejected) and that a passive-only report ships nothing confirmed. The finder-is-not-verifier guarantee is enforced by the DB CHECK and re-checked by the report validator. The §4.2 verification mechanics (the Verifier role driving the repro) depend on the model plane and sandbox and remain out. Covered by 19 adversarial tests (`tests/test_findings_report.py`) wired into CI and `make test`.
- 2026-11-08 (outer control loop): Implemented the HC-AGENT-01 §4 control loop as pure-stdlib code in `harness/loop.py` (`Loop`, `Pair`, `phase_threat_model`), the engine the earlier slices plug into. `Loop.run(target_model)` drives plan -> hunt -> verify -> report: `phase_threat_model` turns the recon target model into candidate pairs by evaluating each card's applicability DSL, the injected Planner orders them, `_hunt` runs the Operator inner loop through `dispatch()` until a success signal fires and `emit_lead` records a lead, and `_verify` reproduces each lead on a disjoint Verifier session. The governing choice is that signal triage lives in harness code, never the Operator's context: the loop reads the probe_event's recorded `deterministic_signals` (new `evidence.get_signals`) and applies the card's success-signal rule through an injected `signal_evaluator` (the seam where Laya replaces the deterministic default), so an injected instruction in a target response cannot forge a lead - only the adapter's observed signal can. finder-is-not-verifier is asserted at the loop before any confirm, over the DB CHECK; with the sandbox guard proofs failing the loop runs passive-only and holds every lead at `needs_validation`; the report ships only if `validate_report` passes. The four roles, the sandbox, and the Reporter are injected (Bifrost-backed LLM sessions and sandbox infrastructure), so the loop is driven by deterministic stub roles and a stub sandbox - the same pattern as dispatch's stub adapters - in 10 tests (`tests/test_loop.py`) that prove the §11 criteria (confirmed-ships-valid, finder!=verifier refused, resume-from-ledger, injected-target-denied-off-the-wire, passive-only), wired into CI and `make test`. The Bifrost-backed role prompts and their virtual keys (§6) and the live `phase_recon` remain to be built against this seam.
- 2026-11-08 (deterministic planner): Implemented the HC-AGENT-01 §3 Planner as `harness/planner.py:DeterministicPlanner`, the first of the four roles with a real rather than stub implementation, slotted into the loop's role seam. It is read-only and model-free: it ranks the candidate (asset, technique) pairs most-severe-first by the card's base severity band, then lowest-blast-tier-first within a band (a cheaper, snapshot-free probe before a heavier one of equal severity), then by a stable (technique, asset) tiebreak so a plan is byte-for-byte reproducible. Done-skipping stays in the loop (the ledger summary is accepted for the re-plan cadence §12 leaves open and does not yet change the ordering), and the reasoning-model planner can swap in later behind the same `plan(target_model, candidates, ledger_summary)` interface. Covered by 6 unit tests (`tests/test_planner.py`) plus a loop run end to end with the real planner (`tests/test_loop.py`), wired into CI and `make test`.
- 2026-11-09 (role I/O boundary): Implemented the trust boundary between a model role and the harness (HC-AGENT-01 §5.1, §7, §9) as `harness/roleio.py`, the emit-time half of the prompt-injection posture that complements the dispose-side guards in `dispatch()`. A role now emits raw text and the harness, never the role, decides what it means. `parse_request` turns that text into a validated `{tool, intent, target, port, args}` request or rejects the turn: surrounding prose, a shell string, a smuggled extra field (the schema is a strict allowlist, so `shell` or any unknown key is dropped), a non-integer or out-of-range port, or a malformed object are not actionable. The loop re-prompts a rejected turn with the schema for bounded retries, then marks the pair inconclusive, mirroring the denial cap. On the context side, `frame_untrusted` wraps target responses as a data block whose unguessable per-call nonce a hostile response cannot forge, so an injected close-delimiter cannot break back into the instruction channel, and `role_context` is the harness-owned probe-history view a role sees (untrusted output framed, a denial or rejected turn rendered as a trusted directive). The Operator and Verifier inner loops call `roleio` on both sides; the roles stay injected stubs, now emitting wire text through `roleio.emit` the same way the Bifrost-backed sessions will. Covered by 29 unit tests (`tests/test_roleio.py`) plus loop-level tests that an unparseable turn and a smuggled field are rejected before dispatch and an injected delimiter stays inside the data block (`tests/test_loop.py`), wired into CI and `make test`. The Bifrost-backed role prompts that assemble `role_context` and emit the text `parse_request` reads remain to be built.
- 2026-11-09 (model plane): Implemented the Bifrost model-plane policy (HC-MODEL-01) as pure-stdlib code in `harness/modelplane.py` (`ModelPlane`, `VirtualKey`), the §12 interface (`call(role, messages, metadata)`, `assert_provider_diversity`). One virtual key per role and no role holds a provider key: the actual Bifrost HTTP client is infrastructure, injected as a `transport` that is the only holder of credentials, the same injected-deps-plus-stubs pattern as the tool adapters and the sandbox, so a role names a role and never a provider. The plane enforces the finder-is-not-verifier invariant at the model plane (operator and verifier providers must be disjoint) and the MCP-tool boundary (only vk-enrich may be brokered a tool) at construction, failing closed before any run; routes with the fallback policy (Planner/Reporter free, Operator within its own set, Verifier pinned with no fallback so it never verifies on the Operator's model); applies the hierarchical per-vkey and engagement budget and the per-vkey rate as fail-closed `PlaneStop` signals (a breached budget has nothing to fall through to because roles hold no keys); serves the semantic cache only for the prose roles and only within an engagement; and writes an append-only audit row for every call and every stop, tying each model turn to its action. `from_config` builds a plane from the §11 config shape and fails startup on a diversity or MCP violation. Covered by 16 tests driving a deterministic stub transport (`tests/test_modelplane.py`) that prove the §13 criteria, wired into CI and `make test`. The real Bifrost-backed role sessions that call this plane (assembling prompts from `role_context`, emitting the text `parse_request` reads) and the live Bifrost HTTP transport remain to be built; this was the first slice whose production path needs the out-of-repo model plane, realized here as policy over an injected transport.
- 2026-11-09 (role sessions): Implemented the Bifrost-backed Operator and Verifier (HC-AGENT-01 §4.1, §4.2) as `harness/roles.py:ModelOperator` / `ModelVerifier`, the first consumers that compose the three pieces built around them: the model plane, the role I/O boundary, and the control loop. Each turn assembles a prompt from the harness-owned `role_context` (the framed, untrusted probe history) plus the trusted task, calls `plane.call` through the role's virtual key, and returns the model's raw text, which the loop parses or rejects with `roleio` and disposes through `dispatch`. No role holds a provider key, and because the plane keeps the Operator and Verifier on disjoint providers, finder-is-not-verifier now holds at the model plane as well as at the loop and the DB. A `PlaneStop` (budget, rate, or a down provider) or a stop sentinel makes a role give up cleanly, so the loop ends the pair or holds the lead rather than burning the turn budget. Two small, backward-compatible loop changes make the sessions real: the Operator session is handed the asset's recon facts (so a model can choose a target), and each lead records its full requests as the repro (so the Verifier reproduces from the recorded steps, not by reading the DB as the stub did). Covered by `tests/test_roles.py`, which runs the whole loop over a deterministic fake model and confirms a finding across disjoint providers plus the budget, sentinel, and down-provider stops, wired into CI and `make test`. What remains needs the out-of-repo infra: the live Bifrost HTTP transport behind the plane, a Reporter LLM over the deterministic reporter, the reasoning-model planner, and the live `phase_recon`.
- 2026-11-09 (enrichment service): Implemented the Tavily enrichment service (HC-ENRICH-01) as pure-stdlib policy in `harness/enrich.py` (`Enricher`, `lookup`, `research`), the last self-contained slice before the remaining work needs out-of-repo infrastructure. Enrichment is optional and advisory: it sharpens threat modeling and never decides, acts, becomes a success signal or a label, or touches the sandbox. The Tavily client egresses from the trusted host and is infrastructure, injected as a `transport` (the same injected-deps-plus-stubs pattern as the Bifrost model transport and the tool adapters). The opsec boundary is enforced in code: `assert_public_identifier` refuses a query that is not a bare product/version or CPE identifier (an IP, an address, or a URL is rejected before any egress), and every query goes out under a generic client identity, never the user's email. Results are bucketed (cves / advisories / default_creds / writeups) and provenance-tagged (source tavily, url, fetched_at, trust low), and `frame` renders them through `roleio.frame_untrusted` as a delimited untrusted block for the enrichment role only; the model plane already refuses to broker the tool to any vkey but vk-enrich, so the Operator never sees it. Lookups are TTL-cached by normalized query, and with no transport the service runs passive-intel-off so the loop proceeds on the KB alone; `research` yields only human-review-required card drafts, never an active card or a live-run path. Covered by 12 tests over a stub transport (`tests/test_enrich.py`) proving the §10 criteria, wired into CI and `make test`. The live Tavily transport and the wiring into live recon and threat modeling remain to be built against this seam.
- 2026-11-09 (live Bifrost transport): Implemented the first live transport, the HTTP client behind the model plane's injected seam (HC-MODEL-01), as `harness/bifrost.py:BifrostTransport`. This is the first infrastructure slice, taken on the constraint that it stay zero-dependency and CI-green: it is pure `urllib` (the running Bifrost gateway is out of repo) and is contract-tested against an in-process stdlib mock Bifrost (`tests/test_bifrost.py`), so the wire shape is exercised end to end without a live gateway or any secret. It POSTs a turn in the OpenAI chat-completions shape and is the only holder of credentials: the plane now passes the role's virtual key name in the transport metadata (a one-line, backward-compatible change to `_serve`), and the client resolves it to the Bifrost secret and presents it as the bearer token, so no role holds a provider key and each role presents its own disjoint key. The plane keeps provider routing and fallback (so the Verifier pin stays enforced in the harness, not the gateway); the client maps a provider outage (a 502/503/504 or an unreachable gateway, including a timeout) to `ProviderDown` so the plane falls back, while a 4xx, an unknown vkey, or a malformed body is a hard `BifrostError` that fails loud rather than masquerading as an outage. Covered by 8 tests driving the real client against the mock in CI and `make test`. What remains is deployment, not code: pointing it at a real gateway with real virtual-key secrets, and the sibling live Tavily transport behind the enrichment service.
- 2026-11-09 (live Tavily transport): Implemented the second live transport, the HTTP client behind the enrichment service's injected seam (HC-ENRICH-01), as `harness/tavily.py:TavilyTransport`, the sibling to the Bifrost client and built on the same constraint: pure `urllib`, zero dependency, contract-tested against an in-process stdlib mock Tavily (`tests/test_tavily.py`) so the wire shape is exercised without the live API or a key. It is the only holder of the Tavily key: the key is a bearer token, never placed in the query, and the query carries only a generic client identity as the User-Agent, never an account id or email, satisfying the §6 opsec posture at the HTTP layer (the enricher already sanitizes the query to a public identifier before the transport is called). Tavily returns generic web results, so the client maps each into the enricher's shape and infers a bucket (cve / advisory / default_cred / writeup) from the result. Because enrichment is optional and advisory, the transport raises a new `enrich.IntelUnavailable` on any failure (an outage, an unreachable endpoint, a bad key, or a malformed body), and the enricher was hardened to catch it and degrade to an `intel-unavailable` result without caching the failure, so a Tavily hiccup can never break a run (a one-method, backward-compatible change to `lookup`). Covered by 7 tests driving the real client against the mock plus the end-to-end degrade-and-retry path through the Enricher, in CI and `make test`. What remains is deployment and wiring: a real Tavily key, and feeding enrichment into live recon and threat modeling. With this the two live transports behind the model plane and the enrichment service are both in place; the remaining out-of-repo work is the sandbox (HC-SUB-01, Linux/KVM, not buildable on the current macOS host), a Reporter LLM and the reasoning-model planner, and live `phase_recon`.
- 2026-11-09 (objective contract, HC-OBJ-01 slice 1): Began HC-OBJ-01 (objective-driven engagements, attack-path chaining, lateral movement) with its foundational, self-contained first slice: the engagement-contract extension (§4). `harness/substrate/contract.py` now parses and fail-closed-validates an optional top-level `objective` block and `policy.lateral_movement`, both additive so a contract with no objective validates and runs exactly as before (acceptance §11 first criterion). The §4.4 rules are enforced at parse: `objective.target` must be a declared in-scope host or an in-scope, non-excluded IP (an out-of-scope or undeclared target is rejected before provisioning); `success` must parse under the HC-KB-01 §4 predicate DSL (reused via `harness/predicates.py`); `type: reach` requires `policy.lateral_movement: true` or the contract is rejected as contradictory; a `canary` proof must carry a 64-hex `sha256` and must not inline the plaintext (a `secret`/`value`/`flag`/... key is rejected); and an `oob_marker` proof must not name an external host or URL. The `Engagement` gains `objective` and `lateral_movement`. The runtime half of §4.4 (host pinning, in-sandbox oob termination) stays with the provisioning scope guard and sandbox, and cross-referencing `success` fact names against the live KB is deferred to threat-model load. Covered by 12 objective cases added to `tests/test_substrate.py` (now 31), in CI and `make test`. The blackboard (§5), the capability-frontier loop (§6), the planner relevance key (§7), and the report `objective_outcome` (§9) remain, each a following slice. The HC-OBJ-01 spec (authored separately) lands with this slice.
- 2026-11-09 (blackboard, HC-OBJ-01 slice 2): Implemented the run-local world-state blackboard (§5) as `harness/blackboard.py` (`Blackboard`, `Fact`), the piece §2 names as specified-but-inert, now live. It is the append-only, provenance-tagged store of facts a card reads as preconditions and the harness writes as yields, with two tiers that carry finder-is-not-verifier into every hop of a chain: a `provisional` fact (written at lead emission) informs exploration but gates nothing, and a `confirmed` fact (written only when the independent Verifier confirms the producing finding) is the only tier that satisfies an escalation or lateral-movement precondition or is read by the objective predicate (§3). Facts are immutable; `put`/`put_many` append to a log and update a current view only when the new fact does not downgrade a higher-tier predecessor, so a confirmed fact supersedes its provisional predecessor of the same `(name, scope)` while the superseded fact stays in the log for the §9 attack-path trace. `view(context, tier)` returns the flat `{name: value}` the HC-KB-01 §4 predicate evaluator consumes, scoped so a host-scoped fact is visible only against that host, with `tier=confirmed` the gating view; the board thus drops straight into applicability and the objective predicate without a new expression language. Only the harness writes facts (a role never does), and the store is run-local in-memory, with durable resume replaying the confirmed findings rather than persisting the board. Covered by 11 tests (`tests/test_blackboard.py`) in CI and `make test`: tier supersession, no-downgrade, append-only history, the confirmed-only gating view, scope satisfaction, and feeding the predicate evaluator. The capability-frontier loop (§6) that seeds, writes, and re-evaluates over it is the next slice; the planner relevance key (§7) and the report `objective_outcome` (§9) follow.
- 2026-11-09 (capability-frontier loop, HC-OBJ-01 slice 6a): Made card chaining live in `harness/loop.py`. `run` now branches on the engagement objective: with none it runs `_run_coverage`, the unchanged HC-AGENT-01 §4 batch run, so every existing contract and test behaves exactly as before (§3, the governing backward-compat rule); with an objective it runs `_run_objective`, the capability-frontier loop. The frontier loop seeds a `Blackboard` (§5) from recon as confirmed ground truth, then repeatedly computes the pending set (`_frontier_pending`: cards whose applicability and preconditions both hold over the confirmed board at the asset's host, not yet in the ledger), hunts the Planner's first pick, writes its `yields_on_success` provisional, verifies it at once on a disjoint session, and on confirmation writes its yields confirmed, so only a verified fact can open the next card and cards chain. A provisional yield never gates, which carries finder-is-not-verifier into every hop, not only the leaf finding; in passive-only nothing is confirmed, so nothing chains. The change is additive: the coverage path is untouched (`phase_threat_model` keeps its two-argument form; `self.board` stays None off the objective path; `_hunt` grew a return value the coverage caller ignores). This slice drives the chain and terminates on frontier exhaustion or a step cap bounded by assets x cards; objective completion (the §4.3 success predicate and the deterministic proof), the achieved/not_achieved outcome and attack_path, and objective-met termination are slice 6b, and the §8 lateral gate follows. Covered by 4 tests (`tests/test_frontier.py`) in CI and `make test`: a confirmed yield opens the next card, a provisional one does not, passive chains nothing, and the same cards with no objective take the coverage path where the second card is `not_applicable`. The 14 existing `test_loop` and 4 `test_roles` tests pass unchanged.
- 2026-11-09 (objective completion, HC-OBJ-01 slice 6b): Completed the objective mechanism in `harness/loop.py`: the frontier loop now evaluates whether the goal is reached and records the outcome. `_objective_met` is deterministic (§4.3): the success predicate must hold over the confirmed board at the target host AND the proof must hold. The proof is harness-observed, never model-asserted (§3, acceptance §11 third criterion): when a finding confirms, `_record_proof` reads the confirming probe's recorded `deterministic_signals` and writes a confirmed proof fact (the retrieved canary's SHA-256 as `proof.canary_sha256`, or the fired in-sandbox marker as `proof.oob_fired`), and `_proof_holds` compares the canary hash to the contract's `proof.sha256` or checks the marker; a `capability` objective's proof is the confirmed fact itself. So a confirmed finding whose predicate holds but whose captured hash does not match is `not_achieved`, and a role claiming success cannot flip it. The outcome (`achieved` / `not_achieved` / `not_applicable`, a proof summary, the `attack_path` of confirmed findings, and `reached_facts` when short) is recorded on `RunResult.objective`; `on_success: stop` ends the frontier on completion (`continue-for-coverage` keeps going), and passive-only is always `not_achieved` (§9.2), enforced both by the no-confirm invariant and an explicit guard. Covered by 6 added tests in `tests/test_frontier.py` (now 10) in CI and `make test`, including the canary hash gating `achieved` vs `not_achieved` on a confirmed finding, `on_success: stop` halting the frontier, and `reached_facts` on a short chain. The precise backward-trace pruning of `attack_path`, the report `objective_outcome` section (§9), the §8 lateral gate, and the §7 planner relevance key remain.

- 2026-11-09 (BR-07 passive-only enforcement): Closed the gap between the passive-only specification and the orchestration path. The loop checks containment before active work, before every dispatch, and before confirming a finding; failed or raised proofs stop further probes and verification, write an audit event, and hold outstanding leads at `needs_validation`. Passive-only reports explain that containment was not proven throughout the run and omit previously confirmed findings without changing stored records. Regression coverage covers initial, mid-run, and pre-confirmation proof failure, exceptions, lead holding, and resumable reports. The sandbox remains infrastructure outside this repository; the deterministic harness behavior is enforced and testable here.

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
- MITRE ATLAS: https://atlas.mitre.org
- OWASP Top 10 for LLM Applications: https://genai.owasp.org
- 2026-11-09 (objective in the report, HC-OBJ-01 slice 9): Made a shipped report state whether the declared objective was met and by what verified path, and made the ship gate prove that claim. `harness/report.py:build_report` embeds an `objective_outcome` block (id, status, proof summary, kill chain, reached facts), defaulting to `not_applicable` so every report carries the field, and `DeterministicReporter.render` plus the control loop thread the recorded outcome through to it. `validate_report` gains the §9.2 checks: an `achieved` outcome must carry a non-empty `attack_path` whose every step is a confirmed, independently verified finding in the report, a matched canary hash or a fired in-sandbox marker for its proof kind, and never `mode: passive-only`; a `not_achieved` outcome must list `reached_facts`. The `attack_path` is no longer every confirmed finding in random-id order: `loop._attack_path` traces the objective's required facts (the `success` predicate's identifiers, via the new `harness/predicates.py:identifiers`, plus the recorded proof facts) back through `yields_on_success <- preconditions` over the confirmed board, keeps only the findings that transitively contributed, and orders them by precondition depth, so a converging branch reads recon-to-goal and an off-path confirmed finding is pruned rather than listed (a correctness point, since finding ids are random UUIDs and gave an arbitrary order). Covered by 10 added tests across `tests/test_frontier.py` (the outcome is embedded and the shipped report validates; an off-path confirmed finding is pruned from the kill chain) and `tests/test_findings_report.py` (the §9.2 validator branches, and `identifiers` reads exactly the facts a predicate depends on), in CI and `make test`. The §8 lateral gate and the §7 planner relevance key remain.
- 2026-11-09 (lateral-movement gate, HC-OBJ-01 slice 8): Made a chain able to cross from one in-scope host to another, under contract control and with no scope widening, in `harness/loop.py` with a ledger sub-reason in `harness/store/ledger.py`. In the frontier, a card is evaluated first over the confirmed facts at the pair's own host; if it does not hold there, `_lateral_facts` gathers the confirmed facts the card references that live on a different in-scope host and that this host lacks. Because host-local recon facts (reachable, asset.type, host) are seeded for every asset, only a capability gained elsewhere (a credential, token, or session) ever registers, which is exactly what separates a lateral move from same-host chaining and avoids a per-fact lateral flag in the KB. When such a cross-host foothold would make the card applicable, `policy.lateral_movement: true` admits the pair and `_effective_facts` merges the foothold into the hunt view so the acquired credential authorizes the probe; `false` marks the pair `blocked_by_policy` with a new ledger detail `blocked_lateral` and never runs it, so the blocked count in the coverage summary carries the denied move and `ledger.detail` names why. A merely provisional foothold never registers, so finder-is-not-verifier holds across the host boundary too. The no-scope-widening invariant (§8.2) holds structurally: the probe target is always the pair's own in-scope asset, never a host the foothold named, and `scope.validate` plus `blast.gate` still run on every probe, so a foothold changes which techniques apply but never which hosts are reachable. The ledger gained a nullable `detail` column and `ledger.mark(..., detail=)` / `ledger.detail(...)`; `summary` is unchanged so the report coverage summary and its test are untouched. Covered by 4 added tests (3 in `tests/test_frontier.py` now 15, 1 in `tests/test_store.py` now 10), in CI and `make test`. The §7 planner relevance key is the last HC-OBJ-01 slice and the teammate is taking it.
- 2026-11-09 (sandbox substrate backend, HC-SUB-01 slice 1): Began the sandbox substrate with the §10 interface and the first self-hostable backend, in `harness/sandbox/`. Decisive design context: the only available host is a VPS with no nested virtualization (no /dev/kvm), and the product goal is that anyone can self-host with no cloud service. So the backend is container-based, not microVM-based, and cloud/managed provisioning is demoted to an optional backend behind the same interface, never a prerequisite. `Sandbox` (base.py) is the backend-agnostic interface the control loop drives; `PassiveOnlySandbox` is the safe default whose proofs all fail, so a harness with no range stays passive-only (§9). `DockerSandbox` (docker.py) provisions one egress-denied Docker network (`--internal`, so the range has no route off the host by construction = G2) holding a target container per in-scope host and one attacker container where tool adapters run. The scope guard (§5) is an nftables ruleset the host installs into the attacker's network namespace via nsenter: default-deny egress, allowing only the pinned in-scope IPs on their allowed ports, built from the same `scope.ports_for` policy the pre-flight check enforces. The attacker runs with no NET_ADMIN and no network tooling, so the agent (which is in the threat model, §2) can neither reach an out-of-scope host nor reconfigure the guard; in the realistic no-escape threat model this is equivalent to a separate gateway, and a separate gateway host plus gVisor/microVM hardening of G4 plug in behind the same interface later. `guard_proof` runs the four §8.1 assertions from inside the attacker container, and `proofs_pass` stays False until the snapshot round-trip (G3), escape-attempt (G4), and kill-switch (G5) drills land, so this backend alone keeps the harness passive-only until all five guarantees prove (§3). The topology was prototyped live on the host before being codified, and the four assertions plus a scope-rule-flip were confirmed (acceptance §12). Every docker/nsenter call goes through an injected runner, so provisioning and proof logic is unit-tested with no Docker present (`tests/test_sandbox.py`, 6 tests, in CI and `make test`); the live path is proven end to end on a real Docker host by `tools/sandbox_selftest.py`, with the golden node image and host notes in `infra/sandbox/`. This is the first macOS-blocked infra slice to land, now that a Linux host is available.
- 2026-11-09 (sandbox snapshot round-trip, HC-SUB-01 slice 2): Gave the Docker sandbox backend reproducibility (G3) in `harness/sandbox/docker.py`. Without nested virtualization there is no VM snapshot, so `snapshot` commits every target container to an image (`docker commit`) and `restore` recreates each target from its image at the same pinned IP, leaving the attacker container and the host-installed scope guard untouched because the guard lives in the attacker netns and the IPs are preserved. This captures filesystem state, which is what the §8.2 proof and recoverable tier-2 actions need; memory checkpointing is left to a backend that needs it. `snapshot_round_trip` proves G3 exactly as §8.2 specifies: write a marker to a target, snapshot, overwrite the marker, restore, and assert the original is back. The mechanism was validated live on the host before being codified. `proofs_pass` now runs the guard proof (G1/G2) and the snapshot round-trip (G3) and still returns False, because the escape-attempt (G4) and kill-switch (G5) drills are unbuilt, so the harness stays passive-only until all five prove (§3). Covered by 3 added tests in `tests/test_sandbox.py` (now 9): the round-trip restores the marker, restore recreates each target at its pinned IP from the snapshot image, and an unknown snapshot id raises. The test runner's fake now models a tiny per-container filesystem so commit/overwrite/recreate/read is exercised with no Docker present; the live path is proven end to end by `tools/sandbox_selftest.py` on the VPS. G4 (escape-attempt plus gVisor or separate-gateway hardening) and G5 (kill-switch drill) remain, behind the same interface.
- 2026-11-09 (sandbox escape-attempt and gVisor hardening, HC-SUB-01 slice 3): Gave the Docker sandbox backend containment (G4) in `harness/sandbox/docker.py`. `escape_attempt` proves §8.3: from the attacker container it probes the operator host's management interface (discovered on the host via `ip route get`), the range gateway (the host's own interface on the range), and a second unrelated host network, and asserts all three unreachable. A live finding drove the design: on an `--internal` network the host's primary IP and other networks are already unreachable, but the range gateway `.1` is the host's bridge interface and its sshd is reachable from the range unless the scope guard blocks it, so the gateway is the real escape path and the guard is load-bearing for G4, not only G1. As the §6.2 isolation mechanism, `provision` now runs every range container under the gVisor `runsc` runtime when the host offers it (auto-detected via `docker info`), so a container escape is contained in a user-space kernel rather than the host kernel, with no nested virtualization required; `escape_attempt` reports the active runtime (`runc` or `runsc`) so an operator knows whether kernel-escape hardening backs the network containment. The box in use has no gVisor, so the live run reports `runc` and still passes the network escape test. `proofs_pass` now runs the guard proof, the snapshot round-trip, and the escape attempt and still returns False, because the kill-switch drill (G5) is the last unbuilt proof, so the harness stays passive-only until all five prove (§3). Covered by 3 added tests in `tests/test_sandbox.py` (now 12): the escape attempt passes when the host and other nets are unreachable and fails when the host is reachable, and provision uses the gVisor runtime when the host offers it. The live path (guard + snapshot + escape) is proven end to end on the VPS by `tools/sandbox_selftest.py`. Only G5 remains before `proofs_pass` can return True and a live engagement can leave passive-only.
- 2026-11-09 (sandbox kill switch and full proof aggregate, HC-SUB-01 slice 4): Completed the five guarantees of the Docker sandbox backend with killability (G5) in `harness/sandbox/docker.py`, so `proofs_pass` now returns True when a range proves all of G1-G5 and the harness may leave passive-only. `kill` is the emergency kill switch (§6.4): one action pauses every range container at once (an instant freeze via the cgroup freezer), commits each frozen container for forensics, and restores the targets from the golden image, leaving the attacker frozen for analysis rather than destroyed. This is deliberately distinct from the new `teardown`, which destroys the range entirely and doubles as pre-provision cleanup (the old `kill` was really a teardown and was renamed). `kill_switch_drill` proves G5 per §8.4: write a marker to a target, invoke the kill switch, assert the freeze lands within a configurable time budget and the target is wiped back to golden (the marker is gone), then revive the frozen attacker so the proven range stays usable. The mechanism was validated live on the host first (freeze in ~0.5s, marker wiped, attacker paused then revived). `proofs_pass` runs the guard proof, snapshot round-trip, escape attempt, and kill-switch drill and returns True only when all hold; each drill leaves the range usable, so a passing run hands back a range ready for the engagement. A real-vs-mock divergence surfaced on the live run and was fixed: reading a wiped marker with a bare `cat` fails on a missing file, while the test fake returned empty, so marker reads now go through a tolerant `cat ... 2>/dev/null || true` helper that returns empty for an absent file in both paths. Covered by 3 added tests in `tests/test_sandbox.py` (now 14): the drill freezes within budget and restores from golden, it fails when the freeze misses its budget, and `proofs_pass` is True only when all five prove and False when an escape path exists. The full five-guarantee path is proven end to end on the VPS by `tools/sandbox_selftest.py` (ALL FIVE GUARANTEES: PASS). The sandbox substrate backend is now complete for self-hosting; wiring DockerSandbox into a live engagement to replace StubSandbox, and live phase_recon, are the next steps, with a separate-gateway-host and gVisor install as further G4 hardening on a dedicated host.
- 2026-11-09 (live engagement wiring, HC-SUB-01 + HC-AGENT-01): Wired the real `DockerSandbox` into the control loop so the harness runs an engagement end to end against a live self-hosted range, the first time the substrate drives a real run rather than a stub. Added `harness/sandbox/probe.py:DockerProbe`, the live tool adapter the dispatcher runs on the attacker VM after it passes scope, blast, and rate: it issues an HTTP request from the attacker container to a pinned in-scope target (resolving a pinned hostname to the IP the scope guard enforces on) and returns the raw observable signals the harness triages into a lead, never the agent. `DockerSandbox.restore` now also serves the Verifier's per-run golden baseline: `restore(GOLDEN)` recreates the targets from the golden image, which is what the loop restores before reproducing a lead (HC-SUB-01 §4.2), so verification runs against a clean baseline. `tools/run_engagement.py` ties it together: parse a contract, provision the real range, gate on the five-guarantee `proofs_pass` (refusing to leave passive-only otherwise), build the target model from the pinned targets, and drive the loop with the real probe adapter and deterministic operator and verifier stand-ins (the Bifrost model plane is a separate deployment). A live run on the VPS provisioned the range, proved all five guarantees, executed a real probe against a real target, triaged it to a lead, verified it on a disjoint identity (finder is not verifier), confirmed an exposed-service finding, and produced a validated report, then tore the range down. Covered by 3 added adapter tests in `tests/test_sandbox.py` (now 17): an HTTP response is a hit, no response is not, and a pinned host resolves to its guarded IP. The deterministic operator and verifier stand in for the model plane; replacing them with the Bifrost-backed roles and adding live `phase_recon` to produce the target model from real reconnaissance are the next steps.
- 2026-11-09 (live reconnaissance, HC-AGENT-01): Replaced the hand-built target model in the live engagement with real reconnaissance, in `harness/recon.py:phase_recon`. Against a provisioned range it probes each pinned in-scope target on its allowed ports from the attacker container (a TCP connect for each port and, for an open port, one HTTP request via the live probe adapter), records which ports are open and the HTTP status of a web port, and returns the `{asset: facts}` target model the threat-model phase consumes, with `reachable` true when any allowed port is open and `asset.type: web_service` set on a port that speaks HTTP. It reads state only and stays within scope because it touches only pinned targets on their allowed ports (via `scope.ports_for`), which the attacker-netns scope guard enforces regardless. `tools/run_engagement.py` now calls it instead of hand-building the model, so the live run discovers its target rather than being told it. A run on the VPS proved all five guarantees, reconned t1 (open port 8080, web_service, HTTP 200), hunted, verified on a disjoint identity, confirmed the exposed-service finding, and shipped a validated report. Covered by 2 added tests in `tests/test_sandbox.py` (now 19): recon builds the target model from live probes, and marks an unreachable target without a service type. phase_recon reuses `harness/sandbox/probe.py:DockerProbe` for the HTTP check, so the recon and hunt paths share one probe implementation. With recon live, the only hand-written pieces left in the live pipeline are the deterministic Operator and Verifier stand-ins; wiring the Bifrost-backed roles into a live run needs a deployed Bifrost endpoint and provider keys, kept off the shared production host.
- 2026-11-09 (one-command model-plane gateway, HC-MODEL-01): Made the Bifrost gateway the model plane talks to come up with one command, so self-hosting it needs no cloud account and no hand-assembled config, in `tools/modelplane.py` (standard library only, cross-platform) with dev notes in `infra/modelplane/README.md`. `up` generates the Bifrost config and an `.env`, mints a per-role virtual key, seeds a Docker-managed volume with the config over the container's stdin (not a host bind mount, so seeding never depends on the daemon seeing a host path, which is what breaks on Docker Desktop file sharing and some /tmp setups) and makes the volume dir group-0 writable so the gateway, which runs as uid 1000 gid 0, can create its config.db and logs.db; `keys` reads the two provider API keys with no echo and restarts; `env` prints the HC_BIFROST_URL / HC_VK_OPERATOR / HC_VK_VERIFIER handles the runner reads; `status` shows health, routes, and whether keys are set; `down`/`destroy` stop or wipe it. The generated config encodes the §4 diversity invariant structurally (operator on DeepSeek, verifier on OpenAI, one provider per virtual key, the two disjoint) and carries only env.VAR references, never a literal secret, with the keys and virtual keys held in an `.env` under ~/.hackculture/modelplane outside the repo so no secret reaches a working tree, and the container binds to 127.0.0.1 so the provider keys it holds are never on the network. The seeding, permission, and single-file-bind-mount failure modes were each reproduced live on the host and designed out (stdin seeding, group-0 writable volume) before being codified, per reproduce-E2E-first. `tools/run_engagement.py` now builds the plane from those handles and runs the Operator on DeepSeek and the Verifier on OpenAI through it, falling back to the deterministic stand-ins when no gateway is configured, so finder-is-not-verifier holds at the model plane too. Covered by 8 tests in `tests/test_modelplane_setup.py` (the config binds each virtual key to one provider and the two are disjoint, no literal secret reaches the config, minted virtual keys are prefixed and distinct, the .env round-trips), in CI and `make test`; the Docker bring-up is proven on a real host. The one step left to the operator is pasting their own provider keys, and the live model-driven run follows once those are set.
- 2026-11-09 (first confirmed finding from real models, HC-AGENT-01 + HC-MODEL-01): Drove a live engagement with the Operator and Verifier on real commercial models through the Bifrost gateway, and got the first confirmed finding from models rather than the deterministic stand-ins. The wiring (`tools/run_engagement.py` building the plane from the gateway handles) and the gateway itself (`tools/modelplane.py`) were already in; this slice fixed the one thing that kept a real model from producing a runnable probe. The Operator's task gave the model an `intent` but never the tool name or a clear target, so DeepSeek emitted well-formed JSON with `tool: "http_probe"` (no such adapter; the registry has `probe`) aimed at the bare hostname. The fix, in `harness/roles.py`, surfaces the card's declared tool in the Operator task and instructs the model to set `target` to the asset's `recon.addr`, so the model proposes a probe the dispatcher accepts; the propose-and-dispose contract is unchanged, since dispatch still validates scope, blast, and rate on every request regardless of what the model names. Diagnosed by replaying the exact Operator turn against the live gateway and parsing the output (the JSON parsed fine, so it was a wiring gap, not a schema-rejection), per reproduce-E2E-first. With the fix the live run on the VPS provisioned the range, proved all five guarantees, reconned t1, had DeepSeek (vk-operator) propose the probe and OpenAI (vk-verifier) reproduce it on a disjoint provider, and shipped a validated report with one confirmed exposed-service finding (found_by != verified_by). Covered by 1 added regression test in `tests/test_roles.py` (now 5) asserting the Operator prompt names its tool and the recon address, in CI and `make test`. The remaining model work is the HC-MODEL-01 §13 prompt and reasoning-model bake-off, iterating behind this same seam.
- 2026-11-09 (the capri CLI and a native model-setup TUI, HC-MODEL-01): Turned the model-plane setup from a hand-run `python3 tools/modelplane.py` into a product: `capri`, one CLI at the repo root (`capri setup` / `capri run` / `capri gateway <status|env|down|destroy|up|keys>` / `capri help` with a banner), installed onto the PATH by `make install` and resolving back to the repo through a symlink, with `capri run` loading the gateway handles into its own env (resolving the invoking user's home under sudo) so there is no export dance. `tools/setup.py` is the interactive setup, a standard-library `curses` full-screen TUI (no third-party dependency; a plain-prompt fallback where curses is absent or output is not a terminal): it shows `tools/catalog.py`, the provider catalog Capri owns, as one scrollable list of models grouped by provider, takes a model for the Operator and a different-provider model for the Verifier (the Verifier list excludes the Operator's provider, so finder-is-not-verifier holds by construction), reads keys with no echo, and launches with a live progress display; Esc steps back a screen and quits only from the first, q quits. `tools/catalog.py` is the owned catalog of the 14 single-API-key providers Bifrost supports (exact Bifrost identifiers, key env vars, suggested models), the one place to add a provider, rather than a narrow hardcoded pair; it was broadened from a first cut of 7 after confirming Bifrost's real direct-provider set, and the decision to own a static catalog rather than query Bifrost's control-plane API was deliberate (that API is behind auth and churns, while the catalog is stable and zero-coupling). `tools/modelplane.py` was refactored so its config generation is driven by the chosen pairing (not a hardcoded table) and the bring-up is a headless `bring_up` the TUI and CLI share, with `runtime_env` handing the runner its handles; `tools/run_engagement.py` now reads the routes the gateway exports, so whichever providers the user picks actually drive the run. Deployment framing moved off the VPS (that was only ever the dev rig) to a user's own machine, where a local terminal UI needs no browser or tunnel. Covered by 6 added tests in `tests/test_catalog.py`, in CI and `make test`; the live path (setup to a confirmed finding from real models) is proven on a real Docker host. Why curses and not Go or Textual: the harness is and stays Python (the auditable core), so a second language buys a thin setup skin at the cost of a build toolchain and either shelling out to Python or duplicating it, and the stdlib keeps the whole tool installable with nothing but a Python interpreter.
- 2026-11-09 (first real tool adapter, nmap, HC-AGENT-01): Gave the §5.3 tool allowlist its first real tool beyond the baseline HTTP probe, so the agent can run `nmap` and the harness turns its output into a verified finding, in `harness/sandbox/adapters.py:NmapAdapter`. The adapter, registered in `dispatch()` as the `nmap` tool, runs `nmap -sV -Pn` on one in-scope port against a pinned target (resolving the pinned name to the IP the scope guard enforces on) and parses the XML into per-port service, product, version, and CPE signals, which is exactly the shape version-based cards and CVE lookups match on; a parse failure or a closed port is tolerated as no-hit rather than raised. The attacker container now runs a toolchain image (`infra/sandbox/Dockerfile.attacker`, alpine plus python3 and nmap) while targets stay the minimal node image, so `harness/sandbox/docker.py` gained an `attacker_image` distinct from the node image; the attacker still holds no NET_ADMIN and cannot touch the host-owned scope guard, so adding tools to it never widens scope, and a new capability stays a new reviewed adapter rather than a general exec primitive. `tools/run_engagement.py` adds a second KB card whose only probe step is `nmap` and registers the adapter, so the model-driven Operator proposes the scan and the loop gates on the adapter's deterministic `hit` signal. Proven live on the VPS: DeepSeek (vk-operator) proposed the nmap scan, nmap ran on the attacker container and disclosed SimpleHTTPServer 0.6 with its CPE, and OpenAI (vk-verifier) reproduced it on a disjoint provider, shipping a valid report with two confirmed findings (the baseline probe and the nmap service scan, found_by != verified_by on both). The parse and signal shape are pinned against captured real `nmap -sV` output through a fake runner with no Docker and no tool present, per reproduce-E2E-first; the two nmap prototype failures found live (NSE needs the `nmap-scripts` package, and container host discovery needs `-Pn`) were designed into the image and the argv before being codified. Covered by 5 added tests in `tests/test_adapters.py`, in CI and `make test`. nmap execution is kept to the range host, never the operator laptop, because endpoint security there flags the scanner. The rest of the allowlist (httpx, ffuf, sqlmap, nuclei, a browser driver) follows behind this same adapter seam.
- 2026-11-09 (httpx web-recon adapter, HC-AGENT-01): Added the second real tool to the §5.3 allowlist, so the agent can fingerprint a web surface, in `harness/sandbox/adapters.py:HttpxAdapter` (registered in `dispatch()` as the `httpx` tool). It issues one request with ProjectDiscovery httpx to a pinned in-scope target and returns the status, title, server and technology fingerprint, the normalized response headers, which of the four baseline security headers are missing (CSP, X-Frame-Options, HSTS, X-Content-Type-Options), any CORS allow-origin, and any redirect target. It reports the Location rather than following it, since a redirect can leave the asset, and the scope guard would drop an out-of-scope hop regardless. This is the web-recon layer the web and auth techniques build on: these signals are exactly what makes the web-protocol-auth and client-side cards applicable, which is where the KB priority starts (Brent wants Web, auth, and the mobile app first when the real KB lands). httpx normalizes header names to lowercase-with-underscores, so the adapter maps them back to canonical hyphenated names before the security-header checks. The attacker image (`infra/sandbox/Dockerfile.attacker`) now carries httpx, pinned by version and verified against the release checksum so a tampered download fails the build, and selected by TARGETARCH so the image builds on amd64 and arm64 (an Apple Silicon host's Docker Desktop is a self-host target, not only a Linux range). Per reproduce-E2E-first, httpx was run live against a real HTTP target first to capture its exact `-json` schema (a base server, a security-header response, and a 302), and the tests pin the parse to that captured output through a fake runner with no Docker or tool present. `tools/run_engagement.py` adds a third KB card whose only probe step is httpx and registers the adapter. Proven live on the VPS: DeepSeek proposed the httpx fingerprint, it ran on the attacker container, and OpenAI verified on a disjoint provider, shipping a valid report with three confirmed findings (probe, nmap, httpx; found_by != verified_by on each). Covered by 7 added tests in `tests/test_adapters.py` (now 12), in CI and `make test`. Next behind the same seam: request-crafting adapters for the injection and auth cards, then ffuf, sqlmap, nuclei, and a browser driver.
- 2026-11-09 (crafted-HTTP adapter and a confirmed reflected XSS, HC-AGENT-01): Gave the §5.3 allowlist its first request-crafting tool, so the agent can send a parametrized HTTP request and the harness can confirm an injection, in `harness/sandbox/adapters.py:HttpRequestAdapter` (registered in `dispatch()` as the `http` tool). The card parametrizes the request (method, path, query parameters); when `reflect_param` names a parameter, the adapter injects a random, tag-breaking marker into it and reports whether that exact marker reflects unencoded in the response body. This is a deterministic reflected-XSS signal the harness owns, not the model: the marker is generated in the adapter from `secrets`, so a model can neither pre-pick one that always matches nor forge the server's echo, and a server that encodes its output never reflects the raw marker; the Verifier reproduces with its own fresh marker, so a confirm means two independent random markers both reflected. The request runs from the attacker container through a stdlib urllib one-liner that prints the status and body, which the adapter parses. Proving an injection needs a target with a real hole, so `harness/sandbox/docker.py:DockerSandbox` gained a `listener_app` option: a python source string seeded into each target over stdin (never baked into the golden image, re-seeded on restore and kill) and run as the listener in place of the bare `http.server`. `infra/sandbox/vulnweb.py` is the deliberately vulnerable stand-in it seeds, reflecting the `q` parameter with no encoding; it stays inside the egress-denied range and is never reachable off it. `harness/roles.py` now surfaces the card's probe-step fields as a `params` block in the Operator task and instructs the model to copy them into `args`, so a real model crafts the request against the right path and injection point (backward compatible: a step with only tool and intent yields an empty params and an unchanged task). `tools/run_engagement.py` adds a fourth KB card (tool http, reflect against /search?q) and provisions the range with the vulnerable listener. Proven live on the VPS: DeepSeek proposed the XSS request, the adapter injected its marker, vulnweb reflected it, and OpenAI reproduced it on a disjoint provider, shipping a valid report with four confirmed findings (probe, nmap, httpx, reflected XSS; found_by != verified_by on each). The adapter signal shape is pinned in `tests/test_adapters.py` through a runner that simulates the vulnerable server so the adapter's own random marker flows through (now 19 tests), and the `listener_app` seeding is covered in `tests/test_sandbox.py` (now 20); both in CI and `make test`. This is the first rung of the Web/auth KB priority Brent set; next behind the same `http` seam are the error, boolean, and time signals for SQLi, a status-differential for IDOR and BFLA, and header reflection for CORS, then the heavier tools (ffuf, sqlmap, nuclei, a browser driver).
- 2026-11-09 (boolean-blind SQL injection, HC-AGENT-01): Added the second injection technique on the crafted-HTTP seam, in `harness/sandbox/adapters.py:SqliAdapter` (registered in `dispatch()` as the `sqli` tool), so the agent confirms SQL injection without the model judging the result. For a named parameter the harness sends three requests, the baseline value and the value with an appended condition that is always true and one that is always false, and reports boolean-blind SQLi only when the true condition reproduces the baseline response while the false one changes it; it tries a numeric and a quoted-string template and stops at the first that splits. Like the XSS marker, the conditions are generated in the adapter from a fixed set, not by the model, so a model cannot force the verdict, and a parameter the query parametrizes safely treats all three as literal data, so its responses never split that way; the signal is deterministic and harness-owned, and the Verifier reruns the differential, so a confirm is two independent splits. The design is deliberately a harness-owned deterministic probe rather than parsing a third-party tool's verdict, which keeps truth in the harness (HC-OBJ-01) and the signal forge-proof; sqlmap, nuclei, and ffuf remain as heavier breadth tools to add later behind the same allowlist. The in-container HTTP send was factored into a shared `_Adapter._send_http` that the crafted-request and SQLi adapters both use. `infra/sandbox/vulnweb.py` gained a SQL-injectable `/item?id=` endpoint backed by an in-memory sqlite table (the id is concatenated into the query), validated live first (reproduce-E2E-first) so the true, false, and error responses split exactly as a real target does, before the adapter and tests were written. `tools/run_engagement.py` adds a fifth KB card (tool sqli, /item?id, CWE-89 high) and registers the adapter. Proven live on the VPS: DeepSeek proposed the SQLi probe, the harness computed the differential, and OpenAI reproduced it on a disjoint provider, shipping a valid report with five confirmed findings (probe, nmap, httpx, reflected XSS, boolean-blind SQLi; found_by != verified_by on each, the SQLi ranked highest at CVSS high). Covered by 5 added tests in `tests/test_adapters.py` (now 24) through a runner that emulates the injectable endpoint's split, in CI and `make test`. Next on this seam: IDOR and BFLA by an authed-vs-unauthed status differential, and CORS by header reflection, then the heavier tools.
- 2026-11-09 (JWT auth substrate and broken object-level authorization, HC-AGENT-01): Started the auth half of the Web/auth KB priority, which needs an authenticated target and an identity in the request, so `infra/sandbox/vulnweb.py` gained a toy JWT layer (stdlib hmac HS256): `/login?user=` issues a signed token and `/account?id=` returns the requested account to any authenticated caller with no ownership check, which is broken object-level authorization (IDOR / BOLA). The identity mechanism is a JWT bearer token, chosen with Brent because it also sets up broken function-level authorization and JWT algorithm confusion on the same substrate later. `harness/sandbox/adapters.py:IdorAdapter` (registered in `dispatch()` as `idor`) authenticates as one identity through the login, then reads that identity's own object and a neighbouring object it should not own, both with the same token, and reports BOLA only when the neighbour returns 200 with distinct data, which an app that checks ownership refuses with a 401 or 403. The identity and the neighbour id are chosen by the harness, not the model, so the model cannot force the verdict, and the Verifier repeats the pair, so a confirm is two independent reads: deterministic and harness-owned, consistent with the XSS and SQLi signals. The shared in-container HTTP send (`_Adapter._send_http`) grew optional request headers (a JSON argument to the urllib one-liner) so the adapter can present the bearer token; the crafted-request and SQLi adapters are unaffected. `tools/run_engagement.py` adds a sixth KB card (tool idor, /account, CWE-639 high) and registers the adapter. The JWT and BOLA behaviour was validated live first (reproduce-E2E-first): a user-1 token read user 2's account while a forged token got 401, exactly the split the signal keys on, before the adapter and tests were written. Proven live on the VPS: DeepSeek proposed the IDOR probe, the harness logged in and read the neighbour, and OpenAI reproduced it on a disjoint provider, shipping a valid report with six confirmed findings (probe, nmap, httpx, reflected XSS, boolean-blind SQLi, BOLA; found_by != verified_by on each, SQLi and BOLA both CVSS high). Covered by 4 added tests in `tests/test_adapters.py` (now 28) through a runner that emulates the JWT app and a safe ownership-checked variant, in CI and `make test`. Next on the JWT substrate: broken function-level authorization (a privileged endpoint with no role check) and JWT algorithm confusion (accepting alg:none or an unsigned token).
- 2026-11-09 (broken function-level authorization, HC-AGENT-01): Added the second auth technique on the JWT substrate, in `harness/sandbox/adapters.py:BflaAdapter` (registered in `dispatch()` as the `bfla` tool). It calls a privileged function first with no token and then with a token for an ordinary, non-privileged user, and reports broken function-level authorization only when the anonymous call is refused (401 or 403) while the ordinary user's executes (200). The two-call shape is what separates the flaw from a merely public endpoint: a public page answers the anonymous call too, so it is not reported, while a function gated on being logged in but not on holding the role is. The identity is the harness's, not the model's, and the Verifier repeats the pair, so the verdict is deterministic and harness-owned, consistent with the IDOR, SQLi, and XSS signals. `infra/sandbox/vulnweb.py` gained an `/admin` function that runs for any authenticated user with no role check (the deliberate flaw), reusing the toy JWT login from the IDOR slice. `tools/run_engagement.py` adds a seventh KB card (tool bfla, /admin, CWE-862 high) and registers the adapter. Proven live on the VPS: DeepSeek called /admin anonymously and got 401, then with an ordinary user's token and got 200, and OpenAI reproduced the pair on a disjoint provider, shipping a valid report with seven confirmed findings (probe, nmap, httpx, reflected XSS, boolean-blind SQLi, BOLA, BFLA; found_by != verified_by on each, SQLi and both authorization findings CVSS high). Covered by 3 added tests in `tests/test_adapters.py` (now 31) through the JWT app runner extended with a privileged endpoint plus role-checked and public variants, in CI and `make test`. The last planned auth technique on this substrate is JWT algorithm confusion (accepting alg:none or an unsigned token); then the heavier real tools.
- 2026-11-09 (CLI setup and presentation): Added a shared ASCII CAPRI banner and command headings; Windows help prints runnable `python .\capri ...` commands, and setup shows progress and selected roles.
Setup now rejects missing provider keys before Docker or state writes, with its regression suite wired into `make check` and CI.
