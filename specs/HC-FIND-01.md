---
tag: HC-FIND-01
title: Findings model and verification protocol
status: draft
parent: SPEC.md#8
depends_on: [HC-KB-01, HC-AGENT-01, HC-SUB-01, HC-DATA-01, HC-MODEL-02]
depended_on_by: [HC-AGENT-01, HC-DATA-01, HC-EVAL-01]
updated: 2026-11-08
---

# HC-FIND-01 - Findings model and verification protocol

## 1. Purpose

This spec defines the output side of the system: the finding lifecycle, the finding record, the independent verification protocol that turns a lead into a confirmed finding, how a card's severity rubric becomes a CVSS/CWE verdict, the hardening-note distinction, and the report schema with its zero-dependency validator.

The rule that shapes all of it: a finding is a hypothesis until a second, independent agent reproduces its success signal in a fresh snapshot.
Confidence never substitutes for reproduction, and the harness, not a model, renders the final verdict.

## 2. Lifecycle

```
  signal fires (confidence >= floor)                 confidence < floor
            |                                               |
         [ lead ] --emit--> [ needs_validation ]       (not a finding;
            |                      |                     logged as weak_signal
   triage: no impact?             |                     evidence for the corpus)
            |                      v
            v              Verifier reproduces in a fresh snapshot?
     [ hardening_note ]      |            |                 |
     (no CVSS, reported      yes          no: disproved     no: environment/time
      separately)            |            or known FP       prevented a verdict
                             v            v                 v
                        [ confirmed ]  [ rejected ]   [ inconclusive ]
```

- `lead`: the Operator's hypothesis the instant a success signal fires at or above the card's confidence floor (HC-KB-01 §5).
- `needs_validation`: a lead awaiting independent verification; also the terminal state for every lead in passive-only mode (HC-SUB-01 §9).
- `confirmed`: the Verifier independently reproduced the success signal, and `verified_by != found_by`.
- `rejected`: actively disproved on reproduction, or a known false positive.
- `inconclusive`: reproduction was attempted but environment or time prevented a verdict; it never ships as confirmed, and it is distinct from rejected.
- `hardening_note`: a defense-in-depth gap with no demonstrated impact, classified at triage, never promoted to a vulnerability.

Universal verification: every lead, including a deterministic one at confidence 1.0, must be reproduced to reach `confirmed`.
The confidence floor only decides whether a signal becomes a lead at all; it is not a shortcut to confirmation.

## 3. Finding record

```json
{
  "id": "F-2026-0007",
  "technique_id": "KB-WEB-INJ-SQLI-001",
  "technique_version": "1.2.0",
  "asset": "api.sandbox.local/orders?id=",
  "classification": "vulnerability",          // vulnerability | hardening_note
  "cwe": ["CWE-89"],
  "cvss": { "version": "4.0", "vector": "CVSS:4.0/AV:N/AC:L/...", "score": 8.1 },
  "verdict": "confirmed",                      // lead|needs_validation|confirmed|rejected|inconclusive
  "signal_confidence": 1.0,
  "found_by": "operator-session-A",
  "verified_by": "verifier-session-B",         // schema rejects if == found_by
  "found_by_event_ids":   ["pe_...", "pe_..."],// HC-DATA-01 probe_events
  "verified_by_event_ids":["pe_..."],
  "repro": ["baseline GET ...", "inject payload ...", "observed db error fingerprint"],
  "evidence": ["artifact://resp/...", "artifact://pcap/..."],
  "impact": "read arbitrary rows from the orders table",
  "remediation": "parameterize the query; see CWE-89",
  "blast_tier_used": 1,
  "status_history": [
    { "to": "lead", "at": "2026-11-08T20:14" },
    { "to": "needs_validation", "at": "2026-11-08T20:14" },
    { "to": "confirmed", "at": "2026-11-08T20:31", "by": "verifier-session-B" }
  ],
  "created_at": "2026-11-08T20:14",
  "resolved_at": "2026-11-08T20:31"
}
```

- `found_by` and `verified_by` are session identities (HC-AGENT-01); `found_by == verified_by` is a schema violation.
- `found_by_event_ids` and `verified_by_event_ids` point at the actual probe_events on each side, so a finding is always backed by raw I/O (HC-DATA-01).
- `status_history` is append-only, mirroring the HC-DATA-01 discipline; a verdict is never silently rewritten.
- `hardening_note` findings carry `classification: hardening_note`, no `cvss`, and skip verification.

## 4. Independent verification protocol

### 4.1 What crosses to the Verifier

Only three things:

- the lead's `repro` steps;
- its `evidence` pointers;
- the originating card's `success_signal` definition, so the Verifier knows what "reproduced" means.

The Verifier never receives the Operator's reasoning, observations, or chat context.
It runs on a provider disjoint from the Operator's via `vk-verifier`, which Bifrost must not let fall back onto the Operator's provider (HC-AGENT-01 §6).

### 4.2 Protocol

```
verify(lead):
    sandbox.restore(golden); fresh = sandbox.snapshot()          # HC-SUB-01
    vctx  = verifier.session(vk-verifier)                        # provider disjoint from Operator
    input = { repro: lead.repro, evidence: lead.evidence, signal: card(lead).success_signal }
    for _ in bounded(attempts, budget):
        obs = run_repro_step(vctx, input, dispatch)              # same propose/dispose chokepoint
        verdict = evaluate_signal(card(lead).success_signal, obs) # HARNESS evaluates, not the model
        if verdict.hit: break
    if verdict.hit and vctx.id != lead.found_by:
        findings.confirm(lead, verified_by=vctx.id, events=obs.event_ids)
    elif verdict.actively_disproved or known_false_positive(lead):
        findings.reject(lead, reason)
    else:
        findings.mark_inconclusive(lead, reason)                 # env/time, not a rejection
```

### 4.3 Who decides

- The Verifier model only drives and adapts the repro (handling dynamic tokens, ids, CSRF, minor drift).
- The harness evaluates the success signal on the Verifier's fresh probe_events and renders the verdict, deterministically for a deterministic evaluator or via Laya for a `laya:` one.
- This split is deliberate: a model cannot talk itself into a confirmation, because it does not get to declare the verdict, it only produces the evidence the harness judges.

### 4.4 Anti-collusion guarantees

- Fresh golden restore and a new snapshot per verification, so no residual state from the Operator's run leaks in.
- Disjoint providers and no shared memory between finder and verifier.
- The final deterministic verdict is the harness's, from re-executed probe_events.
- Stronger-confirmation option (deferred, HC-AGENT-01 open question): allow the Verifier a second, independent technique rather than a replay; a later revision.

## 5. Severity

- `cwe` is copied from the card taxonomy (HC-KB-01).
- Severity starts at `severity_rubric.base` and is adjusted by `raise_if` / `lower_if` clauses evaluated against the blackboard facts and the card's `yields` (HC-KB-01 §4, §6).
- The result renders a CVSS v4 vector and score; severity reflects demonstrated impact, not theoretical reach, so a confirmed read-only SQLi and a writable one diverge through the rubric, not through guesswork.
- A finding that cannot be tied to demonstrated impact is a hardening note, not a low-severity vulnerability.

## 6. Hardening notes

- A defense-in-depth gap with no demonstrated impact (a missing security header, a verbose error with no exploit, a weak-but-unexploited configuration) is a `hardening_note`.
- Hardening notes are not verified as vulnerabilities, carry no CVSS, and are reported in their own section.
- This keeps the vulnerability list honest and severity anchored to impact, and it matches the Cloudflare skill's stance that defense-in-depth gaps are hardening, not findings.

## 7. Report

### 7.1 Schema

```json
{
  "engagement_id": "eng-2026-11-08-001",
  "window": { "start": "...", "end": "..." },
  "scope_summary": { "in_scope_hosts": ["..."], "max_blast_tier": 2 },
  "mode": "sandboxed",                         // sandboxed | passive-only
  "coverage_summary": {                        // from the coverage ledger
    "attempted": 142, "confirmed": 6, "rejected": 11,
    "inconclusive": 3, "not_applicable": 97, "blocked_by_policy": 25
  },
  "findings": [ /* classification: vulnerability */ ],
  "hardening_notes": [ /* classification: hardening_note */ ],
  "method_summary": "phases run, techniques covered, KB version",
  "generated_at": "2026-11-08T23:40"
}
```

### 7.2 Validator (zero-dependency, CI)

The report does not ship unless it validates:

- every finding has `found_by != verified_by`;
- every `confirmed` finding has at least one `verified_by_event_id` and a non-empty `repro`;
- every `vulnerability` has a `cvss` and at least one `cwe`; every `hardening_note` has neither;
- `technique_id` + `technique_version` resolve to a known card;
- no `inconclusive` or `needs_validation` item appears in the `findings` vulnerability list as confirmed;
- user-facing text is target-neutral: it describes the weakness, impact, and remediation, and does not carry raw internal errors or gratuitous target internals.

### 7.3 Coverage summary

Pulled straight from the coverage ledger, so the report answers "what did we try," not only "what did we find."
A technique that was `not_applicable` or `blocked_by_policy` is stated as such, which is what makes a negative result meaningful.

## 8. Interfaces

Consumes:

- HC-KB-01: the card's `success_signal` and `severity_rubric`.
- HC-SUB-01: `sandbox.restore` / `snapshot` for per-verification isolation.
- HC-DATA-01: probe_events for `found_by_event_ids` / `verified_by_event_ids`, and the label hook (a verdict is a gold label, HC-DATA-01 §9).
- HC-AGENT-01: the Operator (emit) and Verifier (reproduce) roles.

Produces:

```
findings.emit_lead(pair, repro, evidence, confidence) -> finding(lead)
findings.confirm(lead, verified_by, events)           -> finding(confirmed)
findings.reject(lead, reason) / mark_inconclusive(lead, reason)
findings.classify_hardening(observation)              -> hardening_note
findings.leads() / confirmed() / hardening_notes()
schema.validate(report)                               -> ok | errors[]
```

A confirm or reject also emits the corresponding `label` to HC-DATA-01 (`source: verifier`, `tier: silver` until audited), which is the self-labeling corpus in action.

## 9. Acceptance criteria

- A finding with `found_by == verified_by` cannot be produced, and the report validator rejects one if constructed by hand.
- Every `confirmed` finding is backed by Verifier probe_events distinct from the Operator's, from a fresh snapshot.
- A deterministic confidence-1.0 lead still requires verification before it is `confirmed`.
- rejected, inconclusive, and hardening_note are never counted as confirmed vulnerabilities in the report.
- Severity tracks the rubric: toggling a `raise_if` fact changes the CVSS score and band.
- In passive-only mode, every lead remains `needs_validation` and the report says `mode: passive-only`.

## 10. Open questions

- Whether a second confirmation technique (not a replay) is required for the highest severities before they ship as `confirmed`.
- How long to retain `inconclusive` leads for re-attempt in a later run versus closing them.
- Report rendering target: the validated JSON is the source of truth; whether the human-readable form is Markdown or an HTML artifact is a Reporter-role concern, deferred.
- De-duplication: when repeated runs confirm the same weakness on the same asset, whether to merge into one finding with multiple observations or keep per-run findings (leaning merge, keyed by technique_id + asset).
