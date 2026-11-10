---
tag: HC-REPORT-01
title: Operator report rendering, reasoning record, and the local run dashboard
status: draft
parent: SPEC.md#8
depends_on: [HC-FIND-01, HC-DATA-01, HC-AGENT-01, HC-SAFE-01, HC-MODEL-01]
depended_on_by: []
updated: 2026-11-10
---

# HC-REPORT-01 - Operator report rendering, reasoning record, and the local run dashboard

## 1. Purpose

This spec defines the operator-facing output of a run: how a finished engagement is persisted so it survives the process, how the agent's per-step reasoning is captured alongside the evidence, how the validated report (HC-FIND-01 §7) is rendered in human form, and the local dashboard a self-hoster launches to browse their runs.

Everything here is presentation and persistence; no new verdict is reached in this layer.

Two rules shape all of it.
First, the dashboard is a read-only window onto persisted, validated truth: it renders what the harness already decided and recorded, adds no judgment of its own, and reaches nothing live.
Second, every word a model produced is untrusted data: it is shown to the operator but never trusted, never fed back into a run, and never crosses from finder to verifier.

## 2. Run persistence

Today a live run opens an in-memory database (`harness/store/db.py:connect()` defaults to `:memory:`), so the engagement, its findings, its probe_events, and its audit chain vanish when the process exits.
A dashboard has nothing to read until a run is durable, so this spec makes a run persist.

A run persists to a per-user data directory, `~/.capri/` by default (overridable), holding two things:

- `~/.capri/engagements.db`: one SQLite file carrying every engagement, so a self-hoster accumulates a history rather than one disposable run. The schema gains one minimal `engagement` summary row per run (its identity, window, scope, mode, and validated report); the evidence, finding, and audit tables are unchanged, and the connection target moves from memory to this file.
- `~/.capri/blobs/`: the content-addressed blob store (HC-DATA-01), already filesystem-backed, rooted here so raw request and response bodies survive with the run that references them.

The store gains a small read API over the existing tables, used only by the dashboard and never by the control loop:

```
engagements.list()            -> [ { id, started_at, mode, scope_summary, coverage_summary } ]  (most recent first)
engagements.get(id)           -> the engagement row plus its report (built via HC-FIND-01)
engagements.audit(id)         -> the ordered audit rows with hash-chain verification status
engagements.reasoning(id)     -> the role-turn records of §3, ordered by step
```

Persistence changes where a run is written, not what the run does.
The append-only discipline of HC-DATA-01 and the audit chain of HC-SAFE-01 are preserved exactly; a durable file simply means they can be read back after the fact, which is the whole point of BR-06 (reproducible, resumable) and BR-08 (defensible after the fact).

## 3. The reasoning record

The control loop already receives each role's raw proposal text (`raw = operator.propose_next(...)`, and the same for the Verifier), parses it into a structured action, and then drops the text.
To satisfy "see the reasoning behind the agent," that text is now captured as a role turn, so the operator can read, step by step, what the agent proposed and why it acted.

A role turn record:

```json
{
  "id": "rt_...",
  "engagement_id": "eng-2026-11-10-001",
  "role": "operator",                       // operator | verifier
  "session_id": "vk-operator-b7188518",     // the finder/verifier identity (HC-AGENT-01)
  "asset": "t1.sandbox.local",
  "technique_id": "KB-WEB-INJ-SQLI-001",
  "step": 1,                                // 0-based index within this pair's budget loop
  "raw": "<the model's verbatim proposal text>",
  "parsed": { "tool": "sqli", "args": { "...": "..." } },   // or null when the turn was unparseable
  "rejection": null,                        // the roleio rejection reason when parsed is null
  "probe_event_id": "pe_...",               // the dispatched action this turn produced, when any
  "at": "2026-11-10T20:14"
}
```

The record is write-only from the loop and read-only from the dashboard, which keeps the finder-is-not-verifier guarantee intact: capturing the Operator's text for later display does not place it in front of the Verifier, because the Verifier still receives only repro, evidence, and the success signal (HC-FIND-01 §4.1).

Trust posture, non-negotiable:

- The reasoning record is untrusted data. It is never read back into a role's context, never used to decide a verdict, and never used to plan the next step.
- It is rendered as escaped text. A model that emits markup, a prompt-injection string, or a fake verdict produces inert text on the page, never active content and never a trusted claim.
- It is isolated per identity. The Operator's turns and the Verifier's turns are stored and shown as what each independent session said, never merged into one voice that implies collusion.

## 4. The decision and evidence trail

The reasoning record is the agent's own words; the decision trail is what the harness did with them, and the two are shown side by side.
The trail is already recorded and needs only to be composed for display:

- the technique and asset the pair targets, and the planner's ordering (HC-AGENT-01 §3);
- per step, the dispatch decision, allow or deny, with the scope, blast, and rate outcomes that produced it (HC-DATA-01 audit row);
- the raw request and response captured for the action (HC-DATA-01 probe_event, bodies in the blob store);
- the deterministic signal the harness read and the verdict transition it drove (HC-FIND-01 §2, §4.3).

So for any confirmed finding the operator can trace: what the Operator proposed (§3), what the harness allowed and ran, the exact bytes that came back, the signal that fired, and the Verifier's independent reproduction of that signal on a fresh snapshot, found-by distinct from verified-by throughout.
That chain is the answer to "how do I know this finding is real," rendered rather than asserted.

## 5. Report rendering

The validated report JSON (HC-FIND-01 §7.1) is the source of truth; this layer renders it in human form, adding no fact the validator did not already pass.

The renderer is a pure function from the report record to a view, so it is unit-tested with no server and no run:

- each finding shows its weakness, impact, remediation, CVSS v4 band and score, and CWE, with links to the raw evidence at find and at verify;
- hardening notes render in their own section with no severity, never counted among the vulnerabilities (HC-FIND-01 §6);
- the coverage summary renders attempted, not-applicable, and blocked counts, so the report says what was tried, not only what was found (BR-05);
- a passive-only run renders a banner explaining containment was not continuously proven and ships no confirmed findings (HC-SUB-01 §9);
- timestamps render in am/pm, not a 24-hour clock, which closes the BR-08 presentation requirement that the stored ISO form (HC-DATA-01) defers to render time;
- the renderer inherits the validator's target-neutral guarantee: it shows only text that already passed `validate_report`, so no stack trace, status code, or raw internal error reaches the page (BR-05).

The same renderer feeds both the dashboard views of §6 and an optional static export (a single self-contained HTML or Markdown file) for handoff, so the on-screen report and the exported one cannot diverge.

## 6. The local dashboard

`capri dashboard` starts a local, read-only web view over the persisted store, as the one command a self-hoster runs to see their runs, consistent with the self-host, no-cloud posture of HC-MODEL-01.

- It is served by the standard-library `http.server` only, with server-rendered HTML and minimal or no client script, so the zero-third-party-dependency rule holds.
- It binds to the loopback interface (127.0.0.1) only, never 0.0.0.0, so a run history is not exposed on the network; it is a single-user local tool, so it carries no auth of its own and relies on the loopback boundary.
- It performs no egress and runs no tool: it provisions no range, dispatches no probe, and reaches no target. It only reads `~/.capri/`, which keeps it outside the sandbox threat model entirely.

Routes:

```
GET /                       run list: id, started_at, mode, confirmed/total, scope
GET /run/{id}               the rendered report (§5): findings, coverage, hardening notes
GET /run/{id}/finding/{fid} finding detail: impact/remediation/CVSS/CWE and the raw request+response at find and verify
GET /run/{id}/reasoning     the step-by-step view: role turns (§3) beside the decision trail (§4)
GET /run/{id}/audit         the audit timeline with its hash-chain verification status (HC-SAFE-01)
GET /blob/{digest}          a single raw evidence body, served read-only from the blob store
```

The audit view renders the result of re-verifying the hash chain, so a tampered or removed row is visible to the operator rather than silently absent (BR-08).

## 7. Safety and trust posture

- Read-only: the dashboard never mutates the store and cannot start, stop, or alter a run. Controlling a run from the UI is deferred (§10).
- Loopback-only and egress-free: it is reachable only from the host it runs on and reaches nothing itself, matching the whole system's default-deny posture.
- Untrusted model text: every byte a model produced, in a reasoning record or quoted in a finding, is rendered escaped and labelled as what that session said, never as a system claim.
- Tamper-evident: the audit view surfaces hash-chain verification, so the record's integrity is shown, not assumed.
- Target-neutral: because it renders only `validate_report`-passed text for findings, internal failure detail never reaches the operator-facing page.

## 8. Interfaces

Consumes:

- HC-FIND-01: `build_report` / `validate_report` and the finding records that the renderer (§5) turns into views.
- HC-DATA-01: probe_events and their raw blobs for the evidence trail (§4), and the audit rows for the timeline (§6).
- HC-SAFE-01: the audit hash chain and its verification, surfaced in the audit view.
- HC-AGENT-01: the control loop, which gains the one write that persists each role turn (§3); the loop's behaviour is otherwise unchanged.
- HC-MODEL-01: the `capri` CLI, which hosts the `dashboard` command and already owns the local, no-cloud operator surface.

Produces:

```
engagements.list() / get(id) / audit(id) / reasoning(id)      the store read API (§2)
reasoning.record(turn)                                        the loop's write of a role turn (§3)
report.render(report_record)                                 the pure renderer (§5)
capri dashboard [--port] [--data-dir]                         the local server (§6)
```

Implementation, pure standard library: run persistence and the read API are built in `harness/store/datadir.py` (the `~/.capri/` data directory, overridable with `HC_DATA_DIR`) and `harness/store/engagements.py` (`save`, `list_all`, `get`, `audit`), with the one-row `engagement` table in `harness/store/schema.sql` and the live runner persisting each finished run (`tools/run_engagement.py`); `tests/test_engagements_store.py` proves a run still lists and re-opens after the writing connection is closed.
Still to build: the role-turn reasoning record written from `harness/loop.py` (§3), the renderer over the validated report (§5), and the local server in `cli/dashboard.py` behind a new `capri` subcommand (§6), with their tests wired into the Makefile and CI per the repo convention.

## 9. Acceptance criteria

- A finished run persists under `~/.capri/` and is still listable and viewable after the process that produced it has exited.
- The rendered report shows, per confirmed finding, impact, severity (CVSS band and score), remediation, CWE, and links to the raw request and response at both find and verify; hardening notes appear separately with no severity.
- The report and the audit render times in am/pm, not a 24-hour clock.
- For any confirmed finding, the operator can read the Operator's proposal text, the harness's allow/deny decision, the raw bytes, the signal, and the Verifier's independent reproduction, with found-by distinct from verified-by.
- Model-authored text renders as inert, escaped text; a reasoning record containing markup or a fabricated verdict changes nothing and is shown as what that session said.
- The audit view reports the hash-chain verification result, and an altered or removed row shows as a detected break.
- The dashboard binds to loopback only, performs no egress, runs no tool, and never mutates the store.
- A passive-only run renders its banner and no confirmed findings.

## 10. Open questions

- Whether the dashboard should be able to launch or stop a run, not only view history; v1 is read-only and this is deferred.
- Retention under `~/.capri/`: how many runs to keep and whether to offer pruning, versus keeping every run forever.
- A Reporter LLM that writes narrative prose over the deterministic report (HC-MODEL-01, future): this spec surfaces captured reasoning and renders the deterministic report, and a model-written summary would layer on top, clearly labelled as model-generated and still bound by the target-neutral guarantee.
- Cross-run de-duplication of the same weakness on the same asset, shared with the HC-FIND-01 open question, and how the dashboard would present a merged finding's multiple observations.
- Whether a remote, authenticated mode is ever wanted; for now loopback-only is deliberate and sufficient for a self-hoster.
