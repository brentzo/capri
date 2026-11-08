# Business requirements

End-to-end, user-facing requirements for the autonomous authorized-pentest
system, each with Gherkin acceptance scenarios that describe how an **operator**
(the security engineer running the assessment), a **security lead** (who
authorizes it), or an **auditor** actually uses the system. These are the
"what and why"; the `HC-*` technical specs in `../specs/` are the "how".

## Convention

- One file per requirement: `BR-<nn>-<slug>.md`.
- Each states the requirement as `As a <role>, I want <capability>, so that
  <value>`, names the `HC-*` specs that implement it, and carries exactly one
  Gherkin `Feature:` with its acceptance scenarios, written from the user's
  point of view (what they do and observe, not how it works inside).
- The executable Gherkin is generated from these docs into `features/*.feature`
  by `../tools/gen_features.py` (`make features`); CI fails if they drift, so
  the docs stay the single source of truth.

## Requirements

| Tag | Requirement | Implemented by |
|-----|-------------|----------------|
| BR-01 | Authorize and scope an engagement | HC-SUB-01 |
| BR-02 | Safe by construction (scope, egress, containment) | HC-SUB-01, HC-SAFE-01 |
| BR-03 | Autonomous hunting grounded in real techniques | HC-AGENT-01, HC-KB-* |
| BR-04 | Report only independently verified findings | HC-FIND-01, HC-MODEL-01 |
| BR-05 | Deliver a trustworthy, actionable report | HC-FIND-01 |
| BR-06 | Reproducible and resumable runs | HC-SUB-01, HC-AGENT-01, HC-DATA-01 |
| BR-07 | Degrade safely when the sandbox is not proven | HC-SUB-01, HC-FIND-01 |
| BR-08 | Full evidence and a tamper-evident audit trail | HC-DATA-01, HC-SAFE-01 |
| BR-09 | Bounded cost and controlled model access | HC-MODEL-01 |
| BR-10 | Optional external intel that never touches the sandbox | HC-ENRICH-01, HC-MODEL-01 |
