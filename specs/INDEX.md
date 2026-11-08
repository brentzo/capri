# HackCulture spec index

This directory holds the detailed component specs that elaborate the sections of [../SPEC.md](../SPEC.md).
SPEC.md stays the overview and decision log; each file here goes deep on exactly one component.

## Tagging convention

Every spec carries a stable tag of the form `HC-<AREA>-<nn>`.
The tag is both the filename prefix and the cross-reference handle used across all docs, for example "see HC-DATA-01".
A tag never changes once assigned, even though the project name (currently the temporary "luna" remote) will.
New specs take the next free number within their area.

Areas:

- `SUB` - substrate (sandbox, scope guard, engagement contract)
- `MODEL` - model plane (Bifrost, Laya)
- `ENRICH` - external enrichment (Tavily)
- `KB` - technique knowledge base
- `AGENT` - agent loop and role orchestration
- `FIND` - findings model and verification
- `DATA` - evidence store and corpus
- `SAFE` - safety and guardrails
- `EVAL` - evaluation

Each spec file opens with this frontmatter:

```yaml
---
tag: HC-DATA-01
title: Evidence store and self-labeling corpus
status: draft          # planned | draft | review | stable | superseded
parent: SPEC.md#9      # the overview section this elaborates
depends_on: [HC-SUB-01, HC-KB-01, HC-FIND-01]
depended_on_by: [HC-MODEL-02, HC-AGENT-01, HC-FIND-01, HC-SAFE-01, HC-EVAL-01]
updated: 2026-11-08
---
```

## Registry

| Tag | Title | Elaborates | Status |
|-----|-------|-----------|--------|
| HC-SUB-01   | Sandbox, scope guard, engagement contract              | SPEC.md#3        | draft   |
| HC-MODEL-01 | Bifrost topology: roles, keys, budgets, MCP boundary   | SPEC.md#5.1      | draft   |
| HC-MODEL-02 | Laya decision layer and fine-tuning pipeline           | SPEC.md#5.2, #10 | draft   |
| HC-ENRICH-01| Tavily enrichment service and untrusted-data handling  | SPEC.md#5.3      | draft   |
| HC-KB-01   | Technique-card schema and KB structure                 | SPEC.md#7        | draft   |
| HC-KB-02   | Web and auth technique-card starter set                | SPEC.md#7        | draft   |
| HC-KB-03   | AI and LLM technique-card starter set                  | SPEC.md#7        | draft   |
| HC-KB-04   | Client-side technique-card starter set                | SPEC.md#7        | draft   |
| HC-KB-05   | Cloud and deployment technique-card starter set       | SPEC.md#7        | draft   |
| HC-KB-06   | Supply-chain technique-card starter set               | SPEC.md#7        | draft   |
| HC-KB-07   | RPC and messaging technique-card starter set          | SPEC.md#7        | draft   |
| HC-KB-08   | Resource-exhaustion technique-card starter set        | SPEC.md#7        | draft   |
| HC-KB-09   | Data-isolation technique-card starter set             | SPEC.md#7        | draft   |
| HC-KB-10   | Memory and binary technique-card starter set          | SPEC.md#7        | draft   |
| HC-KB-11   | Mobile and local-IPC technique-card starter set       | SPEC.md#7        | draft   |
| HC-AGENT-01 | Agent loop and role orchestration                      | SPEC.md#4, #6    | draft   |
| HC-FIND-01  | Findings model and verification protocol               | SPEC.md#8        | draft   |
| HC-DATA-01  | Evidence store and self-labeling corpus                | SPEC.md#9        | draft   |
| HC-SAFE-01  | Safety and guardrails                                  | SPEC.md#11       | draft   |
| HC-EVAL-01  | Evaluation harness and seeded vulns                    | SPEC.md#14       | draft   |

## Status legend

- `planned`: listed here, not yet drafted.
- `draft`: written, not yet reviewed.
- `review`: under review.
- `stable`: agreed and current.
- `superseded`: replaced; the frontmatter names its successor.

Keep this registry in sync when a spec is added or changes status, and mirror structural decisions back into the SPEC.md decision log.

## Dependency edges

`depends_on` is the authoritative forward edge; each spec's `depended_on_by` is the exact reverse and is regenerated whenever an edge changes.
A few specs are mutually dependent by design because they define two halves of one contract: HC-AGENT-01 and HC-MODEL-01, HC-AGENT-01 and HC-FIND-01, and HC-FIND-01 and HC-DATA-01.
The graph is therefore intentionally not a strict DAG, and those cycles are expected rather than errors.

## Tooling

The HC-KB-01 validation gate is implemented in `../tools/validate_kb.py` (pure standard library), with the bundled taxonomy reference in `../tools/taxonomy.py` and adversarial tests in `../tests/test_validator.py`.
It runs in CI (`../.github/workflows/validate.yml`) and locally via `make validate` / `make test`; see `../tools/README.md`.
The cards are materialized from the specs into `../kb/<class>/*.yaml` (with `../kb/_index/index.md` and `../eval/manifests/`) by `../tools/materialize_kb.py`; the validator checks that full-card tree by default.
All 107 cards pass `--strict`, including the shipping-field, filename, and manifest-coverage checks (the two ATLAS ids the validator first flagged, `AML.T0053` and `AML.T0057`, were confirmed against ATLAS v4.9.0 and added to the reference).
