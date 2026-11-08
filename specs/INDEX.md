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
status: draft          # draft | review | stable | superseded
parent: SPEC.md#9      # the overview section this elaborates
depends_on: [HC-FIND-01]
updated: 2026-11-08
---
```

## Registry

| Tag | Title | Elaborates | Status |
|-----|-------|-----------|--------|
| HC-SUB-01   | Sandbox, scope guard, engagement contract              | SPEC.md#3        | draft   |
| HC-MODEL-01 | Bifrost topology: roles, keys, budgets, MCP boundary   | SPEC.md#5.1      | planned |
| HC-MODEL-02 | Laya decision layer and fine-tuning pipeline           | SPEC.md#5.2, #10 | planned |
| HC-ENRICH-01| Tavily enrichment service and untrusted-data handling  | SPEC.md#5.3      | planned |
| HC-KB-01    | Technique-card schema and KB structure                 | SPEC.md#7        | draft   |
| HC-KB-02    | Web and auth technique-card starter set                | SPEC.md#7        | draft   |
| HC-AGENT-01 | Agent loop and role orchestration                      | SPEC.md#4, #6    | draft   |
| HC-FIND-01  | Findings model and verification protocol               | SPEC.md#8        | draft   |
| HC-DATA-01  | Evidence store and self-labeling corpus                | SPEC.md#9        | draft   |
| HC-SAFE-01  | Safety and guardrails                                  | SPEC.md#11       | planned |
| HC-EVAL-01  | Evaluation harness and seeded vulns                    | SPEC.md#14       | draft   |

## Status legend

- `planned`: listed here, not yet drafted.
- `draft`: written, not yet reviewed.
- `review`: under review.
- `stable`: agreed and current.
- `superseded`: replaced; the frontmatter names its successor.

Keep this registry in sync when a spec is added or changes status, and mirror structural decisions back into the SPEC.md decision log.
