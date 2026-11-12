---
tag: HC-PROJ-01
title: Local project assessment
status: draft
parent: SPEC.md#1, SPEC.md#4
depends_on: []
depended_on_by: [HC-PROJ-02]
updated: 2026-11-11
---

# HC-PROJ-01 - Local project assessment

## Purpose

This spec defines Capri's local project assessment path.
The current implementation is a read-only source assessment that accepts any local project directory, whatever its layout or stack.
It does not claim runtime coverage.

## Source assessment

The operator runs `python .\capri source --project <local-path>` from the Capri checkout.
The command requires a locally installed Semgrep CLI and uses only the Capri-owned rules in `rules/source/`.
It disables Semgrep metrics and version checks and does not fetch rules, install tools, execute project code, or contact a model provider.

The scanner excludes private environment files, dependencies, generated/build output, documentation, test fixtures, and binary data.
It reports only the rule id, category, severity, confidence, message, and relative code location.
It omits matched source lines and writes the report outside the selected project, defaulting to `~/.capri/reports/`.
On Windows, snapshot paths near the legacy 260-character limit are skipped and listed as source coverage reasons, so the assessment reports partial coverage instead of failing while copying.

The initial rule pack checks for committed credential patterns, disabled or unrestricted database RLS policies, missing fixed search paths on `SECURITY DEFINER` functions, frontend references to Supabase service-role credentials, Edge Function configuration that requires manual authentication review, and upload handling that requires a trusted-server validation review.
Rules that only apply to client-side code are scoped by directory names (`frontend`, `client`, `web`, `mobile`) or file names containing `upload` at any depth, not by one app's fixed layout, so they fire in monorepos and nested app folders.
The pack is stack-agnostic in what it accepts but Supabase-leaning in what it detects; a project without SQL migrations or Supabase configuration simply produces no findings in those areas.
These are advisory static results and are not runtime-confirmed vulnerabilities.

## Runtime boundary

The current live engagement runner targets Capri's built-in seeded demo and cannot run an arbitrary local app and its backing services inside Capri's proven range.
The source report therefore says runtime assessment was not run.
The existing dynamic sandbox guarantees are unchanged.

## Implementation pointer

The source command is implemented in `tools/project_assessment.py`, invoked by `capri`, and uses local rules under `rules/source/`.
Its tests are in `tests/test_project_assessment.py`.
