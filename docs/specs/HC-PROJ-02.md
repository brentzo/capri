---
tag: HC-PROJ-02
title: Dependency assessment
status: draft
parent: SPEC.md#1
depends_on: [HC-PROJ-01, HC-KB-06]
depended_on_by: []
updated: 2026-11-11
---

# HC-PROJ-02 - Dependency assessment

## Purpose

This spec defines the dependency areas of Capri's local source assessment.
It builds on HC-PROJ-01 and never sends the project's dependency inventory to a network service.

## User contract

`capri source --project <path>` runs source rules and dependency assessment in one read-only command.
The report schema is version 2 and contains `source_assessment`, `dependency_assessment` and `runtime_assessment`.
Dependency results are advisory and remain separate from runtime findings.

The dependency area covers npm package managers (npm, pnpm, yarn v1 and berry, bun), CocoaPods, SwiftPM, Pub and Gradle.
Manifests and lockfiles are discovered at any depth in the clean assessment snapshot.
Installed dependency folders are excluded.

## Privacy and safety boundary

Capri copies accepted regular files into a temporary snapshot outside the project, omitting project-owned ignore and scanner configuration files.
It skips symlinks, does not copy files over 50 MB, and stops if the snapshot would exceed 2 GB.
Semgrep and Trivy scan only this snapshot.
Neither scanner is permitted to run package managers, build tools or project code.
The snapshot is removed after success or failure, and the report is refused inside the selected project.

Semgrep metrics, version checks and user `SEMGREP_*` settings are disabled for the scan.
Trivy receives an empty config and ignore file, has user `TRIVY_*` settings removed, and runs with offline and database-update skip flags.
No assessment command downloads a database.

The report contains dependency findings, package counts and project-relative locations, but not the complete dependency inventory, file contents or source snippets.
The explicit `capri source update-db` command downloads only Trivy's public vulnerability database into `~/.capri/trivy/`.
For air-gapped use, operators copy `trivy.db` and `metadata.json` into `~/.capri/trivy/db/`.

## Assessment areas

### Vulnerable dependencies

Trivy 0.75.0 or newer matches local advisories against npm, CocoaPods, SwiftPM, Pub and Gradle lockfiles.
The database update time, age and stale flag are recorded.
An absent or unusable Trivy installation or database reports `not_run`, prints a warning and does not prevent source rules or hygiene checks from completing.

Each finding records the ecosystem, package, version, resolved or declared version kind, runtime or dev scope, advisory identifiers, advisory severity, fixed versions, title, URL, lockfile or manifest location and the label `present in lockfile, reachability not checked`.
The report deduplicates and sorts findings by advisory severity, ecosystem, location and package.

Gradle exact literal versions from build scripts and `libs.versions.toml` are synthesized into temporary lockfiles when a real Gradle lockfile is absent.
Those findings point to the source declaration and are marked `declared`.
Gradle declared-only coverage is `partial` because transitive dependencies are not assessed.

### Dependency hygiene

Python checks parse npm manifests and text lockfiles with the standard library.
They report missing lockfiles, loose npm version ranges, non-registry npm sources, lockfile entries without integrity data, install scripts, binary-only `bun.lockb`, and private scoped registries without a project scope pin.
Semgrep rules report HTTP registries and repositories, unpinned CocoaPods git sources, SwiftPM branch pins, Pub git or path sources, Gradle dynamic versions, `mavenLocal()` and missing Gradle lockfiles.

Each hygiene finding uses ERROR, WARNING or INFO and high, medium or low confidence.
ERROR is reserved for HTTP or dependency-confusion configurations that allow package substitution.
Every hygiene finding names the related HC-KB-06 supply-chain technique.
User-level package-manager configuration is ignored because the risk must be fixed in project-controlled files.
Dependency-confusion checks are limited to npm, yarn v1 and bun, whose lockfiles expose the registry host; pnpm and yarn berry are excluded because their lockfiles do not make that check precise.

## Coverage model

Each area reports a coverage object for npm, CocoaPods, SwiftPM, Pub and Gradle.
An unused ecosystem is `not_applicable`.
Coverage is `complete`, `partial`, `not_run` or `not_applicable`, with reasons whenever it is incomplete.
Ignoring `not_applicable` ecosystems, an area's overall status is `complete` only when every present ecosystem is complete, `not_run` only when none ran, and `partial` otherwise; an area that found vulnerable dependencies in one ecosystem is never headlined `not_run` because another ecosystem could not be assessed.

Malformed or oversized dependency files make the affected ecosystem `partial` while other ecosystems continue.
Vulnerable dependency coverage is `partial` when only some package units are assessable, when a lockfile receives no scanner results, or when Gradle is declared-only.
It is `not_run` when no unit is assessable or the Trivy readiness gate fails.
Dependency hygiene is `complete` unless a relevant file could not be parsed or was too large.

## Implementation pointer

`tools/project_assessment.py` owns the public assessment and CLI entry points.
`tools/project_snapshot.py` builds the private scan snapshot, and `tools/dependencies/` contains the readers, hygiene checks, Gradle extraction, coverage computation and Trivy integration behind `assess_dependencies`.
Semgrep hygiene rules live in `rules/source/dependencies.yaml`.
Behavior is covered through `tests/test_project_assessment.py`, wired into `make test` and CI with Semgrep pinned to 1.180.0.
The verified Trivy database-only download command is `trivy image --download-db-only`.

The implementation is intentionally package-manager-neutral within each ecosystem: format readers follow the recognized lockfile formats but do not run managers or reimplement their resolution algorithms.
This answers HC-KB-06's ecosystem-fidelity question; the technique cards remain manager-neutral.
