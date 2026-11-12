# Capri

Capri is an autonomous penetration-testing system for authorized, scoped engagements, plus a read-only assessment of a local project's source.
This glossary fixes the words used across specs, code and reports.

## Local project assessment

**Source assessment**:
A read-only, offline examination of a local project's files that never runs the project's code and keeps its results on the operator's machine.
_Avoid_: source scan, SAST run

**Assessment area**:
One named group of checks within a source assessment, reported with its own coverage status.
_Avoid_: category, check group

**Coverage status**:
Whether an assessment area, or one ecosystem within it, was `complete`, `partial` with a stated reason, `not_applicable` because the project has nothing it examines, or `not_run` with a stated reason.
An area's overall status is `complete` only when every ecosystem in it is, `not_run` only when none of them ran, and `partial` otherwise.
_Avoid_: zero findings (as a stand-in for "not checked")

**Advisory finding**:
A static result from a source assessment that has not been confirmed against a running target.
_Avoid_: finding (unqualified, which means a verified runtime finding), vulnerability

**Suppression**:
An operator-owned instruction to leave a specific advisory finding out of a report; never read from the assessed project.
_Avoid_: ignore file, allowlist

## Dependencies

**Dependency assessment**:
The assessment areas of a source assessment that examine the third-party packages a project uses.
_Avoid_: SCA, dependency scan

**Ecosystem**:
A package registry and its naming universe, such as npm, CocoaPods, SwiftPM, Pub or Maven.
_Avoid_: platform, language

**Package manager**:
The tool that resolves dependencies and writes a lockfile within an ecosystem, such as npm, pnpm, yarn or bun within the npm ecosystem.
_Avoid_: ecosystem (when the tool is meant)

**Manifest**:
A file in which a project declares the dependencies it wants.
_Avoid_: dependency file, config

**Lockfile**:
A file a package manager writes to record the exact versions it resolved.
_Avoid_: manifest, shrinkwrap (as a general term)

**Declared version**:
A version or range as written in a manifest, which may not be what gets installed.
_Avoid_: requested version

**Resolved version**:
The exact version recorded in a lockfile.
_Avoid_: installed version

**Dependency inventory**:
The set of packages and versions a project uses, treated as private to the operator's machine.
_Avoid_: SBOM (a file format, not the concept)

**Vulnerable dependency**:
A dependency whose resolved or declared version is named by a published advisory.
_Avoid_: CVE finding

**Dependency scope**:
Whether a dependency ships in the built app (`runtime`) or only in development, test and build tooling (`dev`).
_Avoid_: dev dependency (as the name of the concept)

**Dependency hygiene**:
Properties of manifests and lockfiles that weaken supply-chain integrity and are visible without any vulnerability data.
_Avoid_: best practices, lint

**Vulnerability database**:
A local, operator-provisioned copy of published advisories that a dependency assessment reads without network access.
_Avoid_: feed, rule pack
