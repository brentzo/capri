# 08: Vulnerable dependencies from lockfiles via Trivy

**What to build:** when the readiness gate passes, the vulnerable-dependency area runs one hardened, offline Trivy scan over the assessment snapshot and reports vulnerable dependencies for every lockfile ecosystem: npm, pnpm, yarn, bun (text), CocoaPods, SwiftPM, Pub and `gradle.lockfile`.
Each finding names the ecosystem, package, resolved version, dependency scope, advisory ids, the advisory's own severity, fixed versions, title, advisory link, lockfile path and line, and the reachability label.
Per-ecosystem package counts and coverage are reported, including `partial` for units without an assessable lockfile and for lockfiles Trivy returned nothing for.
Spec: Technical Design > "Algorithm: Trivy invocation and result mapping", "Algorithm: coverage", "Report contract".

**Blocked by:** 04 (npm lockfile hygiene), 07 (update-db and readiness gate)

**Status:** ready-for-agent

- [ ] The Trivy command carries every flag in the spec (vuln scanner only, library packages, dev dependencies included, all packages listed, JSON, quiet, offline scan, all skip flags, telemetry off, Capri cache, empty config and ignore file), runs on the snapshot, never on the project, with `TRIVY_*` scrubbed; asserted in tests.
- [ ] Real Trivy is run locally with a downloaded database against small fixture projects; its JSON is committed as the recorded fixture that CI tests replay.
- [ ] Results map to project-relative paths; `Type` maps to the glossary ecosystems; `Dev` gives scope `dev`, otherwise `runtime`.
- [ ] Advisory ids merge `VulnerabilityID` and `VendorIDs` without duplicates; empty `FixedVersion` gives null; findings are deduplicated and sorted by severity, ecosystem, path, package.
- [ ] A non-empty lockfile with no Trivy result marks its ecosystem `partial` with the reason.
- [ ] Trivy failure, timeout or invalid JSON sets the area `not_run` with the reason; Trivy's stderr never reaches the report.
- [ ] Units with no lockfile, `bun.lockb` only or an oversize lockfile make the ecosystem `partial` with one reason per cause.
- [ ] The report lists findings and package counts only, never the full dependency inventory.
- [ ] HC-PROJ-02 and `harness/README.md` updated; `make check` green.
