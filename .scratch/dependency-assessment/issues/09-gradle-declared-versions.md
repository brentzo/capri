# 09: Gradle declared versions

**What to build:** an Android project without a Gradle lockfile still gets vulnerable-dependency coverage for its directly declared libraries.
Capri reads exact declared versions from the version catalog and from literal coordinates in build scripts, writes them into a temporary Gradle lockfile inside the assessment snapshot (never the project), and lets the same Trivy scan match them.
Findings point back to the original manifest and line, carry version kind `declared` and a scope taken from the build configuration, and Gradle coverage is `partial` because transitive dependencies are not covered.
Spec: Technical Design > "Algorithm: Gradle declared versions".

**Blocked by:** 06 (Mobile hygiene, for the Gradle root rule), 08 (Vulnerable dependencies via Trivy)

**Status:** ready-for-agent

- [ ] Catalog libraries in all three shapes (string, `module` + version, `group` + `name` + version) resolve, including `version.ref` and `{ ref = ... }` through `[versions]`.
- [ ] Build-script string notation and Groovy map notation are read; `test*` and `androidTest*` configurations give scope `dev`.
- [ ] Values with `$`, `+`, `[`, `(`, `,` or `latest.` are not matched.
- [ ] A Gradle root that has a real lockfile is not synthesized; resolved versions win.
- [ ] Findings show the manifest path and the declaring line, never the synthesized file.
- [ ] Gradle coverage is `partial` with the reason "declared versions only; transitive dependencies not covered".
- [ ] Nothing is written inside the project.
- [ ] Verified with real Trivy on an Android fixture; recorded JSON committed for CI.
- [ ] HC-PROJ-02 updated; `make check` green.
