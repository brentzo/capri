# 10: Full ecosystem verification and ship docs

**What to build:** the dependency assessment is verified end to end on real tools and its docs are final.
A documented local run of real Semgrep and real Trivy with a fresh database covers one fixture project per ecosystem, plus a mixed Expo-style project (npm lockfile, `ios/Podfile.lock`, Gradle without a lockfile) and a monorepo with nested workspace lockfiles.
The recorded fixtures are refreshed from that run, and the docs match the shipped behaviour.
Spec: Testing Decisions, Further Notes.

**Blocked by:** 05 (Registry hygiene), 06 (Mobile hygiene), 09 (Gradle declared versions)

**Status:** ready-for-agent

- [ ] The local verification procedure is written down (in HC-PROJ-02 or the tools README) and was run; its output matches the per-ecosystem expectations, including coverage statuses and the stale-database warning.
- [ ] The mixed Expo-style project reports npm and CocoaPods `complete`, Gradle `partial`, and the vulnerable area's overall status `partial`.
- [ ] No network call happens during the assessment (checked by running with networking disabled for the scanner processes, or an equivalent documented check).
- [ ] Recorded Trivy fixtures refreshed from the verification run; CI green.
- [ ] HC-PROJ-02 gets its implementation-pointer paragraph; `README.md` documents `capri source` dependency output and `update-db`; `harness/README.md` section final.
- [ ] HC-KB-06's open question on package-manager fidelity is marked answered with a pointer to HC-PROJ-02.
- [ ] `SPEC.md` decision log records that the dependency inventory never leaves the machine and why; `make check` green.
