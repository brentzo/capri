# 02: Run real Semgrep in CI

**What to build:** CI installs a pinned Semgrep (1.180.0) so Capri's rule pack is exercised for real, not only through a fake scanner.
The existing source rules gain positive and negative fixture tests that run through the source assessment's public entry point with real Semgrep.
Every later rule ticket can then add rule tests that run in CI.
Spec: Testing Decisions.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The CI workflow installs Semgrep at exactly 1.180.0 before the test steps, using the repo's tooling conventions (no unpinned install).
- [ ] Each existing rule (secrets, RLS disabled, unrestricted policy, definer search path, manual auth, service role in client, upload validation) has one fixture that must match and one that must not.
- [ ] Rule tests fail with a clear message, not a skip, when Semgrep is missing locally, so a missing scanner is visible.
- [ ] Any new test suite is wired into both the `test` target in `Makefile` and the step list in the CI workflow.
- [ ] The CI run on the pushed commit is green (`gh-axi run list`).
- [ ] `make check` green locally.
