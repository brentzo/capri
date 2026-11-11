# 04: npm lockfile hygiene across every npm package manager

**What to build:** the dependency hygiene area reads the lockfiles of every npm-ecosystem package manager: `package-lock.json` and `npm-shrinkwrap.json` (v1, v2, v3), `bun.lock`, yarn v1, yarn berry and `pnpm-lock.yaml`, without a YAML library.
It reports lockfile entries without an integrity hash (one finding per lockfile with the count), packages with install scripts (one finding per lockfile with the count), and a binary `bun.lockb` with no text `bun.lock` beside it.
A malformed or oversize lockfile makes that ecosystem's coverage `partial` with the reason instead of crashing the run.
Spec: Technical Design > "Algorithm: format readers", "Algorithm: Python hygiene checks" (missing integrity, install script, binary bun rows), hygiene severity table.

**Blocked by:** 03 (Tracer bullet: dependency section)

**Status:** ready-for-agent

- [ ] Each reader returns entries with line numbers and is tested on a positive and a negative fixture per format.
- [ ] Missing integrity: registry entries without `integrity` (npm, bun, yarn v1), without `checksum` (berry) or with a `resolution` lacking `integrity` (pnpm) are counted; local, bundled and workspace entries are not.
- [ ] Install scripts: `hasInstallScript` (npm) and `requiresBuild: true` (pnpm) are reported as INFO / low with the count.
- [ ] `bun.lockb` without `bun.lock` gives the INFO / high finding.
- [ ] yarn v1 and berry are told apart by the `__metadata:` line.
- [ ] Adversarial inputs are covered: malformed JSON, truncated block files, unknown lockfile versions and a file over the size limit each give `partial` coverage with a reason, and the run still completes.
- [ ] The bun JSONC trailing-comma scanner leaves commas inside strings untouched.
- [ ] HC-PROJ-02 and `harness/README.md` updated; `make check` green.
