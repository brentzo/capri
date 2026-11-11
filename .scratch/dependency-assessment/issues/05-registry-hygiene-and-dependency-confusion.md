# 05: Registry hygiene: http registries and dependency confusion

**What to build:** the dependency hygiene area flags registry configuration that lets an attacker substitute a package.
A Semgrep rule reports `http://` registries in `.npmrc`, `.yarnrc` and `.yarnrc.yml`.
A Python check reports dependency confusion precisely: a scoped package that a lockfile shows was resolved from a non-public registry, with no project registry config pinning that scope to that registry.
The check ships for `package-lock.json`, yarn v1 and `bun.lock`, and deliberately not for pnpm and yarn berry, whose lockfiles do not record the registry host.
Spec: Technical Design > "Algorithm: dependency confusion", "Semgrep hygiene rules" (`source.deps.npm-http-registry`).

**Blocked by:** 02 (Run real Semgrep in CI), 04 (npm lockfile hygiene)

**Status:** ready-for-agent

- [ ] `http://` registry in each of the three config formats is reported ERROR / high; `https://` is not; tested with real Semgrep.
- [ ] A scoped package resolved from a private registry with no scope pin is reported ERROR / medium at the first entry of that scope.
- [ ] The same package with an `.npmrc`, `.yarnrc` or `.yarnrc.yml` scope pin in the lockfile's directory or an ancestor is not reported.
- [ ] Public scoped packages resolved from `registry.npmjs.org` or `registry.yarnpkg.com` (for example `@types/react`) are never reported.
- [ ] User-level config outside the project is ignored, and HC-PROJ-02 says why.
- [ ] HC-PROJ-02 records that pnpm and yarn berry are out of scope for this check and why.
- [ ] `make check` green.
