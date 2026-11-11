# 07: `capri source update-db` and the Trivy readiness gate

**What to build:** an operator can run `capri source update-db` to download only the public Trivy vulnerability database into a Capri-owned cache, with telemetry, version checks and config loading off, and see the database's date printed.
During an assessment, the vulnerable-dependency area checks readiness without touching the network: Trivy installed, Trivy at least 0.75.0, database present.
Any failure sets the area `not_run` with the precise reason and prints a warning while the run still exits 0.
When ready, the report records the scanner version and the database update time, age and stale flag (older than 7 days); matching itself arrives in ticket 08.
Spec: Technical Design > "End-to-end flow" (update-db), "Algorithm: Trivy invocation and result mapping" (gate, database age), "Error handling summary".

**Blocked by:** 03 (Tracer bullet: dependency section)

**Status:** ready-for-agent

- [ ] `update-db` runs Trivy's database-only download with the Capri-owned cache directory, telemetry off, version check off, empty config, and an environment with `TRIVY_*` removed; tested through the CLI's `main` with an injected runner asserting the exact command.
- [ ] `update-db` prints the database `UpdatedAt` time and exits 0; without Trivy, with Trivy below 0.75.0, or on a failed download it exits 1 with the reason and the version requirement.
- [ ] Which Trivy subcommand performs the database-only download is confirmed against the installed Trivy and recorded in HC-PROJ-02.
- [ ] Version comparison handles suffixed versions (for example `0.76.0-rc1`).
- [ ] `UpdatedAt` with nine fractional digits and a `Z` suffix parses correctly; age and the 7-day stale flag are computed from an injected clock.
- [ ] Each gate failure gives its own reason string in the report and a printed warning; hygiene and source rules still run.
- [ ] An assessment never invokes a database download.
- [ ] Operator docs cover first-time setup and the air-gap copy steps (`trivy.db` and `metadata.json` into the cache's `db` folder).
- [ ] `capri` help lists `source update-db`; `harness/README.md` and HC-PROJ-02 updated; `make check` green.
