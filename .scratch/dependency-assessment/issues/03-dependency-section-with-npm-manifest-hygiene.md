# 03: Tracer bullet: dependency section in the report, with npm manifest hygiene

**What to build:** the source assessment report gains a `dependency_assessment` section (report schema version 2) with two assessment areas, vulnerable dependencies and dependency hygiene, each with an overall coverage status and a per-ecosystem coverage map.
Discovery recognises every manifest, lockfile and registry config in the spec's recognised-file table, at any depth, from the assessment snapshot.
The first hygiene checks ship for the npm ecosystem from `package.json`: manifest with no lockfile (ancestor rule for workspaces), loose ranges, and non-registry sources.
The vulnerable-dependency area honestly reports `not_run` with the reason "Trivy not found" for present ecosystems until ticket 08.
The dependency assessment is one deep module behind a single public function that the source assessment calls.
Spec: Technical Design > "Module layout", "Recognised files", "Data model", "Algorithm: pairing manifests with lockfiles", "Algorithm: Python hygiene checks" (no-lockfile, loose range, non-registry rows), "Algorithm: coverage", "Report contract".

**Blocked by:** 01 (Scan an assessment snapshot)

**Status:** ready-for-agent

- [ ] A project with no dependency files reports both areas `not_applicable`.
- [ ] A `package.json` with dependencies and no lockfile in its directory or any ancestor yields the WARNING / high hygiene finding at the manifest; a workspace package under a root lockfile does not.
- [ ] A `package.json` with no dependency maps is not treated as a package unit.
- [ ] Loose ranges (`*`, `""`, `latest`, `x`, open lower bounds) are flagged; `^` and `~` ranges are not.
- [ ] git, http(s), `github:`-style and `owner/repo` sources are flagged; `workspace:` and in-project `file:`/`link:` are not; `file:`/`link:` escaping the project are.
- [ ] Each hygiene finding carries ecosystem, severity, confidence, message, project-relative location and `related_technique` naming its HC-KB-06 card.
- [ ] Coverage per ecosystem and the overall status rule follow the spec; the vulnerable area is `not_run` with the reason when Trivy is absent.
- [ ] The report contains no source snippets and no full dependency inventory; `dependency_inventory_sent_to_network` is false; `source_assessment` fields keep their meaning.
- [ ] `capri source` prints a one-line summary per dependency area.
- [ ] BR-12 ("Assess a project's dependencies privately", with Gherkin scenarios) and HC-PROJ-02 ("Dependency assessment", depends on HC-PROJ-01) are written and added to both registries; `make features` regenerated.
- [ ] `harness/README.md` section and `SPEC.md` decision-log line added; new suite wired into `Makefile` and CI; `make check` green.
