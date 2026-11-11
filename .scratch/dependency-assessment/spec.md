# Dependency assessment for `capri source`

Status: ready-for-agent

## Problem Statement

A project maintainer can run `capri source` to get a private, read-only source assessment of a local project, but it says nothing about the third-party packages the project depends on.
The scan deliberately excludes every lockfile, so the maintainer cannot see whether a web or mobile app ships a vulnerable dependency, or whether its manifests and lockfiles are configured in ways that let an attacker substitute a package.
The existing tools that answer these questions typically send the dependency inventory to an online service, which the maintainer does not want: the inventory reveals the stack and, through private package names, internal project names.
When a check cannot cover part of a project today, the report shows zero findings, which reads as "clean" rather than "not checked".

## Solution

`capri source` gains a dependency assessment that runs in the same command and writes into the same local report.
It examines the manifests and lockfiles of the npm ecosystem (npm, pnpm, yarn v1 and berry, bun) and the mobile ecosystems (CocoaPods, SwiftPM, Pub, Gradle), wherever they sit in the project.
It reports two kinds of advisory findings: vulnerable dependencies, matched against a local vulnerability database, and dependency hygiene problems, which need no database at all.
The dependency inventory never leaves the machine: vulnerabilities are matched offline against a database the operator downloads ahead of time with a separate, explicit command, and the assessment itself never touches the network or runs project code.
Every assessment area states its coverage per ecosystem as `complete`, `partial`, `not_applicable` or `not_run`, with a reason wherever coverage is incomplete, so the maintainer can tell "clean" apart from "not checked".

## User Stories

1. As a project maintainer, I want `capri source` to examine my project's dependencies in the same run as the source rules, so that I get one assessment and one report.
2. As a project maintainer, I want the dependency assessment to work on any project layout, so that I do not have to restructure my repo or name a profile.
3. As a project maintainer, I want every manifest and lockfile found at any depth, so that monorepos and apps with nested `ios/` and `android/` folders are fully covered.
4. As a project maintainer, I want each advisory finding to name the lockfile or manifest it came from, so that I know which app or package in a monorepo to fix.
5. As a project maintainer, I want nested workspace lockfiles reported separately rather than merged, so that each finding points at the file I actually edit.
6. As a project maintainer, I want installed dependency folders such as `node_modules/` and `Pods/` ignored, so that stale or local-only installs do not produce misleading results.
7. As a project maintainer, I want my dependency inventory never sent to any network service, so that my stack and private package names stay on my machine.
8. As a project maintainer, I want the assessment to never execute my project's code or build tools, so that assessing an untrusted project is safe.
9. As a project maintainer, I want the assessment to never change my project's files, so that it is safe to run on a working tree.
10. As a project maintainer, I want vulnerable dependencies in my npm, pnpm, yarn and bun lockfiles reported, so that I can upgrade packages with published advisories.
11. As a mobile developer, I want vulnerable pods from `Podfile.lock` reported, so that my iOS app's CocoaPods dependencies are covered.
12. As a mobile developer, I want vulnerable Swift packages from `Package.resolved` reported, so that my SwiftPM dependencies are covered.
13. As a Flutter developer, I want vulnerable packages from `pubspec.lock` reported, so that my Dart dependencies are covered.
14. As an Android developer, I want vulnerable libraries from `gradle.lockfile` reported, so that my resolved Gradle dependencies are covered.
15. As an Android developer without a Gradle lockfile, I want exact versions declared in my version catalog and build scripts checked for advisories, so that I get useful coverage without running Gradle.
16. As an Android developer, I want findings from declared Gradle versions labelled `declared` and pointed at the manifest line, so that I know they were not resolved and where to change them.
17. As an Android developer, I want Gradle coverage reported as `partial` when only declared versions were checked, so that I know transitive dependencies were not covered.
18. As a project maintainer, I want each vulnerable-dependency finding to carry the package, version, advisory ids, the advisory's own severity and the fixed version when one exists, so that I can act on it directly.
19. As a project maintainer, I want each vulnerable-dependency finding labelled "present in lockfile, reachability not checked", so that I do not mistake presence for exploitability.
20. As a project maintainer, I want each vulnerable-dependency finding tagged with its dependency scope, `runtime` or `dev`, so that I can prioritise shipped code while still seeing risks to developer and CI machines.
21. As a project maintainer, I want vulnerable-dependency severities kept on the advisory's own scale (CRITICAL to LOW), so that they match what advisories and other tools say.
22. As a project maintainer, I want a hygiene finding when a manifest has no lockfile next to it, so that I know my versions are not pinned.
23. As a project maintainer, I want a hygiene finding when lockfile entries lack an integrity hash, so that I know tampered packages would not be detected on install.
24. As a project maintainer, I want a hygiene finding for dependencies pulled from git, http, `file:`, `link:` or path sources, so that I can review packages that bypass the registry.
25. As a project maintainer, I want a hygiene finding for packages that run install scripts, so that I can review code that executes at install time.
26. As a project maintainer, I want a hygiene finding for `*`, `latest` and open `>=` ranges in `package.json`, so that I know which dependencies can drift to any version.
27. As a project maintainer, I want normal caret and tilde ranges left alone, so that the report is not flooded with the npm default.
28. As a project maintainer, I want a hygiene finding when `.npmrc` or `.yarnrc.yml` points at an `http://` registry, so that I know packages can be swapped in transit.
29. As a project maintainer, I want a hygiene finding when a scoped package was resolved from a private registry but its scope is not pinned to that registry, so that I can close a dependency-confusion gap.
30. As a project maintainer, I want public scoped packages such as `@types/react` never flagged for dependency confusion, so that the check stays trustworthy.
31. As a mobile developer, I want a hygiene finding for pods taken from `:git` without a `:tag` or `:commit`, so that I know which pods can change underneath me.
32. As a mobile developer, I want a hygiene finding for Swift packages pinned to a branch, so that I know which packages are not pinned to a version or revision.
33. As a Flutter developer, I want a hygiene finding for git or path dependencies, so that I can review packages that bypass pub.dev.
34. As an Android developer, I want hygiene findings for dynamic versions (`+`, `latest.*`), `http://` repositories, `mavenLocal()` and a missing `gradle.lockfile`, so that I can harden my Gradle setup.
35. As a bun user with only a binary `bun.lockb`, I want an INFO finding telling me to move to the text `bun.lock`, so that I understand why that lockfile could not be assessed.
36. As a bun user with only a binary `bun.lockb`, I want vulnerable-dependency coverage for that manifest reported as `not_run` with the reason, so that I am not told it is clean.
37. As a project maintainer, I want each hygiene finding to name the related supply-chain technique from the knowledge base, so that I can read the attack it guards against.
38. As a project maintainer, I want hygiene findings to use the same ERROR, WARNING and INFO levels and confidence values as the other source rules, so that the report reads consistently.
39. As a project maintainer, I want ERROR reserved for configurations that let an attacker substitute a package, so that the highest level means the most urgent fix.
40. As a project maintainer, I want coverage reported per ecosystem within each dependency area, so that a gap in one ecosystem is not hidden by another.
41. As a project maintainer, I want an area's overall coverage to be the weakest of its ecosystems, so that the headline never overstates coverage.
42. As a project maintainer, I want ecosystems my project does not use reported as `not_applicable`, so that I can tell "nothing to check" from "checked and clean".
43. As a project maintainer, I want the report to state the vulnerability database's age, so that I know how current the matching was.
44. As a project maintainer, I want the report to flag the vulnerability database as stale when it is older than 7 days, so that I know to refresh it.
45. As a project maintainer, I want the assessment to never update the vulnerability database by itself, so that the scan stays offline and predictable.
46. As a project maintainer, I want one explicit command, `capri source update-db`, that downloads only the public advisory database, so that I control when the network is used and nothing from my project is sent.
47. As a project maintainer, I want `update-db` to store the database in a Capri-owned location and print its date, so that I know what the next scan will use, unaffected by any personal Trivy setup.
48. As an operator on an air-gapped host, I want documented steps to copy a database in by hand, so that I can use the dependency assessment without internet access.
49. As a project maintainer without Trivy or its database, I want the vulnerable-dependency area marked `not_run` with the reason while hygiene and source rules still run, so that I still get useful results.
50. As a project maintainer without Trivy or its database, I want a printed warning and a normal exit, so that the gap is visible without the whole run failing.
51. As a project maintainer, I want Semgrep still required for the whole command, so that the existing source-assessment contract is unchanged.
52. As a project maintainer, I want the scanner version and database version recorded in the report, so that a result can be traced and reproduced.
53. As a project maintainer, I want Capri to refuse a Trivy older than its tested minimum with a clear message, so that I am not given results from an untested scanner.
54. As a project maintainer, I want scanner config and suppression files that ship inside my project ignored, so that the project under review cannot hide findings about itself or re-enable network access.
55. As a project maintainer, I want the report to contain findings and per-ecosystem package counts but not my full dependency inventory, so that a shared report reveals no more than it needs to.
56. As a project maintainer, I want the dependency section to contain no source snippets or file contents, so that it keeps the existing snippet-free guarantee.
57. As a project maintainer, I want the report still written outside my project, so that the assessment never writes into the tree it reviews.
58. As a project maintainer, I want the exit code unchanged regardless of how many findings exist, so that existing scripts keep working.
59. As a security lead, I want dependency advisory findings kept distinct from runtime findings, so that static results are never presented as verified vulnerabilities.
60. As a reviewer of Capri itself, I want the new requirement and spec recorded as BR-12 and HC-PROJ-02 alongside the existing docs, so that the design stays traceable.

## Implementation Decisions

- The dependency assessment is a new deep module behind one function that the source assessment calls with the project root, the exclude policy and injected process-runner and tool-locator callables.
  It owns discovery of manifests and lockfiles, the hygiene checks, the vulnerable-dependency matching, the Gradle declared-version handling and the per-ecosystem coverage computation, and returns the dependency section of the report.
- The source assessment keeps its public entry point.
  Its scanner injection becomes a general process runner and tool locator shared by Semgrep and Trivy, so tests drive both through the same entry point.
- The CLI gains an `update-db` subcommand under `capri source`.
  It downloads only the Trivy vulnerability database into a Capri-owned cache under the Capri home directory, with telemetry and version checks off, and prints the database's update time.
  It is never invoked by an assessment.
- Vulnerability matching uses a locally installed Trivy at or above the tested minimum version 0.75.0; newer versions are accepted.
  It always runs fully offline: vulnerability scanning only, library packages only, no database update, no Java database update, no version check, no telemetry, offline scan mode, the Capri-owned cache directory, an empty config file and an empty ignore file, and an environment with every `TRIVY_*` variable removed.
  Trivy never scans the project directory itself; it scans the assessment snapshot described in the Technical Design.
- Database age comes from the database's own metadata (its `UpdatedAt` time).
  Older than 7 days marks the vulnerable-dependency area as stale with a warning, while its coverage stays `complete`.
- Missing Trivy, a too-old Trivy or a missing database sets the vulnerable-dependency area to `not_run` with the reason, prints a warning and still exits 0.
  A missing Semgrep still stops the whole command, as today.
- Discovery finds manifests and lockfiles at any depth using the source assessment's exclude list, minus the lockfile exclusion that exists today, plus the installed-dependency folders (`node_modules`, `Pods`, `.dart_tool`, `.gradle`, `build`).
  The ignore files that projects ship (`.semgrepignore`, `.gitignore`, `.trivyignore`, `trivy.yaml`) are never honoured; Capri's exclude list is the only thing that decides what is skipped.
  Today's source assessment points Semgrep at the project directory, so a project's own `.semgrepignore` and `.gitignore` currently hide files from it (verified locally with Semgrep 1.180.0); the assessment snapshot fixes this for the source rules too.
- Recognised files, by ecosystem:
  - npm ecosystem: manifest `package.json`; lockfiles `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`; registry config `.npmrc`, `.yarnrc.yml`.
  - CocoaPods: `Podfile`, `Podfile.lock`.
  - SwiftPM: `Package.swift`, `Package.resolved`.
  - Pub: `pubspec.yaml`, `pubspec.lock`.
  - Gradle: `build.gradle`, `build.gradle.kts`, `libs.versions.toml`, `gradle.lockfile`.
- Hygiene checks use the simplest mechanism that can express them.
  Line-level patterns are Semgrep rules in Capri's local rule pack: http registries and repositories, git, http, `file:`, `link:` and path sources, `:git` pods without tag or commit, SwiftPM branch pins, Gradle dynamic versions and `mavenLocal()`.
  Checks for missing files and checks that need JSON structure are small standard-library Python checks: a manifest with no lockfile, `package-lock.json` entries without `integrity`, entries flagged `hasInstallScript`, and loose ranges in `package.json`.
  No YAML parser is added.
- The dependency-confusion check fires only when a lockfile shows a scoped package resolved from a registry other than the public npm registry and no `.npmrc` or `.yarnrc.yml` entry pins that scope to that registry.
  If it cannot be made that precise for a lockfile format, it is not shipped for that format.
- Hygiene severities and confidence:

  | Check | Severity / confidence |
  |---|---|
  | `http://` registry or repository | ERROR / high |
  | Scoped package from a private registry with no scope pinning | ERROR / medium |
  | Lockfile entries without an integrity hash | WARNING / medium |
  | git, http, `file:`, `link:` or path sources; `:git` pods without tag or commit; SwiftPM branch pins | WARNING / medium |
  | Manifest with no lockfile; Gradle without `gradle.lockfile` | WARNING / high |
  | `*`, `latest` or open `>=` ranges; Gradle `+` or `latest.*` | WARNING / high |
  | Binary `bun.lockb` only | INFO / high |
  | Package has an install script | INFO / low |
  | `mavenLocal()` | INFO / medium |

- Each hygiene finding carries a `related_technique` naming its HC-KB-06 card, for example `KB-SUPPLY-LOCKFILE-TAMPER-001` for a missing integrity hash and `KB-SUPPLY-POSTINSTALL-001` for an install script.
  The field is a reference, not a claim that the technique was attempted.
- Gradle declared versions: exact versions are read from `libs.versions.toml` with the standard library's TOML parser and from literal `group:artifact:version` coordinates in build scripts by line pattern.
  They are written into a temporary `gradle.lockfile` outside the project, which Trivy scans.
  Findings are mapped back to the original manifest and line and labelled `declared`.
  Ranges and dynamic versions are not matched; they are already hygiene findings.
  Gradle coverage is `partial` with the reason that transitive dependencies are not covered.
- A project or workspace package whose only lockfile is a binary `bun.lockb` gets the INFO hygiene finding, and that ecosystem's vulnerable-dependency coverage is `partial` (or `not_run` if it is the only npm lockfile) with the reason.
- Report contract: the report keeps its current shape and gains a `dependency_assessment` section next to `source_assessment` and `runtime_assessment`.
  It holds two areas, `vulnerable-dependencies` and `dependency-hygiene`.
  Each area carries an overall coverage status and reason, and a per-ecosystem map of `{status, reason, package_count}`.
  The vulnerable-dependency area also records the scanner name and version, the database version and update time, and a `stale` flag.
  - A vulnerable-dependency finding holds: ecosystem, package, version, version kind (`resolved` or `declared`), dependency scope, advisory ids, advisory severity, fixed version or null, the manifest or lockfile path and line where known, and the fixed reachability label.
  - A hygiene finding holds the same fields as a source-rule advisory finding plus ecosystem and `related_technique`.
  - No full dependency inventory, no source snippets and no file contents appear anywhere in the report.
  - The report's schema version is incremented.
- Coverage statuses are `complete`, `partial`, `not_applicable` and `not_run`.
  An area's overall status is the weakest of its ecosystems, in the order not_run < partial < complete, with not_applicable ignored unless every ecosystem is not_applicable.
- The exit code is unchanged: 0 when the assessment completes, whatever the findings.
- Documentation: a new requirement BR-12, "Assess a project's dependencies privately", with Gherkin acceptance scenarios, and a new spec HC-PROJ-02, "Dependency assessment", that depends on HC-PROJ-01, both added to their registries, with the feature files regenerated.
  HC-PROJ-02 records the answer to HC-KB-06's open question about package-manager fidelity: one set of checks per ecosystem, with the technique cards themselves kept neutral.
  The decision that the dependency inventory never leaves the machine is recorded in HC-PROJ-02 and in the `SPEC.md` decision log when the work ships.

## Technical Design

This section is the engineering blueprint for the coding work.
It names modules, files, flags and algorithms because the implementer needs them; treat file names as the intended layout, not as frozen contracts.

### Tools, libraries and versions

| Piece | Choice | Version rule | Why |
|---|---|---|---|
| Language | Python standard library only | Python 3.12 (repo floor) | No new harness dependency is needed; `json`, `tomllib`, `re`, `os`, `pathlib`, `shutil`, `tempfile`, `subprocess`, `dataclasses`, `datetime` cover everything. |
| Source and hygiene rules | Semgrep CLI, local, `generic` language regex rules | Tested with 1.180.0; CI pins exactly 1.180.0 | Already required by `capri source`; rules keep the snippet-free path. |
| Vulnerability matching | Trivy CLI, local, `fs` mode | Minimum 0.75.0, newer accepted, version recorded in the report | Offline, reads every in-scope lockfile, database carries its own age. |
| Vulnerability database | Trivy DB (`trivy.db` + `metadata.json`) in `~/.capri/trivy/db/` | Whatever `update-db` last fetched; stale after 7 days | Capri-owned location, never refreshed by a scan. |
| YAML lockfiles | No YAML library; a small indented-block reader for machine-written lockfiles | n/a | `harness/yamlmini.py` is a strict hand-authored subset and cannot read real lockfiles; a general YAML dependency is not justified for line-structured, machine-written files. |
| TOML | `tomllib` | stdlib | Gradle version catalogs. |

No new entry is added to `pyproject.toml` or `uv.lock`.

### Module layout

```
capri                          CLI entry; `source` already delegates to tools/project_assessment.main
tools/project_assessment.py    orchestrator: validate inputs, build snapshot, run Semgrep, call dependency assessment, write report; `update-db` subcommand
tools/project_snapshot.py      NEW  discovery walk + assessment snapshot (one walk serves source rules and dependency files)
tools/dependencies/__init__.py NEW  public: assess_dependencies(snapshot, semgrep_results, run, find_tool, now) -> dict
tools/dependencies/catalog.py  NEW  recognised file table: filename -> (ecosystem, kind, format)
tools/dependencies/readers.py  NEW  format readers: npm JSON, bun JSONC, yarn v1 blocks, yarn berry blocks, pnpm blocks, Package.resolved JSON, Gradle catalog/build scripts
tools/dependencies/hygiene.py  NEW  Python hygiene checks + merge of Semgrep hygiene results
tools/dependencies/trivy.py    NEW  locate/version-check Trivy, read DB metadata, run scan, map JSON, update-db
tools/dependencies/gradle.py   NEW  declared-version extraction + synthesized gradle.lockfile
tools/dependencies/coverage.py NEW  per-ecosystem coverage computation
rules/source/dependencies.yaml NEW  Semgrep hygiene rules
```

`tools/dependencies` has exactly one public function; everything else is private to the package.
`tools/project_assessment.assess_source` stays the single public entry for an assessment.

### End-to-end flow

```
capri source --project P [--output O]
  1. validate P is a directory; resolve O; refuse O inside P              (existing)
  2. find_tool("semgrep") or stop with the existing error                  (existing contract)
  3. walk P once -> DiscoveredFiles {source targets, dependency files, oversize, skipped}
  4. build assessment snapshot S in a temp dir outside P: copy every accepted file to S/<same relative path>
  5. run Semgrep once on S with rules/source (source rules + dependency hygiene rules)
  6. split Semgrep results by metadata.category: source areas -> source_assessment; dependency-hygiene -> hygiene input
  7. assess_dependencies(S, hygiene Semgrep results, run, find_tool, now):
       a. read dependency files, run Python hygiene checks, merge Semgrep hygiene findings
       b. Trivy gate: located? version >= 0.75.0? DB metadata present?   -> else vulnerable area not_run(reason)
       c. synthesize Gradle declared lockfiles into S/.capri-declared/<n>/gradle.lockfile
       d. run Trivy once on S; parse JSON; map results back to project paths
       e. compute per-ecosystem coverage for both areas
  8. delete S (always, in a finally block)
  9. assemble report (schema_version 2), write to O, print summary + warnings, exit 0

capri source update-db
  1. find_tool("trivy") or exit 1 with install hint; version >= 0.75.0 or exit 1
  2. run Trivy database-only download into ~/.capri/trivy (telemetry, version check, config off)
  3. read ~/.capri/trivy/db/metadata.json; print UpdatedAt; exit 0
```

### Discovery walk and assessment snapshot

- One `os.walk(P, followlinks=False)` with in-place pruning of `dirnames`.
  Pruned directory names: the source assessment's existing directory excludes plus `node_modules`, `Pods`, `.dart_tool`, `.gradle`, `build`, `.build` (SwiftPM), `DerivedData`.
- File filters: the existing file excludes (private env files, docs, tests, binaries, images), minus `*.lock`.
  Always dropped, whatever their location: `.semgrepignore`, `.gitignore`, `.trivyignore`, `.trivyignore.yaml`, `trivy.yaml`, `trivy.yml`, `osv-scanner.toml`.
- Symlinks (files and directories) and non-regular files are skipped and counted in `skipped`, never followed, so nothing outside P is read.
- Size caps: a single file over 50 MB is not copied and is recorded in `oversize`; the snapshot as a whole is capped at 2 GB, and exceeding it stops the run with a clear error naming the cap.
- The snapshot lives in `tempfile.TemporaryDirectory(prefix="capri-snapshot-")`, which is outside P by construction and user-private, and is removed in a `finally` block.
- Effects: Semgrep and Trivy only ever see files Capri accepted; no project ignore or config file exists in the snapshot; the snapshot is not a git repo, so `.gitignore` semantics cannot apply; relative paths inside S equal relative paths inside P, so mapping results back is a string operation.
- Semgrep runs with `--max-target-bytes=50MB` so large lockfiles are not silently skipped (its default is 1 MB), `--metrics=off`, `--disable-version-check`, `--json`, `--quiet`, and an environment with `SEMGREP_*` variables removed except `SEMGREP_SEND_METRICS=off`, so a user-level setting cannot add remote rules.

### Recognised files

| Ecosystem | Manifest | Lockfile (format id) | Registry config |
|---|---|---|---|
| npm | `package.json` | `package-lock.json` (`npm-json`), `npm-shrinkwrap.json` (`npm-json`), `yarn.lock` (`yarn-v1` or `yarn-berry`, decided by a `__metadata:` line), `pnpm-lock.yaml` (`pnpm`), `bun.lock` (`bun-jsonc`), `bun.lockb` (`bun-binary`) | `.npmrc`, `.yarnrc.yml`, `.yarnrc` |
| CocoaPods | `Podfile` | `Podfile.lock` | none |
| SwiftPM | `Package.swift` | `Package.resolved` (also inside `*.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/` and `*.xcworkspace/xcshareddata/swiftpm/`) | none |
| Pub | `pubspec.yaml` | `pubspec.lock` | none |
| Gradle | `build.gradle`, `build.gradle.kts`, `settings.gradle`, `settings.gradle.kts`, `gradle/libs.versions.toml` | `gradle.lockfile`, `*.lockfile` under `gradle/dependency-locks/` | none |

### Data model

```python
@dataclass(frozen=True)
class DependencyFile:
    path: str          # project-relative, POSIX separators
    ecosystem: str     # npm | cocoapods | swiftpm | pub | gradle
    kind: str          # manifest | lockfile | registry-config
    format: str        # npm-json | bun-jsonc | yarn-v1 | ... | manifest formats

@dataclass(frozen=True)
class EcosystemCoverage:
    status: str        # complete | partial | not_applicable | not_run
    reasons: tuple[str, ...]
    package_count: int | None
```

Findings are plain dicts, built by one constructor per finding type so the report shape lives in one place.

### Algorithm: pairing manifests with lockfiles (no-lockfile check and coverage)

- A manifest is a package unit.
  A unit is locked when a lockfile of the same ecosystem exists in the unit's directory or in any ancestor directory up to P.
  The ancestor rule covers npm, pnpm, yarn and bun workspaces without parsing workspace globs; a package outside a workspace but under a root lockfile is treated as locked, which errs toward silence over noise.
- A `package.json` with no `dependencies`, `devDependencies`, `optionalDependencies` or `peerDependencies` is not a package unit (nothing to lock).
- Gradle: the Gradle root is the directory holding `settings.gradle(.kts)`, or a top-most `build.gradle(.kts)` when no settings file exists.
  The root is locked when any `gradle.lockfile` or `gradle/dependency-locks/*.lockfile` exists under it.
- An unlocked unit yields the "manifest with no lockfile" hygiene finding at the manifest, line 1.
  Confidence is high for npm, CocoaPods and Gradle, and medium for SwiftPM and Pub, because Swift and Dart libraries conventionally omit their lockfiles.

### Algorithm: format readers

All readers take text plus the project-relative path and return entries with their line numbers.
They raise one `LockfileParseError` on malformed input, which becomes `partial` coverage with the reason, never a crash.

- `npm-json`: `json.loads`.
  Lockfile v2/v3 reads the `packages` map, skipping the root key `""`; v1 recurses into `dependencies`.
  Fields used: `version`, `resolved`, `integrity`, `link`, `hasInstallScript`, `dev`, `optional`, `inBundle`.
  Line numbers: `json` has none, so a second linear pass maps each package key to the first line containing `"<key>": {`.
- `bun-jsonc`: `bun.lock` is JSON with trailing commas.
  A single-pass, string-aware scanner (tracks in-string and escape state) removes a comma when the next non-whitespace character is `}` or `]`, then `json.loads`.
  Entry shape: `packages[name] = [ "name@version", registry_url_or_empty, info, integrity ]`.
- Indented-block reader, shared by `yarn-v1`, `yarn-berry` and `pnpm`: a linear pass that opens an entry on a header line at the entry indent ending in `:` and collects `key value` / `key: value` field lines at the field indent until the next header.
  Each entry keeps its header, header line and fields with their lines.
  - `yarn-v1`: entry indent 0, fields at 2, values space-separated and optionally quoted (`resolved "url#sha1"`, `integrity sha512-...`).
  - `yarn-berry`: entry indent 0, fields at 2 (`resolution:`, `checksum:`, `linkType:`); entries whose resolution protocol is `workspace:`, `link:` or `portal:` are local.
  - `pnpm`: entries under the top-level `packages:` key at indent 2, fields at 4 (`resolution: {integrity: ...}` or `{tarball: ...}`, `requiresBuild: true`, `dev: true`).
- `Package.resolved`: `json.loads`; v1 reads `object.pins`, v2 and v3 read `pins`; each pin's `state` has `version`, `branch` and `revision`.
- Gradle catalog: `tomllib.loads`; see the Gradle algorithm below.

### Algorithm: Python hygiene checks

| Check | Formats | Rule |
|---|---|---|
| No lockfile | all manifests | Pairing algorithm above. |
| Missing integrity | `npm-json`, `bun-jsonc`, `yarn-v1`, `yarn-berry`, `pnpm` | A registry-resolved entry (not local, not bundled, not a workspace link) has no `integrity` (npm, bun, yarn v1), no `checksum` (berry), or a `resolution` without `integrity` (pnpm). One finding per lockfile, located at the first offending entry, with the count in the message, so a legacy lockfile does not produce thousands of lines. |
| Non-registry source | `package.json` | Dependency values in the four dependency maps starting with `git+`, `git:`, `github:`, `gitlab:`, `bitbucket:`, `http:`, `https:`, `file:` or `link:`, or matching `owner/repo` shorthand. Workspace protocol `workspace:` is ignored. `link:` and `file:` pointing inside P are ignored (local workspace packages). |
| Install script | `npm-json` (`hasInstallScript`), `pnpm` (`requiresBuild: true`) | One finding per lockfile listing the count and the first entry's line. |
| Loose range | `package.json` | A value equal to `*`, `""`, `latest` or `x`, or a range with a lower bound and no upper bound (`>=`, `>` with no `<` or `<=` in the same range set). `^` and `~` are never flagged. |
| Binary bun lockfile | `bun-binary` | A `bun.lockb` with no `bun.lock` beside it. |
| Dependency confusion | `npm-json`, `yarn-v1`, `bun-jsonc` | See next section. |

### Algorithm: dependency confusion

1. Public registry hosts: `registry.npmjs.org`, `registry.yarnpkg.com`.
2. From each lockfile, collect `scope -> set(host)` for every `@scope/name` entry whose resolved URL host (npm `resolved`, yarn v1 `resolved`, bun registry slot) is not a public host.
   Local, git and tarball-path entries are ignored.
3. Collect pinned scopes from the project's own registry config, in the lockfile's directory and every ancestor up to P:
   `.npmrc` lines `@scope:registry=<url>`; `.yarnrc` lines `"@scope:registry" "<url>"`; `.yarnrc.yml` `npmScopes:` blocks (`<scope>:` then an indented `npmRegistryServer: <url>`), read with the indented-block reader.
4. Each scope in step 2 whose host set is not covered by a pinned registry for that scope yields an ERROR / medium finding at the first lockfile entry of that scope.
5. Not shipped for `pnpm` and `yarn-berry`, whose lockfiles do not record the registry host of registry packages, so the check cannot be precise for them.
   User-level config such as `~/.npmrc` is ignored on purpose: a fresh CI install uses only the project's files, which is where the risk lies.

### Semgrep hygiene rules

New file `rules/source/dependencies.yaml`, all `languages: [generic]`, `metadata.category: dependency-hygiene`, plus `metadata.ecosystem` and `metadata.related_technique`.
Each rule scopes itself with `paths.include` file-name patterns, which match at any depth.

| Rule id | Files | Pattern (PCRE2, multiline) | Severity / confidence |
|---|---|---|---|
| `source.deps.npm-http-registry` | `.npmrc`, `.yarnrc`, `.yarnrc.yml` | `^\s*(@[\w.-]+:)?registry\s*=\s*http://` and `registry\s+"http://` and `npmRegistryServer:\s*["']?http://` | ERROR / high |
| `source.deps.pod-git-unpinned` | `Podfile` | `^\s*pod\s+['"][^'"]+['"][^\n#]*(:git\s*=>\|git:)(?![^\n#]*(:tag\|:commit\|tag:\|commit:))` | WARNING / medium |
| `source.deps.swiftpm-branch-pin` | `Package.resolved`, `Package.swift` | `"branch"\s*:\s*"[^"]+"` and `(\.branch\(\|\bbranch:\s*")` | WARNING / medium |
| `source.deps.pub-git-or-path` | `pubspec.lock`, `pubspec.yaml` | `^\s+source:\s*(git\|path)\s*$` and `^\s{4}(git\|path):` | WARNING / medium |
| `source.deps.gradle-dynamic-version` | `*.gradle`, `*.gradle.kts`, `libs.versions.toml` | `["'][\w.\-]+:[\w.\-]+:[^"'\s]*(\+\|latest\.(release\|integration))["']` and `=\s*"[^"]*(\+\|latest\.)[^"]*"` | WARNING / high |
| `source.deps.gradle-http-repository` | `*.gradle`, `*.gradle.kts` | `url\s*[=(]?\s*(uri\()?\s*["']http://` | ERROR / high |
| `source.deps.gradle-maven-local` | `*.gradle`, `*.gradle.kts` | `\bmavenLocal\(\)` | INFO / medium |

Every rule ships with a positive and a negative fixture line in the tests, run through real Semgrep in CI.

### Algorithm: Gradle declared versions

1. Catalog (`libs.versions.toml`): `[versions]` maps a name to a string or a rich table; only a plain string counts.
   `[libraries]` entries take three shapes: `"g:a:v"`; `{ module = "g:a", version = ... }`; `{ group = "g", name = "a", version = ... }`, where `version` is a string, `{ ref = "x" }` or `version.ref = "x"`, resolved through `[versions]`.
2. Build scripts: line regexes for string notation, `^\s*(\w+)\s*\(?\s*["']([\w.\-]+):([\w.\-]+):([^"'@:$\s]+)(:[^"'@]+)?(@\w+)?["']`, and Groovy map notation, `group\s*:\s*["']([^"']+)["']\s*,\s*name\s*:\s*["']([^"']+)["']\s*,\s*version\s*:\s*["']([^"']+)["']`.
   Captured configuration names starting with `test` or `androidTest` give scope `dev`; everything else gives `runtime`.
   Values containing `$`, `+`, `[`, `(`, `,` or `latest.` are not exact and are skipped (dynamic forms are hygiene findings already).
3. Line numbers: build-script lines come from the regex pass; catalog lines come from a pass that finds `^\s*<alias>\s*=`.
4. When a Gradle root has no lockfile, write `S/.capri-declared/<n>/gradle.lockfile` with one `group:artifact:version=compileClasspath,runtimeClasspath` line per coordinate (`testCompileClasspath,testRuntimeClasspath` for dev), and keep a map `(n, group:artifact, version) -> (manifest path, line, scope)`.
   Roots that have a real lockfile are skipped; resolved versions win.

### Algorithm: Trivy invocation and result mapping

- Gate, in order, each failure becoming `not_run` with its reason and a printed warning: Trivy located; `trivy version -f json` returns `Version` >= 0.75.0 (numeric tuple compare after stripping any `-suffix`); `~/.capri/trivy/db/metadata.json` exists and parses.
- Scan command, run with `cwd` set to Capri's own root and a 300-second timeout:

  ```
  trivy fs S --scanners vuln --pkg-types library --include-dev-deps --list-all-pkgs
         --format json --quiet --offline-scan --skip-db-update --skip-java-db-update
         --skip-check-update --skip-version-check --disable-telemetry
         --cache-dir ~/.capri/trivy --config "" --ignorefile ""
  ```

- Database age: parse `UpdatedAt` (RFC 3339 with up to nine fractional digits; truncate to six, map `Z` to `+00:00`, then `datetime.fromisoformat`); `stale = now - UpdatedAt > 7 days`.
- Mapping, for each `Results[]` with `Class == "lang-pkgs"`:
  - The ecosystem comes from `Type`: `npm`, `pnpm`, `yarn` and `bun` map to `npm`; `cocoapods`; `swift` maps to `swiftpm`; `pub`; `gradle`.
  - Index `Packages[]` by `ID` to get `Dev` and `Locations[0].StartLine`; count packages per ecosystem for `package_count`.
  - Each `Vulnerabilities[]` entry joins its package by `PkgID`, giving package `PkgName`, version `InstalledVersion`, advisory ids `[VulnerabilityID] + VendorIDs` deduplicated, severity `Severity`, fixed versions `FixedVersion` split on `, ` (null when empty), `Title` and `PrimaryURL`.
  - Scope is `dev` when `Dev` is true, otherwise `runtime`.
    Lockfiles that cannot mark dev packages (CocoaPods, SwiftPM, pnpm before lockfile v9) therefore report `runtime`, which over-prioritises rather than hides.
  - A target under `.capri-declared/` is mapped through the Gradle map to its manifest path, line and scope, with version kind `declared`; all others are `resolved`, with the target as the path.
  - Deduplicate on `(path, package, version, advisory id)`; sort by severity (CRITICAL to UNKNOWN), then ecosystem, path and package.
- Honesty check: a non-empty lockfile in the snapshot with no matching `Results[]` entry marks its ecosystem `partial` with the reason "scanner returned no packages for <path>", because Trivy may log a parse failure without failing the run.
- Errors: a non-zero exit, a timeout or invalid JSON sets the area to `not_run` with the reason; Trivy's stderr is never copied into the report.

### Algorithm: coverage

- An ecosystem is present when discovery found any of its files; absent ecosystems are `not_applicable`.
- Vulnerable dependencies, per present ecosystem:
  - The gate failed: `not_run`.
  - Every package unit has an assessable lockfile that Trivy returned: `complete`.
  - Some units are assessable and some are not (no lockfile, `bun.lockb` only, oversize, Gradle declared-only, no Trivy result): `partial` with one reason per cause.
  - No unit is assessable: `not_run` with the reasons.
- Dependency hygiene, per present ecosystem: `complete` unless a file failed to parse or was oversize, which gives `partial`.
- Overall per area: `not_applicable` when every ecosystem is; otherwise the minimum over the non-`not_applicable` ecosystems in the order `not_run` < `partial` < `complete`.

### Report contract (schema_version 2)

```json
{
  "schema_version": 2,
  "project": "any-app",
  "created_at": "2026-11-11T10:00:00+00:00",
  "source_assessment": { "...": "unchanged fields, ruleset capri-source-1" },
  "dependency_assessment": {
    "vulnerable_dependencies": {
      "status": "partial",
      "reasons": ["gradle: declared versions only; transitive dependencies not covered"],
      "scanner": {"name": "trivy", "version": "0.75.0"},
      "database": {"updated_at": "2026-11-10T06:00:00+00:00", "age_days": 1, "stale": false},
      "ecosystems": {
        "npm": {"status": "complete", "reasons": [], "package_count": 812},
        "gradle": {"status": "partial", "reasons": ["declared versions only"], "package_count": 41},
        "cocoapods": {"status": "not_applicable", "reasons": [], "package_count": null}
      },
      "findings": [{
        "ecosystem": "npm", "package": "lodash", "version": "4.17.20",
        "version_kind": "resolved", "scope": "runtime",
        "advisory_ids": ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"],
        "severity": "HIGH", "fixed_versions": ["4.17.21"],
        "title": "Command injection in lodash", "advisory_url": "https://avd.aquasec.com/nvd/cve-2021-23337",
        "location": {"path": "apps/web/package-lock.json", "line": 2140},
        "reachability": "present in lockfile, reachability not checked"
      }],
      "finding_count": 1
    },
    "dependency_hygiene": {
      "status": "complete", "reasons": [],
      "ecosystems": {"npm": {"status": "complete", "reasons": [], "package_count": null}},
      "findings": [{
        "rule_id": "source.deps.npm-missing-integrity", "category": "dependency-hygiene",
        "ecosystem": "npm", "severity": "WARNING", "confidence": "medium",
        "message": "12 lockfile entries have no integrity hash.",
        "related_technique": "KB-SUPPLY-LOCKFILE-TAMPER-001",
        "location": {"path": "yarn.lock", "line": 88, "column": null}
      }],
      "finding_count": 1
    },
    "dependency_inventory_sent_to_network": false
  },
  "runtime_assessment": { "...": "unchanged" }
}
```

`source_assessment.areas_reviewed` and `findings_by_area` keep their meaning and do not include dependency hygiene.

### Error handling summary

| Situation | Behaviour |
|---|---|
| Project path invalid, output inside project, Semgrep missing, Semgrep fails, snapshot over 2 GB | Stop with a clear message, exit 1 (existing contract plus the snapshot cap). |
| Trivy missing, too old, database missing, Trivy fails, times out or returns invalid JSON | Vulnerable area `not_run` with the reason; warning printed; exit 0. |
| Database older than 7 days | Area keeps its status; `stale: true`; warning printed. |
| A dependency file is malformed or over 50 MB | That ecosystem is `partial` with the reason in the affected area(s); other files continue. |
| `update-db` without Trivy, with an old Trivy, or on a failed download | Exit 1 with the reason and the Trivy version requirement. |

### Security and privacy invariants

- No network access during an assessment: Semgrep metrics and version checks are off, Trivy runs with every offline and skip flag, and `SEMGREP_*` and `TRIVY_*` environment variables are scrubbed.
- No project code runs: neither tool is asked to build, resolve or execute anything, and Gradle and package managers are never invoked.
- No writes into the project: the snapshot and the synthesized Gradle lockfiles live in a temp dir; the report is refused inside the project.
- No project-controlled scanner behaviour: ignore and config files are never copied into the snapshot, and Trivy gets explicit empty config and ignore files.
- No source content in the report: only rule metadata, advisory metadata, package names and versions of vulnerable packages, and project-relative locations.
- Symlinks are never followed out of the project.

### Performance bounds

- One walk, one copy, one Semgrep run and one Trivy run per assessment, all linear in project size.
- Caps: 50 MB per file, 2 GB per snapshot, 300 seconds per tool run.
- Hygiene findings that can repeat per entry (missing integrity, install scripts) are aggregated per lockfile.

## Testing Decisions

- Tests check behaviour only: given a fixture project and recorded scanner output, they assert on the returned report and the files written, never on internal helpers.
  They also assert what must not happen: no network flag missing from the Trivy command, no source text in the report, no file written into the project, no project ignore file honoured.
- All assessment behaviour is tested through the source assessment's existing public entry point, with fixture project folders built in temporary directories and an injected process runner.
  The runner returns recorded Trivy JSON for Trivy invocations and either recorded or real Semgrep output for Semgrep invocations.
- The `update-db` command is tested through the CLI's `main` entry point with an injected runner, asserting the exact command line (Capri-owned cache, telemetry off, database-only download), the printed database date, and a clear error when Trivy is missing.
- CI installs Semgrep so that the hygiene rules, and the existing source rules, run for real against fixture projects through the same entry point.
  Trivy stays faked in CI with recorded JSON, because downloading the database there would make builds slow, flaky and dependent on a live advisory feed.
- Before shipping, a documented local check runs real Trivy with a downloaded database against one fixture project per ecosystem, the same way the source rules were verified end to end.
  That run's JSON output is what gets committed as the recorded Trivy fixtures, so the faked contract matches real Trivy output.
- Fixtures: small, hand-written fixture projects per ecosystem, checked in under the tests tree, each containing one positive and one negative case per check (for example a `package-lock.json` with one entry missing `integrity` and one complete entry).
  Format readers get adversarial inputs: malformed JSON, a truncated block file, a 50 MB-plus file, an unknown lockfile version.
- Regression test for the existing ignore-file bug: a fixture project whose `.semgrepignore` and `.gitignore` list a file containing a planted credential must still report that credential.
  This test fails on today's code and passes once the assessment snapshot lands.
- Invariant tests: no file is created inside the project during an assessment; the snapshot directory no longer exists after the run (including on error); the Trivy command line contains every offline and skip flag; the Trivy and Semgrep environments contain no `TRIVY_*` or user `SEMGREP_*` variables; a symlink pointing outside the project is not read.
- Prior art: the existing source assessment tests already drive the public entry point with an injected fake scanner and assert redaction, command flags and refusal paths, and the CLI tests drive `main` directly.
  New suites follow the repo's runner convention and are wired into both the `test` target and the CI workflow.

## Out of Scope

- Lockfile drift checks (a lockfile out of sync with its manifest), which need each package manager's resolution rules.
- Gradle transitive dependencies, which need Gradle to run.
- Maven `pom.xml`, Carthage and backend ecosystems such as pip, Go and Cargo.
- Operator-supplied suppressions.
- A CI gating flag that fails the command on findings above a threshold.
- Reachability analysis of vulnerable dependencies, for example linking them to the sink tracer.
- Licence checks and deprecated-package checks.
- Any network lookup during an assessment, including osv.dev and deps.dev.

## Further Notes

- The vocabulary used here is defined in the repo's `GLOSSARY.md`: source assessment, assessment area, coverage status, advisory finding, suppression, dependency assessment, ecosystem, package manager, manifest, lockfile, declared and resolved version, dependency inventory, dependency scope, vulnerable dependency, dependency hygiene and vulnerability database.
- Trivy was chosen over osv-scanner because it reads `Podfile.lock` by default, records its database age, reports fixed versions directly, and never runs project code; osv-scanner's default call analysis runs the Go toolchain and Rust build scripts.
  Neither tool reads `bun.lockb`, build scripts or version catalogs, and neither does any hygiene checking.
- Trivy 0.75.0 is installed locally but has no database yet; the first real run needs `update-db`.
- Lockfiles under folders the source assessment already excludes (tests, docs, fixtures) stay excluded, so deliberately vulnerable test fixtures inside a project are not reported.
- Finishing the slice follows the repo's milestone rule: an implementation-pointer paragraph in HC-PROJ-02, a section in the harness README, and a dated line in the `SPEC.md` decision log.
