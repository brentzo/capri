---
tag: HC-KB-06
title: Supply-chain technique-card starter set
status: draft
parent: SPEC.md#7
depends_on: [HC-KB-01, HC-SUB-01]
depended_on_by: [HC-EVAL-01, HC-PROJ-02]
updated: 2026-11-08
---

# HC-KB-06 - Supply-chain technique-card starter set

## 1. Purpose

Ten cards for the `supply-chain` class, authored against the HC-KB-01 schema.
It covers the paths by which untrusted code or artifacts enter a build or runtime: dependency resolution, the CI pipeline, artifact and update integrity, plugins, and the internal package registry.
The target is a self-hosted build and registry stack on the range (a local package registry, a CI runner, an update server), never a public ecosystem, so nothing egresses.

Each card ships as its own YAML file under `kb/supply-chain/` (HC-KB-01 §7), condensed here to the meaningful fields.
Taxonomy IDs marked `# verify` are plausible but must resolve under the HC-KB-01 validator at authoring time.

## 2. Determinism for a supply-chain target

- Code-execution weaknesses are proven by an out-of-band callback: a planted canary package, workflow, plugin, or lifecycle script calls `range-oob` when installed or run, which is a deterministic `oob_callback`, never a judgment about what "could" run.
- Integrity weaknesses are proven by a deterministic `differential`: a tampered artifact, lockfile, or update is accepted where a correct one would be rejected.
- Secret exposure is a planted canary string surfaced in a reachable log or artifact, a deterministic `content_match`.
- Every code-execution card that installs or publishes is tier 2 and snapshots first, so the build host is restored after the proof.

## 3. Coverage map

| Card | Family | CWE | ATT&CK | Tier | Signal | Yields |
|------|--------|-----|--------|------|--------|--------|
| KB-SUPPLY-REGISTRY-ANON-001 | Registry | CWE-306 | T1195 # verify | 2 | state_change | registry_write |
| KB-SUPPLY-DEP-CONFUSION-001 | Dependency | CWE-1104 | T1195.001 | 2 | oob_callback | build_exec |
| KB-SUPPLY-TYPOSQUAT-001 | Dependency | CWE-1104 | T1195.001 # verify | 1 | content_match | dependency_hijack |
| KB-SUPPLY-LOCKFILE-TAMPER-001 | Dependency | CWE-354 | T1565.001 # verify | 1 | differential | dependency_hijack |
| KB-SUPPLY-POSTINSTALL-001 | Dependency | CWE-94 | T1195.001 | 2 | oob_callback | build_exec |
| KB-SUPPLY-CI-INJECT-001 | CI/CD | CWE-94 | T1195.002 | 2 | oob_callback | build_exec |
| KB-SUPPLY-CI-SECRET-001 | CI/CD | CWE-532 | T1552 # verify | 1 | content_match | ci_secret |
| KB-SUPPLY-ARTIFACT-UNSIGNED-001 | Integrity | CWE-347 | T1195 # verify | 1 | differential | artifact_tamper |
| KB-SUPPLY-UPDATE-INTEGRITY-001 | Integrity | CWE-494 | T1195 # verify | 1 | differential | update_hijack |
| KB-SUPPLY-PLUGIN-UNTRUSTED-001 | Plugin | CWE-829 | T1195 # verify | 2 | oob_callback | plugin_exec |

Tier distribution: five tier-1 (read-only integrity and secret checks) and five tier-2 (installs, publishes, or runs attacker-controlled code; snapshot required).

## 4. Cards

### 4.1 Registry and dependency family

```yaml
id: KB-SUPPLY-REGISTRY-ANON-001
title: Internal package registry allows anonymous publish or overwrite
taxonomy: { attack: {technique: T1195}, cwe: [CWE-306, CWE-284] }
applicability: [ 'asset.type == "package_registry"' ]
preconditions: [ reachable ]
yields_on_success: [ registry_write ]
blast_tier: 2                      # publishes a package to a shared registry
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.supply_probe, intent: anonymous_publish, args: { package: canary_pkg, version: "9.9.9" } }
success_signal: { type: state_change, evaluator: deterministic,
                  assert: "an unauthenticated publish/overwrite of canary_pkg succeeds and is resolvable" }
severity_rubric: { base: high, raise_if: [ { when: "yields.build_exec", to: critical } ] }
```

```yaml
id: KB-SUPPLY-DEP-CONFUSION-001
title: Dependency confusion, internal name shadowed by a publishable source
taxonomy: { attack: {technique: T1195.001}, cwe: [CWE-1104] }
applicability: [ 'asset.type == "build_resolver"' ]
preconditions: [ reachable, registry_write ]
yields_on_success: [ build_exec ]
blast_tier: 2                      # the resolver installs and runs the shadowing package
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.supply_probe, intent: publish_shadow_package, args: { name: internal_canary_pkg, collaborator: range-oob } }
  - { tool: custom.supply_probe, intent: trigger_resolve_and_install }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=build) proving the shadow package ran" }
severity_rubric: { base: critical }
```

```yaml
id: KB-SUPPLY-TYPOSQUAT-001
title: Loose dependency spec resolves a squatted name
taxonomy: { attack: {technique: T1195.001}, cwe: [CWE-1104] }
applicability: [ 'asset.type == "build_resolver"' ]
preconditions: [ reachable, registry_write ]
yields_on_success: [ dependency_hijack ]
blast_tier: 1                      # detection only: would the resolver select the squat
cleanup: none
probe_steps:
  - { tool: custom.supply_probe, intent: offer_near_miss_name, args: { squat: canary_squat }}
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "the resolver selects the attacker-named near-miss over the intended package" }
severity_rubric: { base: high }
```

```yaml
id: KB-SUPPLY-LOCKFILE-TAMPER-001
title: Lockfile integrity not enforced on install
taxonomy: { attack: {technique: T1565.001}, cwe: [CWE-354] }
applicability: [ 'asset.type == "build_resolver"', 'asset.uses_lockfile == true' ]
preconditions: [ reachable ]
yields_on_success: [ dependency_hijack ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.supply_probe, intent: install_with_mismatched_hash }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "an install proceeds when a resolved artifact's hash does not match the lockfile" }
severity_rubric: { base: high }
```

```yaml
id: KB-SUPPLY-POSTINSTALL-001
title: Lifecycle script executes arbitrary code on install
taxonomy: { attack: {technique: T1195.001}, cwe: [CWE-94] }
applicability: [ 'asset.type == "build_resolver"' ]
preconditions: [ reachable, build_pipeline ]
yields_on_success: [ build_exec ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.supply_probe, intent: install_package_with_lifecycle_script, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=install)" }
severity_rubric: { base: high }
```

### 4.2 CI/CD family

```yaml
id: KB-SUPPLY-CI-INJECT-001
title: Build injection via untrusted pipeline input
taxonomy: { attack: {technique: T1195.002}, cwe: [CWE-94] }
applicability: [ 'asset.type == "ci_pipeline"' ]
preconditions: [ reachable, build_pipeline ]
yields_on_success: [ build_exec ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.supply_probe, intent: submit_poisoned_workflow_input, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=ci_runner)" }
severity_rubric: { base: critical }
```

```yaml
id: KB-SUPPLY-CI-SECRET-001
title: CI secret exposed to a build step or log
taxonomy: { cwe: [CWE-532, CWE-200] }
applicability: [ 'asset.type == "ci_pipeline"' ]
preconditions: [ reachable, build_pipeline ]
yields_on_success: [ ci_secret ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.supply_probe, intent: read_reachable_build_log }
success_signal: { type: content_match, evaluator: deterministic,
                  assert: "a build log or artifact exposes the ci_secret_canary" }
severity_rubric: { base: high }
```

### 4.3 Integrity and plugin family

```yaml
id: KB-SUPPLY-ARTIFACT-UNSIGNED-001
title: Unsigned or unverified artifact accepted
taxonomy: { attack: {technique: T1195}, cwe: [CWE-347] }
applicability: [ 'asset.type == "artifact_consumer"' ]
preconditions: [ reachable ]
yields_on_success: [ artifact_tamper ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.supply_probe, intent: offer_tampered_artifact, args: { marker: tamper_canary } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "a tampered artifact is accepted where signature verification should reject it" }
severity_rubric: { base: high }
```

```yaml
id: KB-SUPPLY-UPDATE-INTEGRITY-001
title: Update channel lacks integrity verification
taxonomy: { attack: {technique: T1195}, cwe: [CWE-494] }
applicability: [ 'asset.type == "update_client"' ]
preconditions: [ reachable ]
yields_on_success: [ update_hijack ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: custom.supply_probe, intent: substitute_update_via_range_proxy, args: { marker: update_canary } }
success_signal: { type: differential, evaluator: deterministic,
                  assert: "a substituted update is installed without an integrity or signature check" }
severity_rubric: { base: high }
false_positive_notes: [ "Substitution happens only through the in-range proxy; there is no internet path, so this never leaves scope." ]
```

```yaml
id: KB-SUPPLY-PLUGIN-UNTRUSTED-001
title: Plugin loaded from an untrusted control sphere
taxonomy: { attack: {technique: T1195}, cwe: [CWE-829] }
applicability: [ 'asset.type == "plugin_host"' ]
preconditions: [ reachable ]
yields_on_success: [ plugin_exec ]
blast_tier: 2
cleanup: snapshot-restore
probe_steps:
  - { tool: custom.supply_probe, intent: load_canary_plugin, args: { collaborator: range-oob } }
success_signal: { type: oob_callback, evaluator: deterministic,
                  assert: "oob_received(collaborator=range-oob, from=plugin_host) on plugin load" }
severity_rubric: { base: high }
```

## 5. Chaining in this set

- `KB-SUPPLY-REGISTRY-ANON-001` yields `registry_write`, the precondition for `KB-SUPPLY-DEP-CONFUSION-001` and `KB-SUPPLY-TYPOSQUAT-001`: once an attacker can publish, name-shadowing and squatting become reachable.
- `KB-SUPPLY-DEP-CONFUSION-001`, `KB-SUPPLY-POSTINSTALL-001`, and `KB-SUPPLY-CI-INJECT-001` all yield `build_exec`, which is `rce_foothold` on the build host and feeds the container-escape and lateral chains in HC-KB-05.
- `KB-SUPPLY-CI-SECRET-001` yields `ci_secret`, which is a `cloud_credential` in the HC-KB-05 chain when the leaked secret is a cloud key.
- `KB-SUPPLY-TYPOSQUAT-001` and `KB-SUPPLY-LOCKFILE-TAMPER-001` yield `dependency_hijack`, the mechanism that turns into `build_exec` once the hijacked dependency runs.

## 6. Seed targets and fixtures

v1 stands up a self-hosted build and registry stack on the range (no internet): a package registry allowing anonymous publish, a build resolver configured to prefer a shadowing source and to ignore lockfile hashes, a CI runner that interpolates untrusted input and logs secrets, an artifact consumer with signature verification off, an update client over a range proxy with no pinning, and a plugin host that loads unreviewed plugins.
Each `does_not_fire` fixture applies the control: authenticated publish, scoped internal resolution, enforced lockfile hashes, least-privilege and masked CI secrets, signature and integrity verification, and a plugin allowlist.
Canary packages, workflows, plugins, and lifecycle scripts all terminate at `range-oob`; the update and registry substitutions happen only through range-local services and never egress.
Probing uses `custom.supply_probe`, a reviewed allowlist adapter (HC-AGENT-01 §5.3).

## 7. Acceptance criteria

- All ten cards pass the HC-KB-01 validator, including ATT&CK and CWE resolution and the clearing of each `# verify` id.
- Every card fires on its `fires_on` fixture and stays silent on its `does_not_fire` fixture under HC-EVAL-01.
- The five tier-2 cards refuse to run without a live snapshot and restore the build host cleanly.
- No card causes a scope or egress violation; every install, publish, and update stays range-local and every code-execution proof terminates at `range-oob`, confirmed by the audit log.
- The chain in section 5 executes: an anonymous publish enables dependency confusion that yields build execution, and a leaked CI secret feeds the cloud chain.
- OOB, integrity-differential, and canary signals are evaluated deterministically by the harness.

## 8. Open questions

- Ecosystem fidelity: answered by [HC-PROJ-02](HC-PROJ-02.md), which keeps technique cards manager-neutral and implements format-specific assessment without running package managers or reimplementing their resolution algorithms.
- Whether build-host execution should run in a dedicated throwaway build VM distinct from the attacker VM, to keep snapshot scope tight.
- How to express supply-chain impact in CVSS, since build_exec often implies downstream blast far beyond a single host.
- Whether reproducible-build verification deserves its own card once a build target is standardized.

## 9. Backlog (deferred from this set)

- Compromised signing keys and certificate-authority trust abuse.
- Git-based attacks: submodule and hook injection, protected-branch bypass.
- SBOM falsification and provenance (SLSA) attestation gaps.
- Transitive-dependency confusion several levels deep, needing a richer dependency-graph fixture.
- Model and dataset supply chain for the AI class (poisoned weights, dataset tampering), sequenced with HC-KB-03's deferred poisoning cards.
