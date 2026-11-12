# tools

Two kinds of tooling, both pure Python standard library, no third-party dependency.

**KB build tooling** - the reference implementation of the technique-card validator
specified in [HC-KB-01 §9](../docs/specs/HC-KB-01.md) and its acceptance behavior in
HC-KB-01 §12 (`validate_kb.py`, `materialize_kb.py`, `taxonomy.py`, `gen_features.py`),
runnable in CI and documented below.

**Runtime and setup tooling** - the live-engagement runner and the self-host setup,
documented in [`../harness/README.md`](../harness/README.md) and [`../infra/`](../infra):
`run_engagement.py` (provision the Docker range, gate on the sandbox proofs, recon, and
drive the control loop), `sandbox_selftest.py` (prove the sandbox guarantees on your
host), and `setup.py` / `modelplane.py` / `catalog.py` / `terminal.py` (the `capri setup`
terminal UI, the Bifrost gateway mechanics, the provider catalog, and shared terminal
helpers).

## Files

- `materialize_kb.py` - generator. Reads the condensed card blocks in
  `docs/specs/HC-KB-*.md` and writes the full cards to `kb/<class>/*.yaml`, plus
  `kb/index.md` and the `eval/manifests/*.yaml` ground-truth manifests.
- `validate_kb.py` - the validator. By default checks the materialized
  `kb/<class>/*.yaml` tree (full cards); `--from-specs` checks the condensed
  spec blocks instead.
- `taxonomy.py` - the bundled identifier reference (CWE, ATT&CK, ATLAS, CAPEC)
  the cards cite, so taxonomy resolution runs offline.
- `../tests/test_validator.py` - adversarial tests proving each §12 failure mode.

## Source of truth and materialization

The specs are authored in condensed form and remain the source of truth.
`make materialize` regenerates the `kb/` tree and `eval/manifests/` from them;
the tree is committed, and CI fails if it drifts from the specs. Edit a card in
its `docs/specs/HC-KB-*.md` block, then re-materialize.

## Usage

```sh
make materialize      # regenerate kb/ and eval/manifests from the specs
make validate         # check the materialized kb/ tree (CI default, strict)
make test             # run the validator self-tests
python3 tools/validate_kb.py --from-specs   # check the condensed spec blocks
python3 tools/validate_kb.py kb/ai-llm/KB-AILLM-INJ-DIRECT-001.yaml   # one card
```

## Dependency assessment verification (HC-PROJ-02)

Install Semgrep 1.180.0 and Trivy 0.75.0 or newer on the verification host.
Run `python .\capri source update-db` once on a connected host; the command uses `trivy image --download-db-only` and prints the database timestamp.
For an air-gapped host, copy `trivy.db` and `metadata.json` into `~/.capri/trivy/db/` before scanning.

Run each recorded ecosystem fixture and the mixed and monorepo fixtures from PowerShell:

```powershell
$fixtures = @('npm', 'cocoapods', 'swiftpm', 'pub', 'gradle', 'mixed', 'monorepo')
foreach ($fixture in $fixtures) {
  python .\capri source --project (Join-Path 'tests\fixtures\dependency-assessment' $fixture) `
    --output (Join-Path $env:TEMP "capri-$fixture.json")
}
```

The individual fixtures report complete vulnerability coverage for their ecosystem.
The mixed fixture reports npm and CocoaPods as `complete`, Gradle as `partial` because only literal declared versions are available, and the overall vulnerable-dependency area as `partial`.
The monorepo fixture reports both nested npm lockfiles separately and the overall area as `complete`.
The scanner JSON captured from these real runs is stored beside the fixtures as `trivy-results-*.json` and replayed through the public assessment entry point in CI.

The assessment command does not download data.
The public-entry tests check that the Trivy process receives `--offline-scan`, all four update and version skip flags, `--disable-telemetry`, empty config and ignore-file arguments, and no inherited `TRIVY_*` variables.
They also assert project-controlled scanner settings are absent from the snapshot, so the assessment uses only Capri's rules and the Capri-owned database.
The stale-database warning is exercised with an injected clock and recorded database timestamp, leaving the scan coverage status unchanged.

## What it checks (HC-KB-01 §9)

- id naming `KB-<CLASS>-<...>-<nnn>` and a known class
- required fields present (title, applicability, preconditions,
  yields_on_success, probe_steps, success_signal, taxonomy, severity_rubric)
- the applicability and `when` clauses parse under the predicate DSL (§4):
  only `exists` / `matches` function calls, balanced parens, known operators
- `success_signal.type` is one of the seven signal types and the evaluator is
  `deterministic` or `laya:<decision_point>` (§5)
- `blast_tier` in 0..3, and a non-empty `cleanup` when tier >= 2 (§7, §9)
- an `oob_callback` terminates at an in-sandbox collaborator, never an external
  host (§5)
- `severity_rubric.base` is a valid band and every `raise_if` / `lower_if` entry
  is a `{when, to}` object with a parseable `when` and a valid `to`
- taxonomy ids are well-formed and resolve against `taxonomy.py`

For materialized `kb/` cards it additionally enforces the shipping fields:
semver `version`, a valid `status`, non-empty `references`, a `test_fixture`
with `fires_on` and `does_not_fire`, a CVSS v4 `cvss_base_vector`, and a
`success_signal.confidence_floor`; it also checks that the filename matches the
card id and that every card has an `eval/manifests/` entry (HC-EVAL-01 §9).

## Finding grades

- **ERROR** - a substantive schema / DSL / safety violation. Fails the build.
- **UNRESOLVED** - a well-formed taxonomy id not in the bundled reference. This
  is the `# verify` to-do surface. Non-fatal unless `--strict` (CI uses strict).

## Resolving a `# verify` / UNRESOLVED id

`taxonomy.py` holds only identifiers confirmed real against their upstream
catalog. To clear an UNRESOLVED id: check it at its source (cwe.mitre.org,
attack.mitre.org, atlas.mitre.org), then either add it to the confirmed set in
`taxonomy.py` or fix the card to cite the correct id. All 107 cards currently
resolve (`AML.T0053` and `AML.T0057` were confirmed against ATLAS v4.9.0 and
added to the reference), so `make validate-strict` passes.

## Derived fields (materialized cards)

`materialize_kb.py` fills the full-template fields the condensed blocks omit.
Three are honest defaults rather than hand-authored precision:

- `cvss_base_vector` - a CVSS v4 vector derived from the severity band and class
  (availability-weighted for the DOS class, `AV:L` for mobile). It is a starting
  point the report pipeline refines per finding (HC-FIND-01), not a per-card
  hand-scored vector.
- `references` - the canonical catalog URLs for the card's taxonomy ids.
- `test_fixture` - `seed/<class-dir>/<id>-vuln` and `-patched` by convention.

To change any of these, edit the generator and re-materialize, so the whole tree
stays consistent.
