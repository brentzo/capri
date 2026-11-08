# KB tooling

The reference implementation of the technique-card validator specified in
[HC-KB-01 §9](../specs/HC-KB-01.md) and its acceptance behavior in HC-KB-01 §12.
Pure Python standard library, no third-party dependency, runnable in CI.

## Files

- `materialize_kb.py` - generator. Reads the condensed card blocks in
  `specs/HC-KB-*.md` and writes the full cards to `kb/<class>/*.yaml`, plus
  `kb/_index/index.md` and the `eval/manifests/*.yaml` ground-truth manifests.
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
its `specs/HC-KB-*.md` block, then re-materialize.

## Usage

```sh
make materialize      # regenerate kb/ and eval/manifests from the specs
make validate         # check the materialized kb/ tree (CI default, strict)
make test             # run the validator self-tests
python3 tools/validate_kb.py --from-specs   # check the condensed spec blocks
python3 tools/validate_kb.py kb/ai-llm/KB-AILLM-INJ-DIRECT-001.yaml   # one card
```

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
