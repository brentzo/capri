# KB tooling

The reference implementation of the technique-card validator specified in
[HC-KB-01 §9](../specs/HC-KB-01.md) and its acceptance behavior in HC-KB-01 §12.
Pure Python standard library, no third-party dependency, runnable in CI.

## Files

- `validate_kb.py` - the validator. Reads the condensed technique-card blocks
  from `specs/HC-KB-*.md` (the current source of truth) and checks each card.
- `taxonomy.py` - the bundled identifier reference (CWE, ATT&CK, ATLAS, CAPEC)
  the cards cite, so taxonomy resolution runs offline.
- `../tests/test_validator.py` - adversarial tests proving each §12 failure mode.

## Usage

```sh
make validate         # check all cards (CI default)
make validate-strict  # also fail on UNRESOLVED taxonomy ids
make test             # run the validator self-tests
python3 tools/validate_kb.py specs/HC-KB-03.md   # one spec
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

## Finding grades

- **ERROR** - a substantive schema / DSL / safety violation. Fails the build.
- **UNRESOLVED** - a well-formed taxonomy id not in the bundled reference. This
  is the `# verify` to-do surface. Non-fatal unless `--strict`.
- The run also reports how many cards are still **condensed** (substantive
  fields only); the full-template shipping fields (`version`, `status`,
  `references`, `test_fixture`, `inputs`, `cvss_base_vector`) are filled when the
  KB is materialized to `kb/<class>/*.yaml` at milestone M2.

## Resolving a `# verify` / UNRESOLVED id

`taxonomy.py` holds only identifiers confirmed real against their upstream
catalog. To clear an UNRESOLVED id: check it at its source (cwe.mitre.org,
attack.mitre.org, atlas.mitre.org), then either add it to the confirmed set in
`taxonomy.py` or fix the card to cite the correct id. All 107 cards currently
resolve (`AML.T0053` and `AML.T0057` were confirmed against ATLAS v4.9.0 and
added to the reference), so `make validate-strict` passes.

## M2 note

When cards are materialized to `kb/<class>/*.yaml`, extend `validate_kb.py` with
a block-style loader (the condensed blocks here are flow-style); the check logic
is unchanged.
