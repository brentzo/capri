#!/usr/bin/env python3
"""Adversarial tests for the HC-KB-01 validator.

Proves the HC-KB-01 §12 acceptance behavior: a malformed card, an unresolved
or malformed taxonomy reference, an unparseable predicate, a tier>=2 card with
empty cleanup, and an external oob_callback all fail validation; a well-formed
card passes.

Zero-dependency: run directly with `python3 tests/test_validator.py`
(also discoverable by pytest).
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))
import validate_kb as V  # noqa: E402

VALID = """
id: KB-WEB-INJ-TEST-001
title: valid baseline card
taxonomy: { attack: {technique: T1190}, cwe: [CWE-89] }
applicability: [ 'asset.type == "http_endpoint"', 'exists(asset.params)' ]
preconditions: [ reachable ]
yields_on_success: [ db_read ]
blast_tier: 1
cleanup: none
probe_steps:
  - { tool: httpx, intent: baseline }
success_signal: { type: response_diff, evaluator: deterministic, assert: "x" }
severity_rubric: { base: high }
"""


def grades(block):
    fields, clean = V.parse_card(block)
    return V.validate_card(fields, clean, source="test")


def has(issues, grade, needle):
    return any(g == grade and needle in m for g, m in issues)


def test_valid_card_passes():
    issues = grades(VALID)
    assert not any(g == V.ERROR for g, _ in issues), issues
    assert not any(g == V.UNRESOLVED for g, _ in issues), issues


def test_malformed_missing_success_signal():
    block = VALID.replace(
        'success_signal: { type: response_diff, evaluator: deterministic, assert: "x" }',
        "")
    assert has(grades(block), V.ERROR, "missing success_signal")


def test_malformed_taxonomy_id():
    block = VALID.replace("cwe: [CWE-89]", "cwe: [CWE-notanumber]")
    assert has(grades(block), V.ERROR, "malformed")


def test_unresolved_taxonomy_id():
    # format-valid but not in the bundled reference -> UNRESOLVED (fatal under --strict)
    block = VALID.replace("cwe: [CWE-89]", "cwe: [CWE-89], atlas: [AML.T9999]")
    assert has(grades(block), V.UNRESOLVED, "not in reference")


def test_unparseable_predicate():
    block = VALID.replace("'exists(asset.params)'", "'danger(asset.params)'")
    assert has(grades(block), V.ERROR, "disallowed function")


def test_bad_predicate_syntax():
    block = VALID.replace("'exists(asset.params)'", "'asset.params ?? broken'")
    assert has(grades(block), V.ERROR, "applicability")


def test_tier2_empty_cleanup():
    block = VALID.replace("blast_tier: 1", "blast_tier: 2")
    assert has(grades(block), V.ERROR, "requires a non-empty cleanup")


def test_blast_tier_out_of_range():
    block = VALID.replace("blast_tier: 1", "blast_tier: 7")
    assert has(grades(block), V.ERROR, "out of range")


def test_external_oob_collaborator():
    block = VALID.replace(
        'success_signal: { type: response_diff, evaluator: deterministic, assert: "x" }',
        'success_signal: { type: oob_callback, evaluator: deterministic, assert: "x" }\n'
        'probe_hint: { collaborator: evil.example.com }')
    assert has(grades(block), V.ERROR, "not an in-sandbox listener")


def test_in_range_oob_ok():
    block = VALID.replace(
        'success_signal: { type: response_diff, evaluator: deterministic, assert: "x" }',
        'success_signal: { type: oob_callback, evaluator: deterministic, assert: "x" }\n'
        'probe_hint: { collaborator: range-oob }')
    assert not any(g == V.ERROR for g, _ in grades(block))


def test_unknown_signal_type():
    block = VALID.replace("type: response_diff", "type: vibes_check")
    assert has(grades(block), V.ERROR, "not a known signal type")


def test_bad_severity():
    block = VALID.replace("base: high", "base: catastrophic")
    assert has(grades(block), V.ERROR, "not a valid severity")


def test_bad_evaluator():
    block = VALID.replace("evaluator: deterministic", "evaluator: magic")
    assert has(grades(block), V.ERROR, "evaluator")


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
