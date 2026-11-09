#!/usr/bin/env python3
"""The provider catalog Capri owns (HC-MODEL-01).

The catalog is what the setup surface offers and what the gateway config is generated
from, so these tests pin its shape (every provider has a label, a key env, and at least
one suggested model) and the one invariant it enforces: an operator/verifier pairing
must be two known, different providers.

Zero-dependency: `python3 tests/test_catalog.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import catalog as cat                                     # noqa: E402


def test_catalog_is_non_empty_and_well_shaped():
    assert cat.providers(), "the catalog must list at least one provider"
    for p in cat.providers():
        assert cat.label(p), f"{p} needs a human label"
        assert cat.key_env(p).endswith("_API_KEY"), f"{p} key env should be an API key var"
        assert isinstance(cat.models(p), list), f"{p} models must be a list"
        # default is the first suggestion, or None when the catalog leaves it open
        assert cat.default_model(p) == (cat.models(p)[0] if cat.models(p) else None)


def test_every_provider_has_a_distinct_identifier_and_key_env():
    ids = cat.providers()
    assert len(ids) == len(set(ids)), "provider ids must be unique"
    key_envs = [cat.key_env(p) for p in ids]
    assert len(key_envs) == len(set(key_envs)), "each provider needs its own key env var"


def test_route_is_provider_slash_model():
    assert cat.route("openai", "gpt-4o-mini") == "openai/gpt-4o-mini"


def test_entries_render_shape_for_a_ui():
    es = cat.entries()
    assert {e["id"] for e in es} == set(cat.providers())
    for e in es:
        assert set(e) == {"id", "label", "key_env", "models"}
        assert isinstance(e["models"], list)             # may be empty (model left open)


def test_pairing_requires_two_different_known_providers():
    ids = cat.providers()
    a, b = ids[0], ids[1]
    assert cat.validate_pairing(a, b) is None                   # two distinct known ones: ok
    assert cat.validate_pairing(a, a) is not None               # same provider: rejected
    assert "different providers" in cat.validate_pairing(a, a)
    assert cat.validate_pairing(a, "nope") is not None          # unknown verifier: rejected
    assert cat.validate_pairing("nope", b) is not None          # unknown operator: rejected


def test_default_pairing_is_a_valid_disjoint_pair():
    # the shipped default (operator DeepSeek, verifier OpenAI) must satisfy the invariant
    assert cat.has_provider("deepseek") and cat.has_provider("openai")
    assert cat.validate_pairing("deepseek", "openai") is None


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
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERR  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
