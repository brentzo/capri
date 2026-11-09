#!/usr/bin/env python3
"""Capability registry: the reviewed bridge from KB technique cards to tool adapters.

These tests pin the registry against the real materialized KB, so a capability can never
name a card that does not exist, every mapped technique is one the deterministic signal
rule can actually confirm, and the projection keeps the genuine card while swapping in a
runnable probe step. Pure standard library: `python3 tests/test_capabilities.py`.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from harness import capabilities, kb                                      # noqa: E402

_ADAPTERS = {"probe", "nmap", "httpx", "http", "sqli", "idor", "bfla", "jwt", "ssti",
             "cors", "path", "cmdi", "cache", "sess"}
_KB = kb.load()
_ID_TO_VER = {cid: ver for (cid, ver) in _KB}


def test_every_capability_maps_to_a_real_kb_card():
    for cid in capabilities.CAPABILITIES:
        assert cid in _ID_TO_VER, f"capability {cid} names no real KB card"


def test_every_capability_targets_a_known_adapter():
    for cid, (tool, args) in capabilities.CAPABILITIES.items():
        assert tool in _ADAPTERS, f"{cid} maps to unknown adapter {tool!r}"
        assert isinstance(args, dict)


def test_runnable_cards_have_a_deterministic_success_signal():
    # Only a deterministic evaluator can auto-confirm without Laya, so a capability must
    # not claim a card the loop could never fire (e.g. a laya: DOM-execution signal).
    runnable = capabilities.runnable_index(_KB)
    for (cid, ver), card in runnable.items():
        assert card["success_signal"]["evaluator"] == "deterministic", cid


def test_runnable_index_attaches_a_concrete_probe_step_and_keeps_the_real_card():
    runnable = capabilities.runnable_index(_KB)
    assert set(runnable) == {(cid, _ID_TO_VER[cid]) for cid in capabilities.CAPABILITIES}
    for (cid, ver), card in runnable.items():
        real = _KB[(cid, ver)]
        step = card["probe_steps"][0]
        assert step["tool"] == capabilities.CAPABILITIES[cid][0]
        assert step["tool"] in _ADAPTERS
        # the genuine technique is preserved; only the probe step is swapped
        assert card["applicability"] == real["applicability"]
        assert card["success_signal"] == real["success_signal"]
        assert card["severity_rubric"] == real["severity_rubric"]


def test_runnable_index_drops_an_unimplemented_card():
    # A laya-only technique with no adapter (reflected XSS needs DOM execution) is excluded.
    assert not capabilities.implemented("KB-WEB-INJ-XSS-001")
    runnable = capabilities.runnable_index(_KB)
    assert all(cid != "KB-WEB-INJ-XSS-001" for (cid, ver) in runnable)


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
