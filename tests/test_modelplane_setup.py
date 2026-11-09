"""Model-plane gateway bring-up: the generated config and .env (HC-MODEL-01).

`tools/modelplane.py` stands up the Bifrost gateway with one command. The Docker
orchestration is exercised live on a range host; these tests pin the pure logic it
generates - the gateway config, the virtual keys, and the .env - because that logic
encodes a safety invariant (the operator and verifier resolve to disjoint providers)
and must never carry a real secret into a committed file.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import modelplane as mp                                    # noqa: E402


def test_routes_pair_operator_and_verifier_on_distinct_providers():
    routes = mp.plane_routes()
    assert routes == {"operator": "deepseek/deepseek-chat",
                      "verifier": "openai/gpt-4o-mini"}
    provider = lambda r: r.split("/", 1)[0]
    assert provider(routes["operator"]) != provider(routes["verifier"])


def test_config_binds_each_virtual_key_to_one_provider():
    cfg = mp.build_bifrost_config()
    assert set(cfg["providers"]) == {"openai", "deepseek"}
    vks = {vk["id"]: vk for vk in cfg["governance"]["virtual_keys"]}
    assert set(vks) == {"vk-operator", "vk-verifier"}
    for vk in vks.values():
        assert len(vk["provider_configs"]) == 1          # exactly one provider per role
    assert vks["vk-operator"]["provider_configs"][0]["provider"] == "deepseek"
    assert vks["vk-verifier"]["provider_configs"][0]["provider"] == "openai"


def test_operator_and_verifier_providers_are_disjoint():
    cfg = mp.build_bifrost_config()
    vks = {vk["id"]: vk for vk in cfg["governance"]["virtual_keys"]}
    ops = {pc["provider"] for pc in vks["vk-operator"]["provider_configs"]}
    vers = {pc["provider"] for pc in vks["vk-verifier"]["provider_configs"]}
    assert not (ops & vers), "operator and verifier must not share a provider"


def test_config_carries_no_literal_secret_only_env_references():
    cfg = mp.build_bifrost_config()
    blob = _json_dump(cfg)
    assert "sk-" not in blob, "a real key must never reach the committed config"
    # every credential is an env.VAR reference resolved only in the gateway's env
    for prov in cfg["providers"].values():
        for key in prov["keys"]:
            assert key["value"].startswith("env.")
    for vk in cfg["governance"]["virtual_keys"]:
        assert vk["value"].startswith("env.")


def test_minted_virtual_keys_are_prefixed_and_distinct():
    vks = mp.new_vkeys()
    assert set(vks) == {"VK_OPERATOR", "VK_VERIFIER"}
    assert vks["VK_OPERATOR"].startswith("sk-bf-op-")
    assert vks["VK_VERIFIER"].startswith("sk-bf-ver-")
    assert vks["VK_OPERATOR"] != vks["VK_VERIFIER"]
    # minted fresh each call, never a fixed default
    assert mp.new_vkeys()["VK_OPERATOR"] != vks["VK_OPERATOR"]


def test_env_round_trips_and_ignores_comments_and_blanks():
    env = {"OPENAI_API_KEY": "sk-openai-xyz", "DEEPSEEK_API_KEY": "",
           "VK_OPERATOR": "sk-bf-op-1", "VK_VERIFIER": "sk-bf-ver-2"}
    text = mp.render_env(env)
    assert text.splitlines()[0].startswith("#")          # a header, not a bare key
    parsed = mp.parse_env(text)
    for k, v in env.items():
        assert parsed.get(k, "") == v


def test_missing_provider_keys_flags_only_the_blank_ones():
    assert set(mp.missing_provider_keys({})) == {"OPENAI_API_KEY", "DEEPSEEK_API_KEY"}
    half = {"OPENAI_API_KEY": "sk-x", "DEEPSEEK_API_KEY": "   "}
    assert mp.missing_provider_keys(half) == ["DEEPSEEK_API_KEY"]
    full = {"OPENAI_API_KEY": "sk-x", "DEEPSEEK_API_KEY": "sk-y"}
    assert mp.missing_provider_keys(full) == []


def test_env_keys_order_is_provider_keys_then_virtual_keys():
    assert mp.env_keys() == ["DEEPSEEK_API_KEY", "OPENAI_API_KEY",
                             "VK_OPERATOR", "VK_VERIFIER"]


def _json_dump(obj):
    import json
    return json.dumps(obj)


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
