"""Recon-derived probe binding (HC-AGENT-01 §5.3): the arg binder and the surface-map
projection that feed each other. Pure unit tests, no Docker and no models: a crawl's
surface map projects into endpoint-as-asset facts, and a card's templated probe step
binds to those facts to yield the concrete args the dispatcher would run."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import bind, predicates, recon


def _card(args, tool="sqli", intent="baseline"):
    return {"id": "KB-TEST-001", "version": "1.0.0",
            "probe_steps": [{"tool": tool, "intent": intent, **args}]}


# --- bind_probe_args ----------------------------------------------------------

def test_literal_step_is_returned_unchanged():
    card = _card({"path": "/item", "sqli_param": "id"})
    assert bind.bind_probe_args(card, {"asset.path": "/x"}) is card


def test_whole_string_template_resolves_and_keeps_type():
    card = _card({"path": "{asset.path}", "sqli_param": "{asset.param}"})
    facts = {"asset.path": "/search", "asset.param": "q"}
    out = bind.bind_probe_args(card, facts)
    step = out["probe_steps"][0]
    assert step["path"] == "/search" and step["sqli_param"] == "q"
    assert step["tool"] == "sqli"                      # non-arg fields untouched


def test_whole_string_template_preserves_non_string_fact():
    card = _card({"ids": "{asset.params}"})
    out = bind.bind_probe_args(card, {"asset.params": ["id", "ref"]})
    assert out["probe_steps"][0]["ids"] == ["id", "ref"]   # list kept, not stringified


def test_extra_literal_args_survive_binding():
    card = _card({"path": "{asset.path}", "param": "{asset.param}", "delay_s": 5}, tool="cmdi")
    out = bind.bind_probe_args(card, {"asset.path": "/ping", "asset.param": "host"})
    assert out["probe_steps"][0] == {"tool": "cmdi", "intent": "baseline",
                                     "path": "/ping", "param": "host", "delay_s": 5}


def test_nested_dict_args_are_substituted():
    card = _card({"path": "{asset.path}", "params": {"id": "{asset.param}"}}, tool="jwt")
    out = bind.bind_probe_args(card, {"asset.path": "/account", "asset.param": "uid"})
    assert out["probe_steps"][0]["params"] == {"id": "uid"}


def test_unresolved_fact_returns_none():
    card = _card({"path": "{asset.path}", "sqli_param": "{asset.param}"})
    assert bind.bind_probe_args(card, {"asset.path": "/item"}) is None   # no asset.param


def test_none_valued_fact_is_treated_as_missing():
    card = _card({"path": "{asset.path}"})
    assert bind.bind_probe_args(card, {"asset.path": None}) is None


def test_binding_does_not_mutate_the_source_card():
    card = _card({"path": "{asset.path}", "sqli_param": "{asset.param}"})
    bind.bind_probe_args(card, {"asset.path": "/x", "asset.param": "y"})
    assert card["probe_steps"][0]["path"] == "{asset.path}"


def test_missing_probe_steps_returns_card():
    card = {"id": "KB-TEST-002", "version": "1.0.0"}
    assert bind.bind_probe_args(card, {}) is card


# --- project_surface ----------------------------------------------------------

_SURFACE = {
    "base_url": "http://10.90.0.4:8080/",
    "endpoints": [
        {"path": "/search", "method": "get", "params": ["q", "cat"],
         "status": 200, "renders_html": True},
        {"path": "/download", "method": "GET", "params": ["file"], "status": 200},
        {"path": "/health", "method": "GET", "params": [], "status": 200},
        {"path": "", "method": "GET", "params": ["x"]},
    ],
}


def test_project_surface_makes_one_asset_per_endpoint_param():
    model = recon.project_surface(_SURFACE, "t1.sandbox.local", "10.90.0.4")
    # /search has two params -> two assets; /download one; /health none; "" path skipped
    assert set(model) == {"t1::/search?cat", "t1::/search?q", "t1::/download?file"}


def test_projected_asset_carries_the_routing_facts():
    model = recon.project_surface(_SURFACE, "t1.sandbox.local", "10.90.0.4")
    a = model["t1::/search?q"]
    assert a["asset.type"] == "http_endpoint"
    assert a["asset.path"] == "/search" and a["asset.param"] == "q"
    assert a["asset.params"] == ["q"] and a["asset.method"] == "GET"   # method upcased
    assert a["addr"] == "10.90.0.4" and a["reachable"] is True
    assert a.get("asset.renders_html") is True


def test_endpoint_without_renders_html_omits_the_flag():
    model = recon.project_surface(_SURFACE, "t1.sandbox.local", "10.90.0.4")
    assert "asset.renders_html" not in model["t1::/download?file"]


# --- the two compose: projected facts satisfy applicability and bind a real card ------

def test_sqli_applicability_holds_over_a_projected_asset():
    model = recon.project_surface(_SURFACE, "t1.sandbox.local", "10.90.0.4")
    facts = model["t1::/search?q"]
    for expr in ('asset.type == "http_endpoint"', "exists(asset.params)"):
        assert predicates.evaluate(expr, facts)


def test_path_param_name_heuristic_selects_the_file_asset():
    model = recon.project_surface(_SURFACE, "t1.sandbox.local", "10.90.0.4")
    rx = "matches(asset.params, /file|path|name|template/)"
    assert predicates.evaluate(rx, model["t1::/download?file"])
    assert not predicates.evaluate(rx, model["t1::/search?q"])


def test_recon_derived_routing_end_to_end():
    """A templated SQLi-style card binds to a projected asset's discovered route."""
    model = recon.project_surface(_SURFACE, "t1.sandbox.local", "10.90.0.4")
    card = _card({"path": "{asset.path}", "sqli_param": "{asset.param}"})
    out = bind.bind_probe_args(card, model["t1::/search?cat"])
    step = out["probe_steps"][0]
    assert step["path"] == "/search" and step["sqli_param"] == "cat"


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
