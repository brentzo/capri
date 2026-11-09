#!/usr/bin/env python3
"""Tests for the Bifrost model plane (HC-MODEL-01 §13 acceptance criteria).

Drives the real plane with a deterministic stub transport (the way test_dispatch
drives the chokepoint with stub adapters), proving the criteria that are policy
in code:

  - every call carries a role vkey and an unknown role is refused; no role names a
    provider (only the injected transport does);
  - vk-operator and vk-verifier resolve to disjoint providers, and a config that
    shares one fails startup;
  - a budget breach stops the role and never reaches a provider;
  - Operator/Verifier turns are never served from cache; Planner/Reporter may be,
    scoped to the engagement;
  - only vk-enrich may be brokered MCP tools;
  - every call is an audit row correlated to its action, and the chain stays valid.

Plus the fallback rules: the Operator falls back within its own set, the Verifier
not at all. Zero-dependency: `python3 tests/test_modelplane.py`.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.modelplane import (ModelPlane, PlaneConfigError, PlaneStop,          # noqa: E402
                                ProviderDown, VirtualKey)
from harness.store import audit, db                            # noqa: E402

MSGS = [{"role": "system", "content": "probe"}, {"role": "user", "content": "data"}]


class Raw:
    __slots__ = ("text", "model", "tokens_in", "tokens_out", "latency_ms")

    def __init__(self, text="ok", model="m", tokens_in=10, tokens_out=20, latency_ms=5):
        self.text = text
        self.model = model
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.latency_ms = latency_ms


class StubTransport:
    """Records every (provider, messages) it is asked to serve; raises ProviderDown
    for providers marked down, so fallback order is observable."""

    def __init__(self, down=(), tokens=(10, 20)):
        self.down = set(down)
        self.tokens = tokens
        self.calls = []

    def complete(self, provider, messages, metadata):
        self.calls.append((provider, messages))
        if provider in self.down:
            raise ProviderDown(provider)
        ti, to = self.tokens
        return Raw(model=f"{provider}-model", tokens_in=ti, tokens_out=to)

    def providers_tried(self):
        return [p for (p, _) in self.calls]


def _plane(transport, conn, *, op=("provA/strong",), ver=("provB/strong",),
           op_budget=None, engagement_budget=None, op_fallback="within_set",
           op_rate=None, clock=None):
    vkeys = [
        VirtualKey("planner", ["provA/mid"], cache=True, fallback="free"),
        VirtualKey("operator", op, cache=False, fallback=op_fallback,
                   budget=op_budget, rate=op_rate),
        VirtualKey("verifier", ver, cache=False, fallback="none"),
        VirtualKey("reporter", ["provA/cheap"], cache=True, fallback="free"),
    ]
    kw = {"engagement_budget": engagement_budget}
    if clock is not None:
        kw["clock"] = clock
    return ModelPlane(vkeys, transport, conn, "eng-mp-1", **kw)


def _audit_rows(conn, category=None):
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    return [r for r in rows if category is None or r["category"] == category]


# --- diversity and config (§4, §8, §13.2) --------------------------------
def test_operator_and_verifier_resolve_to_disjoint_providers():
    conn = db.connect()
    tx = StubTransport()
    plane = _plane(tx, conn)
    assert plane.assert_provider_diversity() == ("ok", None)
    op = plane.call("operator", MSGS)
    ver = plane.call("verifier", MSGS)
    assert op.provider == "provA/strong" and ver.provider == "provB/strong"
    assert op.provider != ver.provider


def test_a_shared_provider_fails_startup():
    conn = db.connect()
    try:
        _plane(StubTransport(), conn, ver=("provA/strong",))   # shares operator's provider
        raise AssertionError("expected a diversity failure at construction")
    except PlaneConfigError:
        pass


def test_mcp_tools_are_allowed_only_on_the_enrich_vkey():
    conn = db.connect()
    try:
        ModelPlane([VirtualKey("operator", ["provA"], mcp_tools=["tavily"]),
                    VirtualKey("verifier", ["provB"])], StubTransport(), conn, "e")
        raise AssertionError("expected the Operator MCP-tool config to fail")
    except PlaneConfigError:
        pass
    # the same tool on vk-enrich is allowed
    ModelPlane([VirtualKey("enrich", ["provA/cheap"], cache=True, mcp_tools=["tavily"])],
               StubTransport(), conn, "e")


def test_an_unknown_role_is_refused():
    conn = db.connect()
    plane = _plane(StubTransport(), conn)
    try:
        plane.call("ghost", MSGS)
        raise AssertionError("expected an unknown role to be refused")
    except PlaneConfigError:
        pass


# --- cache (§7, §13.4) ----------------------------------------------------
def test_operator_turns_are_never_served_from_cache():
    conn = db.connect()
    tx = StubTransport()
    plane = _plane(tx, conn)
    a = plane.call("operator", MSGS)
    b = plane.call("operator", MSGS)
    assert not a.cache_hit and not b.cache_hit
    assert len(tx.calls) == 2                      # both reached a provider


def test_planner_prose_is_cached_then_a_new_prompt_misses():
    conn = db.connect()
    tx = StubTransport()
    plane = _plane(tx, conn)
    a = plane.call("planner", MSGS)
    b = plane.call("planner", MSGS)
    assert not a.cache_hit and b.cache_hit
    assert len(tx.calls) == 1                       # second served from cache
    plane.call("planner", MSGS + [{"role": "user", "content": "more"}])
    assert len(tx.calls) == 2                       # a different prompt is a miss


def test_cache_is_namespaced_per_engagement():
    conn = db.connect()
    tx = StubTransport()
    a = ModelPlane([VirtualKey("planner", ["provA/mid"], cache=True)], tx, conn, "eng-1")
    b = ModelPlane([VirtualKey("planner", ["provA/mid"], cache=True)], tx, conn, "eng-2")
    a.call("planner", MSGS)
    hit = b.call("planner", MSGS)                   # same prompt, other engagement
    assert not hit.cache_hit and len(tx.calls) == 2


# --- budgets (§5, §13.3) --------------------------------------------------
def test_budget_breach_stops_the_role_and_never_reaches_a_provider():
    conn = db.connect()
    tx = StubTransport(tokens=(10, 20))             # cost 30 per call
    plane = _plane(tx, conn, op_budget=5)
    plane.call("operator", MSGS)                     # serves, spend now 30 >= 5
    try:
        plane.call("operator", MSGS)
        raise AssertionError("expected a budget stop")
    except PlaneStop as e:
        assert e.reason == "budget_exhausted"
    assert len(tx.calls) == 1                        # the stopped call never served


def test_engagement_budget_caps_the_sum_across_roles():
    conn = db.connect()
    tx = StubTransport(tokens=(10, 20))
    plane = _plane(tx, conn, engagement_budget=5)
    plane.call("operator", MSGS)                     # total now 30 >= 5
    try:
        plane.call("verifier", MSGS)
        raise AssertionError("expected an engagement-budget stop")
    except PlaneStop as e:
        assert e.reason == "engagement_budget_exhausted"
    assert tx.providers_tried() == ["provA/strong"]  # verifier never reached a provider


# --- fallback (§10) -------------------------------------------------------
def test_operator_falls_back_within_its_own_set():
    conn = db.connect()
    tx = StubTransport(down=["provA1"])
    plane = _plane(tx, conn, op=("provA1", "provA2"))
    comp = plane.call("operator", MSGS)
    assert comp.provider == "provA2"
    assert tx.providers_tried() == ["provA1", "provA2"]


def test_verifier_does_not_fall_back_onto_the_operators_provider():
    conn = db.connect()
    tx = StubTransport(down=["provB/strong"])        # the verifier's only provider is down
    plane = _plane(tx, conn)
    try:
        plane.call("verifier", MSGS)
        raise AssertionError("expected the verifier to stop, not fall back")
    except PlaneStop as e:
        assert e.reason == "provider_unavailable"
    assert "provA/strong" not in tx.providers_tried()  # never the operator's provider


def test_a_pinned_verifier_serves_when_its_provider_is_up():
    conn = db.connect()
    plane = _plane(StubTransport(), conn)
    comp = plane.call("verifier", MSGS)
    assert comp.provider == "provB/strong" and not comp.cache_hit


# --- rate (§6) ------------------------------------------------------------
def test_rate_limit_is_per_vkey():
    conn = db.connect()
    tx = StubTransport()
    plane = _plane(tx, conn, op_rate=1, clock=lambda: 0.0)
    plane.call("operator", MSGS)                     # consumes the one token
    try:
        plane.call("operator", MSGS)
        raise AssertionError("expected a rate stop")
    except PlaneStop as e:
        assert e.reason == "rate_limited"
    plane.call("verifier", MSGS)                     # a different vkey is unaffected


# --- observability (§9, §13.6) -------------------------------------------
def test_every_call_is_audited_with_its_vkey_and_the_chain_stays_valid():
    conn = db.connect()
    tx = StubTransport(down=["provB/strong"])
    plane = _plane(tx, conn)
    served = plane.call("operator", MSGS)
    try:
        plane.call("verifier", MSGS)                 # stops: provider down
    except PlaneStop:
        pass
    calls = _audit_rows(conn, "model_call")
    stops = _audit_rows(conn, "model_stop")
    assert len(calls) == 1 and calls[0]["actor"] == "vk-operator"
    assert str(served.tokens_out) in calls[0]["detail"] and "provA/strong" in calls[0]["detail"]
    assert len(stops) == 1 and stops[0]["actor"] == "vk-verifier"
    assert audit.verify_chain(conn) == ("ok", None)


def test_the_correlation_id_ties_the_turn_to_its_action():
    conn = db.connect()
    plane = _plane(StubTransport(), conn)
    plane.call("operator", MSGS, {"correlation_id": "probe://pe-7"})
    row = _audit_rows(conn, "model_call")[0]
    assert row["correlation_id"] == "probe://pe-7"


# --- config sketch (§11) --------------------------------------------------
CONFIG = {
    "virtual_keys": {
        "vk-operator": {"providers": ["providerA/strong"], "cache": False, "fallback": "within_set"},
        "vk-verifier": {"providers": ["providerB/strong"], "cache": False, "fallback": "none"},
        "vk-planner": {"providers": ["providerA/mid"], "cache": True},
        "vk-reporter": {"providers": ["providerA/cheap"], "cache": True},
        "vk-enrich": {"providers": ["providerA/cheap"], "cache": True, "mcp_tools": ["tavily"]},
    },
    "budgets": {"engagement": {"limit": 100000,
                               "children": ["vk-operator", "vk-verifier", "vk-planner",
                                            "vk-reporter", "vk-enrich"]}},
}


def test_from_config_builds_a_plane_and_enforces_diversity():
    conn = db.connect()
    plane = ModelPlane.from_config(CONFIG, StubTransport(), conn, "eng-cfg")
    assert plane.call("operator", MSGS).provider == "providerA/strong"
    bad = {k: dict(v) for k, v in CONFIG.items()}
    bad["virtual_keys"] = dict(CONFIG["virtual_keys"])
    bad["virtual_keys"]["vk-verifier"] = {"providers": ["providerA/strong"], "fallback": "none"}
    try:
        ModelPlane.from_config(bad, StubTransport(), conn, "eng-cfg")
        raise AssertionError("expected the shared-provider config to fail startup")
    except PlaneConfigError:
        pass


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
