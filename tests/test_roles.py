#!/usr/bin/env python3
"""Tests for the Bifrost-backed role sessions (HC-AGENT-01 §4.1, §4.2).

Runs the real control loop with model-driven Operator and Verifier sessions over a
deterministic fake model (the stub transport the model plane injects), closing the
loop between the three pieces built around them: the Operator proposes a probe as
text, the harness parses it (roleio) and disposes it (dispatch), a deterministic
signal becomes a lead, and the Verifier reproduces it on a disjoint provider so the
finding confirms. Also the stop paths: a budget stop and the stop sentinel end a
turn with no probe, and a down Verifier provider does not confirm.

Zero-dependency: `python3 tests/test_roles.py`.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import ratelimit, roleio                        # noqa: E402
from harness.dispatch import Dispatcher                      # noqa: E402
from harness.loop import Loop, Pair                          # noqa: E402
from harness.modelplane import ModelPlane, ProviderDown, VirtualKey  # noqa: E402
from harness.roles import ModelOperator, ModelVerifier       # noqa: E402
from harness.store import blobstore, db, findings            # noqa: E402
from harness.substrate import contract                       # noqa: E402

CONTRACT = """
engagement:
  id: eng-roles-001
  authorized_by: test
  window: { start: 2026-11-09T20:00, end: 2026-11-09T23:59 }
  max_blast_tier: 2
scope:
  in_scope_cidrs: [10.10.0.0/24]
  allowed_ports: { default: [443, 80] }
policy:
  rate: { max_rps_per_target: 1000, max_actions_per_run: 10000 }
  tier3_techniques: []
"""

SQLI_ID = "KB-TEST-SQLI-001"
SQLI = {
    "id": SQLI_ID, "version": "1.0.0",
    "applicability": ['asset.type == "web_api"'], "preconditions": ["reachable"],
    "blast_tier": 1, "taxonomy": {"cwe": ["CWE-89"]},
    "severity_rubric": {"base": "high",
                        "cvss_base_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
    "success_signal": {"type": "status_match", "evaluator": "deterministic",
                       "assert": "error-based injection reflects a db fingerprint"},
    "probe_steps": [{"tool": "probe", "intent": "inject_error_payloads"}],
}
KB = {(SQLI_ID, "1.0.0"): SQLI}
TM = {"web": {"asset.type": "web_api", "reachable": True, "addr": "10.10.0.5"}}
PROV_OP, PROV_VER = "provA/strong", "provB/strong"

OP_REQ = roleio.emit({"tool": "probe", "intent": "inject_error_payloads",
                      "target": "10.10.0.5", "port": 443, "args": {"technique": SQLI_ID}})
VER_REQ = roleio.emit({"tool": "probe", "intent": "reproduce", "target": "10.10.0.5",
                       "port": 443, "args": {"technique": SQLI_ID}})


# --- stubs ---------------------------------------------------------------
class Raw:
    __slots__ = ("text", "model", "tokens_in", "tokens_out", "latency_ms")

    def __init__(self, text, provider):
        self.text = text
        self.model = provider + "-m"
        self.tokens_in = 5
        self.tokens_out = 7
        self.latency_ms = 3


class FakeModel:
    """Scripted transport: canned text per provider per turn, STOP once exhausted.
    Records (provider, correlation_id) so the test can see which provider served."""

    def __init__(self, scripts, down=()):
        self.scripts = scripts
        self.down = set(down)
        self.turn = {}
        self.seen = []

    def complete(self, provider, messages, metadata):
        self.seen.append((provider, metadata.get("correlation_id")))
        if provider in self.down:
            raise ProviderDown(provider)
        i = self.turn.get(provider, 0)
        self.turn[provider] = i + 1
        texts = self.scripts.get(provider, [])
        return Raw(texts[i] if i < len(texts) else "STOP", provider)


class StubSandbox:
    def proofs_pass(self):
        return True

    def snapshot(self):
        return "snap"

    def restore(self, snap_id):
        pass


class ProbeAdapter:
    def __init__(self, hits):
        self.hits = set(hits)

    def run(self, req):
        hit = (req["target"], req["args"].get("technique")) in self.hits
        return {"status": "ok", "parsed": {"probed": req.get("intent")},
                "request_bytes": b"GET /probe HTTP/1.1", "response_bytes": b"HTTP/1.1 200 OK",
                "deterministic_signals": {"hit": hit, "confidence": 0.9 if hit else 0.0}}


class Planner:
    def __init__(self, pairs):
        self.pairs = pairs

    def plan(self, target_model, candidates, ledger_summary):
        return self.pairs


def _build(root, model, *, op_budget=None, hits=((("10.10.0.5", SQLI_ID)),)):
    conn = db.connect()
    eng, errs = contract.parse(CONTRACT)
    assert not errs, errs
    disp = Dispatcher(conn, blobstore.BlobStore(root), eng, {"probe": ProbeAdapter(hits)},
                      ratelimit.RateLimiter(1000, now=lambda: 0.0))
    vkeys = [VirtualKey("operator", [PROV_OP], cache=False, fallback="within_set", budget=op_budget),
             VirtualKey("verifier", [PROV_VER], cache=False, fallback="none")]
    plane = ModelPlane(vkeys, model, conn, eng.id)
    lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=StubSandbox(),
              planner=Planner([Pair("web", SQLI_ID, "1.0.0")]),
              operator=ModelOperator(plane), verifier=ModelVerifier(plane))
    return conn, eng, lp


def _pe_count(conn):
    return conn.execute("SELECT COUNT(*) AS c FROM probe_event").fetchone()["c"]


def _ledger(conn, eng):
    row = conn.execute(
        "SELECT status FROM coverage_ledger WHERE engagement_id=? AND asset='web'",
        (eng.id,)).fetchone()
    return row["status"] if row else None


# --- tests ---------------------------------------------------------------
def test_model_backed_roles_find_and_confirm_across_disjoint_providers():
    model = FakeModel({PROV_OP: [OP_REQ], PROV_VER: [VER_REQ]})
    with tempfile.TemporaryDirectory() as root:
        conn, eng, lp = _build(root, model)
        res = lp.run(TM)
        conf = findings.confirmed(conn, eng.id)
        assert len(conf) == 1, conf
        assert conf[0]["found_by"].startswith("vk-operator-")
        assert conf[0]["verified_by"].startswith("vk-verifier-")
        assert conf[0]["found_by"] != conf[0]["verified_by"]    # finder != verifier
        assert res.valid, res.errors
        assert _ledger(conn, eng) == "confirmed"
        # the two roles ran on the two disjoint providers
        served = {p for (p, _) in model.seen}
        assert PROV_OP in served and PROV_VER in served


def test_operator_budget_stop_yields_no_probe():
    model = FakeModel({PROV_OP: [OP_REQ], PROV_VER: [VER_REQ]})
    with tempfile.TemporaryDirectory() as root:
        conn, eng, lp = _build(root, model, op_budget=0)          # exhausted before serving
        lp.run(TM)
        assert _pe_count(conn) == 0                               # never reached dispatch
        assert findings.leads(conn, eng.id) == []
        assert findings.confirmed(conn, eng.id) == []
        assert _ledger(conn, eng) == "attempted"


def test_operator_stop_sentinel_ends_the_turn():
    model = FakeModel({PROV_OP: ["STOP"]})
    with tempfile.TemporaryDirectory() as root:
        conn, eng, lp = _build(root, model)
        lp.run(TM)
        assert _pe_count(conn) == 0
        assert findings.leads(conn, eng.id) == []
        assert _ledger(conn, eng) == "attempted"


def test_verifier_provider_down_does_not_confirm():
    model = FakeModel({PROV_OP: [OP_REQ], PROV_VER: [VER_REQ]}, down=[PROV_VER])
    with tempfile.TemporaryDirectory() as root:
        conn, eng, lp = _build(root, model)
        lp.run(TM)
        assert findings.confirmed(conn, eng.id) == []             # never verified on a shared model
        fid = conn.execute("SELECT id FROM finding WHERE engagement_id=?",
                           (eng.id,)).fetchone()["id"]
        assert findings.current(conn, fid)["verdict"] == "inconclusive"
        assert PROV_OP in {p for (p, _) in model.seen}            # the operator still probed


def test_operator_prompt_names_its_tool_and_target():
    """The Operator must tell the model which tool the harness will run and to aim at
    the asset's recon address. Without this a real model invents a tool name the
    dispatcher does not have, and the probe never runs (observed live with DeepSeek)."""
    captured = {}

    class Capturing:
        def complete(self, provider, messages, metadata):
            captured["messages"] = messages
            return Raw("STOP", provider)

    plane = ModelPlane([VirtualKey("operator", ["p-op"]), VirtualKey("verifier", ["p-ver"])],
                       Capturing(), db.connect(), "eng-prompt")

    class P:                                            # a minimal pair
        asset = "t1"
        technique_id = "KB-X"

    card = {"probe_steps": [{"tool": "probe", "intent": "http_get"}]}
    session = ModelOperator(plane).begin(P(), {"addr": "10.0.0.9", "host": "t1.sandbox.local"})
    ModelOperator(plane).propose_next(session, card, "(none yet)")
    blob = "\n".join(m["content"] for m in captured["messages"])
    assert '"tool": "probe"' in blob, "the task must name the tool the harness will run"
    assert "recon.addr" in blob, "the Operator must be told to target the recon address"
    assert "10.0.0.9" in blob, "the recon address must reach the model"


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
