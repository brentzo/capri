#!/usr/bin/env python3
"""Tests for the capability-frontier loop and live chaining (HC-OBJ-01 §6a).

Drives the real loop in objective mode (a contract that carries an objective) with
two cards that chain: card A yields `credential`, card B requires `credential`.
Proves that B runs only after A is confirmed (a confirmed yield opens the next
card), that a merely provisional yield does not (finder-is-not-verifier at the
hop), that passive-only confirms nothing and so chains nothing, and that the same
cards under a no-objective contract take the unchanged coverage path where B is
never reached.

Zero-dependency: `python3 tests/test_frontier.py`.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import ratelimit, roleio                         # noqa: E402
from harness.dispatch import Dispatcher                       # noqa: E402
from harness.loop import Loop                                 # noqa: E402
from harness.store import blobstore, db, findings             # noqa: E402
from harness.substrate import contract                        # noqa: E402

_OBJECTIVE = """objective:
  id: obj-dbadmin
  description: "Obtain db admin on the app host."
  type: capability
  target: app.sandbox.local
  success: "exists(db_admin)"
"""

_BASE = """engagement:
  id: eng-frontier-001
  authorized_by: test
  window: {{ start: 2026-11-09T20:00, end: 2026-11-09T23:59 }}
  max_blast_tier: 2
scope:
  in_scope_hosts: [app.sandbox.local]
  in_scope_cidrs: [10.10.0.0/24]
  allowed_ports: {{ default: [443, 80] }}
policy:
  rate: {{ max_rps_per_target: 1000, max_actions_per_run: 10000 }}
  tier3_techniques: []
{objective}"""


def _card(cid, preconds, yields):
    return {"id": cid, "version": "1.0.0", "applicability": ['asset.type == "web_api"'],
            "preconditions": preconds, "yields_on_success": yields, "blast_tier": 1,
            "taxonomy": {"cwe": ["CWE-89"]},
            "severity_rubric": {"base": "high",
                                "cvss_base_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
            "success_signal": {"type": "status_match", "evaluator": "deterministic", "assert": "x"},
            "probe_steps": [{"tool": "probe", "intent": "probe"}]}


A = _card("KB-A", ["reachable"], ["credential"])
B = _card("KB-B", ["reachable", "credential"], ["db_admin"])
KB = {("KB-A", "1.0.0"): A, ("KB-B", "1.0.0"): B}
TM = {"web": {"asset.type": "web_api", "reachable": True, "addr": "10.10.0.5",
              "host": "app.sandbox.local"}}
HITS = [("10.10.0.5", "KB-A"), ("10.10.0.5", "KB-B")]


# --- stubs ---------------------------------------------------------------
class Session:
    def __init__(self, sid):
        self.id = sid
        self.step = 0
        self.disproved = False
        self.pair = None
        self.addr = None


class StubSandbox:
    def __init__(self, proofs=True):
        self._proofs = proofs

    def proofs_pass(self):
        return self._proofs

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
                "request_bytes": b"GET /p HTTP/1.1", "response_bytes": b"HTTP/1.1 200 OK",
                "deterministic_signals": {"hit": hit, "confidence": 0.9 if hit else 0.0}}


class Operator:
    """One probe per pair, aimed at the address the board view carries into begin()."""

    def __init__(self, sid="op"):
        self.sid = sid

    def begin(self, pair, facts=None):
        s = Session(self.sid)
        s.pair = pair
        s.addr = (facts or {}).get("addr")
        return s

    def propose_next(self, session, card, role_context):
        if session.step >= 1:
            return None
        session.step += 1
        return roleio.emit({"tool": "probe", "intent": "probe", "target": session.addr,
                            "port": 443, "args": {"technique": card["id"]}})


class Verifier:
    def __init__(self, sid, conn, *, reproduce=True):
        self.sid = sid
        self.conn = conn
        self.reproduce = reproduce

    def begin(self):
        return Session(self.sid)

    def propose_next(self, session, vinput, role_context):
        if not self.reproduce or session.step >= 1:
            return None
        session.step += 1
        steps = vinput.get("steps") or []
        if not steps:
            return None
        last = steps[-1]
        return roleio.emit({"tool": last["tool"], "intent": "reproduce",
                            "target": last["target"], "port": last.get("port", 443),
                            "args": last.get("args", {})})


class Planner:
    def plan(self, target_model, candidates, ledger_summary):
        return list(candidates)


def _build(root, contract_text, *, proofs=True):
    conn = db.connect()
    eng, errs = contract.parse(contract_text)
    assert not errs, errs
    disp = Dispatcher(conn, blobstore.BlobStore(root), eng, {"probe": ProbeAdapter(HITS)},
                      ratelimit.RateLimiter(1000, now=lambda: 0.0))
    return conn, eng, disp, StubSandbox(proofs)


def _ledger(conn, eng, tid):
    row = conn.execute(
        "SELECT status FROM coverage_ledger WHERE engagement_id=? AND asset='web' AND technique_id=?",
        (eng.id, tid)).fetchone()
    return row["status"] if row else None


# --- tests ---------------------------------------------------------------
def test_a_confirmed_yield_opens_the_next_card():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, _BASE.format(objective=_OBJECTIVE))
        Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox, planner=Planner(),
             operator=Operator(), verifier=Verifier("ver", conn)).run(TM)
        confirmed = {r["technique_id"] for r in findings.confirmed(conn, eng.id)}
        assert confirmed == {"KB-A", "KB-B"}, confirmed          # B ran because A confirmed
        assert _ledger(conn, eng, "KB-B") == "confirmed"


def test_a_provisional_yield_does_not_open_the_next_card():
    # the verifier cannot reproduce A, so `credential` stays provisional and never
    # satisfies B's precondition; B is never hunted.
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, _BASE.format(objective=_OBJECTIVE))
        Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox, planner=Planner(),
             operator=Operator(),
             verifier=Verifier("ver", conn, reproduce=False)).run(TM)
        assert findings.confirmed(conn, eng.id) == []
        assert _ledger(conn, eng, "KB-A") == "inconclusive"
        assert _ledger(conn, eng, "KB-B") is None                # B never became a candidate


def test_passive_only_confirms_nothing_and_chains_nothing():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, _BASE.format(objective=_OBJECTIVE), proofs=False)
        res = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox, planner=Planner(),
                   operator=Operator(), verifier=Verifier("ver", conn)).run(TM)
        assert res.mode == "passive-only"
        assert findings.confirmed(conn, eng.id) == []
        held = findings.leads(conn, eng.id)
        assert len(held) == 1 and held[0]["technique_id"] == "KB-A"
        assert _ledger(conn, eng, "KB-B") is None


def test_no_objective_takes_the_unchanged_coverage_path():
    # the same cards with no objective: coverage evaluates applicability once against
    # recon, so B's unmet `credential` precondition makes it not_applicable, not a
    # chain that ever opens.
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, _BASE.format(objective=""))
        assert eng.objective is None
        Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox, planner=Planner(),
             operator=Operator(), verifier=Verifier("ver", conn)).run(TM)
        confirmed = {r["technique_id"] for r in findings.confirmed(conn, eng.id)}
        assert confirmed == {"KB-A"}                              # B did not chain
        assert _ledger(conn, eng, "KB-B") == "not_applicable"


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
