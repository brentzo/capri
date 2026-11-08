#!/usr/bin/env python3
"""Tests for the outer control loop and role orchestration (HC-AGENT-01 §4, §11).

Drives the real loop, dispatch chokepoint, and store with deterministic stub
roles and a stub sandbox (the same way test_dispatch drives the chokepoint with
stub adapters), and proves the §11 acceptance criteria that are loop properties:

  - a confirmed run ships a report that passes validate_report;
  - finder != verifier is refused at the loop before any confirm (not only the DB);
  - a run killed mid-hunt resumes from the ledger to the same confirmed set;
  - an injected out-of-scope target is denied and never reaches the wire;
  - with the sandbox down, the loop runs passive-only and holds every lead at
    needs_validation, shipping nothing confirmed.

Plus the branch outcomes: blast-tier cap, unmet preconditions, applicability
filtering, and the verifier's cannot-reproduce / actively-disproved verdicts.
Zero-dependency: `python3 tests/test_loop.py`.
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import loop, ratelimit                            # noqa: E402
from harness.dispatch import Dispatcher                        # noqa: E402
from harness.loop import Loop, Pair                            # noqa: E402
from harness.store import blobstore, db, findings              # noqa: E402
from harness.substrate import contract                         # noqa: E402

CONTRACT = """
engagement:
  id: eng-loop-001
  authorized_by: test
  window: {{ start: 2026-11-08T20:00, end: 2026-11-08T23:59 }}
  max_blast_tier: {mbt}
scope:
  in_scope_cidrs: [10.10.0.0/24]
  out_of_scope: [10.10.0.9]
  allowed_ports: {{ default: [443, 80] }}
policy:
  rate: {{ max_rps_per_target: 1000, max_actions_per_run: 10000 }}
  tier3_techniques: []
"""

# --- synthetic KB cards --------------------------------------------------
SQLI = {
    "id": "KB-TEST-SQLI-001", "version": "1.0.0",
    "applicability": ['asset.type == "web_api"'],
    "preconditions": ["reachable"],
    "blast_tier": 1,
    "taxonomy": {"cwe": ["CWE-89"]},
    "severity_rubric": {"base": "high",
                        "cvss_base_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
    "success_signal": {"type": "status_match", "evaluator": "deterministic",
                       "assert": "error-based injection reflects a db fingerprint"},
    "probe_steps": [{"tool": "probe", "intent": "inject_error_payloads"}],
}
DESTRUCT = {  # tier 3, used only to prove the blast cap blocks before dispatch
    "id": "KB-TEST-DESTRUCT-001", "version": "1.0.0",
    "applicability": ['asset.type == "web_api"'],
    "preconditions": ["reachable"],
    "blast_tier": 3,
    "taxonomy": {"cwe": ["CWE-77"]},
    "severity_rubric": {"base": "critical", "cvss_base_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
    "success_signal": {"type": "oob", "evaluator": "deterministic", "assert": "callback"},
    "probe_steps": [{"tool": "probe", "intent": "destructive"}],
}
KB = {(c["id"], c["version"]): c for c in (SQLI, DESTRUCT)}

TM = {
    "web": {"asset.type": "web_api", "reachable": True, "addr": "10.10.0.5"},
    "db": {"asset.type": "web_api", "reachable": True, "addr": "10.10.0.6"},
}


# --- stubs ---------------------------------------------------------------
class Session:
    def __init__(self, sid):
        self.id = sid
        self.step = 0
        self.disproved = False
        self.pair = None


class StubSandbox:
    def __init__(self, proofs=True):
        self._proofs = proofs
        self.snaps = 0
        self.restores = []

    def proofs_pass(self):
        return self._proofs

    def snapshot(self):
        self.snaps += 1
        return f"snap-{self.snaps}"

    def restore(self, snap_id):
        self.restores.append(snap_id)


class ProbeAdapter:
    """Fires the deterministic success signal for the (target, technique) pairs
    seeded as vulnerable; everything else is a clean probe."""

    def __init__(self, hits):
        self.hits = set(hits)

    def run(self, req):
        hit = (req["target"], req["args"].get("technique")) in self.hits
        return {"status": "ok", "parsed": {"probed": req.get("intent")},
                "request_bytes": b"GET /probe HTTP/1.1",
                "response_bytes": b"HTTP/1.1 200 OK",
                "deterministic_signals": {"hit": hit, "confidence": 0.9 if hit else 0.0}}


class Planner:
    def __init__(self, pairs):
        self.pairs = pairs

    def plan(self, target_model, candidates, ledger_summary):
        return self.pairs


class Operator:
    """Proposes one probe per pair against the asset's recon address."""

    def __init__(self, sid, target_model, *, fail_on=(), target_override=None):
        self.sid = sid
        self.tm = target_model
        self.fail_on = set(fail_on)
        self.target_override = target_override

    def begin(self, pair):
        if pair.asset in self.fail_on:
            raise RuntimeError("operator killed mid-hunt")
        s = Session(self.sid)
        s.pair = pair
        return s

    def propose_next(self, session, card, observations):
        if self.target_override is not None:
            # a compromised operator (e.g. prompt-injected) keeps aiming off-scope
            return {"tool": "probe", "intent": "exfil", "target": self.target_override,
                    "port": 443, "args": {"technique": card["id"]}}
        if session.step >= 1:
            return None
        session.step += 1
        facts = self.tm.get(session.pair.asset, {})
        intent = (card.get("probe_steps") or [{}])[0].get("intent", "probe")
        return {"tool": "probe", "intent": intent, "target": facts.get("addr"),
                "port": 443, "args": {"technique": card["id"]}}


class Verifier:
    """Reproduces from the evidence trail: reads the lead's found probe_event and
    re-issues the same request on its own disjoint session."""

    def __init__(self, sid, conn, *, reproduce=True, disprove=False):
        self.sid = sid
        self.conn = conn
        self.reproduce = reproduce
        self.disprove = disprove

    def begin(self):
        s = Session(self.sid)
        s.disproved = self.disprove
        return s

    def propose_next(self, session, vinput, observations):
        if not self.reproduce or session.step >= 1:
            return None
        session.step += 1
        ev = vinput.get("evidence") or []
        if not ev:
            return None
        row = self.conn.execute(
            "SELECT target_asset, tool, tool_args FROM probe_event WHERE id=?",
            (ev[0],)).fetchone()
        if row is None:
            return None
        args = json.loads(row["tool_args"]) if row["tool_args"] else {}
        return {"tool": row["tool"], "intent": "reproduce",
                "target": row["target_asset"], "port": 443, "args": args}


# --- harness -------------------------------------------------------------
def _eng(mbt=2):
    eng, errs = contract.parse(CONTRACT.format(mbt=mbt))
    assert not errs, errs
    return eng


def _build(root, *, proofs=True, hits=(), mbt=2):
    conn = db.connect()
    blobs = blobstore.BlobStore(root)
    eng = _eng(mbt)
    disp = Dispatcher(conn, blobs, eng, {"probe": ProbeAdapter(hits)},
                      ratelimit.RateLimiter(1000, now=lambda: 0.0))
    return conn, eng, disp, StubSandbox(proofs)


def _pe_count(conn, target):
    return conn.execute("SELECT COUNT(*) AS c FROM probe_event WHERE target_asset=?",
                        (target,)).fetchone()["c"]


def _ledger_status(conn, eng, asset, tid):
    row = conn.execute(
        "SELECT status FROM coverage_ledger WHERE engagement_id=? AND asset=? AND technique_id=?",
        (eng.id, asset, tid)).fetchone()
    return row["status"] if row else None


# --- tests ---------------------------------------------------------------
def test_confirmed_run_ships_valid_report():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=[("10.10.0.5", "KB-TEST-SQLI-001")])
        lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                  planner=Planner([Pair("web", "KB-TEST-SQLI-001", "1.0.0")]),
                  operator=Operator("op-strong", TM),
                  verifier=Verifier("ver-disjoint", conn))
        res = lp.run(TM)
        assert res.mode == "sandboxed", res.mode
        assert res.valid, res.errors
        conf = findings.confirmed(conn, eng.id)
        assert len(conf) == 1, len(conf)
        assert conf[0]["found_by"] == "op-strong" and conf[0]["verified_by"] == "ver-disjoint"
        assert len(res.report["findings"]) == 1
        assert _ledger_status(conn, eng, "web", "KB-TEST-SQLI-001") == "confirmed"


def test_finder_is_not_verifier_refused_at_the_loop():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=[("10.10.0.5", "KB-TEST-SQLI-001")])
        lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                  planner=Planner([Pair("web", "KB-TEST-SQLI-001", "1.0.0")]),
                  operator=Operator("same-id", TM),
                  verifier=Verifier("same-id", conn))      # collides with found_by
        res = lp.run(TM)
        assert findings.confirmed(conn, eng.id) == []
        held = findings.leads(conn, eng.id)
        assert len(held) == 1 and held[0]["verdict"] == "needs_validation"
        assert res.valid, res.errors                       # 0 confirmed is a valid report
        assert _ledger_status(conn, eng, "web", "KB-TEST-SQLI-001") == "inconclusive"


def test_resume_from_ledger_reaches_same_confirmed_set():
    hits = [("10.10.0.5", "KB-TEST-SQLI-001"), ("10.10.0.6", "KB-TEST-SQLI-001")]
    pairs = [Pair("web", "KB-TEST-SQLI-001", "1.0.0"), Pair("db", "KB-TEST-SQLI-001", "1.0.0")]

    # uninterrupted baseline
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=hits)
        Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
             planner=Planner(pairs), operator=Operator("op", TM),
             verifier=Verifier("ver", conn)).run(TM)
        baseline = {r["asset"] for r in findings.confirmed(conn, eng.id)}
    assert baseline == {"web", "db"}, baseline

    # killed mid-hunt on the second pair, then resumed
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=hits)
        killed = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                      planner=Planner(pairs), operator=Operator("op", TM, fail_on=["db"]),
                      verifier=Verifier("ver", conn))
        try:
            killed.run(TM)
            raise AssertionError("expected the operator to raise mid-hunt")
        except RuntimeError:
            pass
        assert _ledger_status(conn, eng, "web", "KB-TEST-SQLI-001") == "lead"
        assert _ledger_status(conn, eng, "db", "KB-TEST-SQLI-001") is None   # never reached

        Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
             planner=Planner(pairs), operator=Operator("op", TM),
             verifier=Verifier("ver", conn)).run(TM)
        resumed = {r["asset"] for r in findings.confirmed(conn, eng.id)}
        assert resumed == baseline, resumed
        # web was not re-hunted on resume: exactly one confirmed finding per asset
        assert len(findings.confirmed(conn, eng.id)) == 2


def test_injected_out_of_scope_target_never_reaches_the_wire():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=[("10.10.0.9", "KB-TEST-SQLI-001")])
        # the operator (as if prompt-injected) keeps aiming at an out_of_scope host
        lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                  planner=Planner([Pair("web", "KB-TEST-SQLI-001", "1.0.0")]),
                  operator=Operator("op", TM, target_override="10.10.0.9"),
                  verifier=Verifier("ver", conn), max_denied=4)
        res = lp.run(TM)
        assert findings.leads(conn, eng.id) == []
        assert findings.confirmed(conn, eng.id) == []
        assert _pe_count(conn, "10.10.0.9") == 0            # denied before the adapter ran
        assert _ledger_status(conn, eng, "web", "KB-TEST-SQLI-001") == "inconclusive"
        assert res.valid, res.errors


def test_passive_only_holds_leads_and_ships_nothing_confirmed():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, proofs=False,
                                          hits=[("10.10.0.5", "KB-TEST-SQLI-001")])
        res = lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                        planner=Planner([Pair("web", "KB-TEST-SQLI-001", "1.0.0")]),
                        operator=Operator("op", TM), verifier=Verifier("ver", conn)).run(TM)
        assert res.mode == "passive-only", res.mode
        held = findings.leads(conn, eng.id)
        assert len(held) == 1 and all(r["verdict"] == "needs_validation" for r in held)
        assert findings.confirmed(conn, eng.id) == []
        assert res.report["findings"] == []
        assert res.valid, res.errors


def test_blast_tier_above_cap_blocked_before_dispatch():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, mbt=2)      # card is tier 3
        lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                  planner=Planner([Pair("web", "KB-TEST-DESTRUCT-001", "1.0.0")]),
                  operator=Operator("op", TM), verifier=Verifier("ver", conn))
        lp.run(TM)
        assert _ledger_status(conn, eng, "web", "KB-TEST-DESTRUCT-001") == "blocked_by_policy"
        assert _pe_count(conn, "10.10.0.5") == 0
        assert findings.leads(conn, eng.id) == []


def test_not_applicable_when_preconditions_unmet():
    tm = {"web": {"asset.type": "web_api", "reachable": False, "addr": "10.10.0.5"}}
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=[("10.10.0.5", "KB-TEST-SQLI-001")])
        lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                  planner=Planner([Pair("web", "KB-TEST-SQLI-001", "1.0.0")]),
                  operator=Operator("op", tm), verifier=Verifier("ver", conn))
        lp.run(tm)
        assert _ledger_status(conn, eng, "web", "KB-TEST-SQLI-001") == "not_applicable"
        assert _pe_count(conn, "10.10.0.5") == 0


def test_threat_model_filters_by_applicability():
    tm = {"web": {"asset.type": "web_api", "reachable": True},
          "cache": {"asset.type": "cache", "reachable": True}}
    cands = loop.phase_threat_model(tm, {("KB-TEST-SQLI-001", "1.0.0"): SQLI})
    got = {(p.asset, p.technique_id) for p in cands}
    assert got == {("web", "KB-TEST-SQLI-001")}, got


def test_verifier_cannot_reproduce_marks_inconclusive():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=[("10.10.0.5", "KB-TEST-SQLI-001")])
        lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                  planner=Planner([Pair("web", "KB-TEST-SQLI-001", "1.0.0")]),
                  operator=Operator("op", TM),
                  verifier=Verifier("ver", conn, reproduce=False))
        lp.run(TM)
        assert findings.confirmed(conn, eng.id) == []
        assert findings.leads(conn, eng.id) == []           # inconclusive is terminal, not a lead
        assert _ledger_status(conn, eng, "web", "KB-TEST-SQLI-001") == "inconclusive"


def test_verifier_actively_disproves_rejects():
    with tempfile.TemporaryDirectory() as root:
        conn, eng, disp, sandbox = _build(root, hits=[("10.10.0.5", "KB-TEST-SQLI-001")])
        lp = Loop(conn, eng, kb_index=KB, dispatcher=disp, sandbox=sandbox,
                  planner=Planner([Pair("web", "KB-TEST-SQLI-001", "1.0.0")]),
                  operator=Operator("op", TM),
                  verifier=Verifier("ver", conn, reproduce=False, disprove=True))
        lp.run(TM)
        assert findings.confirmed(conn, eng.id) == []
        assert _ledger_status(conn, eng, "web", "KB-TEST-SQLI-001") == "rejected"
        fid = conn.execute("SELECT id FROM finding WHERE engagement_id=?", (eng.id,)).fetchone()["id"]
        assert findings.current(conn, fid)["verdict"] == "rejected"


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
