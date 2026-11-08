#!/usr/bin/env python3
"""Adversarial tests for the propose-and-dispose chokepoint (HC-AGENT-01 §5.2, §11).

Proves the four guards run in order and short-circuit, that a denial is data and
records no probe_event, that a pass records exactly one probe_event plus one
audit row and preserves the audit chain, and that evidence is content-addressed
and integrity-checkable. Zero-dependency: `python3 tests/test_dispatch.py`.
"""
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import dispatch, ratelimit                     # noqa: E402
from harness.dispatch import Dispatcher, ProbeContext       # noqa: E402
from harness.store import audit, blobstore, db, evidence    # noqa: E402
from harness.substrate import contract                      # noqa: E402

CONTRACT = """
engagement:
  id: eng-test-001
  authorized_by: test
  window: { start: 2026-11-08T20:00, end: 2026-11-08T23:59 }
  max_blast_tier: 2
scope:
  in_scope_cidrs: [10.10.0.0/24]
  out_of_scope: [10.10.0.9]
  allowed_ports: { default: [443, 80] }
policy:
  rate: { max_rps_per_target: 2, max_actions_per_run: 100 }
  tier3_techniques: []
"""


class StubAdapter:
    def __init__(self):
        self.calls = 0

    def run(self, req):
        self.calls += 1
        return {"status": "ok", "parsed": {"echo": req.get("intent")},
                "request_bytes": b"GET /x HTTP/1.1", "response_bytes": b"HTTP/1.1 200 OK",
                "deterministic_signals": {"canary": True}}


class BoomAdapter:
    def run(self, req):
        raise RuntimeError("secret internal failure detail")


def _eng():
    eng, errs = contract.parse(CONTRACT)
    assert not errs, errs
    return eng


def _dispatcher(root, *, rate=None, adapter=None):
    conn = db.connect()
    blobs = blobstore.BlobStore(root)
    adapters = {"httpx": adapter if adapter is not None else StubAdapter()}
    rate = rate or ratelimit.RateLimiter(1000, now=lambda: 0.0)   # frozen, effectively open
    return Dispatcher(conn, blobs, _eng(), adapters, rate), conn, blobs, adapters["httpx"]


def _ctx(tier=0, has_snapshot=False, role="operator"):
    return ProbeContext(pair_asset="10.10.0.5", technique_id="KB-WEB-INJ-SQLI-001",
                        technique_version="1.0.0", blast_tier=tier, role=role,
                        has_snapshot=has_snapshot)


def _req(target="10.10.0.5", port=443, tool="httpx"):
    return {"tool": tool, "intent": "probe", "target": target, "port": port, "args": {"path": "/x"}}


def _n_events(conn):
    return conn.execute("SELECT COUNT(*) AS c FROM probe_event").fetchone()["c"]


def _decisions(conn):
    return [r["decision"] for r in conn.execute("SELECT decision FROM audit_log ORDER BY seq")]


# --- guard short-circuit + denial is data --------------------------------
def test_malformed_request_denied():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, ad = _dispatcher(root)
        out = d.dispatch({"tool": "httpx", "intent": "x"}, _ctx())   # no target/port
        assert out == dispatch.deny("malformed_request")
        assert ad.calls == 0 and _n_events(conn) == 0


def test_unknown_tool_denied():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, ad = _dispatcher(root)
        out = d.dispatch(_req(tool="nmap"), _ctx())
        assert out == dispatch.deny("unknown_tool")
        assert ad.calls == 0 and _n_events(conn) == 0
        assert _decisions(conn) == ["unknown_tool"]


def test_out_of_scope_denied_and_records_no_probe_event():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, ad = _dispatcher(root)
        out = d.dispatch(_req(target="10.10.0.9"), _ctx())   # explicitly out_of_scope
        assert out == dispatch.deny("out_of_scope")
        assert ad.calls == 0 and _n_events(conn) == 0
        assert _decisions(conn) == ["out_of_scope"]


def test_not_in_scope_target_denied():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, _ = _dispatcher(root)
        assert d.dispatch(_req(target="10.20.0.1"), _ctx()) == dispatch.deny("out_of_scope")
        assert d.dispatch(_req(port=22), _ctx()) == dispatch.deny("out_of_scope")  # port not allowed


def test_scope_checked_before_blast():
    # A request that is BOTH out_of_scope AND blast-violating returns out_of_scope,
    # proving guard order (scope #2 before blast #3).
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, _ = _dispatcher(root)
        out = d.dispatch(_req(target="10.10.0.9"), _ctx(tier=3, has_snapshot=False))
        assert out == dispatch.deny("out_of_scope")


def test_blast_denied_without_snapshot():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, ad = _dispatcher(root)
        out = d.dispatch(_req(), _ctx(tier=2, has_snapshot=False))
        assert out == dispatch.deny("blast_denied")
        assert ad.calls == 0 and _n_events(conn) == 0


def test_blast_allowed_with_snapshot():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, ad = _dispatcher(root)
        out = d.dispatch(_req(), _ctx(tier=2, has_snapshot=True))
        assert out["disposition"] == "allow" and ad.calls == 1


def test_tier_above_cap_blocked():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, _ = _dispatcher(root)
        assert d.dispatch(_req(), _ctx(tier=3, has_snapshot=True)) == dispatch.deny("blast_denied")


# --- rate / budget (guard 4) ---------------------------------------------
def test_rate_limited_per_target():
    with tempfile.TemporaryDirectory() as root:
        rate = ratelimit.RateLimiter(1, burst=1, now=lambda: 0.0)   # 1 token, frozen clock
        d, conn, _, ad = _dispatcher(root, rate=rate)
        assert d.dispatch(_req(), _ctx())["disposition"] == "allow"
        assert d.dispatch(_req(), _ctx()) == dispatch.deny("rate_limited")
        assert ad.calls == 1 and _n_events(conn) == 1
        assert _decisions(conn) == ["exec", "rate_limited"]


def test_rate_refills_over_time():
    clock = {"t": 0.0}
    with tempfile.TemporaryDirectory() as root:
        rate = ratelimit.RateLimiter(1, burst=1, now=lambda: clock["t"])
        d, _, _, _ = _dispatcher(root, rate=rate)
        assert d.dispatch(_req(), _ctx())["disposition"] == "allow"
        assert d.dispatch(_req(), _ctx()) == dispatch.deny("rate_limited")
        clock["t"] = 1.0                                   # one second -> one token back
        assert d.dispatch(_req(), _ctx())["disposition"] == "allow"


def test_run_budget_exhausted():
    with tempfile.TemporaryDirectory() as root:
        rate = ratelimit.RateLimiter(1000, max_actions_per_run=1, now=lambda: 0.0)
        d, _, _, _ = _dispatcher(root, rate=rate)
        assert d.dispatch(_req(), _ctx())["disposition"] == "allow"
        assert d.dispatch(_req(), _ctx()) == dispatch.deny("budget_exhausted")


# --- the happy path: evidence + audit ------------------------------------
def test_pass_records_one_event_and_audit_chain_holds():
    with tempfile.TemporaryDirectory() as root:
        d, conn, blobs, ad = _dispatcher(root)
        out = d.dispatch(_req(), _ctx())
        assert out["disposition"] == "allow" and out["status"] == "ok"
        assert out["parsed"] == {"echo": "probe"}
        assert out["probe_event_id"] and out["evidence_uri"] == f"probe://{out['probe_event_id']}"
        assert _n_events(conn) == 1 and ad.calls == 1
        row = conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
        assert len(row) == 1 and row[0]["decision"] == "exec"
        assert row[0]["correlation_id"] == out["probe_event_id"]
        assert audit.verify_chain(conn) == ("ok", None)
        raw = evidence.get_raw(conn, blobs, out["probe_event_id"])
        assert raw["request"] == b"GET /x HTTP/1.1" and raw["response"] == b"HTTP/1.1 200 OK"
        assert evidence.verify_integrity(conn, blobs, out["probe_event_id"]) == ("ok", None)


def test_audit_chain_spans_denials_and_execs():
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, _ = _dispatcher(root)
        d.dispatch(_req(target="10.10.0.9"), _ctx())   # deny
        d.dispatch(_req(), _ctx())                     # exec
        d.dispatch(_req(tool="nmap"), _ctx())          # deny
        assert _decisions(conn) == ["out_of_scope", "exec", "unknown_tool"]
        assert audit.verify_chain(conn) == ("ok", None)


# --- adapter errors are observations, not user-facing failures (§9) -------
def test_adapter_error_recorded_without_leaking_detail():
    with tempfile.TemporaryDirectory() as root:
        d, conn, blobs, _ = _dispatcher(root, adapter=BoomAdapter())
        out = d.dispatch(_req(), _ctx())
        assert out["disposition"] == "allow" and out["status"] == "error"
        assert out["parsed"] == {"error": "adapter_error"}   # no raw exception text
        assert "secret internal failure detail" not in str(out)
        assert _n_events(conn) == 1                           # still recorded as evidence
        raw = evidence.get_raw(conn, blobs, out["probe_event_id"])
        assert b"secret internal failure detail" in raw["response"]   # kept server-side only


# --- injection posture (acceptance §206) ---------------------------------
def test_injected_instruction_cannot_widen_scope():
    # Whatever a target response "tells" the role, the role still only emits a
    # structured request, and dispatch re-validates scope: a new out-of-scope
    # target is denied regardless.
    with tempfile.TemporaryDirectory() as root:
        d, conn, _, _ = _dispatcher(root)
        assert d.dispatch(_req(target="8.8.8.8"), _ctx()) == dispatch.deny("out_of_scope")
        assert _n_events(conn) == 0


# --- blob store properties -----------------------------------------------
def test_blob_dedup_and_integrity():
    with tempfile.TemporaryDirectory() as root:
        blobs = blobstore.BlobStore(root)
        u1 = blobs.put(b"same bytes")
        u2 = blobs.put(b"same bytes")
        assert u1 == u2 and blobs.get(u1) == b"same bytes" and blobs.verify(u1)
        files = [f for _, _, fs in os.walk(root) for f in fs]
        assert len(files) == 1                               # deduplicated to one object


def test_evidence_integrity_detects_blob_tamper():
    with tempfile.TemporaryDirectory() as root:
        d, conn, blobs, _ = _dispatcher(root)
        out = d.dispatch(_req(), _ctx())
        pe = out["probe_event_id"]
        uri = conn.execute("SELECT response_raw_uri AS u FROM probe_event WHERE id=?",
                           (pe,)).fetchone()["u"]
        path = blobs._path(blobs._digest(uri))
        os.chmod(path, 0o644)
        with open(path, "wb") as f:                          # storage-level tampering
            f.write(b"tampered")
        verdict, _ = evidence.verify_integrity(conn, blobs, pe)
        assert verdict == "mismatch"


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
