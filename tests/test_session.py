#!/usr/bin/env python3
"""Caller-supplied session threading and the model-spend cap (HC-AGENT-01 Slice C, HC-SUB-01).

The contract normalizes an optional authenticated session into request headers and bounds a
run's model spend; an adapter attaches that session to every request (a per-call header still
wins); and the auth-gated practice route answers only when the session is presented. The
credential stays off the target model. Pure unit tests: no Docker, no network, no models.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "infra", "sandbox"))

from harness import recon
from harness.sandbox.adapters import _Adapter
from harness.substrate import contract
from harness.substrate.contract import _DEFAULT_MODEL_BUDGET

import noteapp  # the practice target (infra/sandbox on the path)

_BASE = """engagement:
  id: eng-sc-001
  authorized_by: brent / TICKET-1
  window: { start: 2026-11-10T20:00, end: 2026-11-10T23:59 }
  max_blast_tier: 2
%s
scope:
  in_scope_hosts: [t1.sandbox.local]
  in_scope_cidrs: [10.90.0.0/24]
  allowed_ports: { default: [80, 8080] }
policy: { allowed_tactics: [recon], rate: { max_actions_per_run: 100 } }
"""


def _eng(extra=""):
    e, errs = contract.parse(_BASE % extra)
    assert not errs, errs
    return e


# --- contract: session normalization -----------------------------------------

def test_no_session_is_none_and_budget_defaults():
    e = _eng()
    assert e.session_headers is None
    assert e.model_budget == _DEFAULT_MODEL_BUDGET


def test_bearer_becomes_an_authorization_header():
    e = _eng("  session: { bearer: abc.def }")
    assert e.session_headers == {"Authorization": "Bearer abc.def"}


def test_cookie_and_extra_headers_merge():
    e = _eng("  session: { cookie: 'sid=xyz', headers: { X-Actor: ops } }")
    assert e.session_headers == {"Cookie": "sid=xyz", "X-Actor": "ops"}


def test_model_budget_parses_and_rejects_bad_values():
    assert _eng("  model_budget: 50000").model_budget == 50000
    _, errs = contract.parse(_BASE % "  model_budget: -1")
    assert any("model_budget" in x for x in errs)


def test_bad_session_shape_is_rejected():
    _, errs = contract.parse(_BASE % "  session: { bearer: 5 }")
    assert any("session.bearer" in x for x in errs)


def test_session_token_stays_out_of_the_target_model():
    # the credential rides on the engagement, never on a recon fact the report/logs serialize
    e = _eng("  session: { bearer: s3cr3t-token }")
    surface = {"endpoints": [{"path": "/notes", "method": "GET", "params": ["tag"]}]}
    model = recon.project_surface(surface, "t1.sandbox.local", "10.90.0.4", 8080)
    blob = repr(model)
    assert "s3cr3t-token" not in blob and "Authorization" not in blob


# --- adapter: the session rides on every request ------------------------------

class _Capture:
    def __init__(self):
        self.argv = None

    def __call__(self, cmd, input=None):
        self.argv = cmd
        class _R:
            out = "200\n\n"
        return _R()


def test_adapter_attaches_the_session_header():
    cap = _Capture()
    a = _Adapter("att", {"t1": "10.90.0.4"}, run=cap,
                 session_headers={"Authorization": "Bearer tok"})
    a._send_http("http://10.90.0.4:8080/vault/notes?tag=1")
    assert '"Authorization": "Bearer tok"' in cap.argv[-1]   # headers JSON is the last argv


def test_no_session_sends_no_header_arg():
    cap = _Capture()
    _Adapter("att", {}, run=cap)._send_http("http://10.90.0.4/x")
    assert cap.argv[-1] == "http://10.90.0.4/x" or "Authorization" not in cap.argv[-1]


def test_per_call_header_overrides_the_session():
    a = _Adapter("att", {}, run=_Capture(),
                 session_headers={"Authorization": "Bearer base"})
    merged = a._merge_headers({"Authorization": "Bearer forged"})
    assert merged["Authorization"] == "Bearer forged"       # a forged JWT still wins


# --- the auth-gated practice route --------------------------------------------

def test_practice_route_requires_the_session():
    assert noteapp._authorized("Bearer " + noteapp._SESSION_TOKEN) is True
    assert noteapp._authorized(None) is False
    assert noteapp._authorized("Bearer wrong") is False


def test_practice_route_is_boolean_sqli_behind_the_gate():
    # the same oracle the SQLi adapter detects: a true vs false condition changes the rows
    true_rows = noteapp._notes_query("1 OR 1=1")
    false_rows = noteapp._notes_query("1 AND 1=2")
    assert true_rows != false_rows and "groceries" in true_rows


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
