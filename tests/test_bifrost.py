#!/usr/bin/env python3
"""Tests for the live Bifrost transport (HC-MODEL-01).

Drives the real standard-library HTTP client against an in-process mock Bifrost
(stdlib http.server), so the wire contract is exercised end to end without a live
gateway and stays CI-green and zero-dependency. Proves:

  - a role's virtual key is resolved to its secret and presented as the bearer
    token, and the correlation id is forwarded, so no role holds a key;
  - an OpenAI-shaped completion is parsed into text, model, and token counts;
  - a provider outage (502/503/504 or an unreachable gateway) maps to ProviderDown
    so the plane falls back, a 402 (the provider account is out of credit) is a
    ProviderDown that says so, and any other 4xx or a malformed body is a hard
    BifrostError;
  - the transport plugs into the real ModelPlane and serves a call end to end.

Zero-dependency: `python3 tests/test_bifrost.py`.
"""
import http.server
import json
import os
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.bifrost import BifrostError, BifrostTransport                 # noqa: E402
from harness.modelplane import (ModelPlane, PlaneStop, ProviderDown,       # noqa: E402
                                VirtualKey)
from harness.store import db                                              # noqa: E402

MSGS = [{"role": "system", "content": "probe"}, {"role": "user", "content": "data"}]


def _ok_body(text="the completion", model="openai/strong", tin=11, tout=22):
    return {"model": model, "choices": [{"message": {"role": "assistant", "content": text}}],
            "usage": {"prompt_tokens": tin, "completion_tokens": tout}}


class _Server(http.server.HTTPServer):
    responder = None          # body(dict) -> (status, payload dict)
    last = None               # the last received request, for assertions


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.last = {"path": self.path, "auth": self.headers.get("Authorization"),
                            "corr": self.headers.get("X-Correlation-Id"), "body": body}
        status, payload = self.server.responder(body)
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass                  # keep the test output clean


def _serve(responder):
    srv = _Server(("127.0.0.1", 0), _Handler)
    srv.responder = responder
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


SECRETS = {"vk-operator": "secret-op", "vk-verifier": "secret-ver"}


# --- auth, forwarding, parsing -------------------------------------------
def test_presents_the_vkey_secret_and_forwards_the_correlation_id():
    srv, base = _serve(lambda body: (200, _ok_body()))
    try:
        tx = BifrostTransport(base, SECRETS)
        resp = tx.complete("openai/strong", MSGS,
                           {"vkey": "vk-operator", "correlation_id": "probe://pe-3"})
        assert resp.text == "the completion" and resp.model == "openai/strong"
        assert resp.tokens_in == 11 and resp.tokens_out == 22
        assert resp.latency_ms >= 0
        assert srv.last["auth"] == "Bearer secret-op"      # the role's key, resolved here
        assert srv.last["corr"] == "probe://pe-3"
        assert srv.last["path"] == "/v1/chat/completions"
        assert srv.last["body"]["model"] == "openai/strong"
    finally:
        srv.shutdown()


def test_each_role_presents_its_own_disjoint_key():
    srv, base = _serve(lambda body: (200, _ok_body()))
    try:
        tx = BifrostTransport(base, SECRETS)
        tx.complete("openai/strong", MSGS, {"vkey": "vk-verifier"})
        assert srv.last["auth"] == "Bearer secret-ver"
    finally:
        srv.shutdown()


def test_an_unknown_vkey_is_a_hard_error_not_an_outage():
    srv, base = _serve(lambda body: (200, _ok_body()))
    try:
        tx = BifrostTransport(base, SECRETS)
        try:
            tx.complete("openai/strong", MSGS, {"vkey": "vk-ghost"})
            raise AssertionError("expected a BifrostError for an unknown vkey")
        except BifrostError:
            pass
        assert srv.last is None                            # nothing was sent
    finally:
        srv.shutdown()


# --- outage vs hard error (§10 fallback) ---------------------------------
def test_a_provider_outage_maps_to_provider_down():
    for status in (502, 503, 504):
        srv, base = _serve(lambda body, s=status: (s, {"error": "upstream"}))
        try:
            tx = BifrostTransport(base, SECRETS)
            try:
                tx.complete("openai/strong", MSGS, {"vkey": "vk-operator"})
                raise AssertionError(f"expected ProviderDown for {status}")
            except ProviderDown:
                pass
        finally:
            srv.shutdown()


def test_an_unreachable_gateway_maps_to_provider_down():
    srv, base = _serve(lambda body: (200, _ok_body()))
    srv.shutdown()
    srv.server_close()                                     # release the port, then call it
    tx = BifrostTransport(base, SECRETS, timeout=2.0)
    try:
        tx.complete("openai/strong", MSGS, {"vkey": "vk-operator"})
        raise AssertionError("expected ProviderDown for an unreachable gateway")
    except ProviderDown:
        pass


def test_a_bad_request_is_a_hard_error():
    srv, base = _serve(lambda body: (400, {"error": "bad request"}))
    try:
        tx = BifrostTransport(base, SECRETS)
        try:
            tx.complete("openai/strong", MSGS, {"vkey": "vk-operator"})
            raise AssertionError("expected a BifrostError for a 400")
        except BifrostError:
            pass
    finally:
        srv.shutdown()


def test_a_malformed_completion_is_a_hard_error():
    srv, base = _serve(lambda body: (200, {"not": "an openai shape"}))
    try:
        tx = BifrostTransport(base, SECRETS)
        try:
            tx.complete("openai/strong", MSGS, {"vkey": "vk-operator"})
            raise AssertionError("expected a BifrostError for a malformed body")
        except BifrostError:
            pass
    finally:
        srv.shutdown()


def test_an_out_of_credit_provider_maps_to_provider_down_not_a_hard_error():
    srv, base = _serve(lambda body: (402, {"error": {"message": "Insufficient Balance"}}))
    try:
        tx = BifrostTransport(base, SECRETS)
        try:
            tx.complete("openai/strong", MSGS, {"vkey": "vk-operator"})
            raise AssertionError("expected ProviderDown for a 402")
        except ProviderDown as down:
            assert down.reason == "out_of_credit", down.reason
    finally:
        srv.shutdown()


# --- end to end through the plane ----------------------------------------
def test_plugs_into_the_model_plane_end_to_end():
    captured = {}

    def responder(body):
        captured["auth_body"] = body
        return 200, _ok_body(text="ranked plan")

    srv, base = _serve(responder)
    try:
        conn = db.connect()
        tx = BifrostTransport(base, SECRETS)
        plane = ModelPlane([VirtualKey("operator", ["openai/strong"], cache=False),
                            VirtualKey("verifier", ["anthropic/strong"], cache=False)],
                           tx, conn, "eng-bifrost")
        comp = plane.call("operator", MSGS, {"correlation_id": "c1"})
        assert comp.text == "ranked plan" and comp.provider == "openai/strong"
        assert comp.tokens_in == 11 and comp.cost == 33   # 11 + 22, charged by the plane
        assert srv.last["auth"] == "Bearer secret-op"     # the plane handed over vk-operator
        assert captured["auth_body"]["model"] == "openai/strong"
    finally:
        srv.shutdown()


def test_an_out_of_credit_verifier_stops_the_role_instead_of_crashing_the_run():
    # Regression: a 402 from the verifier's provider escaped as a hard BifrostError
    # and aborted the whole engagement at its first verification.
    srv, base = _serve(lambda body: (402, {"error": {"message": "requires more credits"}}))
    try:
        plane = ModelPlane([VirtualKey("operator", ["openai/strong"], cache=False),
                            VirtualKey("verifier", ["anthropic/strong"], cache=False,
                                       fallback="none")],
                           BifrostTransport(base, SECRETS), db.connect(), "eng-credit")
        try:
            plane.call("verifier", MSGS, {"correlation_id": "c1"})
            raise AssertionError("expected the verifier to stop")
        except PlaneStop as stop:
            assert stop.reason == "provider_out_of_credit", stop.reason
        assert plane.stops == {("verifier", "provider_out_of_credit"): 1}, plane.stops
    finally:
        srv.shutdown()


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
