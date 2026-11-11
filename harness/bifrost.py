"""Live Bifrost transport (HC-MODEL-01), the HTTP client behind the model plane.

The model plane (`harness/modelplane.py`) is policy over an injected `transport`;
this is the real transport, a thin standard-library HTTP client to a running
Bifrost gateway. It is the only holder of credentials: the plane passes the role's
virtual key name, and the client resolves it to the Bifrost secret and presents it,
so no role ever holds a provider key. Everything here is `urllib`, no third-party
dependency; the live gateway is out of repo, and `tests/test_bifrost.py` drives
this client against an in-process stdlib mock so the wire contract stays CI-green.

Bifrost speaks the OpenAI chat-completions shape. The plane resolves a provider
route and its own fallback order (so the Verifier's pin is enforced in the harness,
not left to the gateway), and this client issues one request per route: a provider
outage (a 502/503/504 or an unreachable gateway) maps to `ProviderDown` so the
plane falls back, and so does a 402, flagged `out_of_credit`: the provider account
cannot pay for the call, which is an operating condition the role stops on, not a
harness bug. Any other 4xx or a malformed body is a `BifrostError` that fails loud
rather than being mistaken for an outage.
"""
import json
import time
import urllib.error
import urllib.request

from harness.modelplane import ProviderDown

_OUTAGE_STATUS = frozenset({502, 503, 504})
_OUT_OF_CREDIT_STATUS = 402     # Payment Required: the provider account has no credit left


class BifrostError(Exception):
    """A non-outage failure: a bad request, auth, or a malformed completion. Unlike
    ProviderDown it is not a fallback trigger; it surfaces as a hard error."""


class Response:
    __slots__ = ("text", "model", "tokens_in", "tokens_out", "latency_ms")

    def __init__(self, text, model, tokens_in, tokens_out, latency_ms):
        self.text = text
        self.model = model
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.latency_ms = latency_ms


class BifrostTransport:
    def __init__(self, base_url, vkey_secrets, *, timeout=30.0, clock=time.monotonic):
        self.base_url = base_url.rstrip("/")
        self.vkey_secrets = dict(vkey_secrets)   # vkey name -> Bifrost secret (held here only)
        self.timeout = timeout
        self._clock = clock

    def complete(self, provider, messages, metadata):
        """Serve one turn for the plane: POST the messages to Bifrost on `provider`'s
        route under the role's virtual key. Returns a Response or raises ProviderDown
        (outage, so the plane falls back) / BifrostError (a hard failure)."""
        vkey = (metadata or {}).get("vkey")
        secret = self.vkey_secrets.get(vkey)
        if secret is None:
            raise BifrostError(f"no Bifrost secret for virtual key {vkey!r}")

        body = json.dumps({"model": provider, "messages": messages}).encode("utf-8")
        headers = {"Authorization": f"Bearer {secret}", "Content-Type": "application/json",
                   "X-Correlation-Id": str((metadata or {}).get("correlation_id") or "")}
        req = urllib.request.Request(self.base_url + "/v1/chat/completions",
                                     data=body, headers=headers, method="POST")
        started = self._clock()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:         # a response with a non-2xx status
            if e.code in _OUTAGE_STATUS:
                raise ProviderDown(provider)
            if e.code == _OUT_OF_CREDIT_STATUS:
                raise ProviderDown(provider, reason="out_of_credit")
            raise BifrostError(f"bifrost returned status {e.code}")
        except (urllib.error.URLError, TimeoutError):   # unreachable, DNS, timeout: an outage
            raise ProviderDown(provider)
        latency_ms = int((self._clock() - started) * 1000)
        return self._parse(provider, raw, latency_ms)

    @staticmethod
    def _parse(provider, raw, latency_ms):
        try:
            data = json.loads(raw)
            text = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise BifrostError("malformed completion from bifrost")
        usage = data.get("usage") or {}
        return Response(text=text, model=data.get("model", provider),
                        tokens_in=int(usage.get("prompt_tokens", 0)),
                        tokens_out=int(usage.get("completion_tokens", 0)),
                        latency_ms=latency_ms)
