"""Propose-and-dispose chokepoint (HC-AGENT-01 §5.2).

Every action a role proposes reaches the sandbox only through `dispatch()`. It
runs the four guards in order - unknown_tool, out_of_scope, blast_denied, then
the per-target rate / run budget - and short-circuits on the first failure with
a structured denial the role must handle (a denial is data, not an error). On
pass it runs the adapter on the attacker VM, records exactly one probe_event
with raw I/O (HC-DATA-01), writes an audit row (HC-SAFE-01), and returns the
normalized result. This software check is defense in depth; the HC-SUB-01
no-route gateway remains the real enforcement, so even a dispatch bug cannot put
out-of-scope traffic on the wire.
"""
from harness.store import audit, evidence
from harness.substrate.blast import blast_gate
from harness.mobile.protocol import MOBILE_TOOL
from harness.substrate.scope import scope_validate

# The adapter allowlist a deployment registers; an unknown tool is denied (§5.3).
# A new capability is a new reviewed adapter, never a general exec primitive.
_REQUIRED = ("tool", "target", "port")


class ProbeContext:
    """Ambient context for one role session on one (asset, technique) pair."""

    def __init__(self, *, pair_asset, technique_id, technique_version, blast_tier,
                 role, phase="hunting", snapshot_id="golden", has_snapshot=False):
        self.pair_asset = pair_asset
        self.technique_id = technique_id
        self.technique_version = technique_version
        self.blast_tier = blast_tier
        self.role = role
        self.phase = phase
        self.snapshot_id = snapshot_id
        self.has_snapshot = has_snapshot


def deny(reason):
    return {"disposition": "deny", "reason": reason}


def _malformed(req):
    if not isinstance(req, dict):
        return "request must be a structured object"
    for k in _REQUIRED:
        if req.get(k) in (None, ""):
            return f"request.{k} is required"
    if not isinstance(req.get("args", {}), dict):
        return "request.args must be an object"
    return None


class Dispatcher:
    def __init__(self, conn, blobs, eng, adapters, rate, *, audit_actor="harness",
                 provenance="live_engagement", split_bucket="test"):
        self.conn = conn
        self.blobs = blobs
        self.eng = eng
        self.adapters = adapters
        self.rate = rate
        self.audit_actor = audit_actor
        self.provenance = provenance
        self.split_bucket = split_bucket

    def _audit(self, ctx, category, decision, reason=None, correlation_id=None, req=None):
        detail = {}
        if isinstance(req, dict):
            detail = {"tool": req.get("tool"), "target": req.get("target"),
                      "port": req.get("port"), "intent": req.get("intent"),
                      "asset": ctx.pair_asset, "technique": ctx.technique_id}
        audit.record(self.conn, self.eng.id, ctx.role, category, decision=decision,
                     reason=reason, correlation_id=correlation_id, detail=detail)

    def dispatch(self, req, ctx):
        """Dispose of one proposed request. Returns a denial or a normalized result."""
        bad = _malformed(req)
        if bad:
            self._audit(ctx, "dispatch_denial", "malformed_request", reason=bad,
                        req=req if isinstance(req, dict) else None)
            return deny("malformed_request")

        # guard 1: unknown tool
        if req["tool"] not in self.adapters:
            self._audit(ctx, "dispatch_denial", "unknown_tool", reason=req["tool"], req=req)
            return deny("unknown_tool")

        # guard 2: scope (HC-SUB-01 §5.3) - out_of_scope wins, unpinned host denied
        adapter = self.adapters[req["tool"]]
        kind = "mobile" if req["tool"] == MOBILE_TOOL else "network"
        verdict, reason = scope_validate(self.eng, req["target"], req["port"], kind=kind)
        if verdict != "allow":
            self._audit(ctx, "dispatch_denial", "out_of_scope", reason=reason, req=req)
            return deny("out_of_scope")

        # guard 3: blast tier (HC-SUB-01 §7) - cap, snapshot for tier>=2, tier-3 authz
        verdict, reason = blast_gate(self.eng, ctx.blast_tier, ctx.has_snapshot,
                                     ctx.technique_id)
        if verdict != "allow":
            self._audit(ctx, "dispatch_denial", "blast_denied", reason=reason, req=req)
            return deny("blast_denied")

        # guard 4: per-target rate + run budget (may trip the watchdog upstream)
        verdict, reason = self.rate.check(req["target"])
        if verdict != "allow":
            self._audit(ctx, "dispatch_denial", reason, reason=reason, req=req)
            return deny(reason)

        # dispose: execute on the attacker VM. An adapter error is an observation
        # the role adapts to (§9), never a user-facing failure; the detail is kept
        # in the probe_event, not surfaced in the normalized result.
        try:
            raw = adapter.run(req) if hasattr(adapter, "run") else adapter(req)
            status = raw.get("status", "ok")
            parsed = raw.get("parsed", {})
            request_bytes = raw.get("request_bytes", b"")
            response_bytes = raw.get("response_bytes")
            signals = raw.get("deterministic_signals", {})
        except Exception as ex:  # noqa: BLE001 - recorded, not propagated
            status, parsed, signals = "error", {"error": "adapter_error"}, {}
            request_bytes = repr(req).encode("utf-8")
            response_bytes = repr(ex).encode("utf-8")

        pe_id = evidence.record_probe_event(
            self.conn, self.blobs, engagement_id=self.eng.id, role=ctx.role,
            phase=ctx.phase, snapshot_id=ctx.snapshot_id, technique_id=ctx.technique_id,
            technique_version=ctx.technique_version, tool=req["tool"],
            target_asset=req["target"], request_bytes=request_bytes,
            response_bytes=response_bytes, tool_args=req.get("args", {}), parsed=parsed,
            deterministic_signals=signals, provenance=self.provenance,
            split_bucket=self.split_bucket)
        self._audit(ctx, "dispatch_exec", "exec", correlation_id=pe_id, req=req)
        return {"disposition": "allow", "status": status, "parsed": parsed,
                "evidence_uri": f"probe://{pe_id}", "probe_event_id": pe_id}
