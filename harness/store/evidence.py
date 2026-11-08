"""Probe-event evidence recorder (HC-DATA-01 §4.1, §10).

`dispatch()` calls `record_probe_event` exactly once per adapter run. Raw request
and response bytes go to the content-addressed blob store; the probe_event row
holds metadata plus a `content_hash` binding the row to its blob URIs, so a
swapped URI or a corrupted blob is caught by `verify_integrity`.
"""
import hashlib
import json
import uuid

from harness.store.db import now

_SEP = "\x1f"


def _content_hash(req_uri, resp_uri):
    return hashlib.sha256(_SEP.join([req_uri or "", resp_uri or ""]).encode("utf-8")).hexdigest()


def _as_bytes(v):
    if v is None:
        return None
    return v if isinstance(v, (bytes, bytearray)) else str(v).encode("utf-8")


def record_probe_event(conn, blobs, *, engagement_id, role, phase, snapshot_id,
                       technique_id, technique_version, tool, target_asset,
                       request_bytes, response_bytes=None, tool_args=None,
                       parsed=None, deterministic_signals=None,
                       provenance="live_engagement", split_bucket="test", ts=None):
    """Insert one immutable probe_event and return its id (`pe_<uuid>`)."""
    req_uri = blobs.put(_as_bytes(request_bytes) or b"")
    resp = _as_bytes(response_bytes)
    resp_uri = blobs.put(resp) if resp is not None else None
    content_hash = _content_hash(req_uri, resp_uri)
    pe_id = "pe_" + uuid.uuid4().hex
    with conn:
        conn.execute(
            """INSERT INTO probe_event (id, engagement_id, ts, provenance, split_bucket,
                   phase, role, target_asset, snapshot_id, technique_id, technique_version,
                   tool, tool_args, request_raw_uri, response_raw_uri, parsed,
                   deterministic_signals, content_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (pe_id, engagement_id, ts or now(), provenance, split_bucket, phase, role,
             target_asset, snapshot_id, technique_id, technique_version, tool,
             json.dumps(tool_args or {}, sort_keys=True), req_uri, resp_uri,
             json.dumps(parsed or {}, sort_keys=True),
             json.dumps(deterministic_signals or {}, sort_keys=True), content_hash))
    return pe_id


def get_raw(conn, blobs, probe_event_id):
    """Return {'request': bytes, 'response': bytes|None} or None if unknown."""
    row = conn.execute(
        "SELECT request_raw_uri, response_raw_uri FROM probe_event WHERE id=?",
        (probe_event_id,)).fetchone()
    if row is None:
        return None
    return {"request": blobs.get(row["request_raw_uri"]) if row["request_raw_uri"] else None,
            "response": blobs.get(row["response_raw_uri"]) if row["response_raw_uri"] else None}


def get_signals(conn, probe_event_id):
    """Return the probe_event's recorded deterministic_signals dict (or {}).

    The harness, not the Operator, reads these to triage a success signal
    (HC-AGENT-01 §7): the signal stays out of the role's context, so an injected
    instruction in a target response cannot forge a lead - only the adapter's
    observed signal, written here at record time, drives emission."""
    row = conn.execute(
        "SELECT deterministic_signals FROM probe_event WHERE id=?",
        (probe_event_id,)).fetchone()
    if row is None or not row["deterministic_signals"]:
        return {}
    return json.loads(row["deterministic_signals"])


def verify_integrity(conn, blobs, probe_event_id):
    """Return ('ok', None) or ('mismatch', detail)."""
    row = conn.execute(
        "SELECT request_raw_uri, response_raw_uri, content_hash FROM probe_event WHERE id=?",
        (probe_event_id,)).fetchone()
    if row is None:
        return "mismatch", "unknown probe_event"
    for uri in (row["request_raw_uri"], row["response_raw_uri"]):
        if uri and not blobs.verify(uri):
            return "mismatch", f"blob bytes do not match their hash: {uri}"
    if _content_hash(row["request_raw_uri"], row["response_raw_uri"]) != row["content_hash"]:
        return "mismatch", "content_hash does not match the recorded blob URIs"
    return "ok", None
