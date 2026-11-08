"""Tamper-evident audit log (HC-SAFE-01 §3, §9).

Every row carries prev_hash (the previous row's hash) and row_hash (a hash of
this row's content plus prev_hash), forming a chain. verify_chain recomputes it
and reports the first row that does not line up, so an altered or removed row is
detected even though the append-only triggers already forbid UPDATE/DELETE.
The content hash excludes the autoincrement seq, so no post-insert update is
needed to form the chain.
"""
import hashlib
import json

from harness.store.db import now

GENESIS = "GENESIS"
_SEP = "\x1f"


def _row_hash(content, prev_hash):
    parts = ["" if v is None else str(v) for v in content] + [prev_hash]
    return hashlib.sha256(_SEP.join(parts).encode("utf-8")).hexdigest()


def _content(ts, engagement_id, actor, category, decision, reason, correlation_id, detail):
    return (ts, engagement_id, actor, category, decision, reason, correlation_id, detail)


def record(conn, engagement_id, actor, category, decision=None, reason=None,
           correlation_id=None, detail=None, ts=None):
    ts = ts or now()
    detail_s = json.dumps(detail or {}, sort_keys=True)
    with conn:
        prev = conn.execute(
            "SELECT row_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = prev["row_hash"] if prev else GENESIS
        content = _content(ts, engagement_id, actor, category, decision, reason,
                           correlation_id, detail_s)
        rh = _row_hash(content, prev_hash)
        conn.execute(
            """INSERT INTO audit_log (ts, engagement_id, actor, category, decision,
                   reason, correlation_id, detail, prev_hash, row_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            content + (prev_hash, rh))
    return rh


def verify_chain(conn, engagement_id=None):
    """Return ('ok', None) or ('tamper', seq) for the first broken row.

    The chain is global; engagement_id is accepted for API parity (HC-SAFE-01
    §9) and does not change the integrity check."""
    rows = conn.execute("SELECT * FROM audit_log ORDER BY seq").fetchall()
    prev_hash = GENESIS
    for r in rows:
        content = _content(r["ts"], r["engagement_id"], r["actor"], r["category"],
                           r["decision"], r["reason"], r["correlation_id"], r["detail"])
        if r["prev_hash"] != prev_hash or r["row_hash"] != _row_hash(content, r["prev_hash"]):
            return "tamper", r["seq"]
        prev_hash = r["row_hash"]
    return "ok", None
