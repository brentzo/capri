"""Coverage ledger (HC-DATA-01 §4.4, §10).

Drives the loop (HC-AGENT-01 §4) and the report coverage summary
(HC-FIND-01 §7.3). A pair is 'done' once it has any recorded status other than
'pending', so a resumed run skips work it already processed.
"""
from harness.store.db import now

STATUSES = {"pending", "not_applicable", "blocked_by_policy", "attempted",
            "lead", "confirmed", "rejected", "inconclusive"}


def mark(conn, engagement_id, asset, technique_id, status, at=None):
    if status not in STATUSES:
        raise ValueError(f"unknown ledger status: {status!r}")
    with conn:
        conn.execute(
            """INSERT INTO coverage_ledger (engagement_id, asset, technique_id, status, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(engagement_id, asset, technique_id)
               DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at""",
            (engagement_id, asset, technique_id, status, at or now()))


def done(conn, engagement_id, asset, technique_id):
    row = conn.execute(
        "SELECT status FROM coverage_ledger WHERE engagement_id=? AND asset=? AND technique_id=?",
        (engagement_id, asset, technique_id)).fetchone()
    return bool(row) and row["status"] != "pending"


def summary(conn, engagement_id):
    rows = conn.execute(
        "SELECT status, COUNT(*) AS n FROM coverage_ledger WHERE engagement_id=? GROUP BY status",
        (engagement_id,)).fetchall()
    return {r["status"]: r["n"] for r in rows}
