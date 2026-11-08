"""Findings store (HC-DATA-01 §4.2, HC-FIND-01).

A finding is created as a lead, then transitions; verdict changes only through
logged finding_status rows, applied atomically with the denormalized
finding.verdict. finder != verifier is enforced by the database CHECK
constraint, so confirming with verified_by == found_by raises.
"""
import json

from harness.store.db import now

TERMINAL = {"confirmed", "rejected", "inconclusive"}


def insert_lead(conn, finding_id, engagement_id, technique_id, technique_version,
                asset, found_by, classification="vulnerability", cwe=None,
                cvss=None, signal_confidence=None, blast_tier_used=None, at=None):
    at = at or now()
    with conn:
        conn.execute(
            """INSERT INTO finding (id, engagement_id, technique_id, technique_version,
                   asset, classification, cwe, cvss, verdict, signal_confidence,
                   found_by, blast_tier_used, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'lead', ?, ?, ?, ?)""",
            (finding_id, engagement_id, technique_id, technique_version, asset,
             classification, json.dumps(cwe) if cwe is not None else None,
             json.dumps(cvss) if cvss is not None else None,
             signal_confidence, found_by, blast_tier_used, at))
        conn.execute(
            "INSERT INTO finding_status (finding_id, to_state, at, by) VALUES (?, 'lead', ?, ?)",
            (finding_id, at, found_by))
    return finding_id


def transition(conn, finding_id, to_state, by=None, reason=None,
               verified_by=None, at=None):
    """Append a finding_status row and update finding.verdict atomically.

    Passing verified_by sets it on the finding; the DB CHECK rejects the
    transaction if it equals found_by (finder != verifier)."""
    at = at or now()
    resolved = at if to_state in TERMINAL else None
    with conn:
        conn.execute(
            "INSERT INTO finding_status (finding_id, to_state, at, by, reason) VALUES (?, ?, ?, ?, ?)",
            (finding_id, to_state, at, by, reason))
        if verified_by is not None:
            conn.execute(
                "UPDATE finding SET verdict=?, verified_by=?, resolved_at=? WHERE id=?",
                (to_state, verified_by, resolved, finding_id))
        else:
            conn.execute(
                "UPDATE finding SET verdict=?, resolved_at=COALESCE(?, resolved_at) WHERE id=?",
                (to_state, resolved, finding_id))


def confirm(conn, finding_id, verified_by, at=None):
    transition(conn, finding_id, "confirmed", by=verified_by, verified_by=verified_by, at=at)


def reject(conn, finding_id, reason, at=None):
    transition(conn, finding_id, "rejected", reason=reason, at=at)


def mark_inconclusive(conn, finding_id, reason, at=None):
    transition(conn, finding_id, "inconclusive", reason=reason, at=at)


def current(conn, finding_id):
    return conn.execute("SELECT * FROM finding WHERE id=?", (finding_id,)).fetchone()


def history(conn, finding_id):
    return conn.execute(
        "SELECT * FROM finding_status WHERE finding_id=? ORDER BY seq", (finding_id,)).fetchall()
