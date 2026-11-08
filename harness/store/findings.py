"""Findings store (HC-DATA-01 §4.2, HC-FIND-01).

A finding is created as a lead, then transitions; a verdict changes only through
logged finding_status rows, applied atomically with the denormalized
finding.verdict. finder != verifier is enforced by the database CHECK
constraint, so confirming with verified_by == found_by raises. Higher-level
entry points (emit_lead, confirm, reject, classify_hardening) also attach the
backing probe_events and emit the verifier label (HC-FIND-01 §8).
"""
import json

from harness import severity
from harness.store.db import now

TERMINAL = {"confirmed", "rejected", "inconclusive"}


# --- creation ------------------------------------------------------------
def insert_lead(conn, finding_id, engagement_id, technique_id, technique_version,
                asset, found_by, classification="vulnerability", cwe=None, cvss=None,
                signal_confidence=None, blast_tier_used=None, impact=None,
                remediation=None, repro=None, at=None):
    at = at or now()
    with conn:
        conn.execute(
            """INSERT INTO finding (id, engagement_id, technique_id, technique_version,
                   asset, classification, cwe, cvss, verdict, signal_confidence,
                   found_by, impact, remediation, repro, blast_tier_used, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'lead', ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, engagement_id, technique_id, technique_version, asset,
             classification, json.dumps(cwe) if cwe is not None else None,
             json.dumps(cvss) if cvss is not None else None, signal_confidence,
             found_by, impact, remediation,
             json.dumps(repro) if repro is not None else None, blast_tier_used, at))
        conn.execute(
            "INSERT INTO finding_status (finding_id, to_state, at, by) VALUES (?, 'lead', ?, ?)",
            (finding_id, at, found_by))
    return finding_id


def emit_lead(conn, finding_id, engagement_id, card, asset, found_by, *, facts=None,
              repro=None, impact=None, remediation=None, signal_confidence=None,
              blast_tier_used=None, event_ids=None, at=None):
    """Create a vulnerability lead from a technique card: cwe from the card's
    taxonomy, cvss from the severity rubric scored against `facts`."""
    cwe = (card.get("taxonomy") or {}).get("cwe")
    cvss = severity.score(card.get("severity_rubric"), facts)
    insert_lead(conn, finding_id, engagement_id, card["id"], card["version"], asset,
                found_by, classification="vulnerability", cwe=cwe, cvss=cvss,
                signal_confidence=signal_confidence, impact=impact,
                remediation=remediation, repro=repro,
                blast_tier_used=blast_tier_used if blast_tier_used is not None
                else card.get("blast_tier"), at=at)
    for pe in event_ids or []:
        link_event(conn, finding_id, pe, "found")
    return finding_id


def classify_hardening(conn, finding_id, engagement_id, card, asset, found_by, *,
                       note=None, event_ids=None, at=None):
    """A defense-in-depth gap with no demonstrated impact: no cvss, no cwe, no
    verification (HC-FIND-01 §6)."""
    at = at or now()
    with conn:
        conn.execute(
            """INSERT INTO finding (id, engagement_id, technique_id, technique_version,
                   asset, classification, cwe, cvss, verdict, found_by, impact, created_at)
               VALUES (?, ?, ?, ?, ?, 'hardening_note', NULL, NULL, 'hardening_note', ?, ?, ?)""",
            (finding_id, engagement_id, card["id"], card["version"], asset, found_by, note, at))
        conn.execute(
            "INSERT INTO finding_status (finding_id, to_state, at, by) VALUES (?, 'hardening_note', ?, ?)",
            (finding_id, at, found_by))
    for pe in event_ids or []:
        link_event(conn, finding_id, pe, "found")
    return finding_id


# --- transitions ---------------------------------------------------------
def transition(conn, finding_id, to_state, by=None, reason=None, verified_by=None, at=None):
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


def confirm(conn, finding_id, verified_by, events=None, at=None):
    transition(conn, finding_id, "confirmed", by=verified_by, verified_by=verified_by, at=at)
    for pe in events or []:
        link_event(conn, finding_id, pe, "verified")
    if events:
        _emit_label(conn, events[0], "confirmed", at=at)


def reject(conn, finding_id, reason, events=None, at=None):
    transition(conn, finding_id, "rejected", reason=reason, at=at)
    for pe in events or []:
        link_event(conn, finding_id, pe, "verified")
    if events:
        _emit_label(conn, events[0], "rejected", at=at)


def mark_inconclusive(conn, finding_id, reason, at=None):
    transition(conn, finding_id, "inconclusive", reason=reason, at=at)


# --- evidence linkage + labels ------------------------------------------
def link_event(conn, finding_id, probe_event_id, side):
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO finding_event (finding_id, probe_event_id, side) VALUES (?, ?, ?)",
            (finding_id, probe_event_id, side))


def _emit_label(conn, probe_event_id, value, at=None):
    # a verdict is a silver gold-label for the self-labeling corpus (HC-DATA-01 §9)
    with conn:
        conn.execute(
            """INSERT INTO label (probe_event_id, ts, decision_point, value, source, tier)
               VALUES (?, ?, 'verdict', ?, 'verifier', 'silver')""",
            (probe_event_id, at or now(), value))


# --- queries -------------------------------------------------------------
def current(conn, finding_id):
    return conn.execute("SELECT * FROM finding WHERE id=?", (finding_id,)).fetchone()


def history(conn, finding_id):
    return conn.execute(
        "SELECT * FROM finding_status WHERE finding_id=? ORDER BY seq", (finding_id,)).fetchall()


def leads(conn, engagement_id):
    return conn.execute(
        "SELECT * FROM finding WHERE engagement_id=? AND verdict IN ('lead','needs_validation') ORDER BY id",
        (engagement_id,)).fetchall()


def confirmed(conn, engagement_id):
    return conn.execute(
        "SELECT * FROM finding WHERE engagement_id=? AND verdict='confirmed' AND classification='vulnerability' ORDER BY id",
        (engagement_id,)).fetchall()


def hardening_notes(conn, engagement_id):
    return conn.execute(
        "SELECT * FROM finding WHERE engagement_id=? AND classification='hardening_note' ORDER BY id",
        (engagement_id,)).fetchall()


def _event_ids(conn, finding_id, side):
    return [r["probe_event_id"] for r in conn.execute(
        "SELECT probe_event_id FROM finding_event WHERE finding_id=? AND side=? ORDER BY probe_event_id",
        (finding_id, side))]


def _evidence(conn, finding_id):
    rows = conn.execute(
        """SELECT pe.response_raw_uri AS u FROM finding_event fe
             JOIN probe_event pe ON pe.id = fe.probe_event_id
            WHERE fe.finding_id = ? AND pe.response_raw_uri IS NOT NULL
            ORDER BY pe.id""", (finding_id,))
    return [f"artifact://{r['u']}" for r in rows]


def _status_history(conn, finding_id):
    out = []
    for r in history(conn, finding_id):
        item = {"to": r["to_state"], "at": r["at"]}
        if r["by"]:
            item["by"] = r["by"]
        if r["reason"]:
            item["reason"] = r["reason"]
        out.append(item)
    return out


def to_record(conn, row):
    """Build the HC-FIND-01 §3 finding record from a finding row."""
    fid = row["id"]
    return {
        "id": fid,
        "technique_id": row["technique_id"],
        "technique_version": row["technique_version"],
        "asset": row["asset"],
        "classification": row["classification"],
        "cwe": json.loads(row["cwe"]) if row["cwe"] else None,
        "cvss": json.loads(row["cvss"]) if row["cvss"] else None,
        "verdict": row["verdict"],
        "signal_confidence": row["signal_confidence"],
        "found_by": row["found_by"],
        "verified_by": row["verified_by"],
        "found_by_event_ids": _event_ids(conn, fid, "found"),
        "verified_by_event_ids": _event_ids(conn, fid, "verified"),
        "repro": json.loads(row["repro"]) if row["repro"] else [],
        "evidence": _evidence(conn, fid),
        "impact": row["impact"],
        "remediation": row["remediation"],
        "blast_tier_used": row["blast_tier_used"],
        "status_history": _status_history(conn, fid),
        "created_at": row["created_at"],
        "resolved_at": row["resolved_at"],
    }
