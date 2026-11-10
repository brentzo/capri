"""Write-only capture of raw role proposals, read-only for the dashboard (HC-REPORT-01 §3).

The control loop already receives each Operator/Verifier turn's verbatim text, parses it
into a structured action, and then drops the text. This module persists that text as a role
turn, so the operator can later read, step by step, what the agent proposed and why it acted.

The text is untrusted, display-only data. The loop is the only writer; nothing reads it back
into a role, it never crosses the finder -> verifier boundary, and the dashboard HTML-escapes
every field on render. The `role_turn` table is append-only (schema triggers), so a captured
turn is never rewritten. Standard library only.
"""
import json

from harness.store import db


def record(conn, *, engagement_id, role, session_id, asset, technique_id, step,
           raw, parsed=None, rejection=None, probe_event_id=None, at=None):
    """Persist one role turn. `parsed` is the parsed request object (or None); it is
    serialized here so the loop never does store formatting. Caller commits (the run's
    final `engagements.save` does), consistent with the other in-loop writes."""
    conn.execute(
        "INSERT INTO role_turn "
        "(engagement_id, role, session_id, asset, technique_id, step, raw, parsed, "
        " rejection, probe_event_id, at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (engagement_id, role, session_id, asset, technique_id, step, raw,
         json.dumps(parsed, separators=(",", ":")) if parsed is not None else None,
         rejection, probe_event_id, at or db.now()))


def for_run(conn, engagement_id):
    """Every captured turn for a run, in loop order (the Operator's hunt turns, then the
    Verifier's), each as a dict with `parsed` decoded back to an object. Read-only; used
    only by the dashboard (HC-REPORT-01 §6)."""
    rows = conn.execute(
        "SELECT seq, role, session_id, asset, technique_id, step, raw, parsed, "
        "rejection, probe_event_id, at FROM role_turn WHERE engagement_id=? ORDER BY seq",
        (engagement_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["parsed"] = json.loads(d["parsed"]) if d["parsed"] else None
        out.append(d)
    return out
