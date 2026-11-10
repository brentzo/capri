"""Persisted engagement index and read API for the operator dashboard (HC-REPORT-01 §2).

A finished run is saved as one `engagement` summary row carrying its validated report
(HC-FIND-01 §7), so a self-hoster can list past runs and re-open any of them after the
process that produced it has exited. These helpers are the only writer and the readers of
that row; the control loop is unchanged, and the dashboard side is read-only. Standard
library only.
"""
import json

from harness.store import reasoning as _reasoning
from harness.store.audit import verify_chain


def save(conn, report, *, valid=True, started_at=None):
    """Persist a finished run's summary row from its already-built report, and commit so it
    survives the process. Idempotent by engagement id: re-saving a run replaces its row."""
    scope = report.get("scope_summary") or {}
    window = report.get("window") or {}
    conn.execute(
        """INSERT OR REPLACE INTO engagement
             (id, started_at, window_start, window_end, in_scope_hosts,
              max_blast_tier, mode, valid, report, generated_at)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (report["engagement_id"],
         started_at or window.get("start") or report.get("generated_at"),
         window.get("start"), window.get("end"),
         json.dumps(list(scope.get("in_scope_hosts") or [])),
         scope.get("max_blast_tier"),
         report.get("mode"),
         1 if valid else 0,
         json.dumps(report),
         report.get("generated_at")))
    conn.commit()
    return report["engagement_id"]


def list_all(conn):
    """Every persisted run, most recent first, as summary dicts for the run list."""
    rows = conn.execute(
        "SELECT * FROM engagement ORDER BY started_at DESC, id DESC").fetchall()
    return [_summary(r) for r in rows]


def get(conn, engagement_id):
    """One run's full validated report plus its summary fields, or None when absent."""
    row = conn.execute(
        "SELECT * FROM engagement WHERE id=?", (engagement_id,)).fetchone()
    if row is None:
        return None
    out = _summary(row)
    out["report"] = json.loads(row["report"])
    return out


def audit(conn, engagement_id):
    """This run's audit rows in order, plus the global hash-chain verification result
    (HC-SAFE-01), so the dashboard shows the record's integrity instead of assuming it."""
    rows = conn.execute(
        "SELECT * FROM audit_log WHERE engagement_id=? ORDER BY seq",
        (engagement_id,)).fetchall()
    status, broken_seq = verify_chain(conn)
    return {"rows": [dict(r) for r in rows],
            "chain_ok": status == "ok",
            "broken_seq": broken_seq}


def reasoning(conn, engagement_id):
    """The role-turn reasoning records for a run, in loop order (HC-REPORT-01 §3), for
    the dashboard. The write side lives in `harness.store.reasoning`; this is read-only."""
    return _reasoning.for_run(conn, engagement_id)


def _summary(row):
    report = json.loads(row["report"])
    return {"id": row["id"],
            "started_at": row["started_at"],
            "window": {"start": row["window_start"], "end": row["window_end"]},
            "in_scope_hosts": json.loads(row["in_scope_hosts"] or "[]"),
            "max_blast_tier": row["max_blast_tier"],
            "mode": row["mode"],
            "valid": bool(row["valid"]),
            "coverage_summary": report.get("coverage_summary", {}),
            "generated_at": row["generated_at"]}
