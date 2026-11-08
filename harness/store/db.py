"""Store connection + schema bootstrap (HC-DATA-01, HC-SAFE-01).

SQLite realization for a zero-dependency, testable reference. Production target
is Postgres + MinIO (HC-DATA-01 §3); the invariants are the same and enforced
in the database here too.
"""
import os
import sqlite3
from datetime import datetime, timezone

SCHEMA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")


def now():
    """ISO-8601 UTC timestamp (stored form; rendered am/pm for humans)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def connect(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(open(SCHEMA).read())
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
