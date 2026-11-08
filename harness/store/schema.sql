-- Evidence / findings / ledger / audit store (HC-DATA-01, HC-SAFE-01).
--
-- This is a SQLite realization for a zero-dependency, testable reference; the
-- production target is Postgres plus a content-addressed blob store (HC-DATA-01 §3). The invariants the
-- specs insist on are enforced here in the database, not only the app:
--   * finder != verifier               (finding CHECK constraint)
--   * append-only evidence             (triggers reject UPDATE/DELETE)
--   * tamper-evident audit log         (hash chain, verified by audit.verify_chain)

PRAGMA foreign_keys = ON;

-- raw probe I/O: the atomic, immutable record (HC-DATA-01 §4.1)
CREATE TABLE IF NOT EXISTS probe_event (
  id                     TEXT PRIMARY KEY,          -- pe_<ulid>
  engagement_id          TEXT NOT NULL,
  ts                     TEXT NOT NULL,             -- ISO-8601 UTC
  provenance             TEXT NOT NULL CHECK (provenance IN ('eval_seed','live_engagement')),
  split_bucket           TEXT NOT NULL CHECK (split_bucket IN ('train','test')),
  phase                  TEXT NOT NULL,
  role                   TEXT NOT NULL,             -- operator | verifier
  target_asset           TEXT NOT NULL,
  snapshot_id            TEXT NOT NULL,
  technique_id           TEXT NOT NULL,
  technique_version      TEXT NOT NULL,
  tool                   TEXT NOT NULL,
  tool_args              TEXT NOT NULL DEFAULT '{}',
  request_raw_uri        TEXT NOT NULL,             -- blob://<sha256>
  response_raw_uri       TEXT,
  parsed                 TEXT NOT NULL DEFAULT '{}',
  deterministic_signals  TEXT NOT NULL DEFAULT '{}',
  content_hash           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_probe_engagement ON probe_event (engagement_id);
CREATE INDEX IF NOT EXISTS ix_probe_technique  ON probe_event (technique_id, technique_version);

CREATE TRIGGER IF NOT EXISTS probe_event_no_update
  BEFORE UPDATE ON probe_event BEGIN SELECT RAISE(ABORT, 'probe_event is append-only'); END;
CREATE TRIGGER IF NOT EXISTS probe_event_no_delete
  BEFORE DELETE ON probe_event BEGIN SELECT RAISE(ABORT, 'probe_event is append-only'); END;

-- findings reference events; verdicts change only through finding_status (HC-DATA-01 §4.2)
CREATE TABLE IF NOT EXISTS finding (
  id                TEXT PRIMARY KEY,               -- F-YYYY-nnnn
  engagement_id     TEXT NOT NULL,
  technique_id      TEXT NOT NULL,
  technique_version TEXT NOT NULL,
  asset             TEXT NOT NULL,
  classification    TEXT NOT NULL CHECK (classification IN ('vulnerability','hardening_note')),
  cwe               TEXT,                           -- JSON array
  cvss              TEXT,                           -- JSON object
  verdict           TEXT NOT NULL,                  -- current state; equals latest finding_status
  signal_confidence REAL,
  found_by          TEXT,
  verified_by       TEXT,
  impact            TEXT,
  remediation       TEXT,
  blast_tier_used   INTEGER,
  created_at        TEXT NOT NULL,
  resolved_at       TEXT,
  CONSTRAINT finder_not_verifier
    CHECK (verified_by IS NULL OR verified_by <> found_by)   -- enforced in the DB (HC-DATA-01)
);

CREATE TABLE IF NOT EXISTS finding_event (
  finding_id     TEXT NOT NULL REFERENCES finding(id),
  probe_event_id TEXT NOT NULL REFERENCES probe_event(id),
  side           TEXT NOT NULL CHECK (side IN ('found','verified')),
  PRIMARY KEY (finding_id, probe_event_id, side)
);

-- append-only verdict history (HC-DATA-01 §4.2)
CREATE TABLE IF NOT EXISTS finding_status (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id TEXT NOT NULL REFERENCES finding(id),
  to_state   TEXT NOT NULL,
  at         TEXT NOT NULL,
  by         TEXT,
  reason     TEXT
);
CREATE TRIGGER IF NOT EXISTS finding_status_no_update
  BEFORE UPDATE ON finding_status BEGIN SELECT RAISE(ABORT, 'finding_status is append-only'); END;
CREATE TRIGGER IF NOT EXISTS finding_status_no_delete
  BEFORE DELETE ON finding_status BEGIN SELECT RAISE(ABORT, 'finding_status is append-only'); END;

-- the training signal; append-only (HC-DATA-01 §4.3)
CREATE TABLE IF NOT EXISTS label (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  probe_event_id TEXT NOT NULL REFERENCES probe_event(id),
  ts             TEXT NOT NULL,
  decision_point TEXT NOT NULL,
  value          TEXT NOT NULL,
  confidence     REAL,
  source         TEXT NOT NULL CHECK (source IN ('verifier','human_audit','strong_llm_audit','deterministic')),
  tier           TEXT NOT NULL CHECK (tier IN ('gold','silver')),
  labeler_id     TEXT,
  model_version  TEXT,
  supersedes     INTEGER REFERENCES label(id)
);
CREATE TRIGGER IF NOT EXISTS label_no_update
  BEFORE UPDATE ON label BEGIN SELECT RAISE(ABORT, 'label is append-only'); END;
CREATE TRIGGER IF NOT EXISTS label_no_delete
  BEFORE DELETE ON label BEGIN SELECT RAISE(ABORT, 'label is append-only'); END;

-- coverage ledger drives the loop and the report coverage summary (HC-DATA-01 §4.4)
CREATE TABLE IF NOT EXISTS coverage_ledger (
  engagement_id TEXT NOT NULL,
  asset         TEXT NOT NULL,
  technique_id  TEXT NOT NULL,
  status        TEXT NOT NULL,   -- pending|not_applicable|blocked_by_policy|attempted|lead|confirmed|rejected|inconclusive
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (engagement_id, asset, technique_id)
);

-- tamper-evident audit log (HC-SAFE-01 §3); row_hash chains on prev_hash
CREATE TABLE IF NOT EXISTS audit_log (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts             TEXT NOT NULL,
  engagement_id  TEXT NOT NULL,
  actor          TEXT NOT NULL,
  category       TEXT NOT NULL,
  decision       TEXT,
  reason         TEXT,
  correlation_id TEXT,
  detail         TEXT NOT NULL DEFAULT '{}',
  prev_hash      TEXT NOT NULL,
  row_hash       TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
  BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
  BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
