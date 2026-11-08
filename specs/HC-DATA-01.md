---
tag: HC-DATA-01
title: Evidence store and self-labeling corpus
status: draft
parent: SPEC.md#9
depends_on: [HC-SUB-01, HC-KB-01, HC-FIND-01]
depended_on_by: [HC-MODEL-02, HC-AGENT-01, HC-FIND-01, HC-SAFE-01, HC-EVAL-01]
updated: 2026-11-08
---

# HC-DATA-01 - Evidence store and self-labeling corpus

## 1. Purpose

This spec is the data backbone: the schema for probe events, findings, labels, and the coverage ledger; the blob store for raw I/O; the corpus export that feeds Laya fine-tuning; and the retention, sensitivity, and integrity guarantees.

The design commitment from SPEC.md#9, restated: the raw probe I/O is the atomic, immutable record, findings and labels reference it, and the training corpus is a view over it.
Parsed features can be recomputed; raw request and response cannot be reconstructed, so the raw I/O is what we persist, and it is persisted inside our trust boundary.

## 2. Invariants

- Append-only: probe_events and labels are never updated or deleted in place; a correction is a new row that supersedes the old.
- Raw retained, parsed derived: raw I/O is authoritative, parsed fields are a recomputable convenience.
- Content-addressed and deduplicated: blobs are keyed by content hash, so identical responses collapse to one object.
- Engagement-keyed and deterministically split: every event carries `engagement_id` and a `split_bucket` fixed at write time.
- eval_seed is quarantined by construction, not by a filter anyone has to remember.
- The corpus is a sensitive asset: it lives inside the trust boundary, encrypted at rest, access-controlled, and is the hard reason fine-tuning runs locally on Laya (HC-MODEL-02), never on a hosted service.

## 3. Store topology

- Relational store (Postgres): metadata, parsed features, findings, labels, coverage ledger.
- Blob store (self-hosted, inside the trust boundary): raw request/response bodies and pcaps as content-addressed, compressed (zstd) blobs.
- The default blob backend is a content-addressed filesystem store: `blob://<sha256>` maps straight to a path, so deduplication and write-once immutability are intrinsic and no extra service runs on the range.
- If an S3 API is ever required (an external S3-only tool, or scale-out beyond one node), a lightweight S3-compatible server drops in behind the same interface: Garage (lightest) or SeaweedFS (Apache-2.0, adds file-level access). MinIO is deliberately excluded: its community edition was archived in 2026.
- The two stores are linked by `blob://<sha256>` URIs recorded on the probe_event.
- Both are self-hosted with no external managed service, which keeps the sensitive corpus air-gapped and consistent with the HC-SUB-01 egress posture.

## 4. Schema (Postgres DDL)

### 4.1 probe_event (atomic, immutable)

```sql
create table probe_event (
  id                   text primary key,            -- pe_<ulid>
  engagement_id        text not null,
  ts                   timestamptz not null,
  provenance           text not null check (provenance in ('eval_seed','live_engagement')),
  split_bucket         text not null check (split_bucket in ('train','test')),
  phase                text not null,
  role                 text not null,               -- operator | verifier
  target_asset         text not null,
  snapshot_id          text not null,               -- HC-SUB-01; makes the event replayable
  technique_id         text not null,
  technique_version    text not null,               -- HC-KB-01; pinned
  tool                 text not null,
  tool_args            jsonb not null,
  request_raw_uri      text not null,               -- blob://<sha256>
  response_raw_uri     text,
  parsed               jsonb not null default '{}',
  deterministic_signals jsonb not null default '{}',
  content_hash         text not null                -- hash binding metadata to the blobs
);
create index on probe_event (engagement_id);
create index on probe_event (technique_id, technique_version);
create index on probe_event (provenance, split_bucket);
create index on probe_event (target_asset);
-- append-only: a trigger raises on UPDATE or DELETE
```

### 4.2 finding and its history

```sql
create table finding (
  id                text primary key,               -- F-YYYY-nnnn
  engagement_id     text not null,
  technique_id      text not null,
  technique_version text not null,
  asset             text not null,
  classification    text not null check (classification in ('vulnerability','hardening_note')),
  cwe               text[],
  cvss              jsonb,
  verdict           text not null,                  -- current state; equals latest finding_status
  signal_confidence double precision,
  found_by          text,
  verified_by       text,
  impact            text,
  remediation       text,
  blast_tier_used   int,
  created_at        timestamptz not null,
  resolved_at       timestamptz,
  constraint finder_not_verifier
    check (verified_by is null or verified_by <> found_by)   -- enforced in the DB, not only the app
);

create table finding_event (
  finding_id     text not null references finding(id),
  probe_event_id text not null references probe_event(id),
  side           text not null check (side in ('found','verified')),
  primary key (finding_id, probe_event_id, side)
);

create table finding_status (                         -- append-only history
  seq        bigserial primary key,
  finding_id text not null references finding(id),
  to_state   text not null,
  at         timestamptz not null,
  by         text,
  reason     text
);
```

A verdict transition appends a `finding_status` row and updates `finding.verdict` in the same transaction, so the denormalized current verdict always equals the latest history row.
The finding lifecycle is the one place state legitimately changes, and every change is logged.

### 4.3 label (the training signal)

```sql
create table label (
  id             bigserial primary key,
  probe_event_id text not null references probe_event(id),
  ts             timestamptz not null,
  decision_point text not null,                      -- success_signal | applicability | severity_bucket | ...
  value          text not null,
  confidence     double precision,
  source         text not null check (source in ('verifier','human_audit','strong_llm_audit','deterministic')),
  tier           text not null check (tier in ('gold','silver')),
  labeler_id     text,
  model_version  text,
  supersedes     bigint references label(id)
);
create index on label (decision_point);
create index on label (probe_event_id);
create index on label (tier);
-- append-only: re-audit inserts a new row referencing supersedes; never an UPDATE
```

Labels come only from Verifier verdicts (`source: verifier`, `tier: silver`) and audits (`human_audit` or `strong_llm_audit`, `tier: gold`).
Laya's own predictions are never written here as labels, which is what prevents the model from training on its own output (HC-MODEL-02); Laya predictions are logged separately as run telemetry, not as corpus truth.

### 4.4 coverage_ledger

```sql
create table coverage_ledger (
  engagement_id text not null,
  asset         text not null,
  technique_id  text not null,
  status        text not null,   -- pending|not_applicable|blocked_by_policy|attempted|lead|confirmed|rejected|inconclusive
  updated_at    timestamptz not null,
  primary key (engagement_id, asset, technique_id)
);
```

The report's coverage summary (HC-FIND-01 §7.3) aggregates this table.
The audit log is a separate append-only store specified in HC-SAFE-01.

## 5. Blob store

- Key is the sha256 of the content, so storage is content-addressed and identical bodies dedup to one object (ref-counted).
- Bodies and pcaps are compressed with zstd before storage.
- `probe_event.content_hash` binds the row to the exact blobs; a mismatch on read is tamper or corruption detection.
- Encryption at rest, with keys held on the trusted host.

## 6. The corpus export

The payoff of retaining raw I/O: the training set is a view, with eval data impossible to leak in.

```sql
create view corpus_success_signal as
select pe.id              as probe_event_id,
       pe.request_raw_uri, pe.response_raw_uri, pe.parsed,
       lbl.value          as label,
       lbl.confidence,
       lbl.tier
from probe_event pe
join lateral (
   select l.*
   from label l
   where l.probe_event_id = pe.id
     and l.decision_point = 'success_signal'
     and not exists (select 1 from label s where s.supersedes = l.id)  -- latest, not superseded
   order by (l.tier = 'gold') desc, l.ts desc                          -- gold overrides silver
   limit 1
) lbl on true
where pe.split_bucket = 'train'
  and pe.provenance  <> 'eval_seed';                                    -- quarantined by construction
```

- One such view per `decision_point`.
- The export materializes it, fetching raw text from the blob store, into a LoRA-ready dataset of `(raw text + parsed features, label, confidence, tier)`.
- Because the filter is `train` and non-`eval_seed`, the seeded-vuln eval targets can never appear in training, which keeps the HC-EVAL-01 recall metric meaningful.

## 7. Retention and lifecycle

- Retention is per-engagement: raw blobs carry a retention clock, while findings and labels are retained longer because they are the corpus.
- Dedup plus zstd keeps raw-I/O cost bounded; hot recent data stays in the primary store and older data tiers to cold archive.
- `inconclusive` leads are retained for possible re-attempt in a later run per the HC-FIND-01 open question, then closed.

## 8. Sensitivity and PII

- The corpus holds raw target data, so it is treated as a sensitive asset: self-hosted, encrypted at rest, RBAC, and access itself audited.
- An optional PII-tagging pass scans raw blobs (regex plus local NER) and tags events that contain PII-like data; the corpus export can exclude or redact tagged events.
- Seeded golden images (HC-EVAL-01) should avoid real PII in the first place; the PII pass matters only if a target ever mirrors realistic data (HC-SUB-01 open question).
- Fine-tuning runs locally on Laya and the corpus never leaves the boundary; this is the concrete reason hosted Jev is unusable in-loop (HC-MODEL-02).

## 9. Integrity

- Append-only triggers on `probe_event` and `label` reject UPDATE and DELETE, so evidence is immutable and corrections are new rows.
- `content_hash` binds each event to its blobs, and the chain of append-only rows plus hashes forms a defensible evidence trail.
- Finding verdicts change by design, but only through logged `finding_status` transitions, so even the mutable part is auditable.

## 10. Interfaces

```
evidence.record_probe_event(pair, req, result) -> probe_event_id   # called by dispatch() (HC-AGENT-01 §5.2)
evidence.get_raw(probe_event_id)                -> { request, response, pcap }
evidence.verify_integrity(probe_event_id)       -> ok | mismatch
labels.emit(probe_event_id, decision_point, value, source, tier, model_version?)  # HC-FIND-01 confirm/reject + audits
corpus.export(decision_point, split='train')    -> dataset          # HC-MODEL-02
ledger.done(engagement_id, asset, technique_id)  -> bool             # terminal status already recorded (HC-AGENT-01 §4)
ledger.mark(engagement_id, asset, technique_id, status)
ledger.summary(engagement_id)                   -> coverage_summary  # HC-FIND-01 §7.3
```

HC-AGENT-01 pseudocode abbreviates `(asset, technique_id)` as `pair`, with `engagement_id` the ambient run; the canonical keys are the full triple above.

The store is implemented as pure-standard-library code in `harness/store/` (`schema.sql`, `db.py`, `findings.py`, `ledger.py`, `audit.py`), a SQLite realization of the production target (§3: Postgres plus a content-addressed blob store) that enforces the §11 invariants in the database: the `finder_not_verifier` CHECK, append-only triggers on `probe_event`, `finding_status`, and `label`, and the hash-chained audit log verified by `audit.verify_chain`.
Adversarial tests in `tests/test_store.py` run in CI.
Blob storage, deduplication, and the train/test corpus export remain to be built on this backbone.

## 11. Acceptance criteria

- UPDATE or DELETE on `probe_event` or `label` is rejected by the append-only trigger.
- A `finding` row with `verified_by == found_by` is rejected by the `finder_not_verifier` check.
- `corpus_success_signal` never returns a `test` or `eval_seed` event; flipping an event's `provenance` to `eval_seed` removes it from the training export.
- A gold label overrides a silver label for the same event and decision point in the export.
- A `content_hash` mismatch is detected on read, and identical response bodies store as one deduplicated blob.
- A verdict transition appends a `finding_status` row and updates `finding.verdict` atomically.

## 12. Open questions

- Compute `parsed` features at write time (chosen for queryability) versus lazily; either way raw stays authoritative and parsed is recomputable on a schema change.
- Blob backend resolved to a content-addressed filesystem store by default (§3); revisit a lightweight S3 server (Garage or SeaweedFS) only if an external S3-only tool or multi-node scale-out forces it.
- Whether the coverage ledger deserves its own spec once it grows a richer state machine; kept here for v1.
- Label consensus when multiple audits of the same event disagree; likely a gold-with-reviewer-id tiebreak.
- PII detection precision: regex versus local NER and the false-positive cost of over-redacting the corpus.
