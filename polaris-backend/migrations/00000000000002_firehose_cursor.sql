-- Firehose ingest cursor. Single-row table; the row is upserted on every
-- flush. The id = 1 invariant gives us a stable PK without a sequence and
-- makes the "single writer" property visible in the schema itself.
--
-- Replay-safety: on restart, the worker reads `seq` and resumes the
-- `com.atproto.sync.subscribeRepos` WebSocket subscription with
-- `?cursor=<seq>` so no events are lost across the gap (REQ-8 / AC-9).
--
-- The upsert in `flush_cursor()` (see polaris-backend/src/ingest/firehose.rs)
-- carries a `WHERE firehose_cursor.seq < EXCLUDED.seq` guard so a stale
-- writer can never rewind the persisted cursor — i.e. cursor monotonicity
-- is enforced at the database, not just in the worker process.
CREATE TABLE firehose_cursor (
    id         INT         PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    seq        BIGINT      NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO _polaris_schema_version (version, description)
VALUES (3, 'firehose-cursor');
