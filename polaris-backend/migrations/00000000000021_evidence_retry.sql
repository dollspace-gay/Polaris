-- Retry-with-backoff for failed evidence jobs (issue #69).
--
-- The evidence worker (migration 17 / `polaris-backend/src/evidence/worker.rs`)
-- originally marked jobs `failed` after one attempt; #69 makes that
-- failure recoverable. Failed rows are now eligible for re-drain after
-- an exponential-backoff window (`2^attempt * 30s`, capped at 24h, with
-- ±25% jitter) and stay `failed` permanently only after the worker's
-- configured `max_attempts` ceiling is exhausted.
--
-- # Schema additions
--
-- - `last_attempt_at TIMESTAMPTZ` — wall-clock time of the last
--   processing attempt (success or failure). NULL until the first
--   attempt. Operator-visible for "how stale is the last run" queries.
-- - `next_attempt_at TIMESTAMPTZ` — the earliest moment the worker
--   loop may reclaim a failed row. NULL when (a) the row is in a
--   non-failed status (the failure path is the only writer), or (b)
--   the row reached `max_attempts` and is permanently failed.
--
-- # Partial index
--
-- `evidence_jobs_next_attempt_idx` is partial on `(status='failed' AND
-- next_attempt_at IS NOT NULL)` so the worker's "drain due retries"
-- query (`ORDER BY next_attempt_at ASC LIMIT $N FOR UPDATE SKIP
-- LOCKED`) hits an index that excludes both healthy-pending rows and
-- the permanent-failure rows. The original partial index on
-- `(status='pending'|'running')` (migration 17) covers the other half
-- of the worker's claim path; the two indexes together keep the
-- physical scan cost bounded as the queue grows.

ALTER TABLE evidence_jobs
    ADD COLUMN last_attempt_at TIMESTAMPTZ,
    ADD COLUMN next_attempt_at TIMESTAMPTZ;

CREATE INDEX evidence_jobs_next_attempt_idx
    ON evidence_jobs(next_attempt_at)
    WHERE status = 'failed' AND next_attempt_at IS NOT NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (22, 'evidence-retry-with-backoff');
