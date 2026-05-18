-- Durable, decoupled work queue for the per-(subject, labeler)
-- `com.atproto.label.queryLabels` backfill.
--
-- The case-view used to fan a 300-way HTTPS fan-out out inline on
-- every render of a new subject. That fan-out ran against the same
-- glibc resolver the live `subscribeLabels` consumers were saturating
-- with NXDOMAIN attempts, so the backfill timed out at 60s and the
-- moderator saw only the 5-8 labels the fastest labelers managed to
-- return in the allotted window — never the full ecosystem-wide
-- history.
--
-- Decoupling the case-view from the actual queryLabels round-trips
-- turns the handler into a fire-and-forget enqueue (which is fast
-- and durable, even when every labeler is timing out), and lets a
-- single long-running background worker drain the queue at whatever
-- pace the network and the per-labeler dormancy budget tolerate. A
-- refresh that happens five minutes later picks up any additional
-- labels the worker has persisted in the meantime; the panel is
-- eventually-consistent rather than synchronously-complete on first
-- open.
--
-- The unique `(subject_did, labeler_did)` index makes re-enqueuing
-- free: the handler does an `INSERT ... ON CONFLICT DO NOTHING` for
-- every enabled labeler on every case-view render, and the worker's
-- in-flight or `done` rows simply absorb the duplicate without
-- restarting a successful backfill or interrupting an in-progress
-- attempt.
--
-- A separate enum keeps the status type tight at the database level:
-- "pending" / "running" / "done" / "permanent_failure" are the only
-- transitions the worker can take, and Postgres rejects any other
-- value at insert/update time.

CREATE TYPE label_backfill_status AS ENUM (
    'pending',
    'running',
    'done',
    'permanent_failure'
);

CREATE TABLE label_backfill_queue (
    id              BIGSERIAL PRIMARY KEY,
    subject_did     TEXT NOT NULL,
    labeler_did     TEXT NOT NULL,
    status          label_backfill_status NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (subject_did, labeler_did)
);

-- Hot-path index for the worker's drain query:
--   SELECT id, subject_did, labeler_did, attempts
--   FROM label_backfill_queue
--   WHERE status = 'pending'
--     AND next_attempt_at <= now()
--   ORDER BY next_attempt_at
--   LIMIT $1
--   FOR UPDATE SKIP LOCKED
--
-- The partial WHERE restricts the index to rows the worker actually
-- looks at, keeping the index small once most rows have transitioned
-- to `done` / `permanent_failure`.
CREATE INDEX label_backfill_queue_due_idx
    ON label_backfill_queue (next_attempt_at)
    WHERE status = 'pending';

INSERT INTO _polaris_schema_version (version, description)
    VALUES (44, 'label-backfill-queue');
