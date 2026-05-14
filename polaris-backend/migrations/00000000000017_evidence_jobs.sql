-- Evidence-preservation queue (issue #33 / REQ-10 / AC-11).
--
-- design.md companion §H (`.design/polaris-proto-blue-integration.md`):
-- when a moderator commits an action against a record-shaped subject
-- (post / list / feed — i.e. anything that is not an `account`), the
-- backend snapshots the upstream repo slice (record CID + MST proof
-- path) as a CAR file in object storage and references it from the
-- `actions` row. The evidence survives upstream deletion or mutation.
--
-- # Queue shape
--
-- Each row represents one action whose upstream record we need to
-- snapshot. The worker drains this table with bounded concurrency
-- (`tokio::sync::Semaphore`); see `polaris-backend/src/evidence/worker.rs`.
--
-- The `UNIQUE (action_id)` index makes the enqueue path idempotent: a
-- replayed `INSERT … ON CONFLICT (action_id) DO NOTHING` is a no-op,
-- and a retry path reuses the existing row by mutating its `status`
-- rather than inserting another job (see issue #70 for the
-- retry-with-backoff follow-up).

CREATE TABLE evidence_jobs (
    id              BIGSERIAL    PRIMARY KEY,
    action_id       UUID         NOT NULL REFERENCES actions(id),
    -- Record's AT-URI (at://did:plc:.../<collection>/<rkey>). The worker
    -- parses this to drive `describeRepo` + `getRecord`.
    subject_uri     TEXT         NOT NULL,
    -- Worker state machine. The CHECK enforces the closed set;
    -- transitions are: pending → running → done | failed.
    status          TEXT         NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','running','done','failed')),
    attempt_count   INTEGER      NOT NULL DEFAULT 0,
    last_error      TEXT,
    enqueued_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ
);

-- Drain-friendly index for the worker loop's
-- `SELECT … WHERE status IN ('pending','running') ORDER BY enqueued_at`
-- pattern. The partial-WHERE keeps the index small (done/failed rows
-- never need to be scanned).
CREATE INDEX evidence_jobs_pending_idx
    ON evidence_jobs (status, enqueued_at)
    WHERE status IN ('pending', 'running');

-- One job per action — re-enqueue on retry by resetting `status`, not
-- by inserting another row. The enqueue hook uses
-- `ON CONFLICT (action_id) DO NOTHING` against this unique index.
CREATE UNIQUE INDEX evidence_jobs_action_id_uniq
    ON evidence_jobs (action_id);

-- Reference from the `Action` to the CAR's content hash. Filled by the
-- worker on success; remains NULL while pending or failed. The partial
-- index supports the "find the CAR for this action" lookup without
-- paying for non-evidenced rows.
ALTER TABLE actions
    ADD COLUMN evidence_car_cid TEXT;

CREATE INDEX actions_evidence_car_cid_idx
    ON actions (evidence_car_cid)
    WHERE evidence_car_cid IS NOT NULL;

-- ── relax append-only enforcement for evidence-CAR backfill ─────────────
--
-- Issue #33 introduces a new write path: the evidence worker fills
-- `actions.evidence_car_cid` after a successful CAR snapshot. The
-- original `actions_reject_update` trigger (migration 0004) rejects
-- every UPDATE unconditionally; we relax it to allow a single
-- post-insert column transition (NULL → non-NULL on
-- `evidence_car_cid`) while still rejecting every other mutation —
-- the append-only invariant on content fields (reasoning, kind,
-- label, policy_refs, etc.) is preserved exactly.
--
-- The same carve-out also permits the existing label-emit pipeline
-- to set `emitted_to_atproto` once on success (#28 / #36 reserved
-- that column for the emitter); it has not been wired to UPDATE
-- yet, but the schema already declares the column nullable so the
-- carve-out future-proofs the path without a follow-up migration.
--
-- Tests in `tests/actions_append_only.rs` continue to PROVE the
-- invariant by attempting an UPDATE on `reasoning` and asserting the
-- trigger still raises.
CREATE OR REPLACE FUNCTION actions_reject_update()
RETURNS trigger AS $$
BEGIN
    -- Permit the evidence-CAR backfill: setting evidence_car_cid
    -- from NULL to a non-NULL hex CID is the only allowed
    -- transition on that column.
    IF OLD.evidence_car_cid IS DISTINCT FROM NEW.evidence_car_cid
       AND OLD.evidence_car_cid IS NULL
       AND NEW.evidence_car_cid IS NOT NULL
    THEN
        -- Also assert nothing else changed in this UPDATE — protect
        -- against a malformed writer that bundles the CAR backfill
        -- with an illicit content edit.
        IF OLD.id                 IS NOT DISTINCT FROM NEW.id
           AND OLD.incident_id    IS NOT DISTINCT FROM NEW.incident_id
           AND OLD.subject_id     IS NOT DISTINCT FROM NEW.subject_id
           AND OLD.moderator_id   IS NOT DISTINCT FROM NEW.moderator_id
           AND OLD.kind           IS NOT DISTINCT FROM NEW.kind
           AND OLD.label_value    IS NOT DISTINCT FROM NEW.label_value
           AND OLD.reasoning      IS NOT DISTINCT FROM NEW.reasoning
           AND OLD.policy_refs    IS NOT DISTINCT FROM NEW.policy_refs
           AND OLD.reversible_until IS NOT DISTINCT FROM NEW.reversible_until
           AND OLD.reverses_action_id IS NOT DISTINCT FROM NEW.reverses_action_id
           AND OLD.emitted_to_atproto IS NOT DISTINCT FROM NEW.emitted_to_atproto
           AND OLD.created_at     IS NOT DISTINCT FROM NEW.created_at
        THEN
            RETURN NEW;
        END IF;
    END IF;

    -- Permit a one-shot emit-timestamp transition (NULL → non-NULL
    -- on emitted_to_atproto) with all other columns unchanged. Same
    -- semantics as the evidence carve-out; documented separately so
    -- a future writer that flips back to NULL is rejected.
    IF OLD.emitted_to_atproto IS DISTINCT FROM NEW.emitted_to_atproto
       AND OLD.emitted_to_atproto IS NULL
       AND NEW.emitted_to_atproto IS NOT NULL
    THEN
        IF OLD.id                 IS NOT DISTINCT FROM NEW.id
           AND OLD.incident_id    IS NOT DISTINCT FROM NEW.incident_id
           AND OLD.subject_id     IS NOT DISTINCT FROM NEW.subject_id
           AND OLD.moderator_id   IS NOT DISTINCT FROM NEW.moderator_id
           AND OLD.kind           IS NOT DISTINCT FROM NEW.kind
           AND OLD.label_value    IS NOT DISTINCT FROM NEW.label_value
           AND OLD.reasoning      IS NOT DISTINCT FROM NEW.reasoning
           AND OLD.policy_refs    IS NOT DISTINCT FROM NEW.policy_refs
           AND OLD.reversible_until IS NOT DISTINCT FROM NEW.reversible_until
           AND OLD.reverses_action_id IS NOT DISTINCT FROM NEW.reverses_action_id
           AND OLD.evidence_car_cid IS NOT DISTINCT FROM NEW.evidence_car_cid
           AND OLD.created_at     IS NOT DISTINCT FROM NEW.created_at
        THEN
            RETURN NEW;
        END IF;
    END IF;

    RAISE EXCEPTION
        'actions is append-only; reversals write a new row with kind = reverse and reverses_action_id pointing at the original (design.md §5.5). Only evidence_car_cid and emitted_to_atproto can transition NULL → non-NULL post-insert (issue #33).';
END;
$$ LANGUAGE plpgsql;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (18, 'evidence-jobs');
