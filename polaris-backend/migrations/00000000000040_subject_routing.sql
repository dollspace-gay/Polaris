-- Subject queue routing (issue #194 / Ozone-parity `#divertEvent`).
--
-- A moderator can route a subject's future activity to a named
-- alternate queue (e.g., "csam-review", "human-classifier", "low-
-- priority-spam"). The dashboard's queue selector honours this
-- routing so a subject the operator has tagged for specialised
-- review never lands in the default queue again.
--
-- # Schema
--
-- One row per subject. The latest divert wins — re-diverting a
-- subject to a different queue overwrites the prior row (UPSERT on
-- `subject_id`). A `cleared_at` column lets the operator end the
-- diversion without dropping the audit trail; queue selection
-- treats `cleared_at IS NOT NULL` as "no longer diverted".

CREATE TABLE subject_routing (
    subject_id   UUID         NOT NULL PRIMARY KEY REFERENCES subjects(id) ON DELETE CASCADE,
    queue        TEXT         NOT NULL CHECK (length(queue) BETWEEN 1 AND 64),
    diverted_by  UUID         NOT NULL REFERENCES moderators(id),
    diverted_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    reason       TEXT         NOT NULL CHECK (length(reason) BETWEEN 10 AND 2000),
    -- NULL = still diverted; set to terminate the diversion (the
    -- row stays for audit, but queue selection skips it).
    cleared_at   TIMESTAMPTZ,
    cleared_by   UUID         REFERENCES moderators(id),

    -- If a divert is cleared, both `cleared_at` and `cleared_by`
    -- must be set; if it's still active both must be NULL. Keeps
    -- the audit trail honest at the DB layer.
    CHECK ((cleared_at IS NULL AND cleared_by IS NULL)
        OR (cleared_at IS NOT NULL AND cleared_by IS NOT NULL))
);

CREATE INDEX subject_routing_queue_idx
    ON subject_routing (queue)
    WHERE cleared_at IS NULL;

CREATE INDEX subject_routing_diverted_at_idx
    ON subject_routing (diverted_at DESC);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (41, 'subject_routing — divert a subject to an alternate queue');
