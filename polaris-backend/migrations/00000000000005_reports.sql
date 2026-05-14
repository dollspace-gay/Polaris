-- Reports table — time-partitioned (issue #13).
--
-- design.md §4: "Time-partitioned report data is aged out to cold storage
-- after 18 months." Implementing that lifecycle by dropping or detaching
-- monthly partitions is dramatically cheaper than a row-level cleanup job.
--
-- Partitioning shape:
--   - PARTITION BY RANGE (created_at)
--   - One partition per month
--   - This migration creates the current and next-month partitions; a
--     follow-up scheduled job (or a manual `polaris reports add-partition`
--     command in a later issue) creates further partitions ahead of time.
--
-- Composite primary key (id, created_at) is required because Postgres
-- demands the partition key be part of every unique constraint on a
-- partitioned table.
--
-- FK on `subject_id`: Postgres 12+ supports foreign keys from a partitioned
-- table to a regular table, so the constraint applies to every partition.

CREATE TABLE reports (
    id            UUID         NOT NULL DEFAULT gen_random_uuid(),
    subject_id    UUID         NOT NULL REFERENCES subjects(id),
    incident_id   UUID         REFERENCES incidents(id),
    reporter_did  TEXT         NOT NULL,
    category      TEXT         NOT NULL,
    body          TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)
) PARTITION BY RANGE (created_at);

-- Indexes on the parent are propagated to every child partition.
CREATE INDEX reports_subject_id_idx     ON reports (subject_id);
CREATE INDEX reports_incident_id_idx    ON reports (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX reports_reporter_did_idx   ON reports (reporter_did);

-- ── partitions ──────────────────────────────────────────────────────────
-- M1 (issue #13) ships with partitions for the current and next month so a
-- fresh deployment can ingest reports immediately. A later issue introduces
-- a scheduled "partition ahead by N months" maintenance job.
--
-- Naming: `reports_yYYYY_mMM` is unambiguous and sortable lexicographically.

CREATE TABLE reports_y2026_m05 PARTITION OF reports
    FOR VALUES FROM ('2026-05-01 00:00:00+00') TO ('2026-06-01 00:00:00+00');

CREATE TABLE reports_y2026_m06 PARTITION OF reports
    FOR VALUES FROM ('2026-06-01 00:00:00+00') TO ('2026-07-01 00:00:00+00');

INSERT INTO _polaris_schema_version (version, description)
VALUES (6, 'reports-partitioned');
