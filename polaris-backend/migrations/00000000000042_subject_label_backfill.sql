-- Per-subject cache of when we last issued a `queryLabels` fan-out
-- against every known upstream labeler for that subject. The cache
-- exists because the third-party labels panel is rendered on every
-- case-view request and we don't want each render to fire 240+
-- HTTPS calls; instead, the first render of a subject triggers a
-- backfill (asynchronously) and subsequent renders within
-- `BACKFILL_TTL` rely on the populated `indexed_labels` rows the
-- backfill wrote.
--
-- Why a separate table (rather than a column on `subjects`):
--   - The backfill targets *any* DID a moderator might open in the
--     case view, including DIDs Polaris has never seen as a
--     `subjects` row (e.g. a freshly-reported subject that lands on
--     the dashboard before its first action). Keying by DID rather
--     than by `subject_id` avoids the find-or-create dance.
--   - The cache is purely an operational concern; surfacing it on
--     `subjects` would pollute the moderation-domain table with a
--     "when did we last hit a third-party API" timestamp that no
--     business logic depends on.
--
-- The primary key is the DID itself; the row is upserted on each
-- successful backfill via `ON CONFLICT (subject_did) DO UPDATE`.
CREATE TABLE subject_label_backfill (
    subject_did       TEXT        PRIMARY KEY,
    last_backfilled_at TIMESTAMPTZ NOT NULL,
    -- Bookkeeping: how many labelers we tried this round vs how many
    -- returned at least one label. Surfaces in the structured-log
    -- envelope and lets an operator measure ecosystem coverage over
    -- time. Not load-bearing for the panel itself; the panel reads
    -- `indexed_labels` directly.
    labelers_queried   INTEGER     NOT NULL,
    labelers_succeeded INTEGER     NOT NULL,
    labels_persisted   INTEGER     NOT NULL
);

-- Index used by the staleness check in
-- `label_backfill::should_backfill`: "is there a row for this DID,
-- and is it older than X?". The primary key already serves the
-- equality lookup; this index is intentionally NOT added for
-- `last_backfilled_at` because the table will stay small (one row
-- per opened subject, bounded by moderator activity) and a sequential
-- scan filtered by PK is cheaper than maintaining a second index.
