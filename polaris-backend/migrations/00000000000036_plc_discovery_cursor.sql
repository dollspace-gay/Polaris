-- Cursor for the PLC-directory labeler-discovery crawler.
--
-- The discovery worker (`crate::ingest::labeler_discovery`) walks
-- `https://plc.directory/export` chronologically; each response line
-- is one DID-operation record (JSON), and the `?after=<isoTimestamp>`
-- query parameter is the pagination cursor (request the next page
-- of ops created strictly after this timestamp).
--
-- This table persists the last-seen timestamp so a restart picks up
-- where the previous run left off. The bootstrap walk from the very
-- start of the PLC log (Nov 2022) covers ~10M operations; subsequent
-- delta crawls (hourly) only have to ingest the new ops since the
-- last cursor.
--
-- # Why a dedicated table vs. `firehose_cursor`
--
-- `firehose_cursor` (migration 2) holds the bsky-`subscribeRepos`
-- sequence number (a monotonic `i64`). PLC pagination is by RFC3339
-- timestamp, not by seq, so reusing the same table would mean
-- bolting a second column on for an unrelated purpose. A purpose-
-- specific table keeps the two cursors orthogonal and the meaning
-- of each column unambiguous.
--
-- # One-row pattern
--
-- `id BOOLEAN PRIMARY KEY` with a `CHECK (id = TRUE)` constraint
-- enforces a single row at the table level — same shape Polaris
-- already uses for `polaris_setup_state`. The row is INSERTed at
-- migration time so callers can always UPDATE-by-id without a
-- prior existence check.

CREATE TABLE plc_export_cursor (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id = TRUE),

    -- Most-recent `createdAt` timestamp the worker has ingested.
    -- Empty string on first run means "start from the beginning of
    -- the PLC log" — equivalent to no `?after=` parameter.
    last_after TEXT NOT NULL DEFAULT '',

    -- Wall-clock time of the last completed crawl pass. Used by
    -- ops for "how stale is my labeler catalogue?" diagnostics.
    last_run_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Total labelers discovered across all runs (cumulative).
    -- Diagnostic only; the authoritative count is
    -- `SELECT COUNT(*) FROM upstream_labelers`.
    total_labelers_discovered BIGINT NOT NULL DEFAULT 0
);

INSERT INTO plc_export_cursor (id) VALUES (TRUE);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (37, 'plc_export_cursor — pagination cursor for the labeler-discovery crawler');
