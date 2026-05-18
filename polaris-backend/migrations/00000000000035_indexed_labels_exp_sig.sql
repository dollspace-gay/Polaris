-- Extend `indexed_labels` (migration 34) with the wire-shape fields that
-- the case-view panel renders but the original schema omitted.
--
-- # Why an additive migration vs. replacing 34
--
-- Migration 34 has been applied to operator databases. Dropping +
-- recreating would orphan any rows the firehose subscriber persists; the
-- right move is `ALTER TABLE … ADD COLUMN` so existing rows keep their
-- ids and the new columns default to NULL on backfill.
--
-- # Columns added
--
-- * `exp` — labeler-stamped expiry. Most labels are open-ended (NULL);
--   when a labeler sets one (e.g. a 24h takedown window), this is the
--   wall-clock the labeler will retract by. Stored as `TIMESTAMPTZ`
--   to match `cts`; rendered as RFC 3339 on the case-view wire.
-- * `sig` — the verified signature bytes the consumer accepted. Kept
--   so an auditor can re-verify any persisted row against the
--   labeler's signing key without going back to the firehose. The
--   bunnynabbit `atp-label-indexer` pattern (which Polaris mirrors)
--   keeps the signature for the same reason: the local store is the
--   self-contained audit surface.
--
-- # Column NULLability
--
-- Both columns are nullable to keep the migration safe on existing
-- rows (there are none in production today, but the contract is
-- additive). New inserts MAY set `sig = NULL` if the row was
-- backfilled from a non-signature-bearing source; the verify-or-drop
-- discipline in `ingest::upstream_labels::handle_frame` always
-- supplies it for firehose-sourced inserts.

ALTER TABLE indexed_labels
    ADD COLUMN exp TIMESTAMPTZ,
    ADD COLUMN sig BYTEA;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (36, 'indexed_labels: add exp + sig columns for wire-shape parity');
