-- Capture per-row image-blob ownership and walk recency on
-- `subject_image_blobs` so the case-view media gallery can render
-- the correct CDN URL per image AND reap stale rows that a
-- subsequent walk no longer observes.
--
-- # `owner_did`
--
-- The AppView's `getAuthorFeed` returns each image embed as a
-- `https://cdn.bsky.app/img/feed_thumbnail/plain/<owner-did>/<cid>@jpeg`
-- URL. The `<owner-did>` is the DID of the post's authoring repo,
-- which is the subject's own DID for the subject's authored posts.
-- Until now Polaris discarded that segment at extract time and
-- reconstructed the URL on render using the subject's DID — which
-- silently broke for any row whose post was NOT authored by the
-- subject (reposts, quote-embedded media). Storing it explicitly
-- makes the render URL canonical regardless of provenance.
--
-- Nullable because legacy rows (pre-migration) carry no owner DID.
-- The frontend treats `None` as "owner unknown, fall back to the
-- subject's DID" so rendering never panics; the gallery handler
-- always populates the column on subsequent walks.
--
-- # `walked_at`
--
-- Per-row recency timestamp updated on every upsert. Lets the
-- media-gallery refresh path reap rows that the current walk did
-- NOT observe (e.g., the subject deleted the underlying post,
-- or the previous walker had a bug that captured reposts the new
-- filter excludes). Reap rule:
--
--   DELETE FROM subject_image_blobs
--   WHERE subject_id = $1 AND walked_at < $walk_started_at;
--
-- The `$walk_started_at` cutoff is captured BEFORE the walker
-- runs so a concurrent walk's fresh inserts never get reaped by
-- a peer walk's cutoff (each walker only deletes rows older than
-- its own start).
--
-- NOT NULL DEFAULT now() so pre-existing rows are pinned to the
-- migration moment; the first post-migration walk's cutoff will
-- be strictly later, so any pre-existing row that the new walker
-- does not re-observe is correctly reaped.

ALTER TABLE subject_image_blobs
    ADD COLUMN owner_did  TEXT,
    ADD COLUMN walked_at  TIMESTAMPTZ NOT NULL DEFAULT now();

-- Index so the reap-stale DELETE under `(subject_id, walked_at)`
-- avoids a sequential scan on large tables. The existing
-- `subject_image_blobs_subject_id_idx` already covers the
-- `subject_id` filter alone; this composite index is the
-- right shape for the reap query specifically.
CREATE INDEX subject_image_blobs_subject_walked_idx
    ON subject_image_blobs (subject_id, walked_at);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (33, 'subject_image_blobs.owner_did + walked_at — per-image owner DID and walk-recency reap support');
