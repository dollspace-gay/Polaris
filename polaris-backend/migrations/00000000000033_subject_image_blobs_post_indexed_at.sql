-- Capture the post's AppView-indexed timestamp on `subject_image_blobs`
-- so the case-view media gallery can render images in strict
-- reverse-chronological order (newest → oldest).
--
-- # Why a separate column
--
-- The existing `first_seen_at` column records when Polaris itself
-- first observed the blob, NOT when the underlying post was
-- published. On a fresh-table walk every row gets the same
-- `now()` cluster, so ordering by `first_seen_at` produces a
-- visually-random sequence rather than a chronological one.
--
-- `post_indexed_at` mirrors `post.indexedAt` from the AppView's
-- `app.bsky.feed.getAuthorFeed` response — the same field the
-- AppView itself uses to order the feed. Using it here makes the
-- carousel's order match what a moderator would see scrolling the
-- subject's Bluesky profile.
--
-- # Why indexedAt and not record.createdAt
--
-- `record.createdAt` is author-declared and can be backdated.
-- `indexedAt` is set by the AppView at ingest time and is the
-- authoritative ordering signal for the feed. Backdated posts
-- still appear where the AppView put them, not where the author
-- claimed they should appear.
--
-- # Nullable
--
-- Legacy rows (pre-migration) carry NULL. The read query orders
-- with `NULLS LAST` so pre-migration rows fall to the tail of the
-- carousel rather than mixing with the newly-walked set; the
-- next refresh repopulates the column on those rows that survive
-- the reap.

ALTER TABLE subject_image_blobs
    ADD COLUMN post_indexed_at TIMESTAMPTZ;

-- Index for the descending-time ORDER BY the case-view read path
-- and the media-gallery read path both run on every render. The
-- composite `(subject_id, post_indexed_at)` shape lets the planner
-- satisfy the per-subject DESC sort without a heap-driven sort
-- step on busy subjects.
CREATE INDEX subject_image_blobs_subject_indexed_idx
    ON subject_image_blobs (subject_id, post_indexed_at DESC);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (34, 'subject_image_blobs.post_indexed_at — per-row AppView-indexed timestamp for chronological gallery order');
