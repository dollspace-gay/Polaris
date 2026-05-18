-- Subject image-blob index for the network-context panel's
-- shared-image cluster signal (issue #97 / M2 case-view panel).
--
-- The case-view network panel surfaces "this subject shares N image
-- blobs with these other subjects" so moderators can spot
-- coordinated content reuse (re-posted spam imagery, brigaded
-- screenshots, identical promotional pictures across burner accounts).
-- The index is keyed on the AT-Proto blob CID, which is content-
-- addressable: identical bytes produce the same CID across every
-- repo on the network, so a shared CID is a strong signal of
-- duplicate content.
--
-- Populated lazily by `polaris-backend/src/api/network_context.rs`
-- on each case-view load: when the handler walks the subject's
-- `app.bsky.feed.getAuthorFeed` response it extracts every image
-- embed's blob CID and upserts into this table. The same handler
-- then queries the table for "other subjects with the same CIDs"
-- and surfaces the matches in the panel. This is intentionally a
-- read-and-write surface on the same code path: a deeper
-- index-on-ingest would require firehose-side instrumentation
-- (#33 / #70 evidence-worker extension) — the case-view-driven
-- lazy populator is what's reachable today without that workstream.

CREATE TABLE subject_image_blobs (
    -- Synthetic primary key so a single subject can have multiple
    -- blob rows without overlapping the (subject_id, blob_cid)
    -- uniqueness boundary defined below.
    id              BIGSERIAL    PRIMARY KEY,

    -- Subject whose post embedded this blob. `ON DELETE CASCADE`
    -- because the relationship is owned by the subject row; deleting
    -- the subject is the canonical cleanup path.
    subject_id      UUID         NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,

    -- AT-Proto blob CID (content-address). The same bytes produce
    -- the same CID, which is the load-bearing property: a CID
    -- appearing under two different `subject_id`s is the
    -- shared-image signal.
    blob_cid        TEXT         NOT NULL,

    -- AT-URI of the post that embedded this blob. Useful for the
    -- moderator surface ("here's the exact post where this image
    -- appears"). Not unique — the same image may be re-embedded by
    -- the same subject across multiple posts.
    post_uri        TEXT         NOT NULL,

    -- When we first observed this (subject, blob_cid) pair. Used
    -- by the panel to rank matches by recency.
    first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Soft-uniqueness: one row per (subject, blob, post). A
    -- subject re-embedding the same blob in two posts produces two
    -- rows; the panel deduplicates at query time. Allowing the
    -- duplication here keeps the upsert path a no-op INSERT…ON
    -- CONFLICT, which is the simplest concurrency-safe shape.
    UNIQUE (subject_id, blob_cid, post_uri)
);

-- Lookup index for the "given this subject's CIDs, who else has
-- any of them?" query the panel runs. The `blob_cid` index is the
-- hot path because the panel WHERE-clauses on a small set of CIDs
-- and the cardinality of `blob_cid` is high (every distinct
-- network image is a separate value).
CREATE INDEX subject_image_blobs_blob_cid_idx
    ON subject_image_blobs (blob_cid);

-- Subject-side index for cleanup + per-subject queries. Cheaper
-- than scanning the whole table when listing "all images this
-- subject has ever embedded."
CREATE INDEX subject_image_blobs_subject_id_idx
    ON subject_image_blobs (subject_id);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (27, 'subject_image_blobs index for network-context shared-image cluster signal');
