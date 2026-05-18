-- Add `alt_text` to `subject_image_blobs` so the case-view media
-- gallery can surface the author-provided alternative text alongside
-- each image (a11y requirement + investigative signal — alt text often
-- carries crucial context the visual content alone does not).
--
-- The column is NULLABLE because:
--   * Many posts simply have no alt text at all (most users do not set
--     it). NULL is the honest "no alt text was provided" representation
--     and distinguishes that from an explicit empty string the author
--     wrote.
--   * Backfilling historical rows requires re-walking `getAuthorFeed`
--     for every subject — costly and unnecessary; new case-view loads
--     repopulate via `INSERT … ON CONFLICT (subject_id, blob_cid,
--     post_uri) DO UPDATE SET alt_text = EXCLUDED.alt_text` so the
--     column fills in lazily as moderators visit case views.
--
-- The lazy populator in `polaris-backend/src/api/network_context.rs`
-- writes this column on upsert; the case-view DTO surfaces it via
-- `SubjectMediaBlob.alt_text` so the frontend carousel renders the
-- author's description directly under each image.

ALTER TABLE subject_image_blobs
    ADD COLUMN alt_text TEXT;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (32, 'subject_image_blobs.alt_text — author-provided alt text for case-view media gallery');
