-- Labels materialized view — signed-label persistence (issue #28).
--
-- Migration 12 (`00000000000012_labels.sql`) created the `labels` table to
-- back the subscribeLabels / queryLabels XRPC endpoints from issue #26.
-- That schema is read-correct (src, uri, val, neg, cts, sig, …) but lacks
-- the materialized-view fields the label emitter needs:
--
--   subject_did  — denormalised from action -> incident -> subject so the
--                  subscribeLabels query plan does not need a 3-table join
--                  on every read.
--   label_cbor   — the full canonical DAG-CBOR-encoded Label payload, exactly
--                  as it was signed. Re-distributing this on the wire is
--                  byte-identical to what the labeler signed, so downstream
--                  consumers verify the signature against bytes that never
--                  passed through a re-serialisation.
--   signing_did  — did:key the signature was produced under. Pinned per row
--                  so post-rotation labels stay verifiable against the
--                  correct historical key (REQ-12).
--   signed_at    — emit-time timestamp. Indexed for "labels emitted this
--                  week" operator queries.
--
-- Existing migration-12 rows are placeholder fixtures used by integration
-- tests; they backfill with empty `subject_did` and `label_cbor`, and the
-- labeler's own DID for `signing_did`. The placeholder is internally
-- consistent (empty CBOR + empty signature stays empty); the integration
-- test for #26 is updated in the same revision to seed proper bytes.
--
-- Constraint additions:
--
--   labels_action_id_uniq  — UNIQUE partial index on action_id. Actions are
--                            append-only and single-shot from the moderator's
--                            perspective, so a label may only be emitted once
--                            per action. The partial form (`WHERE action_id
--                            IS NOT NULL`) accommodates imported / migrated
--                            labels that have no originating Polaris action.
--
--   labels_signature_len   — CHECK that `sig` is exactly 64 bytes (K-256
--                            compact form per atproto spec). Empty rows are
--                            rejected at the storage layer.

-- 1. Add the new columns. Defaults satisfy NOT NULL on the few placeholder
--    rows the #26 integration test seeds; production rows will always
--    supply explicit values via the emitter's INSERT.
ALTER TABLE labels
    ADD COLUMN subject_did TEXT NOT NULL DEFAULT '',
    ADD COLUMN label_cbor BYTEA NOT NULL DEFAULT '\x'::bytea,
    ADD COLUMN signing_did TEXT NOT NULL DEFAULT '',
    ADD COLUMN signed_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- 2. Drop the defaults so the emitter's INSERT must explicitly supply each
--    column. Defaults stayed in scope only for the ALTER backfill above.
ALTER TABLE labels
    ALTER COLUMN subject_did DROP DEFAULT,
    ALTER COLUMN label_cbor DROP DEFAULT,
    ALTER COLUMN signing_did DROP DEFAULT;

-- 3. Strict signature shape: 64 bytes (K-256 compact form). The `sig`
--    column existed in migration 12 with no length check; we add it here.
--    The CHECK applies to all rows — the #26 integration test is updated
--    in the same revision to seed a 64-byte zero signature where it
--    previously seeded `Vec<u8>::new()`.
ALTER TABLE labels
    ADD CONSTRAINT labels_signature_len CHECK (octet_length(sig) = 64);

-- 4. Materialized-view indexes. `subject_did` and `signed_at` are the
--    two most common operator query keys after `seq`/`uri`; `action_id`
--    already had a non-unique index implied by the FK, but we add a
--    unique partial index here for the "one label per action" invariant.
CREATE INDEX IF NOT EXISTS labels_subject_did_idx ON labels(subject_did);
CREATE INDEX IF NOT EXISTS labels_signed_at_idx ON labels(signed_at);
CREATE UNIQUE INDEX IF NOT EXISTS labels_action_id_uniq
    ON labels(action_id)
    WHERE action_id IS NOT NULL;

INSERT INTO _polaris_schema_version (version, description)
VALUES (14, 'labels-signed');
