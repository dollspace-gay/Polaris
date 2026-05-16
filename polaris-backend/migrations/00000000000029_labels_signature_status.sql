-- Issue #166 / M5 #49 PR 3: hardware-token-mode signature state machine.
--
-- The hardware-token signing modes (attended-batch + attended-realtime,
-- both from issue #153) are inherently asynchronous — Polaris needs a
-- way to mark a label as "constructed but not yet signed" so the
-- subscribeLabels broadcaster (issue #26) doesn't stream unsigned labels
-- to downstream AppViews.
--
-- This migration adds two columns to the existing `labels` table
-- (migration 0012):
--
--   `signature_status` TEXT — discriminator. Default 'signed' so
--     existing rows are unaffected; v1 modes (file_plain,
--     passphrase_sealed, os_keychain, cloud_kms) sign inline at emit
--     time and never insert a row with any other value.
--
--   `signed_at` TIMESTAMPTZ — when the row transitioned to 'signed'.
--     NULL for pending rows.
--
-- Plus a `pending_label_queue` view so the `polaris labeler-sign-pending`
-- CLI (#167 PR 4) and the realtime daemon's promoter (#169 PR 6) can
-- claim oldest-first without re-scanning the whole table.
--
-- File 0029, schema_version 30 (0028 / version 29 = federation_state_machine).

-- ── columns ──────────────────────────────────────────────────────────────

ALTER TABLE labels
    ADD COLUMN signature_status TEXT NOT NULL DEFAULT 'signed'
        CHECK (signature_status IN ('signed', 'pending_signature', 'signing_failed'));

ALTER TABLE labels
    ADD COLUMN signed_at TIMESTAMPTZ;

-- Existing rows are 'signed' by definition (v1 emit path is synchronous).
-- The signed_at column stays NULL for those; production code that needs
-- a timestamp falls back to labels.cts (creation timestamp from the v1
-- emit path).

-- ── view ─────────────────────────────────────────────────────────────────

-- pending_label_queue: ordered FIFO for the sign-pending worker. The
-- view exists so the worker's SELECT is one logical operation; the
-- underlying `labels` table is shared with the emit broadcaster (issue
-- #26) which filters by `signature_status = 'signed'`.
CREATE OR REPLACE VIEW pending_label_queue AS
    SELECT
        id,
        seq,
        src,
        uri,
        cid,
        val,
        neg,
        cts,
        exp,
        sig,
        action_id,
        signature_status,
        signed_at
    FROM labels
    WHERE signature_status = 'pending_signature'
    ORDER BY cts ASC, seq ASC;

-- Index supporting the view's predicate. Without this, the view scans
-- the full labels table; with it, the planner uses the partial index
-- on the rare 'pending_signature' rows.
CREATE INDEX IF NOT EXISTS labels_pending_signature_idx
    ON labels (cts ASC, seq ASC)
    WHERE signature_status = 'pending_signature';

-- ── schema_version ───────────────────────────────────────────────────────

INSERT INTO _polaris_schema_version (version, description)
    VALUES (30, 'labels_signature_status (#166 / M5 #49 PR 3)');
