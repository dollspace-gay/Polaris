-- Key rotation state, history, and revocation (issue #30, REQ-12, AC-15).
--
-- Three append-only tables back the labeler-key rotation flow:
--
--   signing_key_history  — point-in-time active-key lookup. At label-verify
--                          time, the verifier resolves the label's
--                          `signed_at` against the (active_from, active_until)
--                          window to recover the issuance-time key. Only one
--                          row has NULL `active_until` at any moment; this is
--                          enforced by a UNIQUE partial index.
--
--   revoked_keys         — append-only ledger of every public key Polaris
--                          has retired. A verifier confirms "this signature
--                          is from a key Polaris USED to control" by checking
--                          this table for the public key the signature
--                          claims. Never DELETEd.
--
--   rotation_state       — resumable state machine for in-flight rotations.
--                          One row per rotation, keyed by random UUID. The
--                          `last_step` column progresses monotonically
--                          forward through the documented step enum; a
--                          `--resume` CLI invocation reloads the row and
--                          drives the remaining steps idempotently.
--
-- Append-only enforcement is by trigger (DELETE and disallowed UPDATEs raise
-- SQLSTATE P0001). The `_polaris_schema_version` sentinel advances to 15.

-- ── 1. signing_key_history ──────────────────────────────────────────────

-- Active labeler signing key over time. Used by historical-label
-- verification: at sig-verify time, look up the active key whose
-- (active_from, active_until) window contains the label's signed_at.
CREATE TABLE signing_key_history (
    id BIGSERIAL PRIMARY KEY,
    -- did:key:z... multikey form.
    public_key_did TEXT NOT NULL UNIQUE,
    -- Custody mode at time of issuance (file-plain / passphrase-sealed /
    -- os-keychain / cloud-kms-oracle). Diagnostic only; verification is
    -- by public key.
    custody_mode TEXT NOT NULL,
    -- The instant this key BECAME active. NULL active_until = still active.
    active_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    active_until TIMESTAMPTZ,
    -- Append-only: at most one row may have NULL active_until at a time.
    -- Enforced by a UNIQUE partial index.
    CHECK (active_until IS NULL OR active_until >= active_from)
);
CREATE UNIQUE INDEX signing_key_history_only_one_active
    ON signing_key_history (active_until)
    WHERE active_until IS NULL;

-- Append-only trigger: forbid DELETE, and forbid UPDATE that does anything
-- other than the legal "retire" transition (set active_until from NULL to a
-- non-NULL value on the currently-active row).
CREATE OR REPLACE FUNCTION signing_key_history_append_only_trigger()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'signing_key_history is append-only: DELETE rejected'
            USING ERRCODE = 'P0001';
    END IF;
    -- Only UPDATE that's allowed: setting active_until from NULL to a value
    -- (i.e., retiring a key). Forbid all others.
    IF TG_OP = 'UPDATE' THEN
        IF OLD.active_until IS NOT NULL THEN
            RAISE EXCEPTION 'signing_key_history is append-only: cannot modify a retired row'
                USING ERRCODE = 'P0001';
        END IF;
        IF NEW.id != OLD.id
           OR NEW.public_key_did != OLD.public_key_did
           OR NEW.custody_mode != OLD.custody_mode
           OR NEW.active_from != OLD.active_from THEN
            RAISE EXCEPTION 'signing_key_history is append-only: only active_until may be set'
                USING ERRCODE = 'P0001';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER signing_key_history_append_only
    BEFORE UPDATE OR DELETE ON signing_key_history
    FOR EACH ROW EXECUTE FUNCTION signing_key_history_append_only_trigger();

-- ── 2. revoked_keys ─────────────────────────────────────────────────────

-- Revoked keys. A retired key's pubkey lives here for life so a verifier
-- can confirm "this signature is from a key Polaris USED to control."
CREATE TABLE revoked_keys (
    public_key_did TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason TEXT NOT NULL DEFAULT 'rotation'
);

-- Append-only: no DELETE, no UPDATE allowed on revoked rows.
CREATE OR REPLACE FUNCTION revoked_keys_append_only_trigger()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'revoked_keys is append-only: DELETE rejected'
            USING ERRCODE = 'P0001';
    END IF;
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'revoked_keys is append-only: UPDATE rejected'
            USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER revoked_keys_append_only
    BEFORE UPDATE OR DELETE ON revoked_keys
    FOR EACH ROW EXECUTE FUNCTION revoked_keys_append_only_trigger();

-- ── 3. rotation_state ───────────────────────────────────────────────────

-- Rotation state machine. One row per in-flight rotation, keyed by a
-- random UUID. Steps progress monotonically forward. Resumability:
-- a CLI run with --resume picks up at next_step where the prior run died.
CREATE TYPE rotation_step AS ENUM (
    'pending',
    'key_generated',
    'key_written',
    'service_record_published',
    'history_recorded',
    'old_key_revoked',
    'swapped',
    'complete',
    'aborted'
);

CREATE TABLE rotation_state (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_step rotation_step NOT NULL DEFAULT 'pending',
    last_step_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    custody_mode TEXT NOT NULL,
    -- New keypair's public did (filled after key_generated).
    new_public_key_did TEXT,
    -- Old keypair's public did (filled at start).
    old_public_key_did TEXT,
    -- Filesystem path the rotation CLI writes the new key material to
    -- (file-plain mode). Set at step pending->key_generated; consulted at
    -- the resume path's idempotency check so a re-run after a crash between
    -- key_generated and key_written does not re-roll a fresh keypair.
    new_key_path TEXT,
    error TEXT
);

CREATE INDEX rotation_state_last_step_idx ON rotation_state(last_step);

INSERT INTO _polaris_schema_version (version, description) VALUES (15, 'key-rotation');
