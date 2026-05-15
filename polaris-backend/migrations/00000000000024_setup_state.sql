-- Issue #85: setup-wizard tracking. Records the operator's setup
-- progress so a re-visited /setup can resume cleanly.
--
-- The table is a singleton (CHECK id = TRUE) because the setup-state
-- is global to the deployment: one labeler service entry, one signing
-- key, one DID document update. The row is INSERTed by this migration
-- so every `UPDATE polaris_setup_state SET ...` succeeds without a
-- per-call upsert dance.
CREATE TABLE polaris_setup_state (
    id              BOOLEAN     PRIMARY KEY DEFAULT TRUE,
    signing_key_path TEXT,
    signing_pubkey_did TEXT,
    labeler_record_uri TEXT,
    did_document_updated_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (id = TRUE)  -- singleton row
);

INSERT INTO polaris_setup_state (id) VALUES (TRUE)
    ON CONFLICT DO NOTHING;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (25, 'setup-state');
