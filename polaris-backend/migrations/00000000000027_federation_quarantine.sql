-- Issue #107 / M5 PR 1: federation_quarantine table.
--
-- Incoming records from configured peer Polaris instances land here
-- after the Firehose subscription worker receives them. Records stay
-- in quarantine until the state-machine worker (PR 2 / #108) promotes
-- verified records into the active case store.
--
-- Signature status discriminants:
--   'verified'       — signature checked against peer's declared pubkey; OK.
--   'verify_failed'  — signature check ran but did not pass. The record
--                      is kept for audit but MUST NOT influence case state.
--   'unsigned'       — frame carried no signature field. Treated the same
--                      as 'verify_failed' for promotion purposes.
--
-- `cid TEXT PRIMARY KEY` — the record CID is the natural dedup key.
-- `ON CONFLICT DO NOTHING` on insert means replay-on-reconnect is safe.

CREATE TABLE federation_quarantine (
    cid             TEXT        NOT NULL,
    source_did      TEXT        NOT NULL,
    nsid            TEXT        NOT NULL,
    raw_cbor        BYTEA       NOT NULL,
    signature_status TEXT       NOT NULL
        CHECK (signature_status IN ('verified', 'verify_failed', 'unsigned')),
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT federation_quarantine_pkey PRIMARY KEY (cid)
);

-- Fast "give me all rows from peer X" query for the #108 promotion pass.
CREATE INDEX federation_quarantine_source_idx
    ON federation_quarantine (source_did);

-- Fast time-range scans for the admin dashboard (#111) and the
-- promotion worker's "claim the oldest batch" query.
CREATE INDEX federation_quarantine_received_idx
    ON federation_quarantine (received_at);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (28, 'federation-quarantine');
