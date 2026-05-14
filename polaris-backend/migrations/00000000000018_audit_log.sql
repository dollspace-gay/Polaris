-- Hash-chained audit log (design.md §6 + §9).
--
-- Every mutation (action, key rotation, config change, etc.) appends
-- a row here. Each row's this_hash commits the previous row's
-- this_hash. Internal tampering with a historic row breaks the chain
-- at that row and every row after.
--
-- ## Canonical bytes signed by SHA-256
--
-- preimage = prev_hash || canonical_cbor(payload) || iso8601_utc(ts) ||
--            actor_bytes || kind_bytes
--
-- Where ts is rendered "YYYY-MM-DDTHH:MM:SS.ffffffZ" (microsecond
-- precision, always UTC), actor is the actor string UTF-8 bytes, kind
-- is the kind string UTF-8 bytes. prev_hash is 32 zero bytes for the
-- genesis row (seq = 1).
--
-- The canonical CBOR encoder is `proto_blue::lex_cbor::encode`, which
-- enforces strict DAG-CBOR canonicality (length-then-lex sorted map
-- keys, shortest-form integers, no floats, no indefinite-length
-- items). The Rust hash is computed in `polaris-backend/src/audit/log.rs`
-- BEFORE the INSERT; the BEFORE INSERT trigger below verifies the
-- chain ordering but does not recompute the hash (Postgres has no
-- stock DAG-CBOR extension).

CREATE TABLE audit_log (
    seq        BIGSERIAL    PRIMARY KEY,
    ts         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Actor identifier — moderator UUID, "system", "worker", etc.
    actor      TEXT         NOT NULL,
    -- Event kind: action.commit, action.reverse, key.rotate,
    -- config.change, attestation.head, etc. Free-form string; closed
    -- set documented in audit/log.rs.
    kind       TEXT         NOT NULL,
    -- The event payload as JSONB. Canonical CBOR is computed at
    -- record() time from this value (Postgres has no JSON canonical
    -- form, so we re-canonicalize from JSONB to CBOR-deterministic).
    payload    JSONB        NOT NULL DEFAULT '{}'::JSONB,
    -- 32-byte SHA-256 of the previous row's this_hash. For seq = 1,
    -- 32 zero bytes.
    prev_hash  BYTEA        NOT NULL,
    -- 32-byte SHA-256 of (prev_hash || canonical_cbor(payload) || ts || actor || kind).
    -- Computed app-side (Postgres extensions for CBOR are not available
    -- in stock distros); the trigger only enforces the chain ordering.
    this_hash  BYTEA        NOT NULL,

    -- Length invariants.
    CHECK (octet_length(prev_hash) = 32),
    CHECK (octet_length(this_hash) = 32)
);

CREATE INDEX audit_log_ts_idx ON audit_log(ts);
CREATE INDEX audit_log_actor_idx ON audit_log(actor);
CREATE INDEX audit_log_kind_idx ON audit_log(kind);

-- Append-only enforcement: no UPDATE, no DELETE.
CREATE OR REPLACE FUNCTION audit_log_append_only()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % rejected', TG_OP
        USING ERRCODE = 'P0001';
END $$;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- Chain-ordering enforcement: each row's prev_hash MUST equal the
-- this_hash of the row with seq = NEW.seq - 1. Genesis (seq = 1) MUST
-- have prev_hash = 32 zero bytes.
CREATE OR REPLACE FUNCTION audit_log_chain_check()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    expected_prev BYTEA;
BEGIN
    IF NEW.seq = 1 THEN
        expected_prev := decode(repeat('00', 32), 'hex');
    ELSE
        SELECT this_hash INTO expected_prev
            FROM audit_log WHERE seq = NEW.seq - 1;
        IF expected_prev IS NULL THEN
            RAISE EXCEPTION 'audit_log chain hole: seq % missing predecessor seq %',
                NEW.seq, NEW.seq - 1 USING ERRCODE = 'P0001';
        END IF;
    END IF;
    IF NEW.prev_hash != expected_prev THEN
        RAISE EXCEPTION 'audit_log chain break: seq % prev_hash mismatch',
            NEW.seq USING ERRCODE = 'P0001';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER audit_log_chain BEFORE INSERT ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_chain_check();

INSERT INTO _polaris_schema_version (version, description)
    VALUES (19, 'audit-log');
