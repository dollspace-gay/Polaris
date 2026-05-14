-- Operator-configured upstream labelers Polaris ingests from (issue #32,
-- REQ-9 / AC-10). Each row is one upstream subscribeLabels source whose
-- signed labels are turned into `Observation { kind: ExternalLabel { … } }`
-- rows on the matching subject.
--
-- Three tables:
--
--   upstream_labelers          — the operator-managed config: which upstreams
--                                 to subscribe to, per-category trust weights.
--   upstream_labeler_keys      — cache of the upstream's signing pubkey,
--                                 looked up via app.bsky.labeler.service.
--                                 TTL'd; expired rows trigger refresh.
--   upstream_labeler_cursors   — per-upstream resume cursor (the last
--                                 acknowledged subscribeLabels seq). On
--                                 reconnect the consumer resumes from this
--                                 point so no labels are lost.

CREATE TABLE upstream_labelers (
    -- Upstream's DID (their `app.bsky.labeler.service` record subject).
    did TEXT PRIMARY KEY,
    -- Their public hostname / WSS endpoint base (without /xrpc/...).
    hostname TEXT NOT NULL,
    -- Per-category trust weights as a JSON object, e.g.:
    --   { "spam": 0.4, "csam": 0.95, "_default": 0.5 }
    --
    -- Lookup is by label `val`; the optional `_default` key overrides the
    -- hard-coded default weight (0.5) when a label's value isn't in the map.
    weights JSONB NOT NULL DEFAULT '{}'::JSONB,
    -- Soft-disable without dropping the row (preserves historical refs).
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Cached upstream signing keys, looked up via the upstream's
-- `app.bsky.labeler.service` record. Cache has a TTL; expired rows trigger
-- refresh on next consume.
CREATE TABLE upstream_labeler_keys (
    did TEXT PRIMARY KEY REFERENCES upstream_labelers(did) ON DELETE CASCADE,
    -- did:key:z... multikey form (what `proto_blue::crypto::verify_signature`
    -- accepts directly).
    signing_pubkey_did TEXT NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '24 hours')
);
CREATE INDEX upstream_labeler_keys_expires_at_idx
    ON upstream_labeler_keys(expires_at);

-- Per-upstream cursor — the last-acknowledged subscribeLabels seq.
-- Reconnect resumes from this point so AC-10's "no label loss" property
-- holds across transient disconnects (cf. firehose_cursor in migration 2).
CREATE TABLE upstream_labeler_cursors (
    did TEXT PRIMARY KEY REFERENCES upstream_labelers(did) ON DELETE CASCADE,
    last_seq BIGINT NOT NULL DEFAULT 0,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique partial index on subjects.did for kind='account' rows. AC-10's
-- inbound-label consumer maps every label uri to one account subject via
-- `find_or_create_account_subject`; that idempotent upsert needs a unique
-- constraint at the database to make the ON CONFLICT clause meaningful.
-- The (kind, did) partial index already exists for read paths (migration
-- 00000000000003); this adds the uniqueness invariant for accounts. Posts
-- and other record-kinds keep their nullable, non-unique `did` column.
CREATE UNIQUE INDEX subjects_account_did_uniq
    ON subjects (did)
    WHERE kind = 'account' AND did IS NOT NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (17, 'upstream-labelers');
