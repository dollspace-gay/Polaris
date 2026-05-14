-- Labels table — labeler persistence shape (issue #26).
--
-- design.md §5.9 + .design/polaris-proto-blue-integration.md REQ-1, AC-1, §B:
-- Polaris hosts `com.atproto.label.subscribeLabels` and `queryLabels` as the
-- downstream-facing labeler. Every row in this table is a `com.atproto.label.defs::Label`
-- destined for both the WebSocket subscription stream (`subscribeLabels`) and the
-- query-by-URI endpoint (`queryLabels`).
--
-- Column shape mirrors atproto's Label record:
--   src  — DID of the labeler emitter (this Polaris instance's signing DID).
--   uri  — subject AT-URI or DID being labeled.
--   cid  — optional content-CID pin (when the label targets a specific revision).
--   val  — label value (e.g. `spam`, `!hide`).
--   neg  — negation flag (true = retracting an earlier label).
--   cts  — created-at timestamp (server-assigned).
--   exp  — optional expiration timestamp.
--   sig  — K-256 signature bytes over the canonical-JSON serialisation of
--          the unsigned label fields. Filled by #28 via the signing path.
--          NOT NULL with empty-bytes placeholder for #26 backfill rows so
--          existing inserts don't have to thread Option<Vec<u8>> through
--          the wire types before the signer lands.
--
-- `seq` is a BIGSERIAL — Postgres guarantees per-row monotonicity but NOT
-- absence of gaps across rolled-back txns. atproto's subscription protocol
-- only requires monotonicity (gaps are acceptable; consumers track
-- `cursor = max(seq)` and accept that `seq` may skip ahead). The
-- `subscribeLabels` handler streams rows ordered by `seq` from the
-- caller-supplied cursor, so gaps are transparently handled.
--
-- `action_id` is a nullable FK to the originating action. Labels created
-- through the moderator API will carry it; labels migrated/imported from
-- an external source (or the #26 test fixtures) leave it NULL.

CREATE TABLE labels (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    seq        BIGSERIAL    UNIQUE NOT NULL,
    src        TEXT         NOT NULL,
    uri        TEXT         NOT NULL,
    cid        TEXT,
    val        TEXT         NOT NULL,
    neg        BOOLEAN      NOT NULL DEFAULT FALSE,
    cts        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    exp        TIMESTAMPTZ,
    sig        BYTEA        NOT NULL,
    action_id  UUID         REFERENCES actions(id)
);

CREATE INDEX labels_uri_idx ON labels(uri);
CREATE INDEX labels_seq_idx ON labels(seq);

INSERT INTO _polaris_schema_version (version, description)
VALUES (13, 'labels');
