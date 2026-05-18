-- Local label index for the case-view "Third-party labels" panel.
--
-- # Why
--
-- The Bluesky AppView's `getProfile` only returns labels from
-- labelers explicitly named in the `atproto-accept-labelers`
-- header. There is no central registry of labelers, so a header-
-- driven approach can only ever surface labels from a hardcoded
-- subset and silently hides every other label.
--
-- The robust answer (matching the open-source `atp-label-indexer`
-- pattern, https://github.com/BunnyNabbit/atp-label-indexer) is to
-- subscribe to each known labeler's `subscribeLabels` firehose,
-- verify each label's signature, and persist it locally. The case-
-- view then queries the local store for every label that targets
-- the subject's DID — comprehensive coverage without any third-
-- party query-time dependency.
--
-- # Schema shape
--
-- Mirrors the wire shape of `com.atproto.label.defs#label`:
--   * `src` — labeler DID that issued the label
--   * `uri` — target AT-URI or DID
--   * `cid` — content CID (only set for post-level labels)
--   * `val` — label value
--   * `neg` — negation flag (true retracts a prior assertion)
--   * `cts` — labeler-stamped creation timestamp
--   * `ver` — label version (1 today; reserved for protocol bumps)
--   * `seq` — firehose sequence number; lets the subscriber resume
--     across restarts and lets the case-view show the most recent
--     state when multiple labels collide.
--
-- # Uniqueness
--
-- One active row per `(src, uri, val)` triple — a labeler issuing
-- a fresh label with the same val replaces (not duplicates) the
-- prior. Negations are persisted as separate rows with `neg=true`
-- so the case-view can render the full history (assert → retract)
-- if it wants; the default query filters `neg=false`.
--
-- # Why a dedicated table vs. `labels` (Polaris-emitted) or
--   `observations` (Polaris-engine-derived)
--
-- - `labels` is Polaris's OWN emission table; conflating it with
--   inbound third-party labels would risk surfacing them on the
--   `subscribeLabels` endpoint Polaris serves.
-- - `observations` carries detector-derived signals; tying every
--   external label to a Polaris-managed `subject_id` would require
--   subjects to exist for every labeled URI, which they do not.
-- - This table is the simple, signed-and-verified store of
--   "what every known labeler has said about anyone."

CREATE TABLE indexed_labels (
    id          BIGSERIAL    PRIMARY KEY,

    -- Labeler DID. The labeler service identified by this DID has
    -- a verifiable signature on the row; the subscriber dropped
    -- the label if `verify_signature(src_key, cbor(rest)) != ok`.
    src         TEXT         NOT NULL,

    -- Target. May be a DID (account-level label) or an AT-URI
    -- (post-, list-, feed-level label).
    uri         TEXT         NOT NULL,

    -- Content CID. Set for post-level labels; NULL for account
    -- labels (where the target is a DID, not an indexable record).
    cid         TEXT,

    -- Label value, lowercase-snake by AT-Proto convention.
    val         TEXT         NOT NULL,

    -- Negation flag. When TRUE the row represents a labeler
    -- retracting a prior assertion of the same `(src, uri, val)`
    -- triple. Default false so a `WHERE neg = FALSE` filter
    -- catches every legit assertion without redundant predicates.
    neg         BOOLEAN      NOT NULL DEFAULT FALSE,

    -- Labeler-stamped creation timestamp (the label's own `cts`).
    -- Distinct from `inserted_at`: `cts` is what the labeler said,
    -- `inserted_at` is when we observed it.
    cts         TIMESTAMPTZ  NOT NULL,

    -- Protocol version. `1` is the AT-Proto label v1 shape; future
    -- bumps may extend the schema.
    ver         INTEGER      NOT NULL DEFAULT 1,

    -- Firehose sequence number reported by the labeler. The
    -- subscriber persists `MAX(seq)` per labeler in
    -- `upstream_labeler_keys.last_seq` (existing column) so a
    -- reconnect can resume from the next event.
    seq         BIGINT       NOT NULL,

    -- Wall-clock arrival time inside Polaris. Used as a tiebreaker
    -- against `cts` when a labeler's clock skews.
    inserted_at TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- One active assertion per `(src, uri, val)`. A repeated
    -- assertion replaces the prior; negations are persisted as
    -- separate rows so the history is preserved (the case-view's
    -- default query filters by `neg = false`).
    UNIQUE (src, uri, val, neg)
);

-- Hot path: "every label on this DID-or-its-records". Postgres
-- planner uses the index on `uri` LIKE 'at://<did>/%' via prefix
-- match because `uri` is btree-indexable and the like-pattern is
-- left-anchored.
CREATE INDEX indexed_labels_uri_idx
    ON indexed_labels (uri);

-- For per-labeler lookups (e.g. an admin debug surface listing
-- "every label this src has emitted").
CREATE INDEX indexed_labels_src_idx
    ON indexed_labels (src);

-- For chronological queries — the case-view orders by `cts DESC`
-- to show the most-recent assertions first.
CREATE INDEX indexed_labels_cts_idx
    ON indexed_labels (cts DESC);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (35, 'indexed_labels — local index of every label emitted by every subscribed labeler');
