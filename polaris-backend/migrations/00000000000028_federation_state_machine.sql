-- Issue #108 / M5 PR 2: federation state machine — 4 tables.
--
-- These tables implement the persistent half of the cross-instance federation
-- state machine (design.md §M5, REQ-7, AC-7). The companion Rust module
-- (`polaris-backend/src/federation/state.rs`) holds the transition validator;
-- `polaris-backend/src/repo/federation.rs` holds the sqlx queries.
--
-- Tables added:
--   federation_peers             — authorised peer DID ↔ direction ↔ trust label
--   federation_escalations       — one row per incoming escalation, tracks state
--   federation_messages          — append-only per-escalation message log
--   federation_state_transitions — append-only state-change audit trail
--
-- Append-only enforcement:
--   federation_state_transitions and federation_messages are append-only by
--   convention (no UPDATE/DELETE in the repo layer). If this schema is ever
--   deployed with per-table role grants, GRANT INSERT, SELECT on these two
--   tables (omitting UPDATE and DELETE) enforces the invariant at the DB level.
--   A CHECK constraint comment is added below as a policy marker.
--
-- Migration numbering:
--   File 0028, schema_version 29 (0027 / version 28 = federation_quarantine).

-- ── federation_peers ──────────────────────────────────────────────────────

CREATE TABLE federation_peers (
    did             TEXT        NOT NULL,
    direction       TEXT        NOT NULL
        CHECK (direction IN ('bidirectional', 'incoming_only', 'outgoing_only')),
    trust_label     TEXT,               -- operator-assigned label ("verified", "experimental", …)
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT federation_peers_pkey PRIMARY KEY (did)
);

-- ── federation_escalations ────────────────────────────────────────────────

CREATE TABLE federation_escalations (
    id              UUID        NOT NULL,
    source_did      TEXT        NOT NULL,
    target_did      TEXT        NOT NULL,
    state           TEXT        NOT NULL
        CHECK (state IN (
            'proposed',
            'acknowledged',
            'active',
            'resolved',
            'withdrawn_by_source',
            'rejected_by_target'
        )),
    subject_did_or_uri TEXT     NOT NULL,
    -- original_cid is the federation_quarantine CID that was promoted.
    -- UNIQUE ensures quarantine→escalation promotion is idempotent:
    -- a replayed INSERT returns 0 rows without error.
    original_cid    TEXT        NOT NULL,
    reason          TEXT,
    opened_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_event_at   TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT federation_escalations_pkey PRIMARY KEY (id),
    CONSTRAINT federation_escalations_original_cid_unique UNIQUE (original_cid)
);

-- Index for "give me all escalations in state X" (promotion worker + admin UI)
CREATE INDEX federation_escalations_state_idx
    ON federation_escalations (state);

-- Index for "give me all escalations between peer pair" (admin dashboard #111)
CREATE INDEX federation_escalations_peer_pair_idx
    ON federation_escalations (source_did, target_did);

-- ── federation_messages ───────────────────────────────────────────────────
-- APPEND-ONLY: INSERT + SELECT only. No UPDATE or DELETE.

CREATE TABLE federation_messages (
    id              UUID        NOT NULL,
    escalation_id   UUID        NOT NULL
        REFERENCES federation_escalations (id),
    source_did      TEXT        NOT NULL,
    message_cid     TEXT        NOT NULL,
    body            TEXT        NOT NULL,
    signature_status TEXT       NOT NULL,
    signed_at       TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT federation_messages_pkey PRIMARY KEY (id),
    -- UNIQUE on message_cid prevents duplicate delivery on replay.
    CONSTRAINT federation_messages_message_cid_unique UNIQUE (message_cid)
);

-- Index for "give me all messages for escalation X, ordered by time"
CREATE INDEX federation_messages_escalation_time_idx
    ON federation_messages (escalation_id, signed_at);

-- ── federation_state_transitions ──────────────────────────────────────────
-- APPEND-ONLY: INSERT + SELECT only. No UPDATE or DELETE.
-- This table is the audit trail for the state machine. Every state change
-- records who triggered it and what CID carried the event. The BIGSERIAL PK
-- gives a total ordering independent of clock skew.

CREATE TABLE federation_state_transitions (
    id              BIGSERIAL   NOT NULL,
    escalation_id   UUID        NOT NULL
        REFERENCES federation_escalations (id),
    from_state      TEXT        NOT NULL,
    to_state        TEXT        NOT NULL,
    triggered_by_cid TEXT,      -- NULL for internal transitions (e.g. operator action)
    at              TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT federation_state_transitions_pkey PRIMARY KEY (id)
);

-- Index for "give me the full transition history of escalation X"
CREATE INDEX federation_state_transitions_escalation_time_idx
    ON federation_state_transitions (escalation_id, at);

-- ── schema_version ────────────────────────────────────────────────────────

INSERT INTO _polaris_schema_version (version, description)
    VALUES (29, 'federation-state-machine');
