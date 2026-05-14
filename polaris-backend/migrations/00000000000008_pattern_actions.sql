-- Pattern actions (issue #21).
--
-- design.md §5.3: moderators act on patterns directly ("apply label X to every
-- account that posted this image hash in the last 48h"). Every affected
-- subject still gets an individual `actions` row so audit + reversal work the
-- same way as for single-subject actions. Pattern actions affecting more than
-- N subjects require a senior co-sign — the threshold lives in config
-- (default 100; see `PatternActionsConfig::cosign_threshold`).
--
-- Three tables:
--
-- 1. `pattern_actions` — header row carrying the selector, action template,
--    affected-subject count, threshold decision, and workflow status.
-- 2. `pattern_action_signatures` — one row per moderator signature. The
--    proposer's signature lives here implicitly via `pattern_actions.requested_by`;
--    a senior co-sign writes a second row with a different `signing_moderator_id`.
--    No boolean `senior_approved` field — the audit trail wants the signing
--    moderator's id + timestamp, not a flag.
-- 3. `pattern_action_subjects` — the projected affected-subject set. Inserted
--    transactionally alongside the per-subject `actions` rows so the
--    `actions` table never carries dangling per-pattern attribution.

CREATE TABLE pattern_actions (
    id                       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Selector kind. The wire form matches polaris-backend's
    -- `PatternSelector` enum discriminator.
    selector_kind            TEXT         NOT NULL
        CHECK (selector_kind IN (
            'image_hash_cluster',
            'account_cohort',
            'anomaly_bucket'
        )),
    -- Typed payload for the selector. The Rust enum's per-variant fields
    -- live here as a JSON object; the discriminator above is what the
    -- service layer dispatches on when resolving subjects.
    selector_data            JSONB        NOT NULL,
    -- Action template. Same set as `polaris_types::ActionKind` minus the
    -- `reverse` variant (pattern actions don't reverse other actions —
    -- they CREATE per-subject Action rows that can themselves be
    -- reversed individually via the existing #36 path).
    action_kind              TEXT         NOT NULL
        CHECK (action_kind IN (
            'label', 'takedown', 'mute', 'warn', 'escalate', 'no_action'
        )),
    -- Label value, only meaningful when `action_kind = 'label'`.
    label_value              TEXT,
    -- Free-text reasoning. Mirrors the same minimum-length rule applied
    -- to the per-subject `actions` table (§5.5).
    reasoning                TEXT         NOT NULL
        CHECK (length(reasoning) >= 10),
    -- Policy clauses cited. Same TEXT[] shape as `actions.policy_refs`.
    policy_refs              TEXT[]       NOT NULL DEFAULT '{}',
    -- Snapshot of the projected affected-subject count at propose time.
    -- Drives the `requires_cosign` decision and is what the senior sees
    -- before approving. Recorded explicitly (rather than derived from the
    -- subjects join table) so the audit trail captures the propose-time
    -- count even if the underlying selector resolution later changes.
    affected_subject_count   INT          NOT NULL,
    -- Whether this pattern action needs a senior co-sign before
    -- execution. Computed at propose time from the config threshold;
    -- materialised here so the cosign endpoint can reject a "cosign of an
    -- auto-approved action" without re-reading config.
    requires_cosign          BOOLEAN      NOT NULL,
    -- Workflow state.
    --   proposed  — header inserted, awaiting cosign (or about to auto-execute).
    --   executing — transaction in flight (used by future async paths; the
    --               synchronous M2 implementation transitions
    --               proposed → executed directly inside the same txn).
    --   executed  — per-subject Action rows have been inserted.
    --   cancelled — the proposer or a senior cancelled the proposal
    --               before execution.
    status                   TEXT         NOT NULL
        CHECK (status IN ('proposed', 'executing', 'executed', 'cancelled'))
        DEFAULT 'proposed',
    requested_by             UUID         NOT NULL REFERENCES moderators(id),
    requested_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    executed_at              TIMESTAMPTZ
);

CREATE INDEX pattern_actions_status_idx
    ON pattern_actions (status);

CREATE INDEX pattern_actions_requested_by_idx
    ON pattern_actions (requested_by);

CREATE INDEX pattern_actions_requires_cosign_idx
    ON pattern_actions (requires_cosign, status)
    WHERE requires_cosign = TRUE AND status = 'proposed';

-- ── signatures ──────────────────────────────────────────────────────────
-- One row per signature. The proposer is already attributed via
-- `pattern_actions.requested_by`; the cosign endpoint inserts a row here
-- with `signing_moderator_id = <senior>`. The composite PK prevents a
-- duplicate cosign by the same moderator and gives the cosign endpoint a
-- cheap unique-violation channel for re-submissions.
CREATE TABLE pattern_action_signatures (
    pattern_action_id        UUID         NOT NULL
        REFERENCES pattern_actions(id) ON DELETE CASCADE,
    signing_moderator_id     UUID         NOT NULL REFERENCES moderators(id),
    signed_at                TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (pattern_action_id, signing_moderator_id)
);

CREATE INDEX pattern_action_signatures_moderator_idx
    ON pattern_action_signatures (signing_moderator_id);

-- ── affected-subject join ───────────────────────────────────────────────
-- The materialised set of subjects the pattern action targets. Inserted
-- by `execute_pattern_action` inside the same transaction as the
-- per-subject `actions` rows, so the join table can never reference a
-- subject that didn't also get an Action row (transactional all-or-nothing).
-- `incident_id` is recorded when the resolver knows it — for selectors
-- backed by an incident-bearing observation we can attribute the per-
-- subject action to the right incident; otherwise it's NULL and the
-- Action row uses a synthesised incident (future work — for #21 the
-- resolver helpers populate this when possible).
CREATE TABLE pattern_action_subjects (
    pattern_action_id        UUID         NOT NULL
        REFERENCES pattern_actions(id) ON DELETE CASCADE,
    subject_id               UUID         NOT NULL REFERENCES subjects(id),
    incident_id              UUID         REFERENCES incidents(id),
    PRIMARY KEY (pattern_action_id, subject_id)
);

CREATE INDEX pattern_action_subjects_subject_id_idx
    ON pattern_action_subjects (subject_id);

INSERT INTO _polaris_schema_version (version, description)
VALUES (9, 'pattern-actions');
