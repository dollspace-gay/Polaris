-- Pending auto-actions — assisted-mode draft queue (#233, LLM-3 / REQ-E1).
--
-- Materialises the assisted-mode review queue for the LLM moderation
-- assist subsystem (`.design/llm-moderation-assist.md`). When the
-- dispatcher decides a recommendation is good enough to act on but the
-- covering policy is in `autonomy_mode = 'assisted'`, the recommended
-- action is staged here as a draft instead of firing directly. A
-- moderator approves or rejects the draft via the queue endpoints
-- (REQ-E2..E4) — nothing reaches atproto without a human click.
--
-- Schema notes:
--
-- * `recommended_action JSONB` carries the full `RecommendedAction`
--   payload from the LLM (action_kind, label_value, subject_scope,
--   confidence, cited_policy_identifiers, reasoning, caveats). The
--   approve handler in LLM-7 (#236) feeds this verbatim into the
--   existing action-create path.
--
-- * `llm_observation_id` pins the draft to the `LlmRecommendation`
--   observation row (kind = `'llm_recommendation'`, migration 49) that
--   backs it. Two-way audit: from the case-view observation panel
--   you can find the draft, and from the queue page you can pivot
--   back to the LLM's full response.
--
-- * `cited_policy_versions JSONB` is a snapshot of
--   `[{identifier, version}]` so the moderator's eventual
--   approve-click cites the *same* policy versions the LLM saw at
--   recommendation time. The mod_policies workbook (#223) can
--   amend a policy between recommendation and approval; without
--   this snapshot the approve handler would silently re-cite a
--   different version.
--
-- * `state` walks the lifecycle: `pending` → `approved`/`rejected` (or
--   `superseded` when a fresh recommendation invalidates an older
--   draft, or `expired` when the row's `expires_at` lapses without
--   moderator action). The CHECK constraint mirrors the typed
--   repo's enum decoder when LLM-7 (#236) lands.
--
-- * `claimed_by_moderator_id` mirrors the existing case-lock pattern
--   in `incidents.locked_by` — set when a moderator opens the case
--   so two moderators don't race to approve the same draft.
--
-- * `expires_at` defaults to `now() + 7 days`. After expiry a daily
--   sweep transitions `pending → expired` (worker in LLM-7); the
--   dispatcher is then free to ask the LLM to re-recommend if the
--   case is still open.
--
-- Indexes are tuned for three queries:
--
--   1. "give me the moderator's open queue" — partial index on
--      `(state, expires_at)` filtered to `state = 'pending'`.
--   2. "did anyone claim this draft yet?" — partial index on
--      `claimed_by_moderator_id` filtered to `state = 'pending'`.
--   3. "show me every pending draft on this subject" — composite
--      index on `(subject_id, created_at DESC)` for the case-view
--      sidebar.
--
-- Pairs with migration 49 (observations enum) and migration 51
-- (actions audit cols). The repo + endpoints land in LLM-7 (#236)
-- and the dispatcher in LLM-5 (#242).

CREATE TABLE pending_auto_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    incident_id UUID NOT NULL
        REFERENCES incidents(id) ON DELETE CASCADE,

    subject_id UUID NOT NULL
        REFERENCES subjects(id) ON DELETE CASCADE,

    -- Full `RecommendedAction` payload — verbatim from the LLM.
    recommended_action JSONB NOT NULL,

    -- The `LlmRecommendation` observation backing this draft.
    llm_observation_id UUID NOT NULL
        REFERENCES observations(id),

    -- Snapshot `[{identifier, version}]` at recommendation time so
    -- approval cites the same policy versions the LLM grounded
    -- against (REQ-E1).
    cited_policy_versions JSONB NOT NULL,

    -- Lifecycle. The CHECK is the source of truth for the typed
    -- repo's enum decoder; adding a state requires both a migration
    -- and a polaris-types update so wire form and schema stay in
    -- lock-step.
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'approved', 'rejected',
                         'superseded', 'expired')),

    -- Case-lock equivalent: set when a moderator opens the case
    -- and starts working it. Cleared when the row resolves.
    claimed_by_moderator_id UUID
        REFERENCES moderators(id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Set when `state` leaves `pending`; NULL while pending.
    resolved_at TIMESTAMPTZ,

    -- 7-day expiry. The sweeper transitions stale rows to
    -- `expired` and the dispatcher may re-recommend.
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '7 days')
);

-- Moderator-queue read path: "give me the open drafts in
-- expiry order". The partial-index predicate matches the typed
-- repo's query verbatim so Postgres reads the index without
-- a heap visit on the hot path.
CREATE INDEX pending_auto_actions_pending_by_expiry_idx
    ON pending_auto_actions (state, expires_at)
    WHERE state = 'pending';

-- "Who's currently working this draft?" — for the moderator
-- dashboard "claimed by me" filter and the lock-contention
-- detector.
CREATE INDEX pending_auto_actions_claimed_idx
    ON pending_auto_actions (claimed_by_moderator_id)
    WHERE state = 'pending';

-- Case-view sidebar query: "show me every pending draft on
-- this subject" (REQ-J1 will surface this in the LLM panel).
CREATE INDEX pending_auto_actions_subject_created_idx
    ON pending_auto_actions (subject_id, created_at DESC);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (50, 'pending-auto-actions');
