-- Mod policies workbook — structured policy clauses (#223, WB-1).
--
-- Background: the moderator-facing action surface today cites policy via
-- the hardcoded `KNOWN_POLICY_REFS` slice in
-- `polaris-backend/src/api/policy.rs` (five placeholder identifiers) and
-- via free-text `reasoning` on `actions`. That shape blocks three
-- downstream capabilities the operator now needs:
--
--   * operator-configurable policy rules (add / amend / retire),
--   * machine-readable per-action citation of the *exact wording* in
--     force at action-create time (REQ-B1 / REQ-A1 in
--     `.design/mod-policy-workbook.md`),
--   * per-policy autonomy controls consumed by the LLM-assist design
--     (`.design/llm-moderation-assist.md`).
--
-- This migration introduces `mod_policies`, the versioned workbook
-- backing the above. Every edit produces a new row; the prior row
-- stays in place with `effective_until = now()` so historical actions
-- always resolve to the wording that was binding when they fired.
-- Retirement is implemented as a tombstone supersession with
-- `is_retired = TRUE` rather than a destructive DELETE — citations
-- to a retired version remain readable, only *new* citations to it
-- are rejected (REQ-F1).
--
-- The companion table `action_policy_citations` (migration 48) carries
-- the `(action_id, identifier, version)` triple per cited clause and
-- holds the composite FK back into this table; that FK is the reason
-- this migration creates the `UNIQUE (identifier, version)` constraint
-- (a multi-column FK requires a matching unique target).
--
-- Column-by-column notes live alongside the column. The CHECKs encode
-- the contract the typed repo layer reads back; treat them as the
-- source of truth (the Rust enum decoders mirror them).

CREATE TABLE mod_policies (
    -- Row identity. UUID rather than `identifier` so amendments can
    -- chain via `supersedes_id` without colliding with the per-version
    -- natural key (`identifier`, `version`).
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Human-stable identifier — `polaris.harassment`, `polaris.spam`,
    -- etc. The action API cites by `(identifier, version)`; the
    -- `identifier` half is what the moderator types.
    identifier TEXT NOT NULL,

    -- Monotonic edit counter. 1 on initial insert; the amend path
    -- writes `version = prior.version + 1` while holding a
    -- `SELECT … FOR UPDATE` on the prior current-version row, so
    -- concurrent amendments serialise rather than collide on the
    -- `(identifier, version)` UNIQUE constraint.
    version INTEGER NOT NULL,

    -- Short human-readable title surfaced in lists and dropdowns.
    name TEXT NOT NULL,

    -- One-paragraph summary rendered at the top of the policy detail
    -- view and embedded in the LLM context. Required.
    description TEXT NOT NULL,

    -- Atproto `LabelValueDefinition.targets` vocabulary. The CHECK
    -- mirrors the polaris-types enum decoder; adding a new variant
    -- here without updating the Rust decoder is a schema-drift bug
    -- the repo's `RepoError::Decode` variant catches at read time.
    scope TEXT NOT NULL
        CHECK (scope IN ('account', 'post', 'both')),

    -- Atproto severity vocabulary. Same drift contract as `scope`.
    severity TEXT NOT NULL
        CHECK (severity IN ('inform', 'alert', 'hide', 'remove')),

    -- Markdown-formatted multi-line text the moderator (and the LLM)
    -- reads to decide whether the policy applies. The 64-char floor
    -- rejects one-word placeholders ("spam.") at insert time rather
    -- than at LLM-grounding time where the failure mode is silent
    -- low-quality reasoning.
    decision_criteria TEXT NOT NULL
        CHECK (length(decision_criteria) >= 64),

    -- Worked-example corpora. Stored as JSONB arrays of objects with
    -- shape `{excerpt, context, expected_action_kind}` (positive) and
    -- `{excerpt, context, why_not_a_violation}` (negative). The repo
    -- layer ferries them as `serde_json::Value` — the shape is the
    -- frontend's contract, not the database's; the DB just keeps
    -- the bytes.
    examples_positive JSONB NOT NULL DEFAULT '[]',
    examples_negative JSONB NOT NULL DEFAULT '[]',

    -- Non-empty subset of the `actions.kind` enum. The non-empty
    -- check prevents a "policy with no recommended action verbs"
    -- row, which would be ambiguous when the LLM-assist design
    -- consults this column for verb suggestions.
    suggested_action_kinds TEXT[] NOT NULL
        CHECK (array_length(suggested_action_kinds, 1) > 0),

    -- Optional pointer at a value declared in
    -- `polaris_setup_state.label_values`. When non-NULL and the
    -- action kind is `label`, the moderator UI defaults the
    -- action's `label_value` to this.
    linked_label_value TEXT,

    -- Free-text "when this policy does not apply". Surfaced in the
    -- detail view; not parsed.
    exceptions TEXT,

    -- REQ-A2: when TRUE, this policy can never run with
    -- `autonomy_mode = 'autonomous'`. The seed file (WB-5 / #227)
    -- sets this TRUE for the `polaris.csam` placeholder; operators
    -- can flip other policies the same way. The hard block is
    -- enforced at the workbook edit API, the action-create API,
    -- AND the LLM dispatcher (REQ-G3) — this column is the
    -- database-level declarative half of that three-layer floor.
    human_required_always BOOLEAN NOT NULL DEFAULT FALSE,

    -- REQ-A3 autonomy controls consumed by the LLM-assist design.
    -- `manual` (default) means the LLM may suggest but never auto-
    -- creates an action. `assisted` puts a draft in the per-
    -- moderator review queue. `autonomous` lets the LLM both
    -- create the action AND emit to atproto when confidence
    -- exceeds the autonomous threshold.
    autonomy_mode TEXT NOT NULL DEFAULT 'manual'
        CHECK (autonomy_mode IN ('manual', 'assisted', 'autonomous')),

    -- Subset of `actions.kind` allowed when `autonomy_mode =
    -- 'autonomous'`. Default empty; the operator broadens
    -- explicitly. The eligibility floor (REQ-G1: only `label`,
    -- `warn`, `takedown` may auto-fire) is enforced at the API
    -- layer because the DB CHECK cannot reference another table's
    -- enum without a trigger.
    autonomous_action_kinds TEXT[] NOT NULL DEFAULT '{}',

    -- Confidence floors gating the LLM's auto-fire decision.
    autonomous_confidence_threshold REAL NOT NULL DEFAULT 0.95
        CHECK (autonomous_confidence_threshold BETWEEN 0.0 AND 1.0),
    assisted_confidence_threshold REAL NOT NULL DEFAULT 0.7
        CHECK (assisted_confidence_threshold BETWEEN 0.0 AND 1.0),

    -- Kill-switch / circuit-breaker output. When non-NULL and in
    -- the future, autonomous actioning is suspended for this
    -- policy. The LLM dispatcher reads this on every recommend
    -- call (no cache) so an operator pause takes effect
    -- immediately.
    autonomous_paused_until TIMESTAMPTZ,

    -- Tombstone marker (REQ-F1). The retire path writes a
    -- successor version with this set; lookups still find the
    -- row and surface "this policy was retired on Y by Z" in
    -- the UI, but new citations to it are rejected by the
    -- action-create API.
    is_retired BOOLEAN NOT NULL DEFAULT FALSE,

    -- Audit fields. `created_by_moderator_id` is required so every
    -- version has an actor; the seed file uses the bootstrap admin.
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_moderator_id UUID NOT NULL REFERENCES moderators(id),

    -- Bitemporal-style validity window. `effective_until IS NULL`
    -- is the "current version" predicate; the amend path writes
    -- `now()` into the prior row's `effective_until` while
    -- inserting the successor.
    effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_until TIMESTAMPTZ,

    -- Self-reference chain. NULL on the initial version (1);
    -- points at the prior `id` for every amendment. Used by
    -- the history endpoint and the audit-log diff renderer.
    supersedes_id UUID REFERENCES mod_policies(id),

    -- "Why this version was written" surfaced in the version
    -- history view. Optional on the initial version; required
    -- by the admin-edit API for amendments (REQ-C2) — that
    -- constraint lives at the API layer, not the DB, because
    -- the seed loader needs to insert v1 rows without prompting
    -- the operator for a change summary.
    change_summary TEXT,

    -- The natural key. The composite FK from
    -- `action_policy_citations(policy_identifier, policy_version)`
    -- targets this constraint.
    UNIQUE (identifier, version)
);

-- Dominant query: "latest version of policy X". Partial index keyed
-- on the predicate the typed repo uses verbatim
-- (`effective_until IS NULL`), so Postgres reads the index without
-- a heap visit for the common lookup.
CREATE INDEX mod_policies_identifier_current_idx
    ON mod_policies (identifier)
    WHERE effective_until IS NULL;

-- Supports the operator-dashboard query "which policies are
-- currently auto-firing" and the LLM dispatcher's "give me the
-- autonomous-eligible policies" warm path. Restricted to current
-- versions (`effective_until IS NULL`) and the non-default mode
-- so the index stays small.
CREATE INDEX mod_policies_autonomy_mode_active_idx
    ON mod_policies (autonomy_mode)
    WHERE autonomy_mode <> 'manual' AND effective_until IS NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (47, 'mod_policies');
