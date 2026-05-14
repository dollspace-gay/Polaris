-- Actions table — append-only audit substrate (issue #13).
--
-- design.md §4 + §5.5: every moderator decision is recorded as an `Action`.
-- Actions are append-only. Reversal does not mutate the original row;
-- instead, a new action with `kind = 'reverse'` and `reverses_action_id =
-- <original.id>` is written. The original row therefore never carries a
-- back-pointer — `reversed_by` is derived at read time via
--
--     SELECT a.*, r.id AS reversed_by
--       FROM actions a
--       LEFT JOIN actions r ON r.reverses_action_id = a.id
--
-- so the "no UPDATE on actions" invariant is total.
--
-- The append-only invariant is enforced at the database in two ways:
--   1. No code path in polaris-backend emits an UPDATE against `actions` —
--      see `polaris-backend/src/repo/action.rs` (`ActionRepo` exposes only
--      `insert` / `get` / `list_by_incident`).
--   2. A BEFORE UPDATE trigger raises an exception unconditionally so any
--      future writer (a buggy migration, a hand-crafted query, a tool that
--      bypasses the repo) is rejected at the database boundary.

CREATE TABLE actions (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id         UUID         NOT NULL REFERENCES incidents(id),
    subject_id          UUID         NOT NULL REFERENCES subjects(id),
    moderator_id        UUID         NOT NULL REFERENCES moderators(id),
    kind                TEXT         NOT NULL
        CHECK (kind IN ('label', 'takedown', 'mute', 'warn',
                        'escalate', 'no_action', 'reverse')),
    -- Label value (e.g. `spam`, `!hide`). Non-null only for `kind = 'label'`,
    -- but we don't enforce that constraint at the DB layer: the §5.5 design
    -- allows future action verbs that may also carry a label.
    label_value         TEXT,
    -- Free-text reasoning is mandatory per design.md §5.5. The 10-char
    -- minimum rejects trivial fillers like "ok" or "n/a" at the DB.
    reasoning           TEXT         NOT NULL
        CHECK (length(reasoning) >= 10),
    -- Policy refs are stored as a TEXT[] so the typical "cite a handful of
    -- clauses" pattern is one column read, not a join.
    policy_refs         TEXT[]       NOT NULL DEFAULT '{}',
    reversible_until    TIMESTAMPTZ  NOT NULL,
    -- Set only when `kind = 'reverse'` — points at the action this row
    -- reverses. The original action is NOT mutated; this is the only
    -- direction of the reverse-relation that lives in-row.
    reverses_action_id  UUID         REFERENCES actions(id),
    emitted_to_atproto  TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX actions_incident_id_idx
    ON actions (incident_id);

CREATE INDEX actions_subject_id_idx
    ON actions (subject_id);

CREATE INDEX actions_moderator_created_at_idx
    ON actions (moderator_id, created_at);

CREATE INDEX actions_reverses_action_id_idx
    ON actions (reverses_action_id)
    WHERE reverses_action_id IS NOT NULL;

-- ── append-only enforcement ─────────────────────────────────────────────
-- The trigger fires BEFORE UPDATE and raises an exception unconditionally.
-- Any future writer that tries to mutate an action row — for any reason —
-- is rejected at the database boundary with a self-explanatory error.
CREATE OR REPLACE FUNCTION actions_reject_update()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'actions is append-only; reversals write a new row with kind = reverse and reverses_action_id pointing at the original (design.md §5.5)';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER actions_no_update
    BEFORE UPDATE ON actions
    FOR EACH ROW
    EXECUTE FUNCTION actions_reject_update();

INSERT INTO _polaris_schema_version (version, description)
VALUES (5, 'actions-append-only');
