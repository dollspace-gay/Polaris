-- Per-action policy citations (#223, WB-1, REQ-B1).
--
-- Background: today the `actions` table carries policy citations as a
-- flat `policy_refs TEXT[]` — identifiers only, no version pin. That
-- shape was fine while every cited identifier was hardcoded in
-- `KNOWN_POLICY_REFS`, but the workbook (migration 47) introduces
-- versioned amendments: a moderator firing an action under
-- `polaris.harassment v3` must always resolve, on future read, to the
-- v3 wording even if the operator subsequently amends to v4. The
-- `(identifier, version)` snapshot is what makes the action's
-- historical reasoning auditable.
--
-- This table is the per-citation row: one row per (action,
-- policy-version) tuple. An action that cites two clauses produces
-- two rows. The composite PK `(action_id, policy_identifier,
-- policy_version)` prevents the same action from listing the same
-- clause twice, which would be a UI bug — duplicate citations carry
-- no extra information and confuse the per-version diff view.
--
-- The composite FK back into `mod_policies (identifier, version)`
-- uses `ON DELETE RESTRICT` because the workbook never destructively
-- deletes a policy version (retirement is a tombstone supersession,
-- REQ-F1 in `.design/mod-policy-workbook.md`); the RESTRICT is a
-- belt-and-braces guarantee that a stray future DELETE on
-- `mod_policies` would fail loudly rather than silently break
-- historical actions.
--
-- The action-side FK uses `ON DELETE CASCADE`: deleting an action
-- (which currently can only happen via the `actions`-table
-- append-only invariant being lifted in a future migration — not
-- expected) should take its citations with it.
--
-- WB-2 (#224) wires this table into the action-create handler so
-- the action INSERT and the per-citation INSERTs happen in a
-- single transaction. This migration only builds the schema.

CREATE TABLE action_policy_citations (
    -- The action this citation belongs to.
    action_id UUID NOT NULL
        REFERENCES actions(id) ON DELETE CASCADE,

    -- Snapshot of the cited policy's `identifier` at action-create
    -- time. Stored verbatim — never resolved through a join at
    -- read time, so the history is stable under workbook
    -- amendment.
    policy_identifier TEXT NOT NULL,

    -- Snapshot of the cited policy's `version` at action-create
    -- time. The pair `(policy_identifier, policy_version)` is the
    -- target of the composite FK below.
    policy_version INTEGER NOT NULL,

    -- Same instant as `actions.created_at` in normal operation
    -- (the action-create transaction inserts both rows together).
    -- Kept on the row so the per-citation list view does not need
    -- to JOIN against `actions` purely to render a timestamp.
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Composite natural PK. An action can cite multiple policies
    -- but never the same `(identifier, version)` twice.
    PRIMARY KEY (action_id, policy_identifier, policy_version),

    -- The composite FK is the core integrity guarantee: it is
    -- impossible to land a citation row pointing at an
    -- `(identifier, version)` pair that does not exist in
    -- `mod_policies`. The target column pair carries a UNIQUE
    -- constraint in migration 47 so this FK is satisfiable.
    FOREIGN KEY (policy_identifier, policy_version)
        REFERENCES mod_policies (identifier, version)
        ON DELETE RESTRICT
);

-- Supports the "show me every action that cited harassment v3"
-- admin query the workbook detail view (WB-3 / #225) runs when
-- the operator clicks into a historical version.
CREATE INDEX action_policy_citations_policy_idx
    ON action_policy_citations (policy_identifier, policy_version);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (48, 'action_policy_citations');
