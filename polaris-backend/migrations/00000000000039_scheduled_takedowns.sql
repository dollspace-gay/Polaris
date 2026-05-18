-- Scheduled takedowns — deferred takedown execution (L1 / Ozone parity
-- `#scheduleTakedownEvent` + `#cancelScheduledTakedownEvent`).
--
-- # Why a separate table vs. an `actions` row with a future timestamp
--
-- `actions` is append-only and represents work the moderator HAS done.
-- A scheduled takedown is work the moderator INTENDS to do; if the
-- subject self-corrects before the deadline, the intent should
-- evaporate without leaving an Action row claiming an enforcement
-- that didn't happen. Modelling it as a separate row keeps the
-- semantics honest:
--
--   * `scheduled_takedowns` carries the intent and the deadline.
--   * When the background worker fires the takedown, it inserts a
--     fresh `actions` row of `kind = takedown` and marks the
--     scheduled row's `executed_action_id` so the audit trail
--     links the schedule to the enforcement.
--   * Cancellation marks the row `cancelled_at = now()` without
--     inserting any `actions` row.
--
-- # Schema
--
-- One row per scheduled takedown. The `subject_id` + `incident_id`
-- + `created_by` fields mirror the shape of `actions` so the eventual
-- materialised takedown carries identical attribution. `reasoning`
-- + `policy_refs` are captured at schedule time so the moderator's
-- intent is preserved even if their later self changes their mind.

CREATE TABLE scheduled_takedowns (
    id                   UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id           UUID         NOT NULL REFERENCES subjects(id),
    incident_id          UUID         NOT NULL REFERENCES incidents(id),
    created_by           UUID         NOT NULL REFERENCES moderators(id),

    -- When the worker should execute. `execute_at > now()` at insert
    -- time; the worker polls and fires whenever `now() >= execute_at`.
    execute_at           TIMESTAMPTZ  NOT NULL,

    -- Frozen-at-schedule-time reasoning + policy citations. These
    -- carry over verbatim to the materialised `actions` row when
    -- the worker fires the takedown.
    reasoning            TEXT         NOT NULL CHECK (length(reasoning) >= 10),
    policy_refs          TEXT[]       NOT NULL CHECK (array_length(policy_refs, 1) >= 1),

    -- Optional label-value override. When set, the eventually-emitted
    -- takedown uses this `LabelValue` (e.g. `!takedown` vs.
    -- `!moderate-account`); NULL = default takedown class.
    label_value          TEXT,

    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),

    -- Set when the worker successfully fires the takedown.
    executed_at          TIMESTAMPTZ,
    executed_action_id   UUID,

    -- Set when an operator cancels the schedule before it fires.
    cancelled_at         TIMESTAMPTZ,
    cancelled_by         UUID         REFERENCES moderators(id),

    -- Exactly one terminal state. A row can be EXECUTED (executed_at
    -- + executed_action_id set, others NULL) or CANCELLED
    -- (cancelled_at + cancelled_by set, others NULL) or PENDING
    -- (both pairs NULL). The CHECK enforces the contract at the DB.
    CHECK (
        (executed_at IS NULL AND executed_action_id IS NULL AND cancelled_at IS NULL
         AND cancelled_by IS NULL)
        OR
        (executed_at IS NOT NULL AND executed_action_id IS NOT NULL
         AND cancelled_at IS NULL AND cancelled_by IS NULL)
        OR
        (executed_at IS NULL AND executed_action_id IS NULL
         AND cancelled_at IS NOT NULL AND cancelled_by IS NOT NULL)
    )
);

-- Worker hot-path: "pending takedowns whose time has come".
CREATE INDEX scheduled_takedowns_pending_idx
    ON scheduled_takedowns (execute_at)
    WHERE executed_at IS NULL AND cancelled_at IS NULL;

-- Per-subject lookups: "what's scheduled for this subject?"
CREATE INDEX scheduled_takedowns_subject_idx
    ON scheduled_takedowns (subject_id);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (40, 'scheduled_takedowns — deferred takedown execution with cancel');
