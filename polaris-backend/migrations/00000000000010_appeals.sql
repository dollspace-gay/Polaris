-- Appeals workflow (issue #24).
--
-- design.md §5.8: appeals open as a *new* incident type linked to the
-- original action. The reviewing moderator sees the original action, the
-- original reasoning, and the appellant's statement. Reversal-on-appeal
-- surfaces in the original moderator's calibration view as feedback,
-- *not* performance discipline (design.md §5.7).
--
-- Two tables land here:
--
-- 1. `appeals` — one row per submitted appeal. Carries the appealed
--    action id (FK into `actions`), the appellant's free-text statement
--    (≤ 4096 chars; sanitised + length-bounded at the API), an opaque
--    SHA-256 hash of the source IP for rate-limit accounting (we never
--    store raw IPs), the workflow status (string-encoded enum with a
--    CHECK), the assigned reviewer, the decision reasoning, and the
--    timestamps.
--
-- 2. `calibration_events` — append-only stream of feedback events on a
--    moderator's calibration view. `appeal_reversal` is the only kind
--    inserted today; the schema includes the planned `agreement_with_senior`
--    / `disagreement_with_senior` variants from #23's calibration-tracking
--    so a later issue does not need a CHECK constraint migration.
--    Indexed on `(moderator_id, created_at DESC)` so the personal
--    calibration view is one index scan.
--
-- The `appeals.status` enum is encoded as a TEXT column with a CHECK
-- constraint matching `polaris_types::AppealStatus::as_str`. Transition
-- legality is enforced *in code* by `AppealStatus::transition_to` — the
-- DB column accepts any of the four values, the transition function is
-- the audit boundary. This split mirrors how `incidents.status` /
-- `pattern_actions.status` are handled elsewhere in the schema.
--
-- # No `UPDATE actions` anywhere
--
-- Per the forbidden-pattern list for #24, this migration does NOT add
-- any UPDATE-on-`actions` path. Reversal-on-appeal goes through the
-- existing #36 reversal API, which inserts a fresh `actions` row with
-- `kind = 'reverse'` — the append-only trigger from migration 4 stays
-- intact.

CREATE TABLE appeals (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    appealed_action_id      UUID         NOT NULL REFERENCES actions(id),
    -- Free-text statement from the appellant. The API caps inbound length
    -- at 4096 and rejects empty submissions; the CHECK below is the
    -- defense-in-depth backstop so a bypass at the application layer
    -- still cannot persist a value outside the contract.
    appellant_statement     TEXT         NOT NULL
        CHECK (length(appellant_statement) > 0
           AND length(appellant_statement) <= 4096),
    -- SHA-256 of the source IP (32 bytes) plus a deployment-local pepper
    -- baked into the rate-limit window. We never store raw IPs — the
    -- privacy bar is "we cannot honour a deletion request by handing back
    -- the appellant's address, because we don't have it." The pepper is
    -- not in this migration; it lives at the API layer.
    appellant_ip_hash       BYTEA        NOT NULL,
    status                  TEXT         NOT NULL
        CHECK (status IN ('open', 'assigned', 'decided_reversed',
                          'decided_upheld'))
        DEFAULT 'open',
    -- The moderator assigned to review this appeal. The routing engine
    -- writes this column once the appeal is picked up; the appeal API's
    -- `decide` endpoint requires this column to be set and to match the
    -- caller (or for the caller to be a senior).
    assigned_to             UUID         REFERENCES moderators(id),
    decided_at              TIMESTAMPTZ,
    decision_reasoning      TEXT,
    opened_at               TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Status-scan index — the routing engine selects the "open" pool here.
CREATE INDEX appeals_status_idx ON appeals (status);

-- Assigned-to scan index — the moderator dashboard fetches
-- `WHERE assigned_to = $me AND status = 'assigned'`; the composite
-- index covers the hot path without a separate `assigned_to` index.
CREATE INDEX appeals_assigned_to_idx ON appeals (assigned_to);

CREATE TABLE calibration_events (
    id                      UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    moderator_id            UUID         NOT NULL REFERENCES moderators(id),
    -- The event kind enumeration. `appeal_reversal` is the only kind
    -- inserted by this migration's workflow; the additional variants are
    -- declared up-front so #23-class agreement-tracking can write them
    -- without a CHECK-constraint migration.
    kind                    TEXT         NOT NULL
        CHECK (kind IN ('appeal_reversal',
                        'agreement_with_senior',
                        'disagreement_with_senior')),
    -- The original action whose reversal triggered the event. Nullable
    -- because the future `agreement_with_senior` / `disagreement_with_senior`
    -- variants reference a senior review, not a per-action reversal.
    referenced_action_id    UUID         REFERENCES actions(id),
    referenced_appeal_id    UUID         REFERENCES appeals(id),
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Personal-calibration index: `WHERE moderator_id = $me ORDER BY created_at
-- DESC` is the entire calibration-view query.
CREATE INDEX calibration_events_moderator_idx
    ON calibration_events (moderator_id, created_at DESC);

-- Schema-version sentinel. Migration `00000000000009_exposure.sql` recorded
-- version 10 ("exposure-tracking"); this migration is version 11.
INSERT INTO _polaris_schema_version (version, description) VALUES (11, 'appeals');
