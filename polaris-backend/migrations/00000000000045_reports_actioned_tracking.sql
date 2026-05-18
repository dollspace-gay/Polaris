-- Per-report idempotency tracking (issue #202).
--
-- Background: the report-card surface (case view) POSTs to
-- `/api/cases/{subject_id}/actions` on every Acknowledge / Dismiss /
-- Escalate click. Without per-report state on the server side, a
-- moderator clicking Dismiss twice on the same report inserted two
-- `actions` rows; the audit trail then read "this report was dismissed
-- twice" when in fact one moderator made one decision. Worse, the
-- report card stayed visible after the first click (the panel just
-- re-rendered the same `reports[]` set), inviting a second click.
--
-- This migration adds the minimum schema needed to make the server
-- authoritative: once a report has been actioned, the next POST that
-- carries the same `report_id` returns the existing action instead of
-- inserting a new one, and the case-view's `reports[]` query filters
-- the actioned row out so the card stops appearing entirely.
--
-- Columns:
--   actioned_at            — NULL means "still un-actioned" (the
--                           moderator-facing default). Populated by the
--                           submit_action handler inside the same
--                           transaction as the actions INSERT, so
--                           either both land or neither does.
--   actioned_by_action_id  — FK to the `actions` row that closed this
--                           report. `ON DELETE SET NULL` because
--                           reports outlive actions only in pathological
--                           operator-side data repair scenarios; the
--                           append-only invariant on `actions` means
--                           normal operation never deletes an action.
--
-- A partial index supports the "open-reports for this case" query the
-- case view runs on every page render — the predicate column must
-- appear literally in the WHERE clause for Postgres to consider the
-- partial index, which is the shape `build_case_view`'s report list
-- adopts in #202.
--
-- Note on partitioning: `reports` is `PARTITION BY RANGE (created_at)`
-- (migration 5). ALTER TABLE on the partitioned parent propagates the
-- new columns + index predicate to every child partition automatically
-- (Postgres 11+).

ALTER TABLE reports
    ADD COLUMN actioned_at TIMESTAMPTZ,
    ADD COLUMN actioned_by_action_id UUID
        REFERENCES actions(id) ON DELETE SET NULL;

-- Hot-path index for the case-view's "open reports" query.
-- The partial predicate matches the moderator-facing filter exactly
-- (`actioned_at IS NULL`); rows that have been actioned drop out of
-- the index and stop costing storage.
CREATE INDEX reports_actioned_at_idx
    ON reports (actioned_at)
    WHERE actioned_at IS NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (45, 'reports-actioned-tracking');
