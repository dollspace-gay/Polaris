-- Global autonomous kill switch (#233, LLM-3 / REQ-S7).
--
-- The kill switch is the operator's one-click "stop the bleeding"
-- toggle for the LLM moderation assist subsystem
-- (`.design/llm-moderation-assist.md`). While paused, *every*
-- `Recommend` call's effective mode downgrades to `manual`
-- regardless of per-policy `autonomy_mode`. Used in incident
-- response so the operator does not have to remember per-policy
-- state to halt every autonomous action at once.
--
-- Schema choice: a single nullable TIMESTAMPTZ column on the
-- existing singleton `polaris_setup_state` table rather than a
-- dedicated `llm_pause_state` table. Rationale:
--
-- * The kill switch is deployment-global, like the labeler service
--   entry and the signing key — exactly the shape `polaris_setup_state`
--   is for (CHECK `id = TRUE` enforces singleton; migration 24).
-- * NULL = not paused; future timestamp = paused until that moment.
--   Past timestamps are equivalent to NULL (the pause has expired),
--   so the dispatcher's predicate is `... > now()`. No second column
--   needed.
-- * A one-shot toggle (admin re-enable) clears the column to NULL;
--   a time-bounded pause (e.g. "pause for 1 hour") sets a future
--   timestamp. Both shapes round-trip through the same column.
--
-- The dispatcher reads this on every Recommend call (no cache) so
-- an operator pause takes effect immediately. The companion
-- per-policy `mod_policies.autonomous_paused_until` (workbook
-- migration 47) carries the same shape at the policy granularity;
-- the global field here is the deployment-wide override that always
-- wins.
--
-- The admin endpoints `POST /api/admin/llm/pause` and
-- `DELETE /api/admin/llm/pause` (REQ-S7) land in LLM-9 (#238).

ALTER TABLE polaris_setup_state
    ADD COLUMN global_autonomous_pause_until TIMESTAMPTZ;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (52, 'global-autonomous-pause');
