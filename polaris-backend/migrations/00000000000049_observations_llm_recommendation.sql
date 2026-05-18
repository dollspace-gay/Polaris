-- LlmRecommendation observation kind (#233, LLM-3 / REQ-B1).
--
-- The LLM moderation assist subsystem (`.design/llm-moderation-assist.md`)
-- persists every `Recommend` RPC response as an observation row. The
-- variant did not exist in the v1 enum (migration `00000000000006`) nor in
-- the moderator-behavior-anomaly extension (migration `00000000000022`),
-- so this migration extends the `kind` CHECK constraint to accept the new
-- discriminator `'llm_recommendation'`.
--
-- The `evidence` JSONB column carries the full `RecommendResponse`
-- payload verbatim plus a content-hash of the `RecommendRequest` (REQ-B2)
-- so the audit + replay path can reconstruct what the LLM saw. The
-- per-variant payload is shaped by the typed `ObservationKind::
-- LlmRecommendation` variant in `polaris-types/src/observation.rs`; this
-- migration only carries the discriminator-side contract.
--
-- Pairs with:
--   * `00000000000050_pending_auto_actions.sql` — drafts citing this kind.
--   * `00000000000051_actions_autonomous_audit_columns.sql` — autonomous
--     actions point at `observations.id` rows of this kind via
--     `actions.llm_observation_id`.

ALTER TABLE observations
    DROP CONSTRAINT observations_kind_check;

ALTER TABLE observations
    ADD CONSTRAINT observations_kind_check
    CHECK (kind IN (
        'image_hash_cluster',
        'account_cohort',
        'reply_brigade',
        'report_volume_anomaly',
        'external_label',
        'classifier_signal',
        'moderator_behavior_anomaly',
        'llm_recommendation'
    ));

INSERT INTO _polaris_schema_version (version, description)
    VALUES (49, 'observations-llm-recommendation');
