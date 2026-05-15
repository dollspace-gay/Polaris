-- Moderator-behavior-anomaly observation kind (issue #73).
--
-- Threat-model T1 mitigation (design.md §9 #1): when a moderator's labeled-
-- action rate crosses a configurable rolling-window threshold the action-
-- insert path emits an `ObservationKind::ModeratorBehaviorAnomaly` row. The
-- variant did not exist in the v1 enum (migration `00000000000006`), so this
-- migration extends the CHECK constraint to accept the new discriminator.
--
-- The observation is keyed against a *synthetic subject* — one
-- `subjects` row per anomalous moderator, identified by the DID
-- `did:polaris:moderator-anomaly:<moderator_uuid>`. The synthetic
-- subject reuses the existing FK + risk-signals trigger machinery
-- without inventing a parallel storage path. See the rustdoc on
-- `polaris_backend::pattern::moderator_anomaly` for the rationale.

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
        'moderator_behavior_anomaly'
    ));

INSERT INTO _polaris_schema_version (version, description)
    VALUES (23, 'moderator-behavior-anomaly');
