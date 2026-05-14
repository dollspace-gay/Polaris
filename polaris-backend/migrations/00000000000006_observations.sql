-- Observations table (issue #13).
--
-- design.md §3.2 + §4: pattern-engine emissions are *observations*, never
-- direct actions. Each row attaches a structured signal to a subject; the
-- `kind` discriminator is a TEXT column whose values match the serde tags
-- of `polaris_types::ObservationKind` (e.g. `image_hash_cluster`,
-- `external_label`). The full per-variant payload is serialized into the
-- `evidence` JSONB column, and the outer `confidence` is the
-- cross-detector calibrated score.
--
-- A separate denormalization trigger lands in migration 00000000000007.

CREATE TABLE observations (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    subject_id   UUID         NOT NULL REFERENCES subjects(id),
    -- Discriminator. CHECK constraint enumerates the v1 ObservationKind
    -- variants; adding a new variant requires a migration so the wire form
    -- and schema stay in lock-step.
    kind         TEXT         NOT NULL
        CHECK (kind IN (
            'image_hash_cluster',
            'account_cohort',
            'reply_brigade',
            'report_volume_anomaly',
            'external_label',
            'classifier_signal'
        )),
    confidence   REAL         NOT NULL,
    evidence     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    detected_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX observations_subject_id_idx ON observations (subject_id);
CREATE INDEX observations_subject_detected_at_idx
    ON observations (subject_id, detected_at DESC);

INSERT INTO _polaris_schema_version (version, description)
VALUES (7, 'observations');
