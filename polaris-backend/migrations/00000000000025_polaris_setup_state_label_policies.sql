-- Issue #96 / mod-workstation feature #6: persist the labeler's declared
-- label values + per-value definitions on `polaris_setup_state` so the
-- new `GET /api/labeler/policies` endpoint can serve them to the
-- frontend's `SubscriberEffectPreview` component.
--
-- The setup wizard's `publish-labeler-record` handler builds the
-- `app.bsky.labeler.service` record from these inputs, then commits the
-- record to the operator's PDS. Before this migration we kept only the
-- resulting AT-URI (`labeler_record_uri`) — the *contents* of the
-- record were never persisted locally. The subscriber-effect preview
-- needs read-only access to those contents to compute its forecast,
-- and we don't want the frontend to make a remote round-trip to the
-- operator's PDS for every composer keystroke.
--
-- Two columns rather than one JSONB blob:
-- - `label_values TEXT[]` is the cheap "what values does this labeler
--   declare?" lookup; downstream consumers can read it without
--   deserialising the per-value definition payload.
-- - `label_value_definitions JSONB` carries the array of
--   `LabelValueDefinition` (severity, defaultSetting, locales) shaped
--   exactly as the AT-Proto lexicon requires. JSONB lets the policy
--   endpoint stream the field verbatim into the response without
--   round-tripping through a typed schema (the wire shape IS the
--   lexicon shape; any further validation belongs in the wizard's
--   publish step, not here).
--
-- Both columns are nullable: a deployment that has not yet completed
-- the `publish-labeler-record` step has neither value declared, and
-- the policies endpoint returns 404 in that state.

ALTER TABLE polaris_setup_state ADD COLUMN label_values TEXT[];
ALTER TABLE polaris_setup_state ADD COLUMN label_value_definitions JSONB;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (26, 'polaris-setup-state-label-policies');
