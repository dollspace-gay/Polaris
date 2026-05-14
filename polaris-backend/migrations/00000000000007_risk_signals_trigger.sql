-- Risk-signals denormalization trigger (issue #13).
--
-- design.md §4: `Subject.risk_signals` is a computed, denormalized view of
-- the latest pattern-engine observations on that subject. Storing it as a
-- JSONB column on the row keeps the case-view first-paint fast (one
-- subject-row read instead of a per-observation join), but it has to stay
-- in sync with the authoritative `observations` table.
--
-- This migration installs a trigger that re-derives the column whenever
-- observations are inserted or deleted for a subject. The trigger is a
-- per-statement AFTER trigger (rather than a per-row BEFORE) so that
-- bulk inserts pay the recompute cost once per statement, not once per row.

CREATE OR REPLACE FUNCTION refresh_risk_signals_for(subject UUID)
RETURNS void AS $$
BEGIN
    UPDATE subjects s
       SET risk_signals = COALESCE((
           SELECT jsonb_agg(payload ORDER BY (payload->>'detected_at') DESC)
             FROM (
                 SELECT jsonb_build_object(
                            'kind', o.kind,
                            'confidence', o.confidence,
                            'detected_at', o.detected_at
                        ) AS payload
                   FROM observations o
                  WHERE o.subject_id = subject
                  ORDER BY o.detected_at DESC
                  LIMIT 20
             ) AS recent
       ), '[]'::jsonb)
     WHERE s.id = subject;
END;
$$ LANGUAGE plpgsql;

-- Per-statement triggers (`FOR EACH STATEMENT`) cannot reference NEW/OLD
-- directly; the canonical workaround is `REFERENCING NEW TABLE AS new` /
-- `OLD TABLE AS old` which exposes the affected rows as a transition table.
-- The trigger function then iterates the distinct subject_ids touched and
-- recomputes once per subject.

CREATE OR REPLACE FUNCTION observations_refresh_signals()
RETURNS trigger AS $$
DECLARE
    sid UUID;
BEGIN
    IF TG_OP = 'INSERT' THEN
        FOR sid IN SELECT DISTINCT subject_id FROM new_rows LOOP
            PERFORM refresh_risk_signals_for(sid);
        END LOOP;
    ELSIF TG_OP = 'DELETE' THEN
        FOR sid IN SELECT DISTINCT subject_id FROM old_rows LOOP
            PERFORM refresh_risk_signals_for(sid);
        END LOOP;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER observations_refresh_signals_insert
    AFTER INSERT ON observations
    REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT
    EXECUTE FUNCTION observations_refresh_signals();

CREATE TRIGGER observations_refresh_signals_delete
    AFTER DELETE ON observations
    REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT
    EXECUTE FUNCTION observations_refresh_signals();

INSERT INTO _polaris_schema_version (version, description)
VALUES (8, 'risk-signals-trigger');
