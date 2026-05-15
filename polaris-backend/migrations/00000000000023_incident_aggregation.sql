-- Issue #75: T4 mitigation. report_count column on incidents for cheap dashboard
-- reads; trigger keeps it in sync with the reports table.

ALTER TABLE incidents
    ADD COLUMN report_count INTEGER NOT NULL DEFAULT 0;

CREATE OR REPLACE FUNCTION incidents_report_count_trigger()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.incident_id IS NOT NULL THEN
            UPDATE incidents SET report_count = report_count + 1
                WHERE id = NEW.incident_id;
        END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        IF OLD.incident_id IS DISTINCT FROM NEW.incident_id THEN
            IF OLD.incident_id IS NOT NULL THEN
                UPDATE incidents SET report_count = GREATEST(report_count - 1, 0)
                    WHERE id = OLD.incident_id;
            END IF;
            IF NEW.incident_id IS NOT NULL THEN
                UPDATE incidents SET report_count = report_count + 1
                    WHERE id = NEW.incident_id;
            END IF;
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER reports_report_count_sync
    AFTER INSERT OR UPDATE OF incident_id ON reports
    FOR EACH ROW EXECUTE FUNCTION incidents_report_count_trigger();

INSERT INTO _polaris_schema_version (version, description)
    VALUES (24, 'incident-aggregation-report-count');
