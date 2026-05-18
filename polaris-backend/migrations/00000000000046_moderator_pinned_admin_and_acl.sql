-- Issue #214: Ozone-style login allow-list + moderator management.
--
-- The first user to ever complete an OAuth login becomes the bootstrap
-- admin and is hard-pinned via `moderators.pinned_admin = TRUE`. The
-- column is monotone — once TRUE, neither an API handler nor a direct
-- SQL `UPDATE` can clear it. The trigger below enforces the
-- monotonicity at the DB layer so a SQL-injection or a buggy handler
-- cannot get around the rule either.
--
-- The bootstrap admin's role row can still be revoked through the
-- moderator-management API (e.g. on operator handover), but only if
-- another admin remains AND the pinned flag has already been
-- accommodated by a fresh bootstrap. The "can't remove the last admin"
-- check lives in the API handler; the trigger here just protects the
-- pin itself.

ALTER TABLE moderators
    ADD COLUMN pinned_admin BOOLEAN NOT NULL DEFAULT FALSE;

CREATE OR REPLACE FUNCTION moderators_pinned_admin_monotone()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.pinned_admin = TRUE AND NEW.pinned_admin = FALSE THEN
        RAISE EXCEPTION 'moderators.pinned_admin is monotone: cannot clear once set';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER moderators_pinned_admin_monotone_tr
    BEFORE UPDATE OF pinned_admin ON moderators
    FOR EACH ROW
    EXECUTE FUNCTION moderators_pinned_admin_monotone();

-- Most queries that touch pinned_admin filter "is the operator still in
-- there?" — a partial index on TRUE keeps the index tiny (one row in
-- the deployment shape Polaris targets) while still covering the
-- equality lookup the API uses.
CREATE INDEX moderators_pinned_admin_idx ON moderators (pinned_admin)
    WHERE pinned_admin = TRUE;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (46, 'moderator_pinned_admin_and_acl');
