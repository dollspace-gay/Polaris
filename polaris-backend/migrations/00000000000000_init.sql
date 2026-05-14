-- Initial migration: establish schema_version sentinel so the sqlx migration
-- system has at least one applied migration on a fresh database and so future
-- migrations can co-evolve a recorded Polaris schema version separate from
-- sqlx's internal `_sqlx_migrations` bookkeeping table.
--
-- The sqlx CLI tooling already records each migration's checksum + timestamp
-- in `_sqlx_migrations`. The table below is the *application*-level version
-- marker: future migrations append rows here whenever a semantic schema
-- version boundary is crossed (e.g. when M1 lands the subject/incident/action
-- tables). Operators can `SELECT max(version) FROM _polaris_schema_version`
-- to confirm an installation is at the expected level without parsing the
-- sqlx internal table.
CREATE TABLE _polaris_schema_version (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO _polaris_schema_version (version, description) VALUES (1, 'initial');
