-- Subjects and incidents (issue #13).
--
-- design.md §4 verbatim, with the addition of `incident_related_subjects` as
-- a normalized join table for `Incident.related_subjects`. The `subjects` row
-- is the moderation entity (account / post / list / feed). `incidents`
-- cluster reports + observations against one primary subject (plus zero or
-- more related subjects) so moderators act on the pattern, not the report.
--
-- `subjects.risk_signals` is a denormalized JSONB column maintained by a
-- trigger that lands in migration 00000000000007 (after `observations`
-- exists, since the trigger reads from it).

-- ── subjects ────────────────────────────────────────────────────────────
CREATE TABLE subjects (
    id                   UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    kind                 TEXT            NOT NULL
        CHECK (kind IN ('account', 'post', 'list', 'feed')),
    -- `did` is populated for `kind = 'account'` and may be populated for
    -- record-kinds when the authoring DID is known. `uri` is populated for
    -- non-account kinds. Both are nullable because the polaris-types
    -- contract is `Option<Did>` / `Option<AtUri>`.
    did                  TEXT,
    uri                  TEXT,
    created_at           TIMESTAMPTZ     NOT NULL,
    first_seen_by_mod    TIMESTAMPTZ     NOT NULL DEFAULT now(),
    -- Denormalized risk-signal snapshot. Maintained by the trigger in
    -- migration 00000000000007. Starts empty; the trigger fills it as
    -- observations arrive.
    risk_signals         JSONB           NOT NULL DEFAULT '[]'::jsonb
);

-- Lookup-by-DID for accounts (and any record whose DID we know). Partial
-- index so the index only carries rows that can actually be hit by the
-- predicate.
CREATE INDEX subjects_kind_did_idx
    ON subjects (kind, did)
    WHERE did IS NOT NULL;

-- Lookup-by-AT-URI for record kinds.
CREATE INDEX subjects_kind_uri_idx
    ON subjects (kind, uri)
    WHERE uri IS NOT NULL;

-- ── incidents ───────────────────────────────────────────────────────────
CREATE TABLE incidents (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    primary_subject   UUID         NOT NULL REFERENCES subjects(id),
    severity          TEXT         NOT NULL
        CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status            TEXT         NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'in_review', 'actioned', 'closed', 'escalated')),
    assigned_to       UUID         REFERENCES moderators(id),
    locked_by         UUID         REFERENCES moderators(id),
    opened_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    closed_at         TIMESTAMPTZ
);

CREATE INDEX incidents_status_severity_idx
    ON incidents (status, severity);

CREATE INDEX incidents_assigned_to_idx
    ON incidents (assigned_to)
    WHERE assigned_to IS NOT NULL;

CREATE INDEX incidents_primary_subject_idx
    ON incidents (primary_subject);

-- ── related-subjects join table ─────────────────────────────────────────
-- Many-to-many: an incident can implicate many related subjects, and a
-- subject can be implicated in many incidents.
CREATE TABLE incident_related_subjects (
    incident_id   UUID  NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    subject_id    UUID  NOT NULL REFERENCES subjects(id),
    PRIMARY KEY (incident_id, subject_id)
);

CREATE INDEX incident_related_subjects_subject_id_idx
    ON incident_related_subjects (subject_id);

INSERT INTO _polaris_schema_version (version, description)
VALUES (4, 'subjects-incidents');
