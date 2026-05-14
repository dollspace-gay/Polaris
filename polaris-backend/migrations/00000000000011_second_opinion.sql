-- Second-opinion conversation threads attached to incidents (issue #25).
--
-- design.md §5.6: "One-click flag for senior review. The senior moderator
-- sees the case with the original moderator's draft action and reasoning.
-- Their conversation about the decision is attached to the incident
-- permanently, becoming searchable training material for future
-- moderators."
--
-- Two tables land here:
--
-- 1. `second_opinion_threads` — one row per "flag for senior review"
--    invocation. Carries the host incident, the moderator who opened the
--    thread, an optional pointer at the draft action that triggered the
--    flag, and the opened-at timestamp. Threads are never deleted; an
--    incident keeps its second-opinion history forever (the §5.6
--    "permanent training material" rule).
--
-- 2. `second_opinion_messages` — append-only conversation rows. Each row
--    carries the thread id, the author moderator id, the free-text body,
--    a generated `tsvector` column for full-text search, an optional
--    `replaces_message_id` pointer that implements the "edits write a new
--    row" pattern, and the created-at timestamp.
--
-- # Append-only at the database boundary
--
-- The architect's pre-flight + design.md §5.6 require that the message
-- stream be permanent. We enforce that with a BEFORE UPDATE trigger that
-- raises `P0001` (PL/pgSQL RAISE EXCEPTION) on any UPDATE attempt — the
-- same pattern migration 4 uses for `actions`. Edits go through a *new*
-- row whose `replaces_message_id` points at the row being amended; both
-- rows survive forever so the audit trail is total.
--
-- # Full-text search
--
-- `body_tsv` is `GENERATED ALWAYS AS (to_tsvector('english', body)) STORED`
-- so the vector is computed at write time and never drifts from the body.
-- A GIN index over `body_tsv` makes the `GET /api/threads/search?q=…`
-- endpoint a single index probe. The search query layer uses
-- `plainto_tsquery($1)` — the `$1` placeholder is bound through sqlx, so
-- user input cannot be interpreted as tsquery syntax. The architect's
-- pre-flight forbids string-built tsquery construction; this design
-- makes that path mechanically impossible at the API layer.
--
-- English-only FTS is acceptable for v1 (architect's "What to NOT do"
-- list explicitly defers multi-language FTS). A later issue can switch
-- the configuration column or compute the vector against a
-- `pg_dictsize`-aware configuration without a data migration — the
-- generated column simply re-evaluates.

CREATE TABLE second_opinion_threads (
    id                  UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id         UUID         NOT NULL REFERENCES incidents(id),
    requested_by        UUID         NOT NULL REFERENCES moderators(id),
    -- Optional: the draft action that triggered the "flag for senior
    -- review" click. Nullable because §5.6 also covers threads that
    -- discuss a case in the abstract — before any concrete draft.
    draft_action_id     UUID         REFERENCES actions(id),
    opened_at           TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Incident-scan index: "show me every second-opinion thread on this
-- incident" is the case-view side-panel query.
CREATE INDEX second_opinion_threads_incident_idx
    ON second_opinion_threads (incident_id);

CREATE TABLE second_opinion_messages (
    id                       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    thread_id                UUID         NOT NULL
        REFERENCES second_opinion_threads(id) ON DELETE CASCADE,
    moderator_id             UUID         NOT NULL REFERENCES moderators(id),
    body                     TEXT         NOT NULL
        CHECK (length(body) > 0 AND length(body) <= 16384),
    body_tsv                 tsvector     GENERATED ALWAYS AS
                                 (to_tsvector('english', body)) STORED,
    -- "Edits write a new row" — when a moderator amends a message, a
    -- fresh row is inserted with `replaces_message_id` pointing at the
    -- row being amended. The original row stays put; the read path
    -- chooses how to render the chain (typically: latest in chain by
    -- creation time, with the history visible on demand).
    replaces_message_id      UUID         REFERENCES second_opinion_messages(id),
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Thread-scan index: the "render this thread chronologically" query.
CREATE INDEX second_opinion_messages_thread_idx
    ON second_opinion_messages (thread_id, created_at);

-- FTS index over the generated tsvector. GIN is the canonical index
-- type for `tsvector @@ tsquery` queries.
CREATE INDEX second_opinion_messages_body_tsv_idx
    ON second_opinion_messages USING GIN (body_tsv);

-- ── append-only enforcement ─────────────────────────────────────────────
-- Mirrors the pattern in migration 4 (`actions_reject_update`). Any
-- UPDATE on `second_opinion_messages` raises SQLSTATE `P0001`; the row
-- never enters a mutated state because the trigger fires BEFORE the row
-- materialises the change.
CREATE OR REPLACE FUNCTION reject_second_opinion_message_update()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION
        'second_opinion_messages is append-only; edits write a new row with replaces_message_id pointing at the row being amended (design.md §5.6)'
        USING ERRCODE = 'P0001';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER second_opinion_messages_no_update
    BEFORE UPDATE ON second_opinion_messages
    FOR EACH ROW
    EXECUTE FUNCTION reject_second_opinion_message_update();

-- Schema-version sentinel. Migration `00000000000010_appeals.sql`
-- recorded version 11 ("appeals"); this migration is version 12.
INSERT INTO _polaris_schema_version (version, description)
VALUES (12, 'second-opinion');
