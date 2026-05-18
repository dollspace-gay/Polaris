-- Extended moderator controls — Ozone-parity additions.
--
-- Adds four operator-facing primitives the case-view was missing,
-- corresponding to issues #188 / #189 / #191 / #192:
--
--   1. `comment` action verb — moderator note with no state change.
--      Recorded in the existing `actions` table; the `kind` column's
--      CHECK constraint is widened to accept it.
--   2. `subject_tags` table — categorical tags attached to a subject
--      for queue routing and search. Multi-valued (one row per tag).
--   3. `reports.priority_score` column — integer priority on the
--      partitioned `reports` table, surfaced to the case-view ordering.
--      Default 0 = no priority; higher = earlier in the queue.
--   4. `muted_reporters` table — reporter DIDs whose inbound
--      `com.atproto.moderation.createReport` calls Polaris ignores
--      (anti-spam-reporter mitigation; design.md §9.3 cousin).
--
-- # Schema notes
--
-- * `subject_tags(subject_id, tag)` carries a UNIQUE constraint so
--   re-tagging is idempotent. Operator-readable text strings; no
--   enum. Tagging is opinionated per deployment.
-- * `muted_reporters.until` is nullable to support permanent mutes
--   (NULL = mute indefinitely); a check at the API edge interprets
--   `until IS NULL OR until > now()` as "currently muted".

-- 1. Extend the actions kind allow-list to include `comment`.
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (
    kind IN ('label', 'takedown', 'mute', 'warn',
             'escalate', 'no_action', 'reverse', 'comment')
);

-- Mirror the widening to the pattern-actions allow-list so a
-- pattern emit can carry a `comment` verb across many subjects.
ALTER TABLE pattern_actions DROP CONSTRAINT pattern_actions_action_kind_check;
ALTER TABLE pattern_actions ADD CONSTRAINT pattern_actions_action_kind_check CHECK (
    action_kind IN ('label', 'takedown', 'mute', 'warn',
                    'escalate', 'no_action', 'reverse', 'comment')
);

-- 2. subject_tags — operator-curated tags for routing / search.
CREATE TABLE subject_tags (
    subject_id  UUID         NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    tag         TEXT         NOT NULL CHECK (length(tag) BETWEEN 1 AND 64),
    applied_by  UUID         NOT NULL REFERENCES moderators(id),
    applied_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Idempotent re-tagging: a moderator clicking "tag: bot" twice
    -- on the same subject does NOT create two rows.
    PRIMARY KEY (subject_id, tag)
);

CREATE INDEX subject_tags_tag_idx ON subject_tags (tag);
CREATE INDEX subject_tags_applied_by_idx ON subject_tags (applied_by);

-- 3. reports.priority_score — triage ordering hint.
ALTER TABLE reports ADD COLUMN priority_score INTEGER NOT NULL DEFAULT 0;

-- Index supports the ORDER BY priority_score DESC, created_at DESC
-- pattern the dashboard report-queue uses.
CREATE INDEX reports_priority_idx
    ON reports (priority_score DESC, created_at DESC)
    WHERE priority_score > 0;

-- 4. muted_reporters — anti-abuse for spammy report-submitting DIDs.
CREATE TABLE muted_reporters (
    reporter_did TEXT         NOT NULL PRIMARY KEY,
    muted_by     UUID         NOT NULL REFERENCES moderators(id),
    reason       TEXT         NOT NULL CHECK (length(reason) BETWEEN 10 AND 2000),
    muted_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- NULL means muted indefinitely; a positive timestamp is the
    -- automatic-unmute moment. The createReport handler treats
    -- `until IS NULL OR until > now()` as "currently muted".
    until        TIMESTAMPTZ
);

CREATE INDEX muted_reporters_until_idx
    ON muted_reporters (until)
    WHERE until IS NOT NULL;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (38, 'extended-moderator-controls — comment verb, subject_tags, reports.priority_score, muted_reporters');
