-- Wellness exposure tracking (issue #23).
--
-- design.md §5.7: exposure to graphic content is tracked per moderator,
-- surfaced to the moderator first; manager visibility is opt-in via the
-- per-moderator `share_with_manager` flag (default FALSE). Daily caps are
-- set by moderators themselves; the router consults the remaining budget
-- when assigning incidents and a force-break threshold (percent of cap)
-- forces a break before the cap is fully consumed.
--
-- Two tables:
--
-- 1. `moderator_exposure` — per-(moderator, day, category) counter.
--    UPSERT on conflict in `ExposureTracker::record` increments `count`
--    atomically. Primary key is the (moderator_id, day, category) triple so
--    rollup queries are an index seek; the `day` index supports the
--    aggregate-for-today read path.
-- 2. `moderator_exposure_settings` — per-moderator settings: the daily cap,
--    the manager-visibility consent flag, and the force-break percentage.
--    One row per moderator; LEFT JOIN against this table on read so a
--    moderator with no settings row uses the table defaults (50 / FALSE / 90).
--
-- The schema is intentionally minimal: no per-category caps, no graphic
-- score bucketing. Caller (M4 audit chain) wires the per-Action increment;
-- the tracker exposes one `record` call that takes a category string. This
-- keeps the privacy invariant (aggregate visibility gated by consent) at a
-- single function and avoids smearing the access boundary across multiple
-- query paths.

CREATE TABLE moderator_exposure (
    moderator_id UUID NOT NULL REFERENCES moderators(id) ON DELETE CASCADE,
    day          DATE NOT NULL,
    category     TEXT NOT NULL,
    count        INT  NOT NULL DEFAULT 0 CHECK (count >= 0),
    PRIMARY KEY (moderator_id, day, category)
);

CREATE INDEX moderator_exposure_day_idx ON moderator_exposure (day);

CREATE TABLE moderator_exposure_settings (
    moderator_id        UUID         PRIMARY KEY
        REFERENCES moderators(id) ON DELETE CASCADE,
    -- Daily cap of exposure events. Default 50 — see issue #23 deliverable
    -- notes on cap default selection (chosen as a starting point; moderators
    -- are expected to tune via the cap-set endpoint).
    daily_cap           INT          NOT NULL DEFAULT 50 CHECK (daily_cap > 0),
    -- Privacy consent flag. When FALSE, `ExposureTracker::aggregate_for_manager`
    -- returns an empty vector regardless of caller — the invariant is
    -- enforced at the trait level. Default FALSE so newly-onboarded
    -- moderators are private by default.
    share_with_manager  BOOLEAN      NOT NULL DEFAULT FALSE,
    -- Force-break threshold as a percentage of `daily_cap`. When the
    -- moderator's running count meets or exceeds (daily_cap * pct / 100),
    -- the tracker reports `force_break_active = true` and `remaining_budget
    -- = 0` so the router skips them. Default 90 — early enough to leave a
    -- buffer, late enough to permit a full shift.
    force_break_at_pct  SMALLINT     NOT NULL DEFAULT 90
        CHECK (force_break_at_pct > 0 AND force_break_at_pct <= 100),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Schema-version sentinel. Migration `00000000000008_pattern_actions.sql`
-- already inserted version 9 (the `_polaris_schema_version` PK collision
-- would otherwise fail this migration), so #23 records version 10. The
-- filename ordering is preserved because sqlx migrations key off the
-- prefix integer, not the schema-version row.
INSERT INTO _polaris_schema_version (version, description) VALUES (10, 'exposure-tracking');
