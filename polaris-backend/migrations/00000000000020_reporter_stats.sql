-- Reporter reputation stats (design.md §9.3, issue #37). T3 mitigation.
--
-- Adversaries can game the report system to weaponize moderation against
-- innocents (design.md §9 threat #3). The defence is to track per-reporter
-- history (how often their reports led to a label / takedown vs. a no-action)
-- and weight reports in the pattern engine accordingly. This table is the
-- store for that history.
--
-- # Columns
--
-- - `did` — keyed on the raw DID string (the `reports.reporter_did` column
--   in `00000000000005_reports.sql`). One row per reporter, ever.
-- - `reports_filed` / `reports_actioned` / `reports_dismissed` — the count
--   of reports the reporter has filed, the subset that produced a Label or
--   Takedown action against the subject, and the subset that produced a
--   NoAction (the "dismissed" path).
-- - `first_seen` / `last_active` — account-age + activity-recency signal.
--   The reputation function applies time decay against `last_active` so a
--   reporter inactive for half-lives drifts back toward the prior.
-- - `cached_score` / `cached_at` — query-time-friendly cache of the most
--   recently computed `reputation(...)` value. The canonical score is
--   always re-derivable from the counts + `last_active`; this column lets
--   joins (case-view DTO, pattern-engine read paths) avoid recomputing in
--   the hot path. The provider refreshes the cache on every stats update.

CREATE TABLE reporter_stats (
    did                 TEXT         PRIMARY KEY,
    reports_filed       BIGINT       NOT NULL DEFAULT 0,
    reports_actioned    BIGINT       NOT NULL DEFAULT 0,
    reports_dismissed   BIGINT       NOT NULL DEFAULT 0,
    first_seen          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_active         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Cached score from the most recent reputation() call. The
    -- canonical score is recomputed by reputation(stats, now) — this
    -- column is for query-time joins (pattern engine, case-view DTO).
    cached_score        REAL         NOT NULL DEFAULT 0.5,
    cached_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CHECK (reports_filed >= 0),
    CHECK (reports_actioned >= 0),
    CHECK (reports_dismissed >= 0),
    CHECK (cached_score >= 0.0 AND cached_score <= 1.0)
);

CREATE INDEX reporter_stats_last_active_idx ON reporter_stats(last_active);

INSERT INTO _polaris_schema_version (version, description)
    VALUES (21, 'reporter-stats');
