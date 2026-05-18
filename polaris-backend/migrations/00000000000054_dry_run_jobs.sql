-- Dry-run calibration jobs (#240 / LLM-11 /
-- `.design/llm-moderation-assist.md` REQ-H1).
--
-- An operator about to flip a policy to `autonomy_mode = 'autonomous'`
-- needs to know how the LLM would have decided on real historical
-- cases first. A dry-run job replays closed incidents through the
-- LLM Recommend RPC in NO-SIDE-EFFECT mode (no observations
-- persisted, no actions created, no atproto emit) and tallies the
-- agreement rate against the human moderator's actual decision.
--
-- Two tables:
--
-- * `dry_run_jobs` — one row per dry-run invocation. Carries the
--   operator's job request shape plus aggregate stats. State walks
--   `pending → running → (done | failed)` so the API can poll for
--   progress.
-- * `dry_run_results` — per-case comparison. Each row records what
--   the LLM recommended for a single historical case vs. what the
--   human moderator actually did, with the agreement boolean and
--   the LLM's confidence + reasoning so the operator can drill in.
--
-- The `policy_identifier` filter narrows replay to incidents whose
-- primary subject was actioned under that policy (read against
-- `action_policy_citations`). If `NULL`, the job replays across
-- every policy currently in `mod_policies` (use sparingly — costly).
--
-- `lookback_days` clamps which closed incidents are eligible
-- (`incidents.closed_at >= now() - INTERVAL`). The repo applies a
-- per-job ceiling (default 30, max 90) on top.

CREATE TABLE dry_run_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,

    -- Request shape (from POST /api/admin/llm/dry-run body).
    policy_identifier TEXT,
    lookback_days INTEGER NOT NULL CHECK (lookback_days BETWEEN 1 AND 90),

    -- Job state. `failed` carries an `error_message`; `done` rows
    -- carry the aggregate stats below.
    state TEXT NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'running', 'done', 'failed')),
    error_message TEXT,

    -- Aggregate stats populated as the job runs. The fields stay
    -- NULL until the job finishes; the API reads `state = 'done'`
    -- before trusting them.
    cases_evaluated INTEGER NOT NULL DEFAULT 0,
    agreements INTEGER NOT NULL DEFAULT 0,
    disagreements INTEGER NOT NULL DEFAULT 0,
    errors INTEGER NOT NULL DEFAULT 0,

    requested_by_moderator_id UUID NOT NULL
        REFERENCES moderators(id)
);

CREATE INDEX dry_run_jobs_state_created_idx
    ON dry_run_jobs (state, created_at DESC);

CREATE TABLE dry_run_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES dry_run_jobs(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,

    -- What the LLM said this time.
    llm_action_kind TEXT,             -- e.g. 'takedown', 'warn', 'no_action'
    llm_label_value TEXT,             -- when llm_action_kind = 'label'
    llm_confidence REAL,              -- 0.0..1.0
    llm_cited_policy_identifiers TEXT[] NOT NULL DEFAULT '{}',
    llm_reasoning TEXT,

    -- What the human moderator actually did. Read from the most
    -- recent action against the primary subject. NULL when the
    -- incident closed with `no_action` (which the comparison
    -- treats as a real outcome).
    human_action_kind TEXT,
    human_label_value TEXT,

    -- Comparison: did the LLM's recommended action kind match the
    -- human's recorded outcome? `NULL` when the LLM errored out
    -- (`error_message` populated) and we have no recommendation
    -- to compare against.
    matched BOOLEAN,
    error_message TEXT,

    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX dry_run_results_job_idx
    ON dry_run_results (job_id, recorded_at DESC);

CREATE INDEX dry_run_results_disagreements_idx
    ON dry_run_results (job_id)
    WHERE matched = FALSE;

INSERT INTO _polaris_schema_version (version, description)
    VALUES (54, 'dry-run-calibration-jobs');
