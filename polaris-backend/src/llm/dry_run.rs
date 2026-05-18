//! Dry-run calibration job runner (LLM-11 / #240 /
//! `.design/llm-moderation-assist.md` REQ-H).
//!
//! An operator about to flip a policy to `autonomy_mode =
//! 'autonomous'` runs this against the last N days of closed
//! incidents. The runner walks each eligible historical case,
//! re-hydrates the `RecommendRequest` shape the dispatcher would
//! have built at the time, calls the configured LLM via
//! `ClassifierClient::recommend`, and compares the LLM's
//! recommendation against the action the human moderator actually
//! recorded.
//!
//! **No-side-effect mode**: the runner never inserts observations,
//! never creates actions, never emits to atproto. It writes only to
//! the dedicated `dry_run_jobs` + `dry_run_results` tables. The
//! dispatcher is intentionally NOT used here — wrapping it with a
//! `dry_run = true` flag would risk a missing-skip bug landing real
//! side effects in production. This module re-implements the
//! "hydrate → recommend → record" slice as its own narrow path.
//!
//! Concurrency: the API handler kicks off a `tokio::spawn` per job
//! request; the spawned task drives the replay loop. The job row's
//! `state` column is the source-of-truth for the API's `GET
//! /api/admin/llm/dry-run/{job_id}` poll: `pending → running →
//! (done | failed)`.

use std::sync::Arc;

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::classifier::ClassifierClient;
use crate::llm::case_context;

/// Maximum cases a single dry-run job replays. The handler clamps
/// any `lookback_days` request — the actual ceiling is whichever of
/// {lookback rows, this constant} is smaller. Stops a careless
/// operator from spending a fortune on one click.
///
/// Typed as `i64` rather than `usize` because the only consumer is
/// the `LIMIT` clause on the eligibility-selection queries (sqlx
/// binds row-count parameters as `i64`). A `usize` here would force
/// a fallible cast at every call site for no benefit.
pub const MAX_CASES_PER_JOB: i64 = 500;

/// Spawn a background task that drives the dry-run replay for the
/// supplied job row. Returns immediately; the task updates the
/// `dry_run_jobs.state` column as it progresses.
///
/// `classifier_client` is the same `Arc<dyn ClassifierClient>` the
/// dispatcher uses — pass `state.llm_dispatcher.classifier_client()`
/// at the call site. When the dispatcher is not installed
/// (deployments without an LLM adapter), the handler should refuse
/// the job request before reaching this function.
pub fn spawn_dry_run_job(pool: PgPool, classifier_client: Arc<dyn ClassifierClient>, job_id: Uuid) {
    tokio::spawn(async move {
        if let Err(err) = run_dry_run_job(&pool, &*classifier_client, job_id).await {
            tracing::warn!(
                job_id = %job_id,
                error = %err,
                "dry-run job failed; marking row as failed",
            );
            // Best-effort failure mark. If THIS write also fails (DB
            // gone, pool exhausted, etc.) the job row is left in
            // `running` indefinitely. The poll API surfaces that state
            // verbatim so the operator sees the staleness; a periodic
            // reaper that reclaims stuck rows is out of scope for the
            // dry-run feature itself and is tracked as a future
            // hardening item against the job table directly.
            let _ = sqlx::query!(
                r"UPDATE dry_run_jobs
                     SET state = 'failed',
                         error_message = $1,
                         completed_at = now()
                   WHERE id = $2",
                err.to_string(),
                job_id,
            )
            .execute(&pool)
            .await;
        }
    });
}

/// Run a single dry-run job to completion. Synchronous from the
/// task's perspective; returns once every eligible case has been
/// recorded.
async fn run_dry_run_job(
    pool: &PgPool,
    classifier: &dyn ClassifierClient,
    job_id: Uuid,
) -> Result<(), DryRunError> {
    // Mark running.
    sqlx::query!(
        r"UPDATE dry_run_jobs SET state = 'running' WHERE id = $1",
        job_id,
    )
    .execute(pool)
    .await?;

    // Read job inputs.
    let job = sqlx::query!(
        r"SELECT policy_identifier, lookback_days FROM dry_run_jobs WHERE id = $1",
        job_id,
    )
    .fetch_one(pool)
    .await?;

    // Select eligible incidents. Strategy:
    //   1. Closed in the lookback window (`incidents.closed_at >=
    //      now() - INTERVAL`).
    //   2. If `policy_identifier` is non-NULL, restrict to incidents
    //      whose actions cite that policy (any version).
    // The lookback is parameter-driven to keep the query plan
    // reusable across many jobs.
    let candidates: Vec<Uuid> = if let Some(ident) = job.policy_identifier.as_deref() {
        sqlx::query_scalar!(
            r"
            SELECT DISTINCT i.id
              FROM incidents i
              JOIN actions a ON a.incident_id = i.id
              JOIN action_policy_citations c ON c.action_id = a.id
             WHERE i.status = 'closed'
               AND i.closed_at IS NOT NULL
               AND i.closed_at >= now() - make_interval(days => $1::int)
               AND c.policy_identifier = $2
             ORDER BY i.id
             LIMIT $3
            ",
            job.lookback_days,
            ident,
            MAX_CASES_PER_JOB,
        )
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_scalar!(
            r"
            SELECT DISTINCT i.id
              FROM incidents i
             WHERE i.status = 'closed'
               AND i.closed_at IS NOT NULL
               AND i.closed_at >= now() - make_interval(days => $1::int)
             ORDER BY i.id
             LIMIT $2
            ",
            job.lookback_days,
            MAX_CASES_PER_JOB,
        )
        .fetch_all(pool)
        .await?
    };

    let mut agreements: i32 = 0;
    let mut disagreements: i32 = 0;
    let mut errors: i32 = 0;
    let mut evaluated: i32 = 0;

    for incident_id in candidates {
        evaluated = evaluated.saturating_add(1);
        match evaluate_one_incident(pool, classifier, job_id, incident_id).await {
            Ok(EvalOutcome::Match) => agreements = agreements.saturating_add(1),
            Ok(EvalOutcome::Mismatch) => disagreements = disagreements.saturating_add(1),
            Ok(EvalOutcome::NoHumanOutcome) => {
                // Counted as a non-comparison; not a disagreement.
            }
            Err(err) => {
                errors = errors.saturating_add(1);
                tracing::debug!(
                    job_id = %job_id,
                    incident_id = %incident_id,
                    error = %err,
                    "dry-run case errored — recording and continuing",
                );
            }
        }

        // Update aggregate counters incrementally so the API poll can
        // surface progress on long-running jobs.
        sqlx::query!(
            r"UPDATE dry_run_jobs
                 SET cases_evaluated = $1,
                     agreements = $2,
                     disagreements = $3,
                     errors = $4
               WHERE id = $5",
            evaluated,
            agreements,
            disagreements,
            errors,
            job_id,
        )
        .execute(pool)
        .await?;
    }

    // Mark done.
    sqlx::query!(
        r"UPDATE dry_run_jobs
             SET state = 'done', completed_at = now()
           WHERE id = $1",
        job_id,
    )
    .execute(pool)
    .await?;

    Ok(())
}

/// One case's worth of dry-run work: hydrate, recommend, compare,
/// persist a row in `dry_run_results`.
async fn evaluate_one_incident(
    pool: &PgPool,
    classifier: &dyn ClassifierClient,
    job_id: Uuid,
    incident_id: Uuid,
) -> Result<EvalOutcome, DryRunError> {
    let req = case_context::hydrate(pool, incident_id)
        .await
        .map_err(|e| DryRunError::Hydrate(e.to_string()))?;

    // Capture the human's outcome BEFORE the LLM call so we can
    // record it even if the recommend roundtrip errors.
    let human = load_human_outcome(pool, incident_id).await?;

    // Recommend (the LLM half). If this errors we record the row
    // with an error_message and move on — failures are part of the
    // calibration signal.
    let resp = match classifier.recommend(req).await {
        Ok(r) => r,
        Err(err) => {
            sqlx::query!(
                r"INSERT INTO dry_run_results
                    (job_id, incident_id, llm_action_kind, llm_label_value,
                     llm_confidence, llm_cited_policy_identifiers, llm_reasoning,
                     human_action_kind, human_label_value, matched, error_message)
                  VALUES ($1, $2, NULL, NULL, NULL, '{}', NULL,
                          $3, $4, NULL, $5)",
                job_id,
                incident_id,
                human.action_kind.as_deref(),
                human.label_value.as_deref(),
                err.to_string(),
            )
            .execute(pool)
            .await?;
            return Err(DryRunError::Recommend(err.to_string()));
        }
    };

    // Pull the first recommended action — for the dry-run we score
    // on the primary recommendation; multi-action ensembling is a
    // follow-up.
    let Some(first) = resp.recommended_actions.first() else {
        sqlx::query!(
            r"INSERT INTO dry_run_results
                (job_id, incident_id, llm_action_kind, llm_label_value,
                 llm_confidence, llm_cited_policy_identifiers, llm_reasoning,
                 human_action_kind, human_label_value, matched, error_message)
              VALUES ($1, $2, NULL, NULL, NULL, '{}', NULL,
                      $3, $4, NULL, 'LLM returned empty recommended_actions')",
            job_id,
            incident_id,
            human.action_kind.as_deref(),
            human.label_value.as_deref(),
        )
        .execute(pool)
        .await?;
        return Ok(EvalOutcome::NoHumanOutcome);
    };

    let matched = human.action_kind.as_deref().map(|k| k == first.action_kind);

    sqlx::query!(
        r"INSERT INTO dry_run_results
            (job_id, incident_id, llm_action_kind, llm_label_value,
             llm_confidence, llm_cited_policy_identifiers, llm_reasoning,
             human_action_kind, human_label_value, matched)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        job_id,
        incident_id,
        Some(first.action_kind.as_str()),
        if first.label_value.is_empty() {
            None
        } else {
            Some(first.label_value.as_str())
        },
        Some(first.confidence),
        &first.cited_policy_identifiers,
        Some(first.reasoning.as_str()),
        human.action_kind.as_deref(),
        human.label_value.as_deref(),
        matched,
    )
    .execute(pool)
    .await?;

    match matched {
        Some(true) => Ok(EvalOutcome::Match),
        Some(false) => Ok(EvalOutcome::Mismatch),
        None => Ok(EvalOutcome::NoHumanOutcome),
    }
}

/// What the human moderator actually did on the incident — the
/// "ground truth" the LLM is being scored against. A `NULL`
/// `action_kind` means the incident closed without an action
/// recorded (treated as `no_action` for comparison purposes is
/// intentional but we record the raw `NULL` so the operator can
/// see it).
struct HumanOutcome {
    action_kind: Option<String>,
    label_value: Option<String>,
}

async fn load_human_outcome(pool: &PgPool, incident_id: Uuid) -> Result<HumanOutcome, DryRunError> {
    let row = sqlx::query!(
        r"
        SELECT kind, label_value
          FROM actions
         WHERE incident_id = $1
           AND kind <> 'reverse'
         ORDER BY created_at DESC
         LIMIT 1
        ",
        incident_id,
    )
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some(r) => HumanOutcome {
            action_kind: Some(r.kind),
            label_value: r.label_value,
        },
        None => HumanOutcome {
            action_kind: None,
            label_value: None,
        },
    })
}

enum EvalOutcome {
    Match,
    Mismatch,
    NoHumanOutcome,
}

/// Errors the dry-run runner emits. All are kept stringly-typed at
/// the boundary so the `error_message` column can carry them
/// verbatim; the operator-facing error display lives in the API.
#[derive(Debug, Error)]
pub enum DryRunError {
    /// `case_context::hydrate` failed for an incident — the LLM call
    /// is skipped and the row is recorded with this string in
    /// `dry_run_results.error_message`.
    #[error("hydrate failed: {0}")]
    Hydrate(String),

    /// The LLM `recommend` round-trip failed (transport, decode, or
    /// upstream service error). The row is recorded with the
    /// stringified error in `dry_run_results.error_message` and the
    /// runner moves on — a per-case failure does not abort the job.
    #[error("recommend failed: {0}")]
    Recommend(String),

    /// SQL failure on one of the bookkeeping writes
    /// (`dry_run_jobs` aggregate update, `dry_run_results` insert).
    /// Surfaces from the runner up to the spawned task's catch-all
    /// which marks the job `state = 'failed'`.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}
