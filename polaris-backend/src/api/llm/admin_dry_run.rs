//! Admin dry-run calibration endpoints (LLM-11 / #240 /
//! `.design/llm-moderation-assist.md` REQ-H1, REQ-H2).
//!
//! Two endpoints:
//!
//! * `POST /api/admin/llm/dry-run` — kick off a new calibration
//!   job. Body specifies `{policy_identifier?: string, lookback_days:
//!   int}`. Returns the new `job_id` immediately; the actual replay
//!   runs in a background task spawned by
//!   [`crate::llm::dry_run::spawn_dry_run_job`].
//! * `GET /api/admin/llm/dry-run/{job_id}` — poll a job. Returns
//!   the row's current state, aggregate stats (counts), and a
//!   sample of disagreements (capped at 20 so the response stays
//!   tractable while the operator is reading it).
//!
//! RBAC: admin-only. The auth middleware has already attached the
//! [`ModeratorAuthCtx`] extension before this handler runs.

use axum::extract::{Path, State};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::llm::dry_run;

/// Maximum disagreement rows returned alongside the aggregate stats
/// in the poll response. Keeps the JSON payload bounded so the
/// operator's browser doesn't grind on a job that produced hundreds
/// of mismatches.
const DISAGREEMENT_SAMPLE_LIMIT: i64 = 20;

/// Maximum `lookback_days` an operator may request. Matches the SQL
/// CHECK constraint on migration 54.
const MAX_LOOKBACK_DAYS: i32 = 90;

/// Body for `POST /api/admin/llm/dry-run`.
#[derive(Debug, Clone, Deserialize)]
pub struct DryRunRequest {
    /// When supplied, the replay restricts to incidents whose
    /// actions cite this policy. `None` runs across every policy
    /// (use sparingly — the row count multiplies fast).
    #[serde(default)]
    pub policy_identifier: Option<String>,

    /// How far back to look. Server clamps to `[1, 90]`.
    pub lookback_days: i32,
}

/// Response for `POST /api/admin/llm/dry-run` — the freshly-created
/// job id the operator polls.
#[derive(Debug, Clone, Serialize)]
pub struct DryRunStartResponse {
    /// Surrogate primary key of the newly-spawned dry-run job. The
    /// operator polls progress via `GET /api/admin/llm/dry-run/{job_id}`.
    pub job_id: Uuid,
}

/// Response for `GET /api/admin/llm/dry-run/{job_id}`.
#[derive(Debug, Clone, Serialize)]
pub struct DryRunJobView {
    /// Surrogate primary key of the job row.
    pub id: Uuid,
    /// Lifecycle state: one of `pending`, `running`, `done`, `failed`.
    pub state: String,
    /// Policy filter the job is restricted to, or `None` for
    /// "every policy".
    pub policy_identifier: Option<String>,
    /// How far back the replay reaches in days.
    pub lookback_days: i32,
    /// Wall-clock time the job row was inserted.
    pub created_at: DateTime<Utc>,
    /// Wall-clock time the job transitioned to `done`/`failed`,
    /// or `None` while still in progress.
    pub completed_at: Option<DateTime<Utc>>,
    /// Number of historical incidents the runner has visited so far.
    pub cases_evaluated: i32,
    /// Cases where the LLM and the human moderator agreed on the
    /// primary `action_kind`.
    pub agreements: i32,
    /// Cases where the LLM and the human moderator disagreed.
    pub disagreements: i32,
    /// Cases the runner skipped due to a per-case error (hydrate,
    /// recommend, or DB write failure). The job continues past
    /// per-case errors.
    pub errors: i32,
    /// Top-level error message if the job itself failed (vs. a
    /// per-case error), otherwise `None`.
    pub error_message: Option<String>,
    /// Agreement rate as a fraction in `[0.0, 1.0]`, computed
    /// server-side so the operator's UI doesn't have to. `None`
    /// when the job has not evaluated any cases yet.
    pub agreement_rate: Option<f64>,
    /// Sample of disagreement rows (at most
    /// [`DISAGREEMENT_SAMPLE_LIMIT`]). Useful for spotting calibration
    /// patterns at a glance.
    pub disagreement_sample: Vec<DryRunDisagreementRow>,
}

/// One row from `dry_run_results` where the LLM's primary
/// recommendation disagreed with the human moderator's actual outcome.
/// Surfaced in the poll response as a small calibration sample.
#[derive(Debug, Clone, Serialize)]
pub struct DryRunDisagreementRow {
    /// Incident the disagreement is about.
    pub incident_id: Uuid,
    /// `action_kind` the LLM recommended (or `None` if the LLM
    /// errored / returned an empty `recommended_actions` array).
    pub llm_action_kind: Option<String>,
    /// LLM confidence for the primary recommendation, in `[0, 1]`.
    pub llm_confidence: Option<f32>,
    /// Free-text reasoning the LLM emitted on the primary
    /// recommendation.
    pub llm_reasoning: Option<String>,
    /// `action_kind` the human moderator actually committed on the
    /// incident, or `None` if the incident closed without an action.
    pub human_action_kind: Option<String>,
}

/// `POST /api/admin/llm/dry-run` — kick off a job.
///
/// # Errors
/// * [`ApiError::Forbidden`] for non-admin callers.
/// * [`ApiError::Internal`] on DB failure.
/// * `400 Bad Request` (via Internal with a descriptive message) when
///   the LLM dispatcher is not installed (deployment has no LLM
///   adapter wired up — running a dry-run is meaningless without
///   one).
pub async fn start_dry_run(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(req): Json<DryRunRequest>,
) -> Result<Json<DryRunStartResponse>, ApiError> {
    require_admin(&ctx)?;

    if req.lookback_days < 1 || req.lookback_days > MAX_LOOKBACK_DAYS {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "lookback_days must be in [1, {MAX_LOOKBACK_DAYS}]; got {}",
            req.lookback_days,
        )));
    }

    let Some(dispatcher) = state.llm_dispatcher.as_ref() else {
        return Err(ApiError::Internal(anyhow::anyhow!(
            "dry-run requested but no LLM dispatcher is installed",
        )));
    };

    // Insert the job row. The `requested_by_moderator_id` carries
    // the audit trail of who kicked it off — visible only in the
    // admin DB query path, not in any wire payload that crosses
    // the LLM-substrate boundary.
    let row = sqlx::query!(
        r"INSERT INTO dry_run_jobs
            (policy_identifier, lookback_days, requested_by_moderator_id)
          VALUES ($1, $2, $3)
          RETURNING id",
        req.policy_identifier,
        req.lookback_days,
        ctx.moderator_id.0,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("dry-run job insert: {e}")))?;

    let job_id = row.id;
    dry_run::spawn_dry_run_job(state.pool.clone(), dispatcher.classifier_client(), job_id);

    Ok(Json(DryRunStartResponse { job_id }))
}

/// `GET /api/admin/llm/dry-run/{job_id}` — poll a job's state +
/// stats. The disagreement sample is cheap-to-compute via a
/// partial-index query; we include it on every poll so the operator
/// gets the same shape regardless of whether the job is still
/// running or done.
///
/// # Errors
/// * [`ApiError::Forbidden`] for non-admin callers.
/// * [`ApiError::Internal`] on DB failure or missing `job_id`.
pub async fn get_dry_run_job(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<DryRunJobView>, ApiError> {
    require_admin(&ctx)?;

    let job = sqlx::query!(
        r"
        SELECT id, state, policy_identifier, lookback_days, created_at,
               completed_at, cases_evaluated, agreements, disagreements,
               errors, error_message
          FROM dry_run_jobs
         WHERE id = $1
        ",
        job_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("dry-run job lookup: {e}")))?
    .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("dry-run job {job_id} not found")))?;

    // Compute the agreement rate. Denominator is "cases the LLM
    // produced a comparison for" = agreements + disagreements
    // (skipping the no-human-outcome rows so the operator gets a
    // rate that reflects the LLM's actual decision quality).
    let agreement_rate: Option<f64> = {
        let comparable = job.agreements + job.disagreements;
        if comparable > 0 {
            Some(f64::from(job.agreements) / f64::from(comparable))
        } else {
            None
        }
    };

    let disagreements = sqlx::query!(
        r"
        SELECT incident_id, llm_action_kind, llm_confidence, llm_reasoning,
               human_action_kind
          FROM dry_run_results
         WHERE job_id = $1 AND matched = FALSE
         ORDER BY recorded_at DESC
         LIMIT $2
        ",
        job_id,
        DISAGREEMENT_SAMPLE_LIMIT,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!("dry-run disagreement sample: {e}")))?;

    Ok(Json(DryRunJobView {
        id: job.id,
        state: job.state,
        policy_identifier: job.policy_identifier,
        lookback_days: job.lookback_days,
        created_at: job.created_at,
        completed_at: job.completed_at,
        cases_evaluated: job.cases_evaluated,
        agreements: job.agreements,
        disagreements: job.disagreements,
        errors: job.errors,
        error_message: job.error_message,
        agreement_rate,
        disagreement_sample: disagreements
            .into_iter()
            .map(|r| DryRunDisagreementRow {
                incident_id: r.incident_id,
                llm_action_kind: r.llm_action_kind,
                llm_confidence: r.llm_confidence,
                llm_reasoning: r.llm_reasoning,
                human_action_kind: r.human_action_kind,
            })
            .collect(),
    }))
}

/// Mirrors the gate used in [`crate::api::llm::admin_audit`] and the
/// other admin modules — single check on `Role::Admin`.
fn require_admin(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
