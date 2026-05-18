//! Scheduled takedowns — deferred takedown execution (L1 / Ozone-parity
//! `tools.ozone.moderation.defs#scheduleTakedownEvent` and
//! `#cancelScheduledTakedownEvent`).
//!
//! Three surfaces live here:
//!
//! - `POST /api/scheduled-takedowns` — schedule a takedown for a
//!   future timestamp. Persists the operator's intent + frozen
//!   reasoning + policy citations.
//! - `DELETE /api/scheduled-takedowns/{id}` — cancel a pending
//!   schedule. Cannot cancel one that has already executed.
//! - `GET /api/scheduled-takedowns` — list pending + recently-
//!   terminal schedules.
//!
//! The actual execution lives in [`crate::workers::scheduled_takedown_worker`]
//! (a detached tokio task that polls `scheduled_takedowns` for rows
//! whose `execute_at <= now() AND executed_at IS NULL AND cancelled_at
//! IS NULL` and inserts an `actions` row of `kind = takedown` for each).

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use polaris_types::{IncidentId, PolicyId, SubjectId};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;

/// Wire body for `POST /api/scheduled-takedowns`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleTakedownBody {
    /// Subject the takedown will eventually target.
    pub subject_id: SubjectId,
    /// Incident binding (the takedown's eventual `actions` row
    /// references this incident).
    pub incident_id: IncidentId,
    /// When the takedown should fire. Must be strictly in the future.
    pub execute_at: DateTime<Utc>,
    /// Moderator's reasoning. Frozen at schedule time and carried
    /// over to the eventual `actions` row verbatim.
    pub reasoning: String,
    /// Policy clauses cited. At least one; each must appear in the
    /// `policy::KNOWN_POLICY_REFS` allow-list.
    pub policy_refs: Vec<PolicyId>,
    /// Optional label-value override (e.g. `!moderate-account`).
    /// `None` = default takedown class.
    pub label_value: Option<String>,
}

/// Wire shape for a single scheduled-takedown row in API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTakedownRow {
    /// Stable identifier for this schedule.
    pub id: uuid::Uuid,
    /// Subject the takedown targets.
    pub subject_id: SubjectId,
    /// Incident binding.
    pub incident_id: IncidentId,
    /// Moderator who scheduled it.
    pub created_by: uuid::Uuid,
    /// When the worker should fire the takedown.
    pub execute_at: DateTime<Utc>,
    /// Frozen-at-schedule reasoning.
    pub reasoning: String,
    /// Policy refs cited.
    pub policy_refs: Vec<String>,
    /// Optional label-value override.
    pub label_value: Option<String>,
    /// When the schedule was created.
    pub created_at: DateTime<Utc>,
    /// When the worker fired the takedown, if it has fired.
    pub executed_at: Option<DateTime<Utc>>,
    /// The `actions.id` of the materialised takedown row.
    pub executed_action_id: Option<uuid::Uuid>,
    /// When the schedule was cancelled, if cancelled.
    pub cancelled_at: Option<DateTime<Utc>>,
    /// Moderator who cancelled the schedule.
    pub cancelled_by: Option<uuid::Uuid>,
}

/// Response for `GET /api/scheduled-takedowns`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledTakedownListResponse {
    /// Schedules, newest-first.
    pub scheduled: Vec<ScheduledTakedownRow>,
}

/// `POST /api/scheduled-takedowns` — schedule a takedown.
///
/// # Errors
///
/// * `400` when `execute_at` is in the past, `reasoning` is too short,
///   `policy_refs` is empty, or any cited policy is not in the
///   allow-list.
/// * `404` when `subject_id` / `incident_id` do not exist (FK
///   violation → mapped).
/// * `500` on DB failure.
pub async fn schedule(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(body): Json<ScheduleTakedownBody>,
) -> Result<(StatusCode, Json<ScheduledTakedownRow>), ApiError> {
    if body.execute_at <= Utc::now() {
        return Err(ApiError::BadRequest(
            "execute_at must be strictly in the future",
        ));
    }
    if body.reasoning.trim().len() < 10 {
        return Err(ApiError::BadRequest(
            "reasoning must be at least 10 characters",
        ));
    }
    if body.policy_refs.is_empty() {
        return Err(ApiError::BadRequest("policy_refs must be non-empty"));
    }
    // WB-2 / REQ-B3: resolve each cited identifier against the
    // `mod_policies` workbook. Unknown / retired policies are
    // rejected at the edge with the typed shape the action-create
    // path established. The scheduled-takedown handler is cool path
    // (single round-trip on a moderator click); we read through the
    // shared LRU cache so a burst of scheduled actions citing the
    // same policy hits the same warm slot.
    for r in &body.policy_refs {
        let identifier = r.as_str();
        let resolved = crate::api::policy_cache::get_current(&state.pool, identifier)
            .await
            .map_err(|e| match e {
                crate::repo::mod_policies::ModPolicyError::Database(inner) => {
                    ApiError::Repo(crate::repo::RepoError::from(inner))
                }
                _ => ApiError::Internal(anyhow::anyhow!("policy lookup failure: {e}")),
            })?;
        let Some(policy) = resolved else {
            return Err(ApiError::UnknownPolicyRef {
                identifier: identifier.to_owned(),
            });
        };
        if policy.is_retired {
            return Err(ApiError::PolicyRetired {
                identifier: identifier.to_owned(),
                retired_at: policy.effective_from,
            });
        }
    }
    let policy_refs_text: Vec<String> = body
        .policy_refs
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();
    let row = sqlx::query!(
        r#"
        INSERT INTO scheduled_takedowns
            (subject_id, incident_id, created_by, execute_at,
             reasoning, policy_refs, label_value)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, subject_id, incident_id, created_by, execute_at,
                  reasoning, policy_refs, label_value, created_at,
                  executed_at, executed_action_id, cancelled_at, cancelled_by
        "#,
        body.subject_id.0,
        body.incident_id.0,
        ctx.moderator_id.0,
        body.execute_at,
        body.reasoning.trim(),
        &policy_refs_text,
        body.label_value.as_deref(),
    )
    .fetch_one(&state.pool)
    .await
    .map_err(map_fk_or_repo)?;
    tracing::info!(
        id = %row.id,
        subject_id = %row.subject_id,
        execute_at = %row.execute_at,
        "scheduled takedown",
    );
    Ok((
        StatusCode::CREATED,
        Json(row_to_wire(
            row.id,
            row.subject_id,
            row.incident_id,
            row.created_by,
            row.execute_at,
            row.reasoning,
            row.policy_refs,
            row.label_value,
            row.created_at,
            row.executed_at,
            row.executed_action_id,
            row.cancelled_at,
            row.cancelled_by,
        )),
    ))
}

/// `DELETE /api/scheduled-takedowns/{id}` — cancel a pending schedule.
///
/// # Errors
///
/// * `404` when no row matches `id` OR the row is already executed.
/// * `409` when the row is already cancelled.
pub async fn cancel(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, ApiError> {
    // Atomic state-transition: only flip a row that is currently
    // PENDING (both executed_at IS NULL AND cancelled_at IS NULL).
    // Counting the affected rows lets us distinguish "no such id"
    // (404) from "already in a terminal state" (409).
    let result = sqlx::query!(
        r#"
        UPDATE scheduled_takedowns
        SET cancelled_at = now(),
            cancelled_by = $1
        WHERE id = $2
          AND executed_at IS NULL
          AND cancelled_at IS NULL
        "#,
        ctx.moderator_id.0,
        id,
    )
    .execute(&state.pool)
    .await
    .map_err(repo_err)?;
    if result.rows_affected() == 1 {
        return Ok(StatusCode::NO_CONTENT);
    }
    // Distinguish 404 from 409 by looking at the row's terminal state.
    let row = sqlx::query!(
        "SELECT executed_at, cancelled_at FROM scheduled_takedowns WHERE id = $1",
        id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(repo_err)?;
    match row {
        None => Err(ApiError::NotFound),
        Some(r) if r.executed_at.is_some() => {
            Err(ApiError::Conflict("scheduled takedown already executed"))
        }
        Some(r) if r.cancelled_at.is_some() => {
            Err(ApiError::Conflict("scheduled takedown already cancelled"))
        }
        // Race: row exists, no terminal state, but the UPDATE missed it.
        // Treat as 500 — this should be unreachable.
        Some(_) => Err(ApiError::Internal(anyhow::anyhow!(
            "scheduled-takedown cancel: race against in-flight update"
        ))),
    }
}

/// `GET /api/scheduled-takedowns` — list pending + recently-terminal
/// scheduled takedowns, newest-first.
pub async fn list_scheduled(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<ScheduledTakedownListResponse>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT id, subject_id, incident_id, created_by, execute_at,
               reasoning, policy_refs, label_value, created_at,
               executed_at, executed_action_id, cancelled_at, cancelled_by
        FROM scheduled_takedowns
        ORDER BY created_at DESC
        LIMIT 200
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(repo_err)?;
    let scheduled = rows
        .into_iter()
        .map(|r| {
            row_to_wire(
                r.id,
                r.subject_id,
                r.incident_id,
                r.created_by,
                r.execute_at,
                r.reasoning,
                r.policy_refs,
                r.label_value,
                r.created_at,
                r.executed_at,
                r.executed_action_id,
                r.cancelled_at,
                r.cancelled_by,
            )
        })
        .collect();
    Ok(Json(ScheduledTakedownListResponse { scheduled }))
}

#[allow(
    clippy::too_many_arguments,
    clippy::similar_names,
    reason = "thin row-to-wire mapper; one parameter per persisted column. \
              executed_at / executed_action_id / cancelled_at / cancelled_by \
              mirror the column names so renaming them away from the schema \
              would obscure the mapping."
)]
fn row_to_wire(
    id: uuid::Uuid,
    subject_id: uuid::Uuid,
    incident_id: uuid::Uuid,
    created_by: uuid::Uuid,
    execute_at: DateTime<Utc>,
    reasoning: String,
    policy_refs: Vec<String>,
    label_value: Option<String>,
    created_at: DateTime<Utc>,
    executed_at: Option<DateTime<Utc>>,
    executed_action_id: Option<uuid::Uuid>,
    cancelled_at: Option<DateTime<Utc>>,
    cancelled_by: Option<uuid::Uuid>,
) -> ScheduledTakedownRow {
    ScheduledTakedownRow {
        id,
        subject_id: SubjectId(subject_id),
        incident_id: IncidentId(incident_id),
        created_by,
        execute_at,
        reasoning,
        policy_refs,
        label_value,
        created_at,
        executed_at,
        executed_action_id,
        cancelled_at,
        cancelled_by,
    }
}

fn repo_err(e: sqlx::Error) -> ApiError {
    ApiError::Repo(crate::repo::RepoError::from(e))
}

fn map_fk_or_repo(e: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(db) = &e {
        if db.code().as_deref() == Some("23503") {
            return ApiError::NotFound;
        }
    }
    repo_err(e)
}
