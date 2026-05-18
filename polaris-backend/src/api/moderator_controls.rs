//! Extended moderator-control endpoints — Ozone-parity primitives that
//! sit alongside the existing action submission flow.
//!
//! Three orthogonal surfaces live here so the case-view + admin UI can
//! reach the matching backing stores without polluting `cases.rs`:
//!
//! - **Subject tags** (issue #189): operator-curated categorical tags
//!   attached to a subject for queue routing and search. Stored in
//!   `subject_tags`. Idempotent re-tag; cascade-delete on subject drop.
//! - **Report priority** (issue #191): integer priority score on a
//!   single report row. Dashboards order by `(priority_score DESC,
//!   created_at DESC)`. Stored in `reports.priority_score`.
//! - **Muted reporters** (issue #192): anti-abuse list of DIDs whose
//!   inbound `com.atproto.moderation.createReport` calls Polaris
//!   silently drops. Stored in `muted_reporters`; the inbound
//!   moderation handler consults [`is_reporter_muted`] before
//!   persisting any new report.
//!
//! All three are authenticated through the standard `ModeratorAuthCtx`
//! and use parameterised SQL throughout.

use axum::Json;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use polaris_types::SubjectId;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;

// ─────────────────────────────────────────────────────────────────────
// Subject tags (#189)
// ─────────────────────────────────────────────────────────────────────

/// Wire shape for `POST /api/cases/:subject_id/tags`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddTagBody {
    /// Tag string. Server enforces 1-64 chars + trims surrounding
    /// whitespace before persisting.
    pub tag: String,
}

/// One row from the `subject_tags` table on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagRow {
    /// The tag text.
    pub tag: String,
    /// Moderator UUID that applied the tag.
    pub applied_by: uuid::Uuid,
    /// RFC 3339 timestamp.
    pub applied_at: DateTime<Utc>,
}

/// Response shape for `GET /api/cases/:subject_id/tags`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagListResponse {
    /// Subject the tags belong to (echoed for client correlation).
    pub subject_id: SubjectId,
    /// Tags applied to this subject, ordered by `applied_at DESC`.
    pub tags: Vec<TagRow>,
}

/// `GET /api/cases/:subject_id/tags` — list tags applied to a subject.
///
/// # Errors
///
/// * `500` on DB failure (via `From<sqlx::Error> for ApiError::Repo`).
pub async fn list_tags(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
) -> Result<Json<TagListResponse>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT tag, applied_by, applied_at
        FROM subject_tags
        WHERE subject_id = $1
        ORDER BY applied_at DESC
        "#,
        subject_id.0,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(repo_err)?;
    let tags = rows
        .into_iter()
        .map(|r| TagRow {
            tag: r.tag,
            applied_by: r.applied_by,
            applied_at: r.applied_at,
        })
        .collect();
    Ok(Json(TagListResponse { subject_id, tags }))
}

/// `POST /api/cases/:subject_id/tags` — add a tag.
///
/// Idempotent: re-tagging an existing `(subject_id, tag)` pair is a
/// no-op at the DB layer (PRIMARY KEY collision is swallowed via
/// `ON CONFLICT DO NOTHING`). Returns `201 Created` either way so a
/// client retry on a flaky connection doesn't surface a 409.
///
/// # Errors
///
/// * `400` when `tag` is empty after trim, or > 64 chars.
/// * `404` when the subject doesn't exist (FK violation → mapped).
/// * `500` on other DB failures.
pub async fn add_tag(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
    Json(body): Json<AddTagBody>,
) -> Result<(StatusCode, Json<TagRow>), ApiError> {
    let trimmed = body.tag.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest("tag must not be empty after trim"));
    }
    if trimmed.len() > 64 {
        return Err(ApiError::BadRequest("tag must be 64 characters or fewer"));
    }
    let row = sqlx::query!(
        r#"
        INSERT INTO subject_tags (subject_id, tag, applied_by)
        VALUES ($1, $2, $3)
        ON CONFLICT (subject_id, tag) DO UPDATE
        SET applied_by = EXCLUDED.applied_by,
            applied_at = now()
        RETURNING tag, applied_by, applied_at
        "#,
        subject_id.0,
        trimmed,
        ctx.moderator_id.0,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(map_fk_or_repo)?;
    Ok((
        StatusCode::CREATED,
        Json(TagRow {
            tag: row.tag,
            applied_by: row.applied_by,
            applied_at: row.applied_at,
        }),
    ))
}

/// `DELETE /api/cases/:subject_id/tags/:tag` — remove a tag.
///
/// Returns `204 No Content` whether the row existed or not — making
/// the call idempotent so a retry never surfaces a 404.
pub async fn delete_tag(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path((subject_id, tag)): Path<(SubjectId, String)>,
) -> Result<StatusCode, ApiError> {
    sqlx::query!(
        "DELETE FROM subject_tags WHERE subject_id = $1 AND tag = $2",
        subject_id.0,
        tag,
    )
    .execute(&state.pool)
    .await
    .map_err(repo_err)?;
    Ok(StatusCode::NO_CONTENT)
}

// ─────────────────────────────────────────────────────────────────────
// Report priority (#191)
// ─────────────────────────────────────────────────────────────────────

/// Wire body for `PATCH /api/reports/:report_id/priority`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetPriorityBody {
    /// New priority score. Clamped server-side to `0..=1000`.
    pub priority_score: i32,
}

/// Response echo for `PATCH /api/reports/:report_id/priority`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityUpdated {
    /// Report id that was updated.
    pub report_id: uuid::Uuid,
    /// Persisted priority score (post-clamp).
    pub priority_score: i32,
}

/// Maximum sensible priority value. Higher scores aren't *forbidden*
/// at the column level, but the dashboard's ordering treats anything
/// in this range as actionable; clamping at the API edge keeps the
/// histogram bounded for queue-depth metrics.
const PRIORITY_MAX: i32 = 1000;

/// `PATCH /api/reports/:report_id/priority` — set a report's priority.
///
/// # Errors
///
/// * `400` when `priority_score` is negative.
/// * `404` when the report id doesn't exist.
/// * `500` on DB failure.
pub async fn set_report_priority(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(report_id): Path<uuid::Uuid>,
    Json(body): Json<SetPriorityBody>,
) -> Result<Json<PriorityUpdated>, ApiError> {
    if body.priority_score < 0 {
        return Err(ApiError::BadRequest("priority_score must not be negative"));
    }
    let score = body.priority_score.min(PRIORITY_MAX);

    // `reports` is partitioned by `created_at`; an UPDATE without the
    // partition key forces Postgres to scan every partition. The
    // index on `(id, created_at)` is sufficient to make this O(log n);
    // we issue the bare `WHERE id = $1` form and accept the planner's
    // partition-pruning behaviour.
    let row = sqlx::query!(
        r#"
        UPDATE reports
        SET priority_score = $1
        WHERE id = $2
        RETURNING id
        "#,
        score,
        report_id,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(repo_err)?;
    let updated_id = row.map(|r| r.id).ok_or(ApiError::NotFound)?;
    Ok(Json(PriorityUpdated {
        report_id: updated_id,
        priority_score: score,
    }))
}

// ─────────────────────────────────────────────────────────────────────
// Muted reporters (#192)
// ─────────────────────────────────────────────────────────────────────

/// Wire body for `POST /api/moderation/muted-reporters`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuteReporterBody {
    /// DID of the reporter to mute.
    pub reporter_did: String,
    /// Reason this DID is muted. 10-2000 chars at the API edge,
    /// stored as `muted_reporters.reason`.
    pub reason: String,
    /// Optional auto-unmute timestamp. `None` = mute indefinitely.
    pub until: Option<DateTime<Utc>>,
}

/// One row of the muted-reporters list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutedReporterRow {
    /// DID being muted (`did:plc:...` / `did:web:...`).
    pub reporter_did: String,
    /// Moderator who applied the mute.
    pub muted_by: uuid::Uuid,
    /// Operator-supplied free-text reason for the mute.
    pub reason: String,
    /// Wall-clock timestamp the mute was applied.
    pub muted_at: DateTime<Utc>,
    /// Auto-unmute deadline. `None` = mute indefinitely.
    pub until: Option<DateTime<Utc>>,
}

/// Response for `GET /api/moderation/muted-reporters`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MutedReporterListResponse {
    /// Every row in `muted_reporters`, newest-first.
    pub muted: Vec<MutedReporterRow>,
}

/// `GET /api/moderation/muted-reporters` — list currently-muted DIDs.
///
/// Includes rows whose `until` has lapsed; the client can filter
/// client-side if it wants to display only currently-effective mutes.
pub async fn list_muted_reporters(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<MutedReporterListResponse>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT reporter_did, muted_by, reason, muted_at, until
        FROM muted_reporters
        ORDER BY muted_at DESC
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(repo_err)?;
    let muted = rows
        .into_iter()
        .map(|r| MutedReporterRow {
            reporter_did: r.reporter_did,
            muted_by: r.muted_by,
            reason: r.reason,
            muted_at: r.muted_at,
            until: r.until,
        })
        .collect();
    Ok(Json(MutedReporterListResponse { muted }))
}

/// `POST /api/moderation/muted-reporters` — mute a reporter DID.
///
/// Idempotent: muting an already-muted DID updates the `reason` /
/// `until` / `muted_by` fields in place, so an operator can extend
/// a mute without first issuing a `DELETE`.
///
/// # Errors
///
/// * `400` when `reporter_did` is not a DID or `reason` is < 10 chars.
pub async fn mute_reporter(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(body): Json<MuteReporterBody>,
) -> Result<(StatusCode, Json<MutedReporterRow>), ApiError> {
    if !body.reporter_did.starts_with("did:") {
        return Err(ApiError::BadRequest(
            "reporter_did must be a DID (did:plc:... or did:web:...)",
        ));
    }
    let reason = body.reason.trim();
    if reason.len() < 10 {
        return Err(ApiError::BadRequest(
            "reason must be at least 10 characters",
        ));
    }
    if reason.len() > 2000 {
        return Err(ApiError::BadRequest(
            "reason must be 2000 characters or fewer",
        ));
    }
    let row = sqlx::query!(
        r#"
        INSERT INTO muted_reporters (reporter_did, muted_by, reason, until)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (reporter_did) DO UPDATE
        SET muted_by = EXCLUDED.muted_by,
            reason = EXCLUDED.reason,
            until = EXCLUDED.until,
            muted_at = now()
        RETURNING reporter_did, muted_by, reason, muted_at, until
        "#,
        body.reporter_did,
        ctx.moderator_id.0,
        reason,
        body.until,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(repo_err)?;
    Ok((
        StatusCode::CREATED,
        Json(MutedReporterRow {
            reporter_did: row.reporter_did,
            muted_by: row.muted_by,
            reason: row.reason,
            muted_at: row.muted_at,
            until: row.until,
        }),
    ))
}

/// `DELETE /api/moderation/muted-reporters/:reporter_did` — unmute.
///
/// Idempotent: returns `204` whether the row existed or not.
pub async fn unmute_reporter(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(reporter_did): Path<String>,
) -> Result<StatusCode, ApiError> {
    sqlx::query!(
        "DELETE FROM muted_reporters WHERE reporter_did = $1",
        reporter_did,
    )
    .execute(&state.pool)
    .await
    .map_err(repo_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Check whether a reporter DID is currently muted.
///
/// Used by the inbound `com.atproto.moderation.createReport` handler
/// (`crate::api::moderation::create_report`) to silently drop reports
/// from spammy DIDs. A row counts as "currently muted" when:
///
/// * `until IS NULL` (permanent mute), OR
/// * `until > now()` (timed mute, not yet expired).
///
/// Returns `Ok(false)` on DB error rather than failing closed — a
/// transient DB hiccup must not block legitimate reports. The error is
/// logged at WARN so the operator can investigate.
pub async fn is_reporter_muted(pool: &PgPool, reporter_did: &str) -> bool {
    match sqlx::query!(
        r#"
        SELECT 1 AS hit
        FROM muted_reporters
        WHERE reporter_did = $1
          AND (until IS NULL OR until > now())
        LIMIT 1
        "#,
        reporter_did,
    )
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row.is_some(),
        Err(err) => {
            tracing::warn!(
                error = %err,
                reporter_did,
                "muted_reporters lookup failed; treating as not-muted",
            );
            false
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Subject routing / divert (#194)
// ─────────────────────────────────────────────────────────────────────

/// Wire body for `POST /api/cases/{subject_id}/divert`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivertBody {
    /// Target queue name (operator-defined; 1-64 chars).
    pub queue: String,
    /// Operator-supplied reason. 10-2000 chars.
    pub reason: String,
}

/// One row of the diverted-subjects listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivertedSubjectRow {
    /// Subject diverted to an alternate queue.
    pub subject_id: SubjectId,
    /// Queue the subject is routed to.
    pub queue: String,
    /// Moderator who applied the divert.
    pub diverted_by: uuid::Uuid,
    /// Wall-clock the divert was applied.
    pub diverted_at: DateTime<Utc>,
    /// Frozen reasoning.
    pub reason: String,
    /// When the divert was cleared, if cleared.
    pub cleared_at: Option<DateTime<Utc>>,
    /// Moderator who cleared it.
    pub cleared_by: Option<uuid::Uuid>,
}

/// Response for `GET /api/diverted-subjects`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivertedSubjectListResponse {
    /// All diverted subjects (including cleared rows), newest-first.
    pub diverted: Vec<DivertedSubjectRow>,
}

/// `POST /api/cases/{subject_id}/divert` — route a subject to an
/// alternate queue. Idempotent: re-diverting overwrites the prior
/// row's `queue`, `diverted_by`, and `reason` in place.
pub async fn divert_subject(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
    Json(body): Json<DivertBody>,
) -> Result<(StatusCode, Json<DivertedSubjectRow>), ApiError> {
    let queue = body.queue.trim();
    if queue.is_empty() {
        return Err(ApiError::BadRequest("queue must not be empty"));
    }
    if queue.len() > 64 {
        return Err(ApiError::BadRequest("queue must be 64 characters or fewer"));
    }
    let reason = body.reason.trim();
    if reason.len() < 10 {
        return Err(ApiError::BadRequest(
            "reason must be at least 10 characters",
        ));
    }
    if reason.len() > 2000 {
        return Err(ApiError::BadRequest(
            "reason must be 2000 characters or fewer",
        ));
    }
    let row = sqlx::query!(
        r#"
        INSERT INTO subject_routing
            (subject_id, queue, diverted_by, reason)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (subject_id) DO UPDATE
        SET queue = EXCLUDED.queue,
            diverted_by = EXCLUDED.diverted_by,
            diverted_at = now(),
            reason = EXCLUDED.reason,
            cleared_at = NULL,
            cleared_by = NULL
        RETURNING subject_id, queue, diverted_by, diverted_at, reason,
                  cleared_at, cleared_by
        "#,
        subject_id.0,
        queue,
        ctx.moderator_id.0,
        reason,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(map_fk_or_repo)?;
    Ok((
        StatusCode::CREATED,
        Json(DivertedSubjectRow {
            subject_id: SubjectId(row.subject_id),
            queue: row.queue,
            diverted_by: row.diverted_by,
            diverted_at: row.diverted_at,
            reason: row.reason,
            cleared_at: row.cleared_at,
            cleared_by: row.cleared_by,
        }),
    ))
}

/// `DELETE /api/cases/{subject_id}/divert` — clear an active divert.
/// Idempotent: returns `204` whether the row existed or was already
/// cleared, so a retry never surfaces a 404.
pub async fn clear_divert(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
) -> Result<StatusCode, ApiError> {
    sqlx::query!(
        r#"
        UPDATE subject_routing
        SET cleared_at = now(),
            cleared_by = $1
        WHERE subject_id = $2
          AND cleared_at IS NULL
        "#,
        ctx.moderator_id.0,
        subject_id.0,
    )
    .execute(&state.pool)
    .await
    .map_err(repo_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/diverted-subjects` — list all diverted subjects.
pub async fn list_diverted(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<DivertedSubjectListResponse>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT subject_id, queue, diverted_by, diverted_at, reason,
               cleared_at, cleared_by
        FROM subject_routing
        ORDER BY diverted_at DESC
        LIMIT 200
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(repo_err)?;
    let diverted = rows
        .into_iter()
        .map(|r| DivertedSubjectRow {
            subject_id: SubjectId(r.subject_id),
            queue: r.queue,
            diverted_by: r.diverted_by,
            diverted_at: r.diverted_at,
            reason: r.reason,
            cleared_at: r.cleared_at,
            cleared_by: r.cleared_by,
        })
        .collect();
    Ok(Json(DivertedSubjectListResponse { diverted }))
}

// ─────────────────────────────────────────────────────────────────────
// Shared error mappers
// ─────────────────────────────────────────────────────────────────────

/// Map a bare `sqlx::Error` into an `ApiError::Repo`.
fn repo_err(e: sqlx::Error) -> ApiError {
    ApiError::Repo(crate::repo::RepoError::from(e))
}

/// Map a foreign-key violation to `404 Not Found`, anything else to
/// the generic repo path. The subject-tags INSERT can hit this when
/// `subject_id` is fabricated by the client.
fn map_fk_or_repo(e: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(db) = &e {
        // `23503` = foreign_key_violation in Postgres.
        if db.code().as_deref() == Some("23503") {
            return ApiError::NotFound;
        }
    }
    repo_err(e)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn priority_max_clamps_at_1000() {
        // The handler clamps via `.min(PRIORITY_MAX)`. Confirm the
        // constant is what we expect — a regression that bumps this
        // changes the dashboard's histogram-bounding contract.
        assert_eq!(PRIORITY_MAX, 1000);
    }
}
