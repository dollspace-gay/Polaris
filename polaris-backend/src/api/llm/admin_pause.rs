//! Admin-only global LLM kill switch (REQ-S7; issue #241 / LLM-12).
//!
//! Two endpoints — both admin-only, both audit-logged — toggle
//! `polaris_setup_state.global_autonomous_pause_until` (the column
//! migration 52 added under LLM-3). While that column carries a
//! future timestamp, every `Recommend` call's effective mode is
//! downgraded to `manual` by [`crate::llm::safety_floors::check_s7_global_pause`]
//! regardless of per-policy autonomy configuration. Used in incident
//! response so the operator does not have to remember per-policy state
//! to halt every autonomous action at once.
//!
//! # Endpoints
//!
//! - `POST /api/admin/llm/pause` — body `{"until": "<RFC3339>"}`
//!   optional. Empty body / missing `until` pauses **forever** (the
//!   sentinel `9999-12-31T23:59:59Z` operator-readable distant future).
//!   A future timestamp is the right shape for "pause for the next 4
//!   hours"; the sentinel is the right shape for "pause until I
//!   explicitly clear this".
//! - `DELETE /api/admin/llm/pause` — clears the column (NULL).
//!
//! Both write inside a single transaction alongside an `audit_log`
//! event so a failed audit append rolls the toggle back. The
//! `polaris_llm_safety_floor_tripped_total{policy, floor="global_pause"}`
//! Prometheus counter (REQ-I1) records every dispatcher evaluation —
//! the kill switch's downstream effect is therefore observable without
//! a dedicated kill-switch counter.
//!
//! # Wire shapes
//!
//! `POST` request body:
//!
//! ```json
//! { "until": "2026-05-19T12:00:00Z" }   // or {} for forever
//! ```
//!
//! `POST` response body (`200 OK`):
//!
//! ```json
//! { "paused_until": "2026-05-19T12:00:00Z" }
//! ```
//!
//! `DELETE` response: `204 No Content` (empty body).

use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};

/// Sentinel "pause forever" timestamp.
///
/// Chosen as `9999-12-31T23:59:59Z` — the operator-readable end of the
/// `TIMESTAMPTZ`'s practical range. The S7 floor's predicate is
/// `column > now()` so any far-future value works; we pin the sentinel
/// so the audit-log payload is deterministic and grep-able.
///
/// Note: Postgres `TIMESTAMPTZ` supports up to `294276-01-01` so this
/// value is well-inside the storage range; chrono accepts it through
/// `DateTime::<Utc>` construction.
fn pause_forever_sentinel() -> DateTime<Utc> {
    // `unwrap()` is safe by construction — every component is in the
    // valid chrono range. The doctest below pins the literal.
    Utc.with_ymd_and_hms_or_unreachable(9999, 12, 31, 23, 59, 59)
}

/// Wrapper around `chrono::TimeZone::with_ymd_and_hms` that returns
/// the single valid result directly rather than the
/// [`chrono::LocalResult`] enum. The constant inputs we pass always
/// resolve to `Single(_)` so the helper unwraps that variant; an
/// ill-formed call panics with a clear message rather than silently
/// returning a wrong value via `unwrap_or_default`.
trait Utc9999Helper {
    fn with_ymd_and_hms_or_unreachable(
        self,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> DateTime<Utc>;
}

impl Utc9999Helper for Utc {
    #[allow(
        clippy::expect_used,
        reason = "the only caller passes constant inputs that always resolve to Single"
    )]
    fn with_ymd_and_hms_or_unreachable(
        self,
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        min: u32,
        sec: u32,
    ) -> DateTime<Utc> {
        use chrono::TimeZone as _;
        self.with_ymd_and_hms(year, month, day, hour, min, sec)
            .single()
            .expect("constant timestamp must construct")
    }
}

/// Request body for `POST /api/admin/llm/pause`.
///
/// `until` is optional. Missing / `None` means "pause forever" (the
/// sentinel `9999-12-31T23:59:59Z`); a present timestamp is the
/// time-bounded pause. The two shapes round-trip through the same
/// column.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PauseRequest {
    /// Future timestamp at which the pause expires. When omitted, the
    /// handler writes the sentinel value (`9999-12-31T23:59:59Z`) so
    /// the pause persists until an explicit `DELETE`.
    pub until: Option<DateTime<Utc>>,
}

/// Response body for `POST /api/admin/llm/pause`.
#[derive(Debug, Clone, Serialize)]
pub struct PauseResponse {
    /// The timestamp that landed in
    /// `polaris_setup_state.global_autonomous_pause_until`. Echoes
    /// the request's `until` value, or the forever sentinel if the
    /// request omitted it.
    pub paused_until: DateTime<Utc>,
}

/// Verify the caller is `Role::Admin`. Mirrors the shape of
/// `crate::api::admin_moderators::require_admin`.
fn require_admin(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// `POST /api/admin/llm/pause` — set the global LLM kill switch.
///
/// Writes `polaris_setup_state.global_autonomous_pause_until` and
/// appends an `audit_log` event in the same transaction (a failed
/// audit append rolls the toggle back). When the request body omits
/// `until` the handler writes the forever sentinel
/// (`9999-12-31T23:59:59Z`) so the operator can engage the switch
/// without committing to a specific re-enable time.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::Internal`] on DB or audit-log failure.
///
/// # Example
///
/// ```ignore
/// // Pause until 4pm UTC:
/// // curl -X POST -H 'cookie: <session>' -H 'content-type: application/json' \
/// //      -d '{"until":"2026-05-18T16:00:00Z"}' /api/admin/llm/pause
/// //
/// // Pause forever:
/// // curl -X POST -H 'cookie: <session>' -H 'content-type: application/json' \
/// //      -d '{}' /api/admin/llm/pause
/// ```
pub async fn pause_llm(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    body: Option<Json<PauseRequest>>,
) -> Result<Json<PauseResponse>, ApiError> {
    require_admin(&ctx)?;

    let req = body.map_or_else(PauseRequest::default, |Json(b)| b);
    let until = req.until.unwrap_or_else(pause_forever_sentinel);

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    sqlx::query!(
        r"UPDATE polaris_setup_state
          SET global_autonomous_pause_until = $1
          WHERE id = TRUE",
        until,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "llm_pause_engaged".to_owned(),
            payload: serde_json::json!({
                "paused_until": until,
                "forever": req.until.is_none(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tracing::warn!(
        moderator_id = %ctx.moderator_id,
        paused_until = %until,
        forever = req.until.is_none(),
        "llm kill switch engaged",
    );

    Ok(Json(PauseResponse {
        paused_until: until,
    }))
}

/// `DELETE /api/admin/llm/pause` — clear the global LLM kill switch.
///
/// Writes `polaris_setup_state.global_autonomous_pause_until = NULL`
/// and appends an `audit_log` event in the same transaction. Idempotent
/// — clearing a non-paused state is a no-op write that still records
/// the operator's action in the audit log.
///
/// Returns `204 No Content` on success.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::Internal`] on DB or audit-log failure.
///
/// # Example
///
/// ```ignore
/// // curl -X DELETE -H 'cookie: <session>' /api/admin/llm/pause
/// ```
pub async fn resume_llm(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx)?;

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    sqlx::query!(
        r"UPDATE polaris_setup_state
          SET global_autonomous_pause_until = NULL
          WHERE id = TRUE",
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "llm_pause_cleared".to_owned(),
            payload: serde_json::json!({}),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tracing::info!(
        moderator_id = %ctx.moderator_id,
        "llm kill switch cleared",
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use crate::auth::ModeratorId;
    use std::collections::HashSet;

    fn ctx_with(roles: &[Role]) -> ModeratorAuthCtx {
        ModeratorAuthCtx::new(
            ModeratorId::new_v4(),
            roles.iter().copied().collect::<HashSet<_>>(),
        )
    }

    #[test]
    fn require_admin_accepts_admin() {
        require_admin(&ctx_with(&[Role::Admin])).unwrap();
    }

    #[test]
    fn require_admin_rejects_non_admin() {
        let err = require_admin(&ctx_with(&[Role::SeniorModerator])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[Role::Moderator])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[Role::Triage])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn require_admin_rejects_empty_role_set() {
        let err = require_admin(&ctx_with(&[])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn pause_forever_sentinel_is_9999_year() {
        let s = pause_forever_sentinel();
        assert_eq!(
            s.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "9999-12-31T23:59:59Z"
        );
    }

    #[test]
    fn pause_request_default_is_empty() {
        let r = PauseRequest::default();
        assert!(r.until.is_none());
    }
}
