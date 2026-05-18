//! Moderator-facing read-only policy browse handlers (REQ-D4 / #225).
//!
//! Anyone who can take a moderation action can look up the rules
//! they're enforcing — so the read paths gate at `Role::Moderator`
//! (or above), not `Role::Admin`. Write paths live under
//! `/api/admin/policies/*` and stay admin-only.
//!
//! # Endpoints
//!
//! - `GET /api/policies` — list current-version summaries.
//! - `GET /api/policies/:identifier` — current full payload.
//!
//! # What moderators see
//!
//! Per the issue plan: moderators see the same fields admins see
//! (autonomy controls included). The design's REQ-D4 calls for a
//! read-only browse view; nothing in the workbook says moderators
//! get a redacted projection. Audit metadata (`created_*`,
//! `effective_*`, `supersedes_id`) is on the wire either way — it
//! is the row identity material the frontend may surface inline
//! (e.g. "policy version 5, in force since…").

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};

use crate::api::admin_policies::dto::{ModPolicyDto, ModPolicySummaryDto};
use crate::api::admin_policies::handlers::ListPoliciesQuery;
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::repo::mod_policies::{self, ModPolicyError, ModPolicyFilters};

/// Verify the caller holds at least one moderator-tier role. The
/// design says "anyone who can take a moderation action can read
/// the rules they're enforcing" — that maps to anything other than
/// the [`Role::ReadOnly`] audit role, and to having *some* role
/// (no role set means "not yet onboarded").
fn require_moderator(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    // Any of: Admin, SeniorModerator, Moderator, Triage. ReadOnly
    // is the audit role — they should NOT receive an Unauthorized,
    // they receive a Forbidden. Empty role set means "no role" —
    // an authenticated stranger; also Forbidden, not Unauthorized
    // (the auth middleware short-circuits unauthenticated traffic
    // before this handler runs).
    if ctx.roles.contains(&Role::Admin)
        || ctx.roles.contains(&Role::SeniorModerator)
        || ctx.roles.contains(&Role::Moderator)
        || ctx.roles.contains(&Role::Triage)
    {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Map [`ModPolicyError`] to the wire-facing [`ApiError`] for the
/// moderator-facing surface. Mirrors
/// [`crate::api::admin_policies::handlers`]'s mapping; kept local so
/// the module is self-contained.
fn map_policy_err(err: ModPolicyError) -> ApiError {
    match err {
        ModPolicyError::UnknownIdentifier { .. } => ApiError::NotFound,
        ModPolicyError::ConcurrentEdit { .. } | ModPolicyError::StaleVersion { .. } => {
            ApiError::Conflict("policy version is stale")
        }
        ModPolicyError::RetiredPolicy { .. } => ApiError::BadRequest("policy is retired"),
        ModPolicyError::Database(e) => ApiError::Internal(anyhow::Error::new(e)),
    }
}

/// `GET /api/policies`.
///
/// Returns the slim summary projection of every current-version
/// policy, filtered per the query string. Same payload shape the
/// admin list returns (REQ-C3 keeps the wire DTO unified).
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks any moderator-
///   tier role.
/// - [`ApiError::BadRequest`] when a vocabulary filter is invalid.
/// - [`ApiError::Internal`] on DB failure.
///
/// # Example
///
/// ```ignore
/// // Moderator browses all `assisted`-mode policies:
/// // GET /api/policies?autonomy_mode=assisted
/// ```
pub async fn list_policies(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Query(filters): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<ModPolicySummaryDto>>, ApiError> {
    require_moderator(&ctx)?;
    // Mirror the admin-list vocabulary checks so an invalid filter
    // returns 400 rather than swallowing it as a no-op.
    if let Some(scope) = &filters.scope {
        if !["account", "post", "both"].contains(&scope.as_str()) {
            return Err(ApiError::BadRequest(
                "scope must be one of: account, post, both",
            ));
        }
    }
    if let Some(mode) = &filters.autonomy_mode {
        if !["manual", "assisted", "autonomous"].contains(&mode.as_str()) {
            return Err(ApiError::BadRequest(
                "autonomy_mode must be one of: manual, assisted, autonomous",
            ));
        }
    }
    let rows = mod_policies::list(
        &state.pool,
        ModPolicyFilters {
            scope: filters.scope,
            autonomy_mode: filters.autonomy_mode,
            q: filters.q,
        },
    )
    .await
    .map_err(map_policy_err)?;
    Ok(Json(
        rows.into_iter().map(ModPolicySummaryDto::from).collect(),
    ))
}

/// `GET /api/policies/:identifier`.
///
/// Returns the current version of `identifier`. Same DTO shape the
/// admin GET serves.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks any moderator-
///   tier role.
/// - [`ApiError::NotFound`] when no current-version row exists.
/// - [`ApiError::Internal`] on DB failure.
///
/// # Example
///
/// ```ignore
/// // GET /api/policies/polaris.harassment
/// ```
pub async fn get_policy(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(identifier): Path<String>,
) -> Result<Json<ModPolicyDto>, ApiError> {
    require_moderator(&ctx)?;
    let policy = mod_policies::current_by_identifier(&state.pool, &identifier)
        .await
        .map_err(map_policy_err)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(policy.into()))
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
    fn moderator_tier_roles_pass() {
        assert!(require_moderator(&ctx_with(&[Role::Admin])).is_ok());
        assert!(require_moderator(&ctx_with(&[Role::SeniorModerator])).is_ok());
        assert!(require_moderator(&ctx_with(&[Role::Moderator])).is_ok());
        assert!(require_moderator(&ctx_with(&[Role::Triage])).is_ok());
    }

    #[test]
    fn read_only_or_empty_get_forbidden_not_unauthorized() {
        assert!(matches!(
            require_moderator(&ctx_with(&[Role::ReadOnly])),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            require_moderator(&ctx_with(&[])),
            Err(ApiError::Forbidden)
        ));
    }
}
