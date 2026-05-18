//! `GET /api/whoami` — authenticated moderator's own context (issue #83b).
//!
//! Returns the moderator's id, external identifier (DID for atproto,
//! `sub` for OIDC), authentication backend, the role set granted to
//! them, plus a `first_run` flag the frontend uses to decide whether to
//! land on the future setup wizard (#84) or the dashboard.
//!
//! # First-run detection
//!
//! Polaris does not carry a dedicated `polaris_setup` flag today —
//! adding one is bigger than this issue's scope. The endpoint instead
//! reads the empty-database signal from two existing append-only
//! tables:
//!
//! 1. `actions` is empty — no moderator has committed an action yet
//!    against any subject.
//! 2. `labels` is empty — no signed label has been emitted to the
//!    `subscribeLabels` firehose yet.
//!
//! When both are empty, the deployment is treated as "fresh install"
//! and the frontend should route to `/setup` rather than `/`. The
//! signal is permanently sticky once either side fires (both tables
//! are append-only by design), so a `first_run = false` reply is a
//! durable contract — the wizard never re-appears after the first
//! committed action or emitted label.
//!
//! Issue #84 will replace this heuristic with an explicit
//! `polaris_setup` flag if the operational story needs to model "the
//! wizard was completed" distinctly from "actions exist".
//!
//! # Forbidden patterns observed
//!
//! - No `unwrap()` / `expect()` on the production path — every SQL
//!   error is surfaced through [`ApiError::Repo`].
//! - The moderator id and role set come from the
//!   [`ModeratorAuthCtx`] extension; the URL never accepts a
//!   moderator id (passing one would be a privilege-escalation
//!   regression).

use axum::Json;
use axum::extract::{Extension, State};
use serde::Serialize;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::repo::RepoError;

/// Wire shape returned by `GET /api/whoami`.
///
/// The `roles` field is a list of stable role identifiers (the same
/// strings the `moderator_roles.role` column carries — `admin`,
/// `senior_moderator`, `moderator`, `triage`, `read_only`). The list
/// is unsorted because [`ModeratorAuthCtx`] keeps the role set in a
/// `HashSet<Role>`; clients that need a deterministic order should sort
/// at the consumer.
#[derive(Debug, Serialize)]
pub struct WhoamiResponse {
    /// Stable moderator UUID rendered as a hyphenated hex string.
    pub moderator_id: String,
    /// External identifier for the moderator — the DID for
    /// `auth_backend='atproto'`, the `sub` claim for
    /// `auth_backend='oidc'`.
    pub external_id: String,
    /// Discriminator from the `moderators.auth_backend` column —
    /// `"atproto"` or `"oidc"`. The CHECK constraint at the table
    /// level pins the set; the column is therefore safe to surface
    /// verbatim.
    pub auth_backend: String,
    /// Role set granted to this moderator. Empty when the moderator
    /// has not been granted any role (the post-first-run default for
    /// every subsequent moderator — the operator must grant).
    pub roles: Vec<&'static str>,
    /// `true` when the database carries no actions and no emitted
    /// labels — the frontend uses this to route to `/setup` instead
    /// of `/`. See the module-level rustdoc for the rationale on the
    /// chosen signal.
    pub first_run: bool,
}

/// Axum handler for `GET /api/whoami`.
///
/// The route is mounted under the authed subtree, so the
/// [`ModeratorAuthCtx`] extractor never produces `None` — the auth
/// middleware short-circuits with `401 Unauthorized` before this
/// handler is invoked.
///
/// # Errors
///
/// - [`ApiError::Repo`] for any database failure (moderator row read,
///   first-run probe).
pub async fn whoami(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<WhoamiResponse>, ApiError> {
    // The moderator row must exist: the auth middleware would have
    // rejected the cookie if the session row's moderator_id pointed
    // at a deleted moderator (the FK has `ON DELETE CASCADE`).
    // Surface a missing row as a 500 via the Repo error path so the
    // operator sees the structured log.
    let row = sqlx::query!(
        r"SELECT external_id, auth_backend FROM moderators WHERE id = $1",
        ctx.moderator_id.0,
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(RepoError::from)?
    .ok_or(RepoError::NotFound)?;

    let first_run = is_first_run(&state).await?;

    let mut roles: Vec<&'static str> = ctx.roles.iter().map(Role::as_db_str).collect();
    // Stable wire order so snapshot tests / clients can reason about
    // the response without re-sorting. The role set is small (≤ 5)
    // so the sort cost is negligible.
    roles.sort_unstable();

    Ok(Json(WhoamiResponse {
        moderator_id: ctx.moderator_id.to_string(),
        external_id: row.external_id,
        auth_backend: row.auth_backend,
        roles,
        first_run,
    }))
}

/// First-run heuristic.
///
/// Three independent "setup is done" signals; the flag is `false`
/// when any one of them fires:
///
/// 1. `polaris_setup_state.did_document_updated_at IS NOT NULL` —
///    the setup wizard (#85) completed step 3 (PLC DID-document
///    update). This is the **primary** signal: it flips the moment
///    the operator finishes the wizard, before any moderation
///    happens. Without this signal a freshly-set-up labeler would
///    loop back to `/setup` indefinitely because `actions` and
///    `labels` only fill in as moderation traffic flows.
/// 2. `actions` is non-empty — at least one moderator action has
///    been committed. Catches deployments that pre-date #85 or that
///    skipped the wizard.
/// 3. `labels` is non-empty — at least one signed label has been
///    emitted to the `subscribeLabels` firehose. Same fallback
///    rationale as `actions`.
///
/// All three tables are append-only (the trigger on `actions`
/// rejects every UPDATE / DELETE; `labels` is a write-once audit
/// substrate; `polaris_setup_state.did_document_updated_at` is only
/// written by the wizard and is never `NULL`-ed back). The flag
/// therefore flips from `true` → `false` exactly once per
/// deployment and stays `false` thereafter.
async fn is_first_run(state: &ApiState) -> Result<bool, ApiError> {
    let setup_done: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar!(
        r"SELECT did_document_updated_at FROM polaris_setup_state WHERE id = TRUE",
    )
    .fetch_optional(&state.pool)
    .await
    .map_err(RepoError::from)?
    .flatten();
    if setup_done.is_some() {
        return Ok(false);
    }
    let action_count: i64 = sqlx::query_scalar!("SELECT count(*) FROM actions")
        .fetch_one(&state.pool)
        .await
        .map_err(RepoError::from)?
        .unwrap_or(0);
    if action_count > 0 {
        return Ok(false);
    }
    let label_count: i64 = sqlx::query_scalar!("SELECT count(*) FROM labels")
        .fetch_one(&state.pool)
        .await
        .map_err(RepoError::from)?
        .unwrap_or(0);
    Ok(label_count == 0)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn whoami_response_round_trips_through_serde() {
        let body = WhoamiResponse {
            moderator_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            external_id: "did:plc:test".to_owned(),
            auth_backend: "atproto".to_owned(),
            roles: vec!["admin"],
            first_run: true,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(json["moderator_id"], "00000000-0000-0000-0000-000000000001");
        assert_eq!(json["external_id"], "did:plc:test");
        assert_eq!(json["auth_backend"], "atproto");
        assert_eq!(json["roles"], serde_json::json!(["admin"]));
        assert_eq!(json["first_run"], true);
    }
}
