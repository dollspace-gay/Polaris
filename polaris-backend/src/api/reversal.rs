//! Action reversal API (issue #36).
//!
//! Per `design.md` §5.5: every moderator action is reversible for 24 hours
//! by the original moderator, and indefinitely by senior moderators with
//! audit. Reversal preserves the append-only invariant introduced in
//! migration `00000000000004_actions.sql` — it writes a *new* `Action` row
//! with `kind = Reverse` and `reverses_action_id = <original.id>`. The
//! original row is never `UPDATE`d.
//!
//! # Module shape
//!
//! - [`can_reverse`] — pure authorization function over a `(requester,
//!   original, existing_reversal, now)` tuple. Testable in isolation,
//!   re-used at the API edge.
//! - [`ReversalAuthError`] — typed authorization-failure variants. Mapped
//!   to HTTP status codes by [`reverse_action`] (`AlreadyReversed` → 409,
//!   `NotEligible` / `WindowExpired` → 403).
//! - [`reverse_action`] — Axum handler. Looks up the original, queries
//!   `ActionRepo::find_reversal` for the double-reverse guard, runs the
//!   authorization function, validates the new reasoning, and inserts the
//!   `kind = Reverse` row.
//! - [`ReverseBody`] — wire DTO for the request payload.
//!
//! # Label `neg = true` follow-up (deferred to #28)
//!
//! When the original action emitted an ATProto label, the design calls for
//! the reversal to trigger a follow-up label emission with `neg = true`
//! (per `.design/polaris-proto-blue-integration.md` §B). The signing /
//! emission pipeline lands in M4 (#28); this handler deliberately does
//! NOT call into it. The persisted `Action` row with `kind = Reverse`
//! carries everything #28 needs to construct the neg-label event when the
//! emission worker subscribes to the actions stream.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use polaris_types::{Action, ActionId, ActionKind};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::repo::{ActionRepo, NewAction as RepoNewAction};

/// The reversal action's own reversibility window.
///
/// Reversals are themselves [`Action`] rows; per the append-only contract
/// they cannot be rewritten, but the `reversible_until` column still
/// drives the eligibility check if the reversal itself needs to be undone
/// (a reverse-of-reverse). One hour is conservative: it gives a moderator
/// a brief window to undo a fat-finger reversal but stops the chain from
/// growing into a long-running soap opera. A senior moderator can still
/// reverse the reversal at any time per `can_reverse`.
pub const REVERSAL_REVERSIBLE_WINDOW: chrono::Duration = chrono::Duration::hours(1);

/// Minimum reasoning length. Mirrors the same rule applied to other
/// submission paths (`api::cases::validate_submit_action`) and to the
/// `reasoning` column's CHECK constraint in migration 4.
pub const MIN_REASONING_LEN: usize = 10;

/// Request body for `POST /api/actions/:action_id/reverse`.
///
/// Only the reasoning is carried on the wire. The moderator identity
/// comes from the authenticated session ([`ModeratorAuthCtx`]); the
/// target action id comes from the URL; everything else (incident,
/// subject, kind) is copied from the original action by the handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseBody {
    /// Free-text reasoning for the reversal. Must be at least
    /// [`MIN_REASONING_LEN`] characters.
    pub reasoning: String,
}

/// Authorization-failure variants for [`can_reverse`].
///
/// Mapped to HTTP status codes by the handler:
///
/// - [`Self::AlreadyReversed`] → `409 Conflict`. The action already has
///   a `kind = Reverse` row pointing at it; reversing it again would
///   produce two reversals of the same row, which the append-only schema
///   permits structurally but the policy forbids.
/// - [`Self::NotEligible`] → `403 Forbidden`. The caller is neither a
///   senior moderator nor the original author.
/// - [`Self::WindowExpired`] → `403 Forbidden`. The caller IS the
///   original author but is acting after `reversible_until`. A senior
///   moderator must take over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReversalAuthError {
    /// The caller is neither a senior moderator nor the action's author.
    #[error(
        "only the original moderator (within window) or a senior moderator may reverse this action"
    )]
    NotEligible,
    /// The caller IS the original author but the 24h window has elapsed.
    #[error("the 24h reversibility window has expired; only a senior moderator may reverse")]
    WindowExpired,
    /// The action has already been reversed.
    #[error("this action has already been reversed")]
    AlreadyReversed,
}

/// Authorization for the reversal endpoint. Pure function — no I/O,
/// no clock, fully testable in isolation.
///
/// # Rules (per `design.md` §5.5)
///
/// 1. If a reversal of `original` already exists (`existing_reversal` is
///    `Some(_)`) the call is rejected with [`ReversalAuthError::AlreadyReversed`].
///    This is checked first so the policy reasoning never has to handle
///    "what if the original is already reversed".
/// 2. Members of the senior role set ([`Role::Admin`] or
///    [`Role::SeniorModerator`]) may reverse any action at any time.
/// 3. The original action's author may reverse it while
///    `now < original.reversible_until`. Outside that window the request
///    fails with [`ReversalAuthError::WindowExpired`].
/// 4. Everyone else is rejected with [`ReversalAuthError::NotEligible`].
///
/// # Errors
///
/// Returns a [`ReversalAuthError`] variant matching the failed rule.
pub fn can_reverse(
    requester: &ModeratorAuthCtx,
    original: &Action,
    existing_reversal: Option<&Action>,
    now: DateTime<Utc>,
) -> Result<(), ReversalAuthError> {
    if existing_reversal.is_some() {
        return Err(ReversalAuthError::AlreadyReversed);
    }
    let is_senior =
        requester.roles.contains(&Role::Admin) || requester.roles.contains(&Role::SeniorModerator);
    if is_senior {
        return Ok(());
    }
    let is_original_author = requester.moderator_id.0 == original.moderator_id.0;
    if !is_original_author {
        return Err(ReversalAuthError::NotEligible);
    }
    if now >= original.reversible_until {
        return Err(ReversalAuthError::WindowExpired);
    }
    Ok(())
}

/// Validate the reasoning field on a reversal payload.
///
/// Rejects strings shorter than [`MIN_REASONING_LEN`]. The static error
/// message is consumed by [`ApiError::BadRequest`].
fn validate_reasoning(reasoning: &str) -> Result<(), ApiError> {
    if reasoning.len() < MIN_REASONING_LEN {
        return Err(ApiError::BadRequest(
            "reasoning must be at least 10 characters",
        ));
    }
    Ok(())
}

/// Map a [`ReversalAuthError`] to an [`ApiError`]. Kept as a free
/// function so the handler stays under the 25-line ceiling.
fn auth_to_api_error(err: ReversalAuthError) -> ApiError {
    match err {
        ReversalAuthError::AlreadyReversed => ApiError::Conflict("action already reversed"),
        ReversalAuthError::NotEligible | ReversalAuthError::WindowExpired => ApiError::Forbidden,
    }
}

/// Build the `NewAction` row for the reversal. Copies subject + incident
/// from the original (the reversal targets the same logical record) and
/// sets `kind = Reverse` + `reverses_action_id` so the audit chain is
/// intact for read-side joins.
fn build_reversal_row(
    original: &Action,
    moderator_id: polaris_types::ModeratorId,
    reasoning: String,
    now: DateTime<Utc>,
) -> RepoNewAction {
    RepoNewAction {
        incident_id: original.incident_id,
        subject_id: original.subject_id,
        moderator_id,
        kind: ActionKind::Reverse,
        label: None,
        reasoning,
        policy_refs: vec![],
        reversible_until: now + REVERSAL_REVERSIBLE_WINDOW,
        reverses_action_id: Some(original.id),
    }
}

/// Axum handler: `POST /api/actions/:action_id/reverse`.
///
/// On success returns `201 Created` with the newly-inserted reversal
/// [`Action`] row in the body.
///
/// # Errors
///
/// - `404 Not Found` if `action_id` does not exist.
/// - `403 Forbidden` if the caller is not authorized.
/// - `409 Conflict` if the action has already been reversed.
/// - `400 Bad Request` if the reasoning fails validation.
pub async fn reverse_action(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(action_id): Path<ActionId>,
    Json(body): Json<ReverseBody>,
) -> Result<(StatusCode, Json<Action>), ApiError> {
    let now = Utc::now();
    let original = state
        .actions
        .get(action_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let existing = state.actions.find_reversal(action_id).await?;
    can_reverse(&ctx, &original, existing.as_ref(), now).map_err(auth_to_api_error)?;
    validate_reasoning(&body.reasoning)?;
    let moderator_id = polaris_types::ModeratorId(ctx.moderator_id.0);
    let new_row = build_reversal_row(&original, moderator_id, body.reasoning, now);
    let inserted = state.actions.insert(new_row).await?;
    Ok((StatusCode::CREATED, Json(inserted)))
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
    use chrono::Duration;
    use polaris_types::{
        ActionId, ActionKind, IncidentId, ModeratorId as TypesModeratorId, SubjectId,
    };
    use std::collections::HashSet;

    use crate::auth::ModeratorId as AuthModeratorId;

    /// Build an `Action` with `moderator_id` as the author, a window that
    /// extends `hours_from_now` hours into the future, and otherwise
    /// boring defaults. The fixture is a Label kind so the reversal
    /// policy has something concrete to point at.
    fn fixture_action(moderator: TypesModeratorId, hours_from_now: i64) -> Action {
        let now = Utc::now();
        Action {
            id: ActionId::new(),
            incident_id: IncidentId::new(),
            subject_id: SubjectId::new(),
            moderator_id: moderator,
            kind: ActionKind::Label,
            label: None,
            reasoning: "Original action reasoning, ten or more chars.".to_owned(),
            policy_refs: vec![],
            reversible_until: now + Duration::hours(hours_from_now),
            reverses_action_id: None,
            created_at: now,
            emitted_to_atproto: None,
        }
    }

    /// Build a `ModeratorAuthCtx` around `moderator_id` with the given
    /// role set. Tests construct callers as senior/original-author/other
    /// via this helper so the role wiring is named, not magic.
    fn ctx_with(moderator_id: AuthModeratorId, roles: &[Role]) -> ModeratorAuthCtx {
        let mut set = HashSet::new();
        for r in roles {
            set.insert(*r);
        }
        ModeratorAuthCtx::new(moderator_id, set)
    }

    #[test]
    fn senior_reverses_anytime_even_past_window() {
        let original_author = TypesModeratorId(uuid::Uuid::new_v4());
        // Original is from a different moderator; window is already expired.
        let mut original = fixture_action(original_author, -48);
        // sanity: window is in the past
        assert!(original.reversible_until < Utc::now());
        original.kind = ActionKind::Takedown;

        let senior = ctx_with(AuthModeratorId::new_v4(), &[Role::SeniorModerator]);
        let admin = ctx_with(AuthModeratorId::new_v4(), &[Role::Admin]);

        assert!(can_reverse(&senior, &original, None, Utc::now()).is_ok());
        assert!(can_reverse(&admin, &original, None, Utc::now()).is_ok());
    }

    #[test]
    fn original_author_reverses_within_window() {
        let author_uuid = uuid::Uuid::new_v4();
        let original = fixture_action(TypesModeratorId(author_uuid), 24);
        let ctx = ctx_with(AuthModeratorId(author_uuid), &[Role::Moderator]);
        assert!(can_reverse(&ctx, &original, None, Utc::now()).is_ok());
    }

    #[test]
    fn original_author_after_window_is_window_expired() {
        let author_uuid = uuid::Uuid::new_v4();
        // -1h: window elapsed an hour ago.
        let original = fixture_action(TypesModeratorId(author_uuid), -1);
        let ctx = ctx_with(AuthModeratorId(author_uuid), &[Role::Moderator]);
        let err = can_reverse(&ctx, &original, None, Utc::now()).unwrap_err();
        assert_eq!(err, ReversalAuthError::WindowExpired);
    }

    #[test]
    fn non_author_non_senior_is_not_eligible() {
        let original_author = TypesModeratorId(uuid::Uuid::new_v4());
        let original = fixture_action(original_author, 24);
        // A different moderator with only Moderator/Triage roles.
        let other = ctx_with(AuthModeratorId::new_v4(), &[Role::Moderator, Role::Triage]);
        let err = can_reverse(&other, &original, None, Utc::now()).unwrap_err();
        assert_eq!(err, ReversalAuthError::NotEligible);
    }

    #[test]
    fn already_reversed_takes_precedence_over_eligibility() {
        // Even a senior cannot double-reverse — the AlreadyReversed branch
        // is checked first so the policy decision is consistent.
        let original_author = TypesModeratorId(uuid::Uuid::new_v4());
        let original = fixture_action(original_author, 24);
        let reversal = {
            let mut a = fixture_action(TypesModeratorId(uuid::Uuid::new_v4()), 1);
            a.kind = ActionKind::Reverse;
            a.reverses_action_id = Some(original.id);
            a
        };
        let senior = ctx_with(AuthModeratorId::new_v4(), &[Role::SeniorModerator]);
        let err = can_reverse(&senior, &original, Some(&reversal), Utc::now()).unwrap_err();
        assert_eq!(err, ReversalAuthError::AlreadyReversed);
    }

    #[test]
    fn read_only_role_cannot_reverse_anything() {
        let original_author = TypesModeratorId(uuid::Uuid::new_v4());
        let original = fixture_action(original_author, 24);
        let read_only = ctx_with(AuthModeratorId::new_v4(), &[Role::ReadOnly]);
        let err = can_reverse(&read_only, &original, None, Utc::now()).unwrap_err();
        assert_eq!(err, ReversalAuthError::NotEligible);
    }

    #[test]
    fn validate_reasoning_accepts_ten_chars() {
        assert!(validate_reasoning("1234567890").is_ok());
        assert!(validate_reasoning("This is sufficiently long reasoning.").is_ok());
    }

    #[test]
    fn validate_reasoning_rejects_short() {
        let err = validate_reasoning("short").unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("reasoning")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn auth_to_api_error_maps_already_reversed_to_conflict() {
        match auth_to_api_error(ReversalAuthError::AlreadyReversed) {
            ApiError::Conflict(_) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn auth_to_api_error_maps_eligibility_failures_to_forbidden() {
        assert!(matches!(
            auth_to_api_error(ReversalAuthError::NotEligible),
            ApiError::Forbidden
        ));
        assert!(matches!(
            auth_to_api_error(ReversalAuthError::WindowExpired),
            ApiError::Forbidden
        ));
    }

    #[test]
    fn build_reversal_row_copies_incident_and_subject_from_original() {
        let original_author = TypesModeratorId(uuid::Uuid::new_v4());
        let original = fixture_action(original_author, 24);
        let reverser = TypesModeratorId(uuid::Uuid::new_v4());
        let timestamp = Utc::now();
        let built = build_reversal_row(
            &original,
            reverser,
            "Reasoning text long enough.".to_owned(),
            timestamp,
        );
        assert_eq!(built.incident_id, original.incident_id);
        assert_eq!(built.subject_id, original.subject_id);
        assert_eq!(built.kind, ActionKind::Reverse);
        assert_eq!(built.reverses_action_id, Some(original.id));
        assert_eq!(built.moderator_id, reverser);
        assert!(built.label.is_none());
        assert!(built.policy_refs.is_empty());
        // Window is `timestamp + REVERSAL_REVERSIBLE_WINDOW`.
        assert_eq!(
            built.reversible_until,
            timestamp + REVERSAL_REVERSIBLE_WINDOW
        );
    }
}
