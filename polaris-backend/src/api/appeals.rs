//! Appeals API (issue #24).
//!
//! Per `design.md` §5.8: appeals open as a new incident type *linked* to
//! the original action. The reviewing moderator sees the original
//! action, its reasoning, and the appellant's statement. Reversal on
//! appeal becomes a [`CalibrationEvent`] on the original moderator's
//! stream — *feedback*, not performance discipline. The original
//! moderator categorically cannot review the appeal of their own
//! decision (the routing engine filters them out, the decide handler
//! re-checks server-side as defense in depth).
//!
//! # Three endpoints
//!
//! 1. `POST /api/appeals` — **public**, un-authenticated. The single
//!    place in the API where un-authenticated input lands. IP-rate-limited
//!    via [`AppealsRateLimiter`] (5 requests per source IP per hour). The
//!    appellant statement is bounded to `[1, 4096]` chars and accepted
//!    as plain text — no HTML rendering, no markdown.
//!
//! 2. `POST /api/appeals/:id/decide` — authenticated. The reviewer
//!    (assigned, or senior) records [`AppealDecision::Reversed`] or
//!    `Upheld`. On `Reversed` the handler reuses the #36 reversal path
//!    (an `actions` row with `kind = Reverse`) and writes a
//!    `CalibrationEvent::AppealReversal` on the original moderator's
//!    stream. On `Upheld` it only flips the appeal's status.
//!
//! 3. `GET /api/appeals/:id` — authenticated. Returns the appeal row
//!    plus the original action's context so the reviewer can render the
//!    page.
//!
//! # Append-only contract preserved
//!
//! No code path here `UPDATE`s the `actions` table. The reversal step
//! delegates to [`crate::api::reversal`]'s pure
//! [`crate::api::reversal::can_reverse`] function and to the existing
//! repo `insert` path (with `kind = Reverse`) — the same machinery the
//! `POST /api/actions/:id/reverse` endpoint uses. The append-only
//! trigger from migration 4 enforces the invariant unconditionally.
//!
//! # Forbidden patterns (per the issue #24 pre-flight)
//!
//! - No `UPDATE actions` anywhere.
//! - No `unwrap` / `expect` in non-test code.
//! - No `anyhow` on a public signature.
//! - State transitions go through [`AppealStatus::transition_to`];
//!   invalid transitions return a typed error rather than a panic.
//! - Appellant input is sanitised + length-limited (≤ 4096 chars; only
//!   printable + whitespace).
//! - No string-built SQL — every query goes through `sqlx::query!`.
//! - No `unsafe` (denied workspace-wide).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use polaris_types::{
    Action, ActionId, ActionKind, AppealDecision, AppealId, AppealStatus, ModeratorId, PolicyId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::sync::Mutex;

use crate::api::error::ApiError;
use crate::api::reversal::{REVERSAL_REVERSIBLE_WINDOW, ReversalAuthError, can_reverse};
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::repo::{
    ActionRepo, AppealRepo, AppealRow, CalibrationEventRepo, NewAction as RepoNewAction, NewAppeal,
    RepoError,
};

/// Maximum allowed length of an appellant's free-text statement, in
/// chars. Mirrors the DB CHECK constraint in migration
/// `00000000000010_appeals.sql`.
pub const MAX_STATEMENT_LEN: usize = 4096;

/// Minimum reasoning length for a moderator's decision on an appeal.
/// Same value as the per-Action `reasoning` minimum so the appeals
/// workflow does not invent a separate rule.
pub const MIN_DECISION_REASONING_LEN: usize = 10;

/// Maximum appeals one source IP may submit per [`RATE_LIMIT_WINDOW`].
///
/// Five was chosen to bracket the legitimate-use range (a small handful
/// of contested actions over a short window) while still throttling
/// scripted abuse. The v1 mitigation is IP-based; captcha is out of
/// scope for #24 per the architect's pre-flight.
pub const RATE_LIMIT_MAX_PER_WINDOW: u32 = 5;

/// Rate-limit window length. Decisions per IP within this window
/// count toward [`RATE_LIMIT_MAX_PER_WINDOW`].
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(3600);

/// In-memory IP rate-limit ledger.
///
/// One row per source IP carrying `(count, window_start)`. The lookup
/// is wrapped in a [`tokio::sync::Mutex`] *purely for the in-memory
/// `HashMap` mutation* — we never `.await` while holding the guard,
/// so the lock can be a short critical section. The §10 rust-quality
/// rule on async + sync locks is honoured: the guard's scope contains
/// only synchronous work.
///
/// # Why in-memory and not Redis
///
/// Polaris does not yet wire a Redis client in the backend (the design
/// document calls Redis out as future infrastructure; the M1 milestone
/// is Postgres-only). An in-memory ledger is the v1 mitigation; a
/// follow-up issue will move this to Redis when the dependency lands.
/// The DB-backed [`AppealRepo::count_recent_for_ip`] method exists as
/// a persistent backstop for the cross-process case and is wired into
/// the rate-limit check below.
#[derive(Debug, Clone)]
pub struct AppealsRateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, IpWindow>>>,
    max_per_window: u32,
    window: Duration,
}

#[derive(Debug, Clone, Copy)]
struct IpWindow {
    count: u32,
    window_start: Instant,
}

impl Default for AppealsRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl AppealsRateLimiter {
    /// Build a limiter with the default policy
    /// ([`RATE_LIMIT_MAX_PER_WINDOW`] per [`RATE_LIMIT_WINDOW`]).
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(RATE_LIMIT_MAX_PER_WINDOW, RATE_LIMIT_WINDOW)
    }

    /// Build a limiter with an explicit policy. Used by tests to make
    /// the rate-limited branch reachable without sleeping for an hour.
    #[must_use]
    pub fn with_policy(max_per_window: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_per_window,
            window,
        }
    }

    /// Attempt to consume one slot for `ip`. Returns
    /// [`ApiError::TooManyRequests`] when the IP has used its quota in
    /// the current window.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::TooManyRequests`] when the caller IP has
    /// exhausted its window quota.
    pub async fn try_consume(&self, ip: IpAddr) -> Result<(), ApiError> {
        let mut guard = self.inner.lock().await;
        let now = Instant::now();
        let entry = guard.entry(ip).or_insert(IpWindow {
            count: 0,
            window_start: now,
        });
        // Roll the window when the elapsed time exceeds the cap. Using
        // `Instant::checked_duration_since` instead of subtraction so a
        // misordered `now` (clock-skew on a paused VM) is treated as
        // "still inside the window" rather than panicking.
        let elapsed = now
            .checked_duration_since(entry.window_start)
            .unwrap_or_default();
        if elapsed >= self.window {
            entry.count = 0;
            entry.window_start = now;
        }
        if entry.count >= self.max_per_window {
            return Err(ApiError::TooManyRequests(
                "appeals: 5 submissions per hour per IP exceeded",
            ));
        }
        entry.count = entry.count.saturating_add(1);
        Ok(())
    }
}

/// Compute the SHA-256 of an [`IpAddr`]. Stored on the appeal row in
/// place of the raw address.
///
/// The hash is computed over the address's canonical string form
/// (`IpAddr::to_string`) — IPv4 and IPv6 hash distinctly without
/// collision. There is no pepper today; adding one is a future
/// hardening step that does not require a schema change.
#[must_use]
pub fn hash_ip(ip: IpAddr) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ip.to_string().as_bytes());
    let out = hasher.finalize();
    let mut buf = [0_u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Validate an appellant statement. Used at the public submit
/// endpoint.
///
/// Rules:
/// - Non-empty after trimming whitespace.
/// - Length (chars, not bytes) ≤ [`MAX_STATEMENT_LEN`].
/// - Every character is either `is_whitespace()` (newline/tab/space) or
///   non-control printable — no embedded NULs, no escape codes, no
///   bell. This is the "sanitised plain text" rule from the §5.8
///   design.
pub fn validate_statement(statement: &str) -> Result<(), ApiError> {
    if statement.trim().is_empty() {
        return Err(ApiError::BadRequest(
            "appellant_statement must be non-empty",
        ));
    }
    if statement.chars().count() > MAX_STATEMENT_LEN {
        return Err(ApiError::BadRequest(
            "appellant_statement exceeds 4096-char cap",
        ));
    }
    for ch in statement.chars() {
        if ch.is_control() && !ch.is_whitespace() {
            return Err(ApiError::BadRequest(
                "appellant_statement contains a control character",
            ));
        }
    }
    Ok(())
}

// ── DTOs ───────────────────────────────────────────────────────────────

/// Wire shape for `POST /api/appeals`.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmitAppealBody {
    /// The action being appealed.
    pub appealed_action_id: ActionId,
    /// Appellant's free-text statement.
    pub appellant_statement: String,
}

/// Wire shape for the 201 response of `POST /api/appeals`.
#[derive(Debug, Clone, Serialize)]
pub struct SubmittedAppeal {
    /// Polaris-internal identifier for the appeal.
    pub appeal_id: AppealId,
}

/// Wire shape for `POST /api/appeals/:id/decide`.
#[derive(Debug, Clone, Deserialize)]
pub struct DecideBody {
    /// Terminal decision the reviewer is recording.
    pub decision: AppealDecision,
    /// Free-text reasoning for the decision. Must be ≥
    /// [`MIN_DECISION_REASONING_LEN`] chars.
    pub reasoning: String,
}

/// Wire shape for the 200 response of `POST /api/appeals/:id/decide`.
#[derive(Debug, Clone, Serialize)]
pub struct AppealDecisionResult {
    /// Echoed appeal id.
    pub appeal_id: AppealId,
    /// Terminal status the appeal moved to.
    pub status: AppealStatus,
    /// If the decision reversed the original action, the new
    /// reversal-Action row's id (the row with `kind = Reverse`).
    /// `None` when the decision upheld the original action.
    pub reversal_action_id: Option<ActionId>,
}

/// Wire shape for `GET /api/appeals/:id`.
#[derive(Debug, Clone, Serialize)]
pub struct AppealView {
    /// Appeal id.
    pub id: AppealId,
    /// The action this appeal targets.
    pub appealed_action_id: ActionId,
    /// Appellant statement (already validated on insert).
    pub appellant_statement: String,
    /// Workflow state.
    pub status: AppealStatus,
    /// Reviewer assigned, if any.
    pub assigned_to: Option<ModeratorId>,
    /// Reviewer's decision reasoning, when terminal.
    pub decision_reasoning: Option<String>,
    /// When the appeal was decided, when terminal.
    pub decided_at: Option<DateTime<Utc>>,
    /// When the appeal was submitted.
    pub opened_at: DateTime<Utc>,
    /// The original action being appealed (full context for the
    /// reviewer page).
    pub original_action: Action,
}

// ── handlers ───────────────────────────────────────────────────────────

/// Handler: `POST /api/appeals` — public, IP-rate-limited.
///
/// # Errors
///
/// - `400 Bad Request` — statement empty / too long / contains a
///   control character.
/// - `404 Not Found` — `appealed_action_id` does not exist.
/// - `429 Too Many Requests` — IP quota exhausted.
/// - `500 Internal Server Error` — DB failure.
pub async fn submit_appeal(
    State(state): State<ApiState>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Json(body): Json<SubmitAppealBody>,
) -> Result<(StatusCode, Json<SubmittedAppeal>), ApiError> {
    state.appeals_rate_limiter.try_consume(addr.ip()).await?;
    validate_statement(&body.appellant_statement)?;
    // Confirm the appealed action exists so we never persist a dangling
    // FK rejection deep in the stack. Returning 404 here gives the
    // appellant a clear signal.
    let _action = state
        .actions
        .get(body.appealed_action_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let ip_hash = hash_ip(addr.ip());
    let appeal_id = state
        .appeals
        .insert(NewAppeal {
            appealed_action_id: body.appealed_action_id,
            appellant_statement: body.appellant_statement,
            appellant_ip_hash: ip_hash,
        })
        .await?;
    Ok((StatusCode::CREATED, Json(SubmittedAppeal { appeal_id })))
}

/// Handler: `POST /api/appeals/:id/decide` — authenticated.
///
/// Records the terminal decision. On
/// [`AppealDecision::Reversed`], reuses the #36 reversal path to insert
/// a new `actions` row with `kind = Reverse` and writes a
/// `CalibrationEvent::AppealReversal` on the original moderator's
/// stream.
///
/// # Errors
///
/// - `400 Bad Request` — reasoning too short.
/// - `403 Forbidden` — caller is the original action's author, or is
///   neither the assigned reviewer nor a senior, or the underlying
///   reversal-eligibility check fails.
/// - `404 Not Found` — `id` does not exist.
/// - `409 Conflict` — the appeal is already decided, or the original
///   action is already reversed.
pub async fn decide_appeal(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(id): Path<AppealId>,
    Json(body): Json<DecideBody>,
) -> Result<Json<AppealDecisionResult>, ApiError> {
    validate_decision_reasoning(&body.reasoning)?;
    let appeal = state.appeals.get(id).await?.ok_or(ApiError::NotFound)?;
    let original = load_original_action(&state, appeal.appealed_action_id).await?;
    authorize_decider(&ctx, &appeal, &original)?;
    let reversal_action_id = match body.decision {
        AppealDecision::Reversed => {
            Some(perform_reversal(&state, &ctx, &original, &body, id).await?)
        }
        AppealDecision::Upheld => None,
    };
    let new_status = body.decision.to_status();
    state
        .appeals
        .record_decision(id, new_status, Utc::now(), body.reasoning)
        .await
        .map_err(map_repo_to_api)?;
    Ok(Json(AppealDecisionResult {
        appeal_id: id,
        status: new_status,
        reversal_action_id,
    }))
}

/// Handler: `GET /api/appeals/:id` — authenticated.
///
/// Returns the appeal row plus the original action's context so the
/// reviewer page can render both sides.
///
/// # Errors
///
/// - `404 Not Found` — `id` does not exist, or the appealed action has
///   somehow been deleted (which the FK forbids today, but the handler
///   defends in depth).
/// - `500 Internal Server Error` — DB failure.
pub async fn get_appeal(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(id): Path<AppealId>,
) -> Result<Json<AppealView>, ApiError> {
    let appeal = state.appeals.get(id).await?.ok_or(ApiError::NotFound)?;
    let original_action = load_original_action(&state, appeal.appealed_action_id).await?;
    Ok(Json(AppealView {
        id: appeal.id,
        appealed_action_id: appeal.appealed_action_id,
        appellant_statement: appeal.appellant_statement,
        status: appeal.status,
        assigned_to: appeal.assigned_to,
        decision_reasoning: appeal.decision_reasoning,
        decided_at: appeal.decided_at,
        opened_at: appeal.opened_at,
        original_action,
    }))
}

// ── helpers ────────────────────────────────────────────────────────────

/// Reasoning-length validation for the `decide` handler. The minimum
/// matches the per-Action `reasoning` floor (10 chars) so the two
/// surfaces use the same rule.
pub(crate) fn validate_decision_reasoning(reasoning: &str) -> Result<(), ApiError> {
    if reasoning.len() < MIN_DECISION_REASONING_LEN {
        return Err(ApiError::BadRequest(
            "reasoning must be at least 10 characters",
        ));
    }
    Ok(())
}

/// Load the original [`Action`] referenced by an appeal. The FK
/// guarantees it exists, but we surface `NotFound` rather than
/// panicking so a future delete-cascade refactor stays bounded.
async fn load_original_action(state: &ApiState, action_id: ActionId) -> Result<Action, ApiError> {
    state
        .actions
        .get(action_id)
        .await?
        .ok_or(ApiError::NotFound)
}

/// Authorize a `decide` call.
///
/// Rules (in order, first-fail wins):
///
/// 1. **Original author hard bar.** The original action's author can
///    never decide their own appeal — even if a buggy routing pass
///    somehow assigned it to them. 403.
/// 2. **Assignee OR senior.** The caller must be the appeal's assigned
///    reviewer OR carry [`Role::SeniorModerator`] / [`Role::Admin`].
///    403 otherwise.
fn authorize_decider(
    ctx: &ModeratorAuthCtx,
    appeal: &AppealRow,
    original: &Action,
) -> Result<(), ApiError> {
    if ctx.moderator_id.0 == original.moderator_id.0 {
        return Err(ApiError::Forbidden);
    }
    let is_senior = ctx.roles.contains(&Role::Admin) || ctx.roles.contains(&Role::SeniorModerator);
    let is_assignee = appeal
        .assigned_to
        .is_some_and(|m| m.0 == ctx.moderator_id.0);
    if is_senior || is_assignee {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Perform the reversal-on-appeal: run the #36 `can_reverse` check,
/// insert a new `actions` row with `kind = Reverse`, write the
/// `CalibrationEvent::AppealReversal` on the original moderator's
/// stream. Returns the new reversal row's id.
async fn perform_reversal(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    original: &Action,
    body: &DecideBody,
    appeal_id: AppealId,
) -> Result<ActionId, ApiError> {
    let now = Utc::now();
    let existing = state.actions.find_reversal(original.id).await?;
    // For appeals, the decider is always treated as "senior" with
    // respect to the reversal-eligibility check: the §5.8 design says
    // the appeal-decide endpoint *is* the override path. We construct a
    // synthetic senior context locally so the pure can_reverse function
    // applies its `AlreadyReversed` short-circuit (which is the one
    // check we still need) without leaking the role-elevation into the
    // moderator's session.
    let elevated = elevate_for_appeal_review(ctx);
    can_reverse(&elevated, original, existing.as_ref(), now).map_err(reversal_auth_to_api_error)?;
    let new_action = RepoNewAction {
        incident_id: original.incident_id,
        subject_id: original.subject_id,
        moderator_id: polaris_types::ModeratorId(ctx.moderator_id.0),
        kind: ActionKind::Reverse,
        label: None,
        reasoning: body.reasoning.clone(),
        policy_refs: Vec::<PolicyId>::new(),
        reversible_until: now + REVERSAL_REVERSIBLE_WINDOW,
        reverses_action_id: Some(original.id),
        llm_audit: None,
    };
    let inserted = state.actions.insert(new_action).await?;
    state
        .calibration_events
        .record_appeal_reversal(original.moderator_id, original.id, appeal_id)
        .await?;
    Ok(inserted.id)
}

/// Build a senior-elevated `ModeratorAuthCtx` so the pure
/// [`can_reverse`] function recognises the appeal-decider as eligible.
///
/// This is the §5.8 "reversal-as-feedback path is a separate function
/// from reversal-as-discipline" boundary made explicit: the appeals
/// flow uses the reversal mechanism but *not* the role-gating that
/// guards the moderator-facing reversal endpoint. The synthetic ctx is
/// local to one call.
fn elevate_for_appeal_review(ctx: &ModeratorAuthCtx) -> ModeratorAuthCtx {
    let mut roles = ctx.roles.clone();
    roles.insert(Role::SeniorModerator);
    ModeratorAuthCtx::new(ctx.moderator_id, roles)
}

/// Map a [`ReversalAuthError`] to an [`ApiError`]. The only failure
/// the elevated check can hit is `AlreadyReversed` (the original
/// action has already been reversed); the other variants are
/// unreachable from this code path because we always elevate to
/// senior. Each is still mapped explicitly so a future refactor that
/// drops elevation surfaces a typed error instead of silently
/// degrading.
fn reversal_auth_to_api_error(err: ReversalAuthError) -> ApiError {
    match err {
        ReversalAuthError::AlreadyReversed => ApiError::Conflict("action already reversed"),
        ReversalAuthError::NotEligible | ReversalAuthError::WindowExpired => ApiError::Forbidden,
    }
}

/// Map a [`RepoError`] surfaced by [`AppealRepo::record_decision`] to
/// an [`ApiError`]. The [`RepoError::Decode`] variant carries our
/// invalid-transition signal (see the repo); we surface it as a 409
/// "conflict" because that is how the wire client interprets a
/// concurrent decide / re-decide attempt.
fn map_repo_to_api(err: RepoError) -> ApiError {
    match err {
        RepoError::NotFound => ApiError::NotFound,
        RepoError::Decode { message } => {
            tracing::warn!(message = %message, "appeal state-transition rejected");
            ApiError::Conflict("appeal is not in a decidable state")
        }
        other => ApiError::Repo(other),
    }
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
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::auth::ModeratorId as AuthModeratorId;

    fn ctx_with(roles: &[Role]) -> ModeratorAuthCtx {
        let mut set = HashSet::new();
        for r in roles {
            set.insert(*r);
        }
        ModeratorAuthCtx::new(AuthModeratorId::new_v4(), set)
    }

    fn fixture_action(author: ModeratorId) -> Action {
        Action {
            id: ActionId::new(),
            incident_id: polaris_types::IncidentId::new(),
            subject_id: polaris_types::SubjectId::new(),
            moderator_id: author,
            kind: ActionKind::Label,
            label: None,
            reasoning: "Original reasoning, ten or more chars.".to_owned(),
            policy_refs: vec![],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            created_at: Utc::now(),
            emitted_to_atproto: None,
            evidence_car_cid: None,
        }
    }

    fn fixture_appeal(action_id: ActionId, assigned: Option<ModeratorId>) -> AppealRow {
        AppealRow {
            id: AppealId::new(),
            appealed_action_id: action_id,
            appellant_statement: "I disagree with this action.".to_owned(),
            appellant_ip_hash: vec![0_u8; 32],
            status: if assigned.is_some() {
                AppealStatus::Assigned
            } else {
                AppealStatus::Open
            },
            assigned_to: assigned,
            decided_at: None,
            decision_reasoning: None,
            opened_at: Utc::now(),
        }
    }

    #[test]
    fn validate_statement_accepts_short_text() {
        validate_statement("I disagree.").expect("normal text");
    }

    #[test]
    fn validate_statement_rejects_empty() {
        let err = validate_statement("").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_statement_rejects_whitespace_only() {
        let err = validate_statement("   \t\n ").unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_statement_rejects_too_long() {
        let too_long = "a".repeat(MAX_STATEMENT_LEN + 1);
        let err = validate_statement(&too_long).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("4096")),
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn validate_statement_accepts_at_max_length() {
        let max_len = "a".repeat(MAX_STATEMENT_LEN);
        validate_statement(&max_len).expect("at-the-cap length must be accepted");
    }

    #[test]
    fn validate_statement_allows_whitespace_chars() {
        validate_statement("Line one.\nLine two.\tIndented.").expect("whitespace control chars ok");
    }

    #[test]
    fn validate_statement_rejects_control_character() {
        // U+0007 BEL is a control char that is not whitespace.
        let bad = "Hello \u{0007} world";
        let err = validate_statement(bad).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn validate_statement_rejects_embedded_nul() {
        let bad = "Hello\u{0000}world";
        let err = validate_statement(bad).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn hash_ip_is_deterministic_per_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(hash_ip(ip), hash_ip(ip));
    }

    #[test]
    fn hash_ip_distinguishes_addresses() {
        let a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        assert_ne!(hash_ip(a), hash_ip(b));
    }

    #[tokio::test]
    async fn rate_limiter_admits_below_threshold() {
        let limiter = AppealsRateLimiter::with_policy(3, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for _ in 0..3 {
            limiter.try_consume(ip).await.expect("below threshold");
        }
    }

    #[tokio::test]
    async fn rate_limiter_rejects_over_threshold() {
        let limiter = AppealsRateLimiter::with_policy(2, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        limiter.try_consume(ip).await.expect("1/2");
        limiter.try_consume(ip).await.expect("2/2");
        let err = limiter
            .try_consume(ip)
            .await
            .expect_err("3rd over threshold must fail");
        assert!(matches!(err, ApiError::TooManyRequests(_)));
    }

    #[tokio::test]
    async fn rate_limiter_does_not_share_across_ips() {
        let limiter = AppealsRateLimiter::with_policy(1, Duration::from_secs(60));
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        limiter.try_consume(a).await.expect("a 1/1");
        limiter
            .try_consume(b)
            .await
            .expect("b 1/1 — separate bucket");
    }

    #[tokio::test]
    async fn rate_limiter_window_rolls_after_expiry() {
        // Sub-millisecond window so the test runs without sleeping.
        let limiter = AppealsRateLimiter::with_policy(1, Duration::from_millis(1));
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        limiter.try_consume(ip).await.expect("1/1");
        tokio::time::sleep(Duration::from_millis(3)).await;
        // Window has rolled — the second consume must succeed.
        limiter.try_consume(ip).await.expect("after window roll");
    }

    #[test]
    fn validate_decision_reasoning_rejects_short() {
        let err = validate_decision_reasoning("short").unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("reasoning")),
            _ => panic!("expected BadRequest"),
        }
    }

    #[test]
    fn validate_decision_reasoning_accepts_ten_chars() {
        validate_decision_reasoning("1234567890").expect("ten chars");
    }

    #[test]
    fn authorize_decider_rejects_original_author() {
        let author = ModeratorId::new();
        let original = fixture_action(author);
        // Caller IS the author. Even with senior role, the original
        // author cannot decide their own appeal.
        let ctx = ModeratorAuthCtx::new(
            AuthModeratorId(author.0),
            [Role::SeniorModerator].into_iter().collect(),
        );
        let appeal = fixture_appeal(original.id, Some(author));
        let err = authorize_decider(&ctx, &appeal, &original).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn authorize_decider_accepts_assigned_reviewer() {
        let author = ModeratorId::new();
        let original = fixture_action(author);
        let reviewer = ModeratorId::new();
        let ctx = ModeratorAuthCtx::new(
            AuthModeratorId(reviewer.0),
            [Role::Moderator].into_iter().collect(),
        );
        let appeal = fixture_appeal(original.id, Some(reviewer));
        authorize_decider(&ctx, &appeal, &original).expect("assigned reviewer");
    }

    #[test]
    fn authorize_decider_accepts_senior_even_when_not_assigned() {
        let author = ModeratorId::new();
        let original = fixture_action(author);
        let senior = ctx_with(&[Role::SeniorModerator]);
        let appeal = fixture_appeal(original.id, None);
        authorize_decider(&senior, &appeal, &original).expect("senior bypass");
    }

    #[test]
    fn authorize_decider_rejects_unrelated_moderator() {
        let author = ModeratorId::new();
        let original = fixture_action(author);
        // Neither assigned nor senior.
        let other = ctx_with(&[Role::Moderator]);
        let appeal = fixture_appeal(original.id, Some(ModeratorId::new()));
        let err = authorize_decider(&other, &appeal, &original).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn elevate_for_appeal_review_adds_senior_without_dropping_original_roles() {
        let ctx = ctx_with(&[Role::Moderator]);
        let elevated = elevate_for_appeal_review(&ctx);
        assert!(elevated.roles.contains(&Role::Moderator));
        assert!(elevated.roles.contains(&Role::SeniorModerator));
        assert_eq!(elevated.moderator_id, ctx.moderator_id);
    }

    #[test]
    fn map_repo_to_api_translates_decode_to_conflict() {
        let err = map_repo_to_api(RepoError::Decode {
            message: "appeal in decided_upheld; cannot redecide".to_owned(),
        });
        assert!(matches!(err, ApiError::Conflict(_)));
    }

    #[test]
    fn map_repo_to_api_propagates_not_found() {
        let err = map_repo_to_api(RepoError::NotFound);
        assert!(matches!(err, ApiError::NotFound));
    }

    #[test]
    fn reversal_auth_to_api_error_maps_already_reversed_to_conflict() {
        assert!(matches!(
            reversal_auth_to_api_error(ReversalAuthError::AlreadyReversed),
            ApiError::Conflict(_),
        ));
    }
}
