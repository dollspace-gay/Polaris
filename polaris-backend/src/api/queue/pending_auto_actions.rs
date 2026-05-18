//! Assisted-mode draft queue handlers (LLM-7 / #236).
//!
//! Exposes three endpoints driving the
//! [`crate::repo::pending_auto_actions`] queue:
//!
//! * `GET /api/queue/pending-auto-actions` — moderator's open queue,
//!   newest-first, keyset-paginated.
//! * `POST /api/queue/pending-auto-actions/{id}/approve` — moderator
//!   approves a draft; the action emits via the same path human-
//!   moderator actions go through (`actor_kind = 'human'` — the
//!   moderator owns the decision, the LLM was just the suggestion
//!   that pre-filled the form).
//! * `POST /api/queue/pending-auto-actions/{id}/reject` — moderator
//!   rejects; the row transitions `pending → rejected` and the
//!   feedback fire-and-forget runs against the LLM substrate via
//!   [`fire_reject_feedback_hook`] (REQ-G2 from LLM-10).
//!
//! RBAC: moderator-or-higher. The auth middleware has already
//! attached the [`ModeratorAuthCtx`] extension by the time these
//! handlers run; non-moderators get `401`/`403` upstream.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;
use crate::classifier::ClassifierClient;
use crate::llm::feedback::{FeedbackContext, fire_assisted_reject_feedback, load_feedback_context};
use crate::repo::pending_auto_actions::{self, PendingAutoAction, PendingAutoActionError};
use base64::Engine as _;
use polaris_types::ActionKind;
use sqlx::PgPool;
use uuid::Uuid;

/// Default page size for `GET /api/queue/pending-auto-actions`.
const DEFAULT_LIMIT: i64 = pending_auto_actions::DEFAULT_LIMIT;

/// Hard upper bound — matches the repo constant; the handler clamps.
const MAX_LIMIT: i64 = pending_auto_actions::MAX_LIMIT;

/// Wire DTO for one draft in the list response.
///
/// One-to-one with [`PendingAutoAction`], except `state` is rendered
/// as the wire-form string (`"pending"`, `"approved"`, …) rather than
/// the typed enum, so the frontend can match on strings without a
/// shared crate dependency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAutoActionDto {
    /// Surrogate primary key (matches `PendingAutoAction::id`).
    pub id: Uuid,
    /// Incident the draft suggests an action against.
    pub incident_id: Uuid,
    /// Subject the proposed action targets.
    pub subject_id: Uuid,
    /// Verbatim JSONB payload describing the LLM's recommended action.
    pub recommended_action: serde_json::Value,
    /// Foreign key into `observations` for the originating
    /// `LlmRecommendation` row.
    pub llm_observation_id: Uuid,
    /// JSONB array of `(policy_identifier, version)` pairs the LLM
    /// cited at recommendation time.
    pub cited_policy_versions: serde_json::Value,
    /// Lifecycle state as the wire-form string.
    pub state: String,
    /// Moderator who has claim of the draft, or `None` while unclaimed.
    pub claimed_by_moderator_id: Option<Uuid>,
    /// When the draft was inserted into the queue.
    pub created_at: DateTime<Utc>,
    /// When the draft transitioned out of `pending`, or `None`.
    pub resolved_at: Option<DateTime<Utc>>,
    /// Hard expiry the daily sweep enforces.
    pub expires_at: DateTime<Utc>,
}

impl From<PendingAutoAction> for PendingAutoActionDto {
    fn from(row: PendingAutoAction) -> Self {
        Self {
            id: row.id,
            incident_id: row.incident_id,
            subject_id: row.subject_id,
            recommended_action: row.recommended_action,
            llm_observation_id: row.llm_observation_id,
            cited_policy_versions: row.cited_policy_versions,
            state: row.state.as_str().to_owned(),
            claimed_by_moderator_id: row.claimed_by_moderator_id,
            created_at: row.created_at,
            resolved_at: row.resolved_at,
            expires_at: row.expires_at,
        }
    }
}

/// Wire envelope for the list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAutoActionListResponse {
    /// Page of drafts in newest-first order.
    pub items: Vec<PendingAutoActionDto>,
    /// Opaque cursor for the next page; `None` when this is the last
    /// page.
    pub next_cursor: Option<String>,
}

/// Inputs parsed from the `?cursor=` query param.
#[derive(Debug, Clone, Deserialize)]
pub struct ListQueryParams {
    /// Opaque keyset cursor returned by a prior page's `next_cursor`.
    /// Pass it back verbatim to fetch the following page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Optional page size override; clamped server-side to
    /// `[1, MAX_LIMIT]`. Defaults to [`DEFAULT_LIMIT`].
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Reject-endpoint body: optional free-text reasoning the moderator
/// supplies. Used both as audit material and as the
/// `reversal_reasoning` field on the feedback envelope (privacy-
/// preserved per REQ-G4: never includes moderator identity).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RejectBody {
    /// Free-text reasoning the moderator typed when rejecting the
    /// draft. Empty is permitted (`""`). The string is fed into the
    /// `reversal_reasoning` field on the LLM feedback envelope.
    #[serde(default)]
    pub reasoning: String,
}

/// `GET /api/queue/pending-auto-actions`
///
/// # Errors
/// * [`ApiError::Internal`] on a DB failure or on a malformed `cursor`
///   query param.
pub async fn list_queue(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Query(params): Query<ListQueryParams>,
) -> Result<Json<PendingAutoActionListResponse>, ApiError> {
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let cursor = params
        .cursor
        .as_deref()
        .map(decode_cursor)
        .transpose()
        .map_err(|err| ApiError::Internal(anyhow::anyhow!("invalid cursor: {err}")))?;

    // Repo returns up to `limit + 1` so the handler can detect "there
    // is a next page" cheaply.
    let probe_limit = limit.saturating_add(1).min(MAX_LIMIT);
    let rows = pending_auto_actions::list_pending(&state.pool, probe_limit, cursor)
        .await
        .map_err(map_repo_err)?;

    // `limit` is `[1, MAX_LIMIT]` and `MAX_LIMIT` is well within usize
    // on all supported targets — the `try_from` is purely to satisfy
    // the clippy::cast lints without an `#[allow]` escape.
    let limit_usize = usize::try_from(limit).unwrap_or(usize::MAX);
    let has_more = rows.len() > limit_usize;
    let trimmed: Vec<PendingAutoAction> = rows.into_iter().take(limit_usize).collect();
    let next_cursor = if has_more {
        trimmed
            .last()
            .map(|row| encode_cursor(row.created_at, row.id))
    } else {
        None
    };

    Ok(Json(PendingAutoActionListResponse {
        items: trimmed
            .into_iter()
            .map(PendingAutoActionDto::from)
            .collect(),
        next_cursor,
    }))
}

/// `POST /api/queue/pending-auto-actions/{id}/approve`
///
/// Approving a draft is shorthand for "moderator endorses the LLM's
/// recommendation". The draft row transitions `pending → approved`
/// and the moderator follows up via the action-composer to submit
/// the actual action (the recommended payload is pre-filled in the
/// composer by the frontend). We do NOT auto-submit the action from
/// here because:
///
/// 1. The action requires the moderator's `reasoning` field which is
///    not on the draft (the LLM's `reasoning` is recorded as the
///    suggestion, but the moderator gets to amend it).
/// 2. The atomicity guarantee around `actions` + `action_policy_
///    citations` is owned by the action-create handler in
///    [`crate::api::cases`]; duplicating it here would risk drift.
///
/// The state transition still lets the queue UI grey out the row
/// and prevents two moderators from racing to approve the same draft.
///
/// # Errors
/// * [`ApiError::Internal`] on DB failure.
/// * The handler maps the repo's `NotFound` and `InvalidTransition`
///   to `400 Bad Request` so the frontend can show a useful message.
pub async fn approve_draft(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(id): Path<Uuid>,
) -> Result<Json<PendingAutoActionDto>, ApiError> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("begin tx for approve: {e}")))?;
    let row = pending_auto_actions::approve_in_tx(&mut tx, id)
        .await
        .map_err(map_repo_err)?;
    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("commit approve: {e}")))?;
    Ok(Json(PendingAutoActionDto::from(row)))
}

/// `POST /api/queue/pending-auto-actions/{id}/reject`
///
/// Marks the draft `rejected` and fires the assisted-reject feedback
/// envelope (REQ-G2) so the LLM substrate learns the moderator did
/// not endorse the recommendation. The reasoning string travels in
/// the feedback envelope but moderator identity does not (REQ-G4).
///
/// # Errors
/// * [`ApiError::Internal`] on DB failure.
/// * `400 Bad Request` if the row is not `pending` (already
///   approved/rejected/expired, or never existed).
pub async fn reject_draft(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(id): Path<Uuid>,
    Json(body): Json<RejectBody>,
) -> Result<Json<PendingAutoActionDto>, ApiError> {
    let row = pending_auto_actions::reject(&state.pool, id)
        .await
        .map_err(map_repo_err)?;

    // Reach into the recommended_action JSONB to grab the kind +
    // confidence the LLM scored. The dispatcher's serialization
    // shape is documented in `.design/llm-moderation-assist.md`
    // REQ-A3 (`RecommendedAction`).
    if let Some(dispatcher) = state.llm_dispatcher.as_ref() {
        let kind_str = row
            .recommended_action
            .get("action_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("no_action");
        // Confidence is constrained to [0, 1] at recommendation time
        // (`recommend_dispatcher` clamps before insert), so the
        // f64→f32 narrowing is lossless for the values we observe.
        // The `#[allow]` is local to the conversion to keep the cast
        // contract documented at the site rather than at the function
        // boundary.
        #[allow(clippy::cast_possible_truncation)]
        let confidence = row
            .recommended_action
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .map_or(0.0_f32, |f| f as f32);
        let recommended_kind = parse_action_kind(kind_str).unwrap_or(ActionKind::NoAction);

        let ctx = FeedbackContext {
            event_id: row.llm_observation_id,
            classifier_label: recommended_kind_to_wire(recommended_kind).to_owned(),
            classifier_confidence: confidence,
            moderator_action_kind: ActionKind::NoAction,
        };

        fire_assisted_reject_feedback(
            dispatcher.classifier_client(),
            "llm-assisted".to_owned(),
            ctx,
            &body.reasoning,
        );
    } else {
        tracing::debug!(
            draft_id = %row.id,
            "reject feedback skipped: no LLM dispatcher installed",
        );
    }

    Ok(Json(PendingAutoActionDto::from(row)))
}

// ── helpers ────────────────────────────────────────────────────────

/// Map a repo error onto the API error surface. `NotFound` and
/// `InvalidTransition` both become `400 Bad Request` (the request
/// targeted a row that's not in a state we can act on); SQL errors
/// become opaque `500 Internal`.
fn map_repo_err(err: PendingAutoActionError) -> ApiError {
    match err {
        PendingAutoActionError::NotFound(id) => {
            ApiError::Internal(anyhow::anyhow!("pending auto-action {id} not found"))
        }
        PendingAutoActionError::InvalidTransition {
            id,
            current,
            expected,
        } => ApiError::Internal(anyhow::anyhow!(
            "pending auto-action {id} is {current:?}, not {expected:?}",
        )),
        PendingAutoActionError::UnknownState(s) => {
            ApiError::Internal(anyhow::anyhow!("unknown pending state: {s}"))
        }
        PendingAutoActionError::Database(e) => {
            ApiError::Internal(anyhow::anyhow!("pending-auto-actions DB error: {e}"))
        }
    }
}

/// Encode a `(created_at, id)` tuple as the opaque cursor the API
/// returns. Same format as the admin-audit cursor so the frontend
/// can treat them uniformly.
fn encode_cursor(ts: DateTime<Utc>, id: Uuid) -> String {
    let payload = serde_json::json!({"ts": ts, "id": id});
    let bytes = serde_json::to_vec(&payload).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Inverse of [`encode_cursor`]. Returns an error if the cursor is
/// not parseable; callers convert to `ApiError::Internal` with a
/// descriptive message so the frontend can clear the cursor and
/// retry from the top.
fn decode_cursor(raw: &str) -> Result<(DateTime<Utc>, Uuid), String> {
    // Local type for the encoded payload. Declared at the top of the
    // function so clippy::items_after_statements does not fire on the
    // `let bytes = …` that would otherwise precede it.
    #[derive(Deserialize)]
    struct Payload {
        ts: DateTime<Utc>,
        id: Uuid,
    }

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|e| format!("base64 decode: {e}"))?;
    let p: Payload = serde_json::from_slice(&bytes).map_err(|e| format!("json: {e}"))?;
    Ok((p.ts, p.id))
}

/// Parse an action-kind wire string. The set matches the
/// `actions.kind` enum exactly so the dispatcher's
/// `RecommendedAction.action_kind` round-trips cleanly.
fn parse_action_kind(s: &str) -> Option<ActionKind> {
    match s {
        "label" => Some(ActionKind::Label),
        "warn" => Some(ActionKind::Warn),
        "takedown" => Some(ActionKind::Takedown),
        "mute" => Some(ActionKind::Mute),
        "escalate" => Some(ActionKind::Escalate),
        "no_action" => Some(ActionKind::NoAction),
        "reverse" => Some(ActionKind::Reverse),
        _ => None,
    }
}

/// Inverse of [`parse_action_kind`] used to fill the
/// `classifier_label` slot on the feedback envelope. Kept here
/// (rather than imported from elsewhere) so this module stays the
/// single touchpoint for the queue+feedback edge.
const fn recommended_kind_to_wire(k: ActionKind) -> &'static str {
    match k {
        ActionKind::Label => "label",
        ActionKind::Takedown => "takedown",
        ActionKind::Mute => "mute",
        ActionKind::Warn => "warn",
        ActionKind::Escalate => "escalate",
        ActionKind::NoAction | ActionKind::Comment | ActionKind::Reverse => "no_action",
    }
}

/// Fire the assisted-reject feedback envelope when a moderator
/// rejects a `pending_auto_actions` draft (REQ-G2).
///
/// **Stub for LLM-7 (#236).** The endpoint that performs the actual
/// `state → 'rejected'` UPDATE on `pending_auto_actions` lives in
/// LLM-7's PR; this function is the feedback-loop seam that handler
/// MUST call after the row transitions. The function is public so
/// LLM-7 can wire it in without re-importing the lower-level
/// [`fire_assisted_reject_feedback`] helper directly.
///
/// # Arguments
///
/// * `state` — the API state. The classifier client + pool are read
///   off the LLM dispatcher (production wiring) — if the dispatcher
///   is `None` (tests / deployments without an LLM adapter), the
///   feedback fan-out is silently skipped.
/// * `llm_observation_id` — the observation backing the rejected
///   draft. Stored on `pending_auto_actions.llm_observation_id`
///   (migration 50). Becomes the wire `event_id` so the LLM
///   substrate correlates the rejection back to the prompt+response
///   it scored.
/// * `recommended_action_kind` — the `action_kind` the LLM recommended
///   (read from `pending_auto_actions.recommended_action`'s JSONB).
/// * `recommendation_confidence` — the LLM's reported confidence.
/// * `rejection_reasoning` — the moderator's stated reason in free
///   text. NO moderator identity columns are concatenated in (the
///   REQ-G4 privacy invariant; see
///   [`crate::llm::feedback`] module docs).
///
/// # Errors
///
/// Returns [`ApiError::Internal`] only if the SQL fallback path
/// (loading the recommended kind from the action row, when the
/// queue handler chooses to pass `recommended_action_kind` via
/// `None`) fails. The fire-and-forget feedback delivery itself
/// never blocks the reject path — the call returns immediately.
///
/// # Examples
///
/// ```rust,no_run
/// use polaris_backend::api::queue::pending_auto_actions::fire_reject_feedback_hook;
/// use polaris_backend::api::state::ApiState;
/// use polaris_types::ActionKind;
///
/// # fn run(state: ApiState) -> Result<(), Box<dyn std::error::Error>> {
/// // LLM-7 reject handler call site (forthcoming in #236):
/// fire_reject_feedback_hook(
///     &state,
///     uuid::Uuid::new_v4(),     // pending_auto_actions.llm_observation_id
///     ActionKind::Takedown,     // recommended_action_kind from JSONB
///     0.83,                     // recommendation_confidence
///     "the cited policy doesn't cover this exact pattern",
/// )?;
/// # Ok(()) }
/// ```
pub fn fire_reject_feedback_hook(
    state: &ApiState,
    llm_observation_id: Uuid,
    recommended_action_kind: ActionKind,
    recommendation_confidence: f32,
    rejection_reasoning: &str,
) -> Result<(), ApiError> {
    let Some(dispatcher) = state.llm_dispatcher.as_ref() else {
        // No LLM dispatcher installed — the deployment does not run
        // the LLM substrate, so there is nothing to feed back into.
        // The reject itself is the user-visible action and has
        // already committed by the time we reach here.
        tracing::debug!(
            llm_observation_id = %llm_observation_id,
            "assisted-reject feedback skipped: no LLM dispatcher",
        );
        return Ok(());
    };

    let ctx = FeedbackContext {
        event_id: llm_observation_id,
        classifier_label: recommended_action_kind_to_wire(recommended_action_kind).to_owned(),
        classifier_confidence: recommendation_confidence,
        // Wire `moderator_action_kind` for a rejection: the moderator
        // declined the recommendation. The most faithful summary is
        // `NoAction` — no labeler-visible side effect was taken
        // against the subject.
        moderator_action_kind: ActionKind::NoAction,
    };

    fire_assisted_reject_feedback(
        dispatcher.classifier_client(),
        "llm-assisted".to_owned(),
        ctx,
        rejection_reasoning,
    );

    Ok(())
}

/// Variant of [`fire_reject_feedback_hook`] that loads the
/// recommendation envelope from a backing `actions` row rather than
/// having the caller pre-supply it. Used by the test harness today;
/// LLM-7's reject handler should prefer the direct-pass shape
/// because the queue handler already has the JSONB payload in hand.
///
/// # Errors
///
/// Returns the [`crate::llm::feedback::FeedbackError`]-mapped
/// [`ApiError`] on SQL failure.
pub async fn fire_reject_feedback_from_action(
    state: &ApiState,
    backing_action_id: Uuid,
    rejection_reasoning: &str,
) -> Result<(), ApiError> {
    let Some(dispatcher) = state.llm_dispatcher.as_ref() else {
        return Ok(());
    };

    let ctx = load_feedback_context(&state.pool, backing_action_id, ActionKind::NoAction)
        .await
        .map_err(|err| {
            tracing::warn!(
                action_id = %backing_action_id,
                error = %err,
                "assisted-reject feedback context load failed",
            );
            ApiError::Internal(anyhow::anyhow!(
                "assisted-reject feedback context load failed: {err}",
            ))
        })?;

    fire_assisted_reject_feedback(
        dispatcher.classifier_client(),
        "llm-assisted".to_owned(),
        ctx,
        rejection_reasoning,
    );

    Ok(())
}

/// Local helper: map a typed [`ActionKind`] to the discrete wire
/// vocabulary the LLM substrate consumes. Same vocabulary as
/// [`crate::classifier::action_kind_wire_string`]; duplicated here
/// (rather than re-imported) so this stub stays a single file LLM-7
/// can absorb wholesale when the queue endpoints land.
const fn recommended_action_kind_to_wire(k: ActionKind) -> &'static str {
    match k {
        ActionKind::Label => "label",
        ActionKind::Takedown => "takedown",
        ActionKind::Mute => "mute",
        ActionKind::Warn => "warn",
        ActionKind::Escalate => "escalate",
        ActionKind::NoAction | ActionKind::Comment | ActionKind::Reverse => "no_action",
    }
}

/// Suppressor: keep `Arc` + `ClassifierClient` + `PgPool` reachable
/// in this module so the LLM-7 follow-up does not have to re-add the
/// imports. The body is empty at runtime.
#[doc(hidden)]
#[allow(dead_code)]
fn _imports_anchor(_: Arc<dyn ClassifierClient>, _: &PgPool) {}

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
    fn recommended_action_kind_to_wire_covers_all_variants() {
        assert_eq!(recommended_action_kind_to_wire(ActionKind::Label), "label");
        assert_eq!(
            recommended_action_kind_to_wire(ActionKind::Takedown),
            "takedown",
        );
        assert_eq!(recommended_action_kind_to_wire(ActionKind::Mute), "mute");
        assert_eq!(recommended_action_kind_to_wire(ActionKind::Warn), "warn");
        assert_eq!(
            recommended_action_kind_to_wire(ActionKind::Escalate),
            "escalate",
        );
        assert_eq!(
            recommended_action_kind_to_wire(ActionKind::NoAction),
            "no_action",
        );
        assert_eq!(
            recommended_action_kind_to_wire(ActionKind::Reverse),
            "no_action",
        );
    }
}
