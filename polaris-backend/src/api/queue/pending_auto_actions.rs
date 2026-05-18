//! Assisted-mode draft queue handlers (LLM-7 / #236) —
//! reject-feedback hook only in LLM-10 / #239.
//!
//! The full queue endpoints (`GET /api/queue/pending-auto-actions`,
//! `POST /api/queue/pending-auto-actions/:id/approve`,
//! `POST /api/queue/pending-auto-actions/:id/reject`) are owned by
//! LLM-7 (#236) and ship in that issue. This file exists today as the
//! structural seam those handlers will hang off of, plus the
//! feedback hook the reject handler MUST call when LLM-7 lands.
//!
//! TODO(#236, LLM-7): When the reject handler lands, replace
//! [`fire_reject_feedback_hook`] with the in-handler invocation site.
//! The function signature here is the contract the reject handler is
//! expected to satisfy; LLM-7 should not need to add any new public
//! surface to [`crate::llm::feedback`] beyond what already exists.

use std::sync::Arc;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::classifier::ClassifierClient;
use crate::llm::feedback::{
    FeedbackContext, fire_assisted_reject_feedback, load_feedback_context,
};
use polaris_types::ActionKind;
use sqlx::PgPool;
use uuid::Uuid;

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
/// * `recommended_action_kind` — the action_kind the LLM recommended
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
/// # async fn run(state: ApiState) -> Result<(), Box<dyn std::error::Error>> {
/// // LLM-7 reject handler call site (forthcoming in #236):
/// fire_reject_feedback_hook(
///     &state,
///     uuid::Uuid::new_v4(),     // pending_auto_actions.llm_observation_id
///     ActionKind::Takedown,     // recommended_action_kind from JSONB
///     0.83,                     // recommendation_confidence
///     "the cited policy doesn't cover this exact pattern",
/// )
/// .await?;
/// # Ok(()) }
/// ```
pub async fn fire_reject_feedback_hook(
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
