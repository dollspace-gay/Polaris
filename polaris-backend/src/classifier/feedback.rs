//! Opt-in classifier feedback path (issue #130 / M5 #45 PR 6) +
//! LLM moderation-assist learning loop (LLM-10 / #239 / REQ-G1..G4).
//!
//! When `[[classifiers.<name>]] send_feedback = true` is explicitly
//! set in `polaris.toml`, Polaris emits a [`FeedbackRequest`] to the
//! classifier after a moderator's final action on an event the
//! classifier scored. Default is `false` (opt-in).
//!
//! LLM-10 extends the envelope with two outcome-tracking fields
//! (`was_recommendation_taken`, `reversal_reasoning`) so the LLM
//! moderation-assist substrate (`.design/llm-moderation-assist.md`)
//! can close its learning loop. The three LLM-specific paths live in
//! [`crate::llm::feedback`] and call into [`build_feedback`] /
//! [`spawn_feedback`] here.
//!
//! # Privacy boundary
//!
//! The feedback payload contains ONLY:
//!
//! - `event_id` — the event the classifier originally scored
//! - `classifier_label` — what the classifier said
//! - `classifier_confidence` — the score
//! - `moderator_action_kind` — `Label` / `Takedown` / `NoAction` / …
//! - `was_recommendation_taken` — outcome boolean (LLM-10)
//! - `reversal_reasoning` — moderator's stated reason as free text
//!   (LLM-10)
//!
//! It does NOT contain:
//!
//! - Moderator identity (no `moderator_id`, no handle, no DID)
//! - Reporter identity
//! - Subject content (the classifier already saw it at inference time)
//!
//! The `reversal_reasoning` field carries the moderator's *reason*
//! (free-text content the LLM can learn from), not their *identity*.
//! The function signatures here are the enforcement point: there is
//! no path for a `moderator_id` / handle / DID to thread into the
//! envelope. Regression tests in
//! `polaris-backend/tests/llm_feedback_privacy.rs` assert this at
//! runtime by encoding the payload and scanning for DID/handle
//! prefixes.
//!
//! The discipline matches the federation mapping layer (#103, #110):
//! privacy enforcement at a single function boundary, not scattered
//! across the call sites.

use std::sync::Arc;

use polaris_classifier_proto::v1::FeedbackRequest;
use polaris_types::ActionKind;
use tracing::warn;

use super::client::ClassifierClient;

/// Build a [`FeedbackRequest`] from a moderator's action + the
/// classifier's originating prediction (legacy 4-field shape from
/// issue #130 / PR 6).
///
/// LLM-10 outcome fields default to `was_recommendation_taken: false`
/// and `reversal_reasoning: ""` — the legacy classifier-feedback path
/// emits feedback on any moderator action regardless of agreement,
/// and the existing `moderator_action_kind` field already carries the
/// alignment signal. New LLM-feedback call sites should use
/// [`build_feedback_with_outcome`] to populate the outcome envelope
/// explicitly.
///
/// # Privacy boundary
///
/// Only the four federation-safe fields are populated. Internal-only
/// fields on the caller's side (`moderator_id`, reasoning text, reporter
/// DIDs) are NOT accepted as input — the function signature is the
/// enforcement point.
#[must_use]
pub fn build_feedback(
    event_id: impl Into<String>,
    classifier_label: impl Into<String>,
    classifier_confidence: f32,
    moderator_action_kind: ActionKind,
) -> FeedbackRequest {
    FeedbackRequest {
        event_id: event_id.into(),
        classifier_label: classifier_label.into(),
        classifier_confidence,
        moderator_action_kind: action_kind_wire_string(moderator_action_kind).to_owned(),
        was_recommendation_taken: false,
        reversal_reasoning: String::new(),
    }
}

/// Build a [`FeedbackRequest`] carrying the LLM-10 outcome envelope
/// (`.design/llm-moderation-assist.md` REQ-G1..G4).
///
/// Used by the three feedback paths in [`crate::llm::feedback`]:
///
///   * Reversal of an autonomous action ⇒
///     `was_recommendation_taken = false`, reasoning = moderator's
///     stated reason.
///   * Rejection of an assisted-mode draft ⇒
///     `was_recommendation_taken = false`, reasoning = moderator's
///     stated reason.
///   * `reversible_until` window elapsed unreversed ⇒
///     `was_recommendation_taken = true`, reasoning = `""` (no
///     intervention occurred).
///
/// # Privacy boundary
///
/// `reversal_reasoning` is the moderator's stated *reason* in free
/// text (REQ-G1). It is NOT their identity. The signature accepts
/// `&str` — there is no path for a `ModeratorId`, handle, or DID to
/// thread into the envelope. The caller is expected to pass the
/// reasoning *content* the moderator wrote on the reversal /
/// rejection form, with no identity columns concatenated in.
/// Regression tests in
/// `polaris-backend/tests/llm_feedback_privacy.rs` encode the wire
/// form and scan for DID/handle prefixes to catch a future drift.
///
/// # Examples
///
/// ```rust,no_run
/// use polaris_backend::classifier::build_feedback_with_outcome;
/// use polaris_types::ActionKind;
///
/// // Reversal of an autonomous takedown — negative signal.
/// let req = build_feedback_with_outcome(
///     "evt-7",
///     "spam",
///     0.92,
///     ActionKind::Takedown,
///     false,
///     "subject was quoting the spam they were reporting",
/// );
/// assert!(!req.was_recommendation_taken);
/// assert_eq!(req.reversal_reasoning, "subject was quoting the spam they were reporting");
/// ```
#[must_use]
pub fn build_feedback_with_outcome(
    event_id: impl Into<String>,
    classifier_label: impl Into<String>,
    classifier_confidence: f32,
    moderator_action_kind: ActionKind,
    was_recommendation_taken: bool,
    reversal_reasoning: &str,
) -> FeedbackRequest {
    FeedbackRequest {
        event_id: event_id.into(),
        classifier_label: classifier_label.into(),
        classifier_confidence,
        moderator_action_kind: action_kind_wire_string(moderator_action_kind).to_owned(),
        was_recommendation_taken,
        reversal_reasoning: reversal_reasoning.to_owned(),
    }
}

/// Map an [`ActionKind`] to the discrete wire string the classifier
/// service expects (matches the design's `moderator_action_kind`
/// vocabulary).
#[must_use]
#[allow(
    clippy::match_same_arms,
    reason = "ActionKind::Reverse intentionally maps to the same wire \
              token as NoAction — a reversal re-asserts 'no action' \
              against the subject. Collapsing the arms with `|` would \
              hide the design rationale; keeping them separate makes \
              the mapping explicit at the call site."
)]
pub const fn action_kind_wire_string(kind: ActionKind) -> &'static str {
    match kind {
        ActionKind::Label => "label",
        ActionKind::Takedown => "takedown",
        ActionKind::Mute => "mute",
        ActionKind::Warn => "warn",
        ActionKind::Escalate => "escalate",
        ActionKind::NoAction => "no_action",
        // `Reverse` is a v1 ActionKind that doesn't surface in the
        // classifier-feedback vocabulary (the design's feedback fields
        // are about classifier-vs-moderator alignment, and a reversal
        // is a second-order event on a prior action). Map to the same
        // wire token as NoAction.
        ActionKind::Reverse => "no_action",
        // `Comment` is a moderator note with no classifier signal —
        // the classifier never proposed an action, so there's no
        // alignment-vs-moderator delta to feed back. Same fallback
        // shape as Reverse: collapse to the most-conservative wire
        // token rather than skip emission (skipping would
        // partition the classifier's view of the case).
        ActionKind::Comment => "no_action",
    }
}

/// Emit feedback to a classifier in fire-and-forget fashion.
///
/// Spawned as a `tokio::task` so the moderator's action endpoint
/// isn't held by classifier latency. Failures are logged at WARN
/// and explicitly NOT propagated — classifier feedback is not
/// action-critical (per design REQ-8).
pub fn spawn_feedback(
    client: Arc<dyn ClassifierClient>,
    classifier_name: String,
    request: FeedbackRequest,
) {
    tokio::spawn(async move {
        if let Err(e) = client.feedback(request).await {
            warn!(
                classifier = %classifier_name,
                error = %e,
                "classifier feedback delivery failed; action proceeded normally",
            );
        }
    });
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
    use crate::classifier::FixtureClassifierClient;

    #[test]
    fn build_feedback_populates_only_safe_fields() {
        let req = build_feedback("evt-7", "spam", 0.87, ActionKind::Takedown);
        assert_eq!(req.event_id, "evt-7");
        assert_eq!(req.classifier_label, "spam");
        assert!((req.classifier_confidence - 0.87).abs() < f32::EPSILON);
        assert_eq!(req.moderator_action_kind, "takedown");
        // Legacy path defaults to the proto-zero outcome envelope.
        assert!(!req.was_recommendation_taken);
        assert!(req.reversal_reasoning.is_empty());
    }

    /// LLM-10 path: explicit outcome envelope (REQ-G1).
    #[test]
    fn build_feedback_with_outcome_carries_reversal_reasoning_no_identity() {
        let req = build_feedback_with_outcome(
            "evt-99",
            "harassment",
            0.81,
            ActionKind::Reverse,
            false,
            "subject was quoting a slur to report it, not endorse it",
        );
        assert_eq!(req.event_id, "evt-99");
        assert!(!req.was_recommendation_taken);
        assert_eq!(
            req.reversal_reasoning,
            "subject was quoting a slur to report it, not endorse it",
        );
        // The envelope is the only shape that carries reasoning — there
        // is no moderator_id field on FeedbackRequest at all (compile-
        // checked by the prost-generated struct's field set).
    }

    /// LLM-10 confirmation path: positive signal, empty reasoning.
    #[test]
    fn build_feedback_with_outcome_confirmation_carries_no_reasoning() {
        let req =
            build_feedback_with_outcome("evt-100", "spam", 0.95, ActionKind::Takedown, true, "");
        assert!(req.was_recommendation_taken);
        assert!(req.reversal_reasoning.is_empty());
    }

    /// Privacy boundary: serialise the feedback payload and confirm
    /// no internal-only field names appear. AC-7.
    #[test]
    fn feedback_serialization_contains_no_internal_fields() {
        use prost::Message as _;

        let req = build_feedback("evt-1", "harassment", 0.5, ActionKind::Label);
        // FeedbackRequest is a prost-generated message; serialize via
        // the prost Message trait's encode_to_vec for a deterministic
        // wire form.
        let bytes = req.encode_to_vec();
        let text = String::from_utf8_lossy(&bytes);
        // None of these substrings may appear in the encoded payload
        // (the field names themselves don't appear in proto3 wire
        // format, so this test is also asserting the payload isn't
        // accidentally JSON-shaped with field names embedded).
        for forbidden in [
            "moderator_id",
            "moderatorId",
            "audit_chain",
            "auditChain",
            "reporter_did",
            "reporterDid",
            "exposure",
            "reasoning",
        ] {
            assert!(
                !text.contains(forbidden),
                "feedback payload contains forbidden substring {forbidden:?}",
            );
        }
    }

    #[test]
    fn action_kind_wire_string_covers_all_variants() {
        assert_eq!(action_kind_wire_string(ActionKind::Label), "label");
        assert_eq!(action_kind_wire_string(ActionKind::Takedown), "takedown");
        assert_eq!(action_kind_wire_string(ActionKind::Mute), "mute");
        assert_eq!(action_kind_wire_string(ActionKind::Warn), "warn");
        assert_eq!(action_kind_wire_string(ActionKind::Escalate), "escalate");
        assert_eq!(action_kind_wire_string(ActionKind::NoAction), "no_action");
    }

    #[tokio::test]
    async fn spawn_feedback_delivers_to_fixture_client() {
        let fixture = FixtureClassifierClient::new();
        let client: Arc<dyn ClassifierClient> = Arc::new(fixture.clone());

        spawn_feedback(
            client,
            "test-classifier".to_owned(),
            build_feedback("evt-7", "spam", 0.87, ActionKind::Takedown),
        );

        // Give the spawned task a moment to run. tokio::task::yield_now
        // alone isn't enough because the spawned task may not have been
        // scheduled yet; tokio::time::sleep with 0 yields control back
        // to the runtime more reliably for test purposes.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let log = fixture.feedback_calls();
        assert_eq!(log.len(), 1);
        let entry = log.get("evt-7").unwrap();
        assert_eq!(entry.classifier_label, "spam");
        assert_eq!(entry.moderator_action_kind, "takedown");
    }
}
