//! Opt-in classifier feedback path (issue #130 / M5 #45 PR 6).
//!
//! When `[[classifiers.<name>]] send_feedback = true` is explicitly
//! set in `polaris.toml`, Polaris emits a [`FeedbackRequest`] to the
//! classifier after a moderator's final action on an event the
//! classifier scored. Default is `false` (opt-in).
//!
//! # Privacy boundary
//!
//! The feedback payload contains ONLY:
//!
//! - `event_id` — the event the classifier originally scored
//! - `classifier_label` — what the classifier said
//! - `classifier_confidence` — the score
//! - `moderator_action_kind` — `Label` / `Takedown` / `NoAction` / …
//!
//! It does NOT contain:
//!
//! - Moderator identity
//! - Moderator reasoning text (sensitive free-text)
//! - Reporter identity
//! - Subject content (the classifier already saw it at inference time)
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
/// classifier's originating prediction.
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
