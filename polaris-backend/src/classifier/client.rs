//! [`ClassifierClient`] trait + production tonic-backed impl + in-memory
//! fixture impl (issue #126 / M5 #45 PR 2).
//!
//! # Architecture
//!
//! The trait abstracts over the gRPC transport so tests don't need a
//! live classifier service. Two impls ship:
//!
//! - [`TonicClassifierClient`] — production. Wraps a `tonic` channel
//!   connected to the operator-configured classifier endpoint.
//! - [`FixtureClassifierClient`] — test-only. Holds a `DashMap` of
//!   pre-baked `ClassifyResponse` values keyed by `event_id`; integration
//!   tests in #127 + #128 use this without needing a running gRPC server.
//!
//! Per rust-quality §2: trait + multiple impls is the right pattern for
//! testability when the abstraction's cost (boxed dispatch) is dwarfed
//! by the operation cost (a gRPC round-trip).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use polaris_classifier_proto::v1::{
    ClassifyRequest, ClassifyResponse, FeedbackRequest, HealthResponse,
    classifier_client::ClassifierClient as TonicClient,
};
use tonic::transport::{Channel, Endpoint};

use super::error::ClassifierError;

/// gRPC client abstraction for the Polaris classifier service.
///
/// Production deployments use [`TonicClassifierClient`]; tests use
/// [`FixtureClassifierClient`]. The trait surface is intentionally
/// narrow — fan-out (#127) calls `classify`; the circuit-breaker
/// probe (#128) calls `health`; the opt-in feedback path (#130) calls
/// `feedback`.
///
/// All implementors must be `Send + Sync + 'static` so the fan-out
/// worker can hand them to per-classifier `tokio::task::JoinSet`s.
#[async_trait::async_trait]
pub trait ClassifierClient: Send + Sync + 'static {
    /// Classify a single event.
    ///
    /// The per-call timeout (default 500 ms; operator-configurable per
    /// classifier in #128) is applied by the IMPLEMENTOR, not by the
    /// caller. The production impl wraps the inner gRPC call in
    /// `tokio::time::timeout`; the fixture impl returns immediately.
    ///
    /// # Errors
    ///
    /// - [`ClassifierError::Timeout`] if the per-call timeout elapses.
    /// - [`ClassifierError::RateLimited`] if the per-classifier
    ///   semaphore is exhausted.
    /// - [`ClassifierError::Transport`] for any tonic-level failure.
    /// - [`ClassifierError::BadResponse`] if the classifier returns a
    ///   response that violates the wire-shape contract.
    async fn classify(&self, req: ClassifyRequest) -> Result<ClassifyResponse, ClassifierError>;

    /// Probe the classifier's health endpoint.
    ///
    /// Used by the circuit breaker (#128) when transitioning from `Open`
    /// to `HalfOpen` to decide whether to attempt a real `classify` call.
    ///
    /// # Errors
    ///
    /// Same set as [`Self::classify`].
    async fn health(&self) -> Result<HealthResponse, ClassifierError>;

    /// Send moderator-action feedback to the classifier (opt-in).
    ///
    /// Called by [`crate::api::cases::submit_action`] ONLY when the
    /// classifier's `[[classifiers.<name>]] send_feedback = true`
    /// config is set. Fire-and-forget — feedback failures do not
    /// affect the moderator's action.
    ///
    /// # Errors
    ///
    /// Same set as [`Self::classify`]; callers typically log + ignore.
    async fn feedback(&self, req: FeedbackRequest) -> Result<(), ClassifierError>;
}

/// Production [`ClassifierClient`] backed by `tonic::transport::Channel`.
///
/// One instance per configured classifier (`[[classifiers]]` entry in
/// `polaris.toml`). Held in an `Arc` in `ApiState` so the fan-out
/// worker, the feedback path, and any future direct-call sites share
/// the same channel pool.
pub struct TonicClassifierClient {
    /// Operator-allocated name (matches `[[classifiers.<name>]]`).
    name: String,
    /// Per-call timeout. Default 500 ms; operator-overridable in
    /// `[[classifiers.<name>]] timeout_ms`.
    timeout: Duration,
    /// The underlying gRPC channel. `tonic::transport::Channel` is
    /// `Clone` (it's reference-counted internally), so cloning the
    /// client to spawn per-event tasks is cheap.
    channel: Channel,
}

impl TonicClassifierClient {
    /// Construct a client by connecting to `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns [`ClassifierError::Transport`] if the channel cannot be
    /// established (invalid URL, TLS handshake failure, etc.).
    pub async fn connect(
        name: impl Into<String>,
        endpoint: impl AsRef<str>,
        timeout: Duration,
    ) -> Result<Self, ClassifierError> {
        let endpoint_str = endpoint.as_ref().to_owned();
        let endpoint = Endpoint::from_shared(endpoint_str.clone()).map_err(|e| {
            ClassifierError::BadResponse {
                classifier: name.into(),
                reason: format!("invalid endpoint URL `{endpoint_str}`: {e}"),
            }
        })?;
        let channel = endpoint.connect().await.map_err(|e| {
            // Map transport errors via a tonic::Status wrap so downstream
            // breaker logic can dispatch on `ClassifierError::Transport`.
            ClassifierError::Transport(tonic::Status::unavailable(format!(
                "channel connect failed: {e}"
            )))
        })?;
        Ok(Self {
            name: endpoint_str,
            timeout,
            channel,
        })
    }
}

#[async_trait::async_trait]
impl ClassifierClient for TonicClassifierClient {
    async fn classify(&self, req: ClassifyRequest) -> Result<ClassifyResponse, ClassifierError> {
        let mut client = TonicClient::new(self.channel.clone());
        let fut = client.classify(tonic::Request::new(req));
        let response = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ClassifierError::Timeout {
                classifier: self.name.clone(),
            })??;
        Ok(response.into_inner())
    }

    async fn health(&self) -> Result<HealthResponse, ClassifierError> {
        let mut client = TonicClient::new(self.channel.clone());
        let fut = client.health_check(tonic::Request::new(()));
        let response = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ClassifierError::Timeout {
                classifier: self.name.clone(),
            })??;
        Ok(response.into_inner())
    }

    async fn feedback(&self, req: FeedbackRequest) -> Result<(), ClassifierError> {
        let mut client = TonicClient::new(self.channel.clone());
        let fut = client.feedback(tonic::Request::new(req));
        let _response = tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ClassifierError::Timeout {
                classifier: self.name.clone(),
            })??;
        Ok(())
    }
}

impl std::fmt::Debug for TonicClassifierClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print the channel internals — they're noisy and not
        // useful for debugging Polaris-side issues.
        f.debug_struct("TonicClassifierClient")
            .field("name", &self.name)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// In-memory fixture [`ClassifierClient`] for integration tests.
///
/// Test setup populates the `responses` map keyed by `event_id`;
/// `classify` looks up by `event_id` and returns the canned response.
/// Cloneable so the same fixture can be wired into multiple
/// per-classifier task spawns.
#[derive(Debug, Clone, Default)]
pub struct FixtureClassifierClient {
    /// Canned classify responses keyed by `event_id`.
    responses: Arc<DashMap<String, ClassifyResponse>>,
    /// Canned health response. Set via [`Self::set_health_status`];
    /// defaults to a no-op `HealthResponse { status: "ok", message: None }`.
    health_status: Arc<DashMap<(), HealthResponse>>,
    /// Captured feedback calls keyed by `event_id`. Tests assert on
    /// this map to verify the opt-in feedback path is gated correctly.
    feedback_log: Arc<DashMap<String, FeedbackRequest>>,
}

impl FixtureClassifierClient {
    /// Construct an empty fixture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-bake a `classify` response for the given `event_id`.
    pub fn set_response(&self, event_id: impl Into<String>, response: ClassifyResponse) {
        self.responses.insert(event_id.into(), response);
    }

    /// Set the `health_check` response.
    pub fn set_health_status(&self, response: HealthResponse) {
        self.health_status.insert((), response);
    }

    /// Read back the feedback calls the fixture has received.
    ///
    /// Used by tests to assert AC-7 (privacy boundary on the feedback
    /// payload — verifies no `moderator_id` / reasoning text leaked).
    #[must_use]
    pub fn feedback_calls(&self) -> HashMap<String, FeedbackRequest> {
        self.feedback_log
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().clone()))
            .collect()
    }
}

#[async_trait::async_trait]
impl ClassifierClient for FixtureClassifierClient {
    async fn classify(&self, req: ClassifyRequest) -> Result<ClassifyResponse, ClassifierError> {
        self.responses
            .get(&req.event_id)
            .map(|r| r.value().clone())
            .ok_or_else(|| ClassifierError::BadResponse {
                classifier: "fixture".to_owned(),
                reason: format!("no canned response for event_id={}", req.event_id),
            })
    }

    async fn health(&self) -> Result<HealthResponse, ClassifierError> {
        Ok(self
            .health_status
            .get(&())
            .map_or_else(default_health_response, |r| r.value().clone()))
    }

    async fn feedback(&self, req: FeedbackRequest) -> Result<(), ClassifierError> {
        self.feedback_log.insert(req.event_id.clone(), req);
        Ok(())
    }
}

fn default_health_response() -> HealthResponse {
    HealthResponse {
        status: "ok".to_owned(),
        message: None,
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
    use polaris_classifier_proto::v1::Label;

    fn sample_request() -> ClassifyRequest {
        ClassifyRequest {
            event_id: "evt-1".to_owned(),
            subject_did: "did:plc:test123".to_owned(),
            text_content: Some(b"check out my crypto giveaway".to_vec()),
            image_blob_cid: None,
            model_hint: None,
        }
    }

    fn sample_response() -> ClassifyResponse {
        ClassifyResponse {
            model: "spam-v1".to_owned(),
            model_version: "2026.05.01".to_owned(),
            labels: vec![Label {
                value: "spam".to_owned(),
                confidence: 0.85,
            }],
            produced_at: None,
        }
    }

    #[tokio::test]
    async fn fixture_returns_canned_response_for_known_event() {
        let fixture = FixtureClassifierClient::new();
        fixture.set_response("evt-1", sample_response());

        let resp = fixture.classify(sample_request()).await.unwrap();
        assert_eq!(resp.model, "spam-v1");
        assert_eq!(resp.labels.len(), 1);
        assert_eq!(resp.labels[0].value, "spam");
        assert!((resp.labels[0].confidence - 0.85).abs() < f32::EPSILON);
    }

    #[tokio::test]
    async fn fixture_returns_bad_response_for_unknown_event() {
        let fixture = FixtureClassifierClient::new();
        let req = sample_request();
        let err = fixture.classify(req).await.unwrap_err();
        match err {
            ClassifierError::BadResponse { reason, .. } => {
                assert!(reason.contains("no canned response"));
            }
            other => panic!("expected BadResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fixture_default_health_is_ok() {
        let fixture = FixtureClassifierClient::new();
        let resp = fixture.health().await.unwrap();
        assert_eq!(resp.status, "ok");
        assert!(resp.message.is_none());
    }

    #[tokio::test]
    async fn fixture_health_status_overrides_default() {
        let fixture = FixtureClassifierClient::new();
        fixture.set_health_status(HealthResponse {
            status: "degraded".to_owned(),
            message: Some("queue lag 800ms".to_owned()),
        });
        let resp = fixture.health().await.unwrap();
        assert_eq!(resp.status, "degraded");
        assert_eq!(resp.message.as_deref(), Some("queue lag 800ms"));
    }

    #[tokio::test]
    async fn fixture_captures_feedback_calls() {
        let fixture = FixtureClassifierClient::new();
        let req = FeedbackRequest {
            event_id: "evt-1".to_owned(),
            classifier_label: "spam".to_owned(),
            classifier_confidence: 0.85,
            moderator_action_kind: "takedown".to_owned(),
        };
        fixture.feedback(req.clone()).await.unwrap();

        let log = fixture.feedback_calls();
        assert_eq!(log.len(), 1);
        let entry = log.get("evt-1").unwrap();
        assert_eq!(entry.classifier_label, "spam");
        assert_eq!(entry.moderator_action_kind, "takedown");
    }

    /// Trait-object compatibility check: both impls must satisfy
    /// `dyn ClassifierClient + Send + Sync + 'static` so the fan-out
    /// dispatcher can hold them in `Box<dyn ClassifierClient>`.
    #[test]
    fn impls_are_dyn_compatible() {
        fn assert_dyn_compatible<T: ClassifierClient>() {}
        assert_dyn_compatible::<FixtureClassifierClient>();
        assert_dyn_compatible::<TonicClassifierClient>();
    }
}
