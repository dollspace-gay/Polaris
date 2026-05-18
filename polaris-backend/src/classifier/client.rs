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
use std::time::{Duration, Instant};

use dashmap::DashMap;
use polaris_classifier_proto::v1::{
    ClassifyRequest, ClassifyResponse, FeedbackRequest, HealthResponse, RecommendRequest,
    RecommendResponse, classifier_client::ClassifierClient as TonicClient,
};
use tonic::transport::{Channel, Endpoint};

use super::budget::{BudgetRegistry, DEFAULT_MAX_IN_FLIGHT};
use super::circuit::{BreakerRegistry, BreakerVerdict};
use super::error::ClassifierError;

/// Default per-call timeout for the [`ClassifierClient::recommend`]
/// RPC (REQ-A5 in `.design/llm-moderation-assist.md`).
///
/// 15 seconds — substantially higher than the 500 ms classifier
/// default because LLM inference is slow. Operator-overridable per
/// classifier through [`TonicClassifierClient::connect`]'s
/// `recommend_timeout` parameter or
/// [`TonicClassifierClient::with_recommend_timeout`].
pub const DEFAULT_RECOMMEND_TIMEOUT: Duration = Duration::from_secs(15);

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

    /// Request a structured moderation recommendation for a hydrated
    /// case bundle (issue #232 / `.design/llm-moderation-assist.md`
    /// REQ-A1, REQ-A4, REQ-A5; AC-2).
    ///
    /// Unlike [`Self::classify`] (which emits per-label confidence
    /// scores against a model-specific vocabulary), `recommend` produces
    /// a structured action suggestion — `action_kind`, `subject_scope`,
    /// confidence, cited policies, reasoning. The downstream dispatcher
    /// (LLM-4 / issue #234) routes the result through the manual /
    /// assisted / autonomous mode machinery.
    ///
    /// # Behaviour
    ///
    /// The IMPLEMENTOR is responsible for:
    ///
    /// 1. Gating the call through the per-classifier `Semaphore` from
    ///    [`super::budget::BudgetRegistry`] (REQ-A4 — no new resource
    ///    primitives).
    /// 2. Consulting the per-classifier `BreakerRegistry`
    ///    ([`super::circuit::BreakerRegistry`]) and short-circuiting
    ///    with [`ClassifierError::CircuitOpen`] when the breaker is
    ///    `Open` (REQ-A4).
    /// 3. Applying a 15 s default timeout per REQ-A5
    ///    ([`DEFAULT_RECOMMEND_TIMEOUT`]) via
    ///    [`tokio::time::timeout`]; operator-overridable through the
    ///    classifier config block.
    /// 4. Recording the outcome on the breaker — successes call
    ///    `record_success`; timeouts, transport errors, and bad
    ///    responses call `record_failure` (so the breaker counter
    ///    behaves identically to `Classify`).
    ///
    /// # Errors
    ///
    /// - [`ClassifierError::Timeout`] if the per-call timeout elapses.
    ///   Counts toward the breaker's consecutive-failure counter — same
    ///   shape as `Classify`.
    /// - [`ClassifierError::RateLimited`] if the per-classifier
    ///   semaphore is exhausted.
    /// - [`ClassifierError::CircuitOpen`] if the breaker is `Open` and
    ///   the call is short-circuited without going to the wire.
    /// - [`ClassifierError::Transport`] for any tonic-level failure.
    /// - [`ClassifierError::BadResponse`] if the classifier returns a
    ///   response that violates the wire-shape contract.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use polaris_backend::classifier::{ClassifierClient, FixtureClassifierClient};
    /// # use polaris_classifier_proto::v1::{RecommendRequest, RecommendResponse};
    /// # async fn doc() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = FixtureClassifierClient::new();
    /// client.set_recommend_response(
    ///     "evt-1",
    ///     RecommendResponse {
    ///         event_id: "evt-1".into(),
    ///         model: "claude-sonnet-4-6".into(),
    ///         model_version: "2026.05.01".into(),
    ///         prompt_template_id: "v1".into(),
    ///         recommended_actions: vec![],
    ///         overall_reasoning: String::new(),
    ///         input_tokens: 0,
    ///         output_tokens: 0,
    ///     },
    /// );
    /// let req = RecommendRequest {
    ///     event_id: "evt-1".into(),
    ///     ..Default::default()
    /// };
    /// let resp = client.recommend(req).await?;
    /// assert_eq!(resp.model, "claude-sonnet-4-6");
    /// # Ok(()) }
    /// ```
    async fn recommend(&self, req: RecommendRequest) -> Result<RecommendResponse, ClassifierError>;
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
    /// Per-call timeout for `classify` / `health` / `feedback`. Default
    /// 500 ms; operator-overridable in `[[classifiers.<name>]] timeout_ms`.
    timeout: Duration,
    /// Per-call timeout for `recommend` (REQ-A5 of
    /// `.design/llm-moderation-assist.md`). Default
    /// [`DEFAULT_RECOMMEND_TIMEOUT`] (15 s); operator-overridable in
    /// `[[classifiers.<name>]] recommend_timeout_ms`.
    recommend_timeout: Duration,
    /// The underlying gRPC channel. `tonic::transport::Channel` is
    /// `Clone` (it's reference-counted internally), so cloning the
    /// client to spawn per-event tasks is cheap.
    channel: Channel,
    /// Shared per-classifier concurrency budget (REQ-A4 — reuse, do
    /// not create new). The `recommend()` impl acquires a permit on
    /// `name`'s semaphore for the duration of the RPC. `Cloneable`.
    budget: BudgetRegistry,
    /// Shared per-classifier circuit breaker (REQ-A4). `recommend()`
    /// consults the breaker before the wire call and records the
    /// outcome afterward. `Cloneable`.
    breaker: BreakerRegistry,
    /// Maximum in-flight `recommend` calls allowed per classifier.
    /// Defaults to [`DEFAULT_MAX_IN_FLIGHT`]; operator-overridable in
    /// `[[classifiers.<name>]] max_in_flight`.
    max_in_flight: usize,
}

impl TonicClassifierClient {
    /// Construct a client by connecting to `endpoint`.
    ///
    /// Uses [`DEFAULT_RECOMMEND_TIMEOUT`] for the `recommend` RPC and
    /// [`DEFAULT_MAX_IN_FLIGHT`] for the concurrency budget. Override
    /// via [`Self::with_recommend_timeout`], [`Self::with_breaker`],
    /// [`Self::with_budget`], and [`Self::with_max_in_flight`].
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
            recommend_timeout: DEFAULT_RECOMMEND_TIMEOUT,
            channel,
            budget: BudgetRegistry::new(),
            breaker: BreakerRegistry::new(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        })
    }

    /// Override the per-call timeout used by [`ClassifierClient::recommend`].
    ///
    /// Builder method; the operator config layer (`polaris.toml`
    /// `[[classifiers.<name>]] recommend_timeout_ms`) calls this when
    /// the operator declares a non-default value.
    #[must_use]
    pub fn with_recommend_timeout(mut self, timeout: Duration) -> Self {
        self.recommend_timeout = timeout;
        self
    }

    /// Wire the client to a shared [`BudgetRegistry`].
    ///
    /// All `TonicClassifierClient`s in a process should share the same
    /// registry so the per-classifier semaphore count is the
    /// in-process truth (REQ-A4: reuse, don't re-create).
    #[must_use]
    pub fn with_budget(mut self, budget: BudgetRegistry) -> Self {
        self.budget = budget;
        self
    }

    /// Wire the client to a shared [`BreakerRegistry`].
    ///
    /// Same shared-registry discipline as [`Self::with_budget`].
    #[must_use]
    pub fn with_breaker(mut self, breaker: BreakerRegistry) -> Self {
        self.breaker = breaker;
        self
    }

    /// Override the per-classifier concurrency cap.
    #[must_use]
    pub const fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
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

    async fn recommend(&self, req: RecommendRequest) -> Result<RecommendResponse, ClassifierError> {
        // REQ-A4: consult the breaker before any wire activity.
        match self.breaker.check(&self.name, Instant::now()) {
            BreakerVerdict::Allowed | BreakerVerdict::Probe => {}
            BreakerVerdict::Blocked => {
                return Err(ClassifierError::CircuitOpen {
                    classifier: self.name.clone(),
                });
            }
        }

        // REQ-A4: gate on the per-classifier semaphore. The borrowed
        // permit lives until the end of the RPC; on drop it returns
        // the permit to the semaphore. Rate-limit failure does NOT
        // count toward the breaker's failure counter (the call never
        // went to the wire).
        let semaphore = self.budget.semaphore(&self.name, self.max_in_flight);
        let Ok(_permit) = semaphore.try_acquire() else {
            return Err(ClassifierError::RateLimited {
                classifier: self.name.clone(),
            });
        };

        // REQ-A5: 15 s default timeout, operator-overridable through
        // `recommend_timeout_ms` config (see [`Self::with_recommend_timeout`]).
        let mut client = TonicClient::new(self.channel.clone());
        let fut = client.recommend(tonic::Request::new(req));
        let outcome = tokio::time::timeout(self.recommend_timeout, fut).await;

        match outcome {
            Err(_elapsed) => {
                // Timeout counts toward the breaker's failure counter
                // — same as Classify (REQ-A5).
                self.breaker.record_failure(&self.name, Instant::now());
                Err(ClassifierError::Timeout {
                    classifier: self.name.clone(),
                })
            }
            Ok(Err(status)) => {
                self.breaker.record_failure(&self.name, Instant::now());
                Err(ClassifierError::Transport(status))
            }
            Ok(Ok(response)) => {
                self.breaker.record_success(&self.name);
                Ok(response.into_inner())
            }
        }
    }
}

impl std::fmt::Debug for TonicClassifierClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't print the channel internals — they're noisy and not
        // useful for debugging Polaris-side issues.
        f.debug_struct("TonicClassifierClient")
            .field("name", &self.name)
            .field("timeout", &self.timeout)
            .field("recommend_timeout", &self.recommend_timeout)
            .field("max_in_flight", &self.max_in_flight)
            .finish_non_exhaustive()
    }
}

/// In-memory fixture [`ClassifierClient`] for integration tests.
///
/// Test setup populates the `responses` map keyed by `event_id`;
/// `classify` looks up by `event_id` and returns the canned response.
/// Cloneable so the same fixture can be wired into multiple
/// per-classifier task spawns.
///
/// For [`ClassifierClient::recommend`], call
/// [`Self::set_recommend_response`] to pre-bake the response, and
/// optionally [`Self::set_recommend_delay`] to simulate a slow
/// classifier for timeout tests. The fixture mirrors
/// [`TonicClassifierClient`]'s breaker + budget gating semantics so
/// tests can exercise REQ-A4 / REQ-A5 without a live gRPC server.
#[derive(Debug, Clone)]
pub struct FixtureClassifierClient {
    /// Operator-allocated classifier name. Used as the breaker /
    /// budget registry key so multiple fixtures in one test can
    /// represent independent classifiers.
    name: String,
    /// Canned classify responses keyed by `event_id`.
    responses: Arc<DashMap<String, ClassifyResponse>>,
    /// Canned health response. Set via [`Self::set_health_status`];
    /// defaults to a no-op `HealthResponse { status: "ok", message: None }`.
    health_status: Arc<DashMap<(), HealthResponse>>,
    /// Captured feedback calls keyed by `event_id`. Tests assert on
    /// this map to verify the opt-in feedback path is gated correctly.
    feedback_log: Arc<DashMap<String, FeedbackRequest>>,
    /// Canned recommend responses keyed by `event_id`.
    recommend_responses: Arc<DashMap<String, RecommendResponse>>,
    /// Simulated wire latency for `recommend()`; if `Some(d)` and `d`
    /// exceeds [`Self::recommend_timeout`], the call surfaces as
    /// [`ClassifierError::Timeout`].
    recommend_delay: Arc<DashMap<(), Duration>>,
    /// Per-call timeout for `recommend()`. Default
    /// [`DEFAULT_RECOMMEND_TIMEOUT`].
    recommend_timeout: Arc<DashMap<(), Duration>>,
    /// Same breaker the production client uses (REQ-A4 — fixtures
    /// reuse the production primitive so timing tests are realistic).
    breaker: BreakerRegistry,
    /// Same budget the production client uses (REQ-A4).
    budget: BudgetRegistry,
    /// Concurrency cap fed to [`BudgetRegistry::semaphore`].
    max_in_flight: usize,
}

impl Default for FixtureClassifierClient {
    fn default() -> Self {
        Self {
            name: "fixture".to_owned(),
            responses: Arc::new(DashMap::new()),
            health_status: Arc::new(DashMap::new()),
            feedback_log: Arc::new(DashMap::new()),
            recommend_responses: Arc::new(DashMap::new()),
            recommend_delay: Arc::new(DashMap::new()),
            recommend_timeout: Arc::new(DashMap::new()),
            breaker: BreakerRegistry::new(),
            budget: BudgetRegistry::new(),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }
}

impl FixtureClassifierClient {
    /// Construct an empty fixture under the default name `"fixture"`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a fixture under a custom name. Useful when a test
    /// wires multiple fixtures into one [`BreakerRegistry`] /
    /// [`BudgetRegistry`] and needs them to be independent.
    #[must_use]
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// Wire this fixture to a shared [`BreakerRegistry`]. Tests that
    /// assert "10 consecutive timeouts trip the breaker" share the
    /// registry across calls by reusing the same fixture instance.
    #[must_use]
    pub fn with_breaker(mut self, breaker: BreakerRegistry) -> Self {
        self.breaker = breaker;
        self
    }

    /// Wire this fixture to a shared [`BudgetRegistry`].
    #[must_use]
    pub fn with_budget(mut self, budget: BudgetRegistry) -> Self {
        self.budget = budget;
        self
    }

    /// Override the concurrency cap (default [`DEFAULT_MAX_IN_FLIGHT`]).
    #[must_use]
    pub const fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Pre-bake a `classify` response for the given `event_id`.
    pub fn set_response(&self, event_id: impl Into<String>, response: ClassifyResponse) {
        self.responses.insert(event_id.into(), response);
    }

    /// Pre-bake a [`ClassifierClient::recommend`] response for the
    /// given `event_id`.
    pub fn set_recommend_response(&self, event_id: impl Into<String>, response: RecommendResponse) {
        self.recommend_responses.insert(event_id.into(), response);
    }

    /// Simulate wire latency on [`ClassifierClient::recommend`]. When
    /// `delay` exceeds the configured `recommend_timeout`, the call
    /// surfaces as [`ClassifierError::Timeout`].
    pub fn set_recommend_delay(&self, delay: Duration) {
        self.recommend_delay.insert((), delay);
    }

    /// Override the per-call timeout used by
    /// [`ClassifierClient::recommend`] on this fixture. Defaults to
    /// [`DEFAULT_RECOMMEND_TIMEOUT`] if unset.
    pub fn set_recommend_timeout(&self, timeout: Duration) {
        self.recommend_timeout.insert((), timeout);
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

    /// Resolve the active `recommend_timeout` (override or default).
    fn resolved_recommend_timeout(&self) -> Duration {
        self.recommend_timeout
            .get(&())
            .map_or(DEFAULT_RECOMMEND_TIMEOUT, |kv| *kv.value())
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

    async fn recommend(&self, req: RecommendRequest) -> Result<RecommendResponse, ClassifierError> {
        // Mirror TonicClassifierClient: breaker check → semaphore →
        // (simulated) wire call inside tokio::time::timeout → breaker
        // bookkeeping. Keeping the gate semantics identical means
        // integration tests against the fixture exercise the same
        // happy/sad paths the production client takes.
        match self.breaker.check(&self.name, Instant::now()) {
            BreakerVerdict::Allowed | BreakerVerdict::Probe => {}
            BreakerVerdict::Blocked => {
                return Err(ClassifierError::CircuitOpen {
                    classifier: self.name.clone(),
                });
            }
        }

        let semaphore = self.budget.semaphore(&self.name, self.max_in_flight);
        let Ok(_permit) = semaphore.try_acquire() else {
            return Err(ClassifierError::RateLimited {
                classifier: self.name.clone(),
            });
        };

        let timeout = self.resolved_recommend_timeout();
        let canned = self
            .recommend_responses
            .get(&req.event_id)
            .map(|kv| kv.value().clone());
        let delay = self.recommend_delay.get(&()).map(|kv| *kv.value());

        let fut = async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }
            canned
        };

        let outcome = tokio::time::timeout(timeout, fut).await;
        match outcome {
            Err(_elapsed) => {
                self.breaker.record_failure(&self.name, Instant::now());
                Err(ClassifierError::Timeout {
                    classifier: self.name.clone(),
                })
            }
            Ok(None) => {
                // No canned response for this event_id — treat as a
                // classifier-side contract violation, not a wire
                // failure. Don't count toward the breaker's failure
                // counter; the call "succeeded" from the breaker's
                // point of view (the wire returned), and BadResponse
                // is the contract-shape error variant.
                Err(ClassifierError::BadResponse {
                    classifier: self.name.clone(),
                    reason: format!("no canned recommend response for event_id={}", req.event_id),
                })
            }
            Ok(Some(response)) => {
                self.breaker.record_success(&self.name);
                Ok(response)
            }
        }
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
