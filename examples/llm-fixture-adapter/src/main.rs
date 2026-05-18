//! Minimal gRPC fixture for the `polaris.classifier.v1.Classifier`
//! service (`.design/llm-moderation-assist.md` AC-11; issue #241).
//!
//! Returns canned [`RecommendResponse`]s so an operator can walk
//! through the LLM moderation-assist plumbing end-to-end without
//! standing up a real model. The fixture implements `Recommend` and
//! `HealthCheck`; every other RPC (`Classify`, `ClassifyStream`,
//! `Feedback`) returns `Status::unimplemented` with a message that
//! names this binary so an operator wiring the fixture in by
//! accident sees a clear "use a real classifier adapter for that
//! RPC" line.
//!
//! # Running
//!
//! ```sh
//! cargo run --manifest-path examples/llm-fixture-adapter/Cargo.toml
//! # Listens on 127.0.0.1:50052 by default.
//! ```
//!
//! # Configuration knobs (env vars)
//!
//! - `FIXTURE_LISTEN_ADDR` — `host:port` (default `127.0.0.1:50052`).
//! - `FIXTURE_RECOMMEND_ACTION_KIND` — `"label" | "warn" | "takedown"
//!   | "no_action"` (default `"warn"`).
//! - `FIXTURE_RECOMMEND_CONFIDENCE` — float in `[0.0, 1.0]` (default
//!   `0.6`). Below `0.6` the safety floors typically downgrade to
//!   `manual`; the default sits at the assisted/autonomous edge so
//!   the walkthrough produces a visible recommendation.
//! - `FIXTURE_RECOMMEND_LABEL_VALUE` — string, used only when
//!   `action_kind = "label"`. Default empty.
//! - `FIXTURE_RECOMMEND_POLICY_IDENT` — the cited policy identifier
//!   (default `"polaris.spam"`). Must exist in the operator's
//!   `mod_policies` workbook for the recommendation to ground.
//! - `FIXTURE_MODEL_NAME` / `FIXTURE_MODEL_VERSION` /
//!   `FIXTURE_PROMPT_TEMPLATE_ID` — adapter-attribution strings the
//!   dispatcher echoes into the audit row (default
//!   `"polaris-fixture"`, `"v1"`, `"polaris.fixture.recommend.v1"`).
//!
//! No other RPC consults these — the fixture is `Recommend`-only by
//! design.

use std::env;
use std::net::SocketAddr;

use polaris_classifier_proto::v1::classifier_server::{Classifier, ClassifierServer};
use polaris_classifier_proto::v1::{
    ClassifyRequest, ClassifyResponse, FeedbackRequest, FeedbackResponse, HealthResponse,
    RecommendRequest, RecommendResponse, RecommendedAction,
};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:50052";
const DEFAULT_ACTION_KIND: &str = "warn";
const DEFAULT_CONFIDENCE: f32 = 0.6;
const DEFAULT_POLICY_IDENT: &str = "polaris.spam";
const DEFAULT_MODEL_NAME: &str = "polaris-fixture";
const DEFAULT_MODEL_VERSION: &str = "v1";
const DEFAULT_PROMPT_TEMPLATE_ID: &str = "polaris.fixture.recommend.v1";

/// Snapshot of the env-driven configuration. Read once at startup;
/// every RPC reads from this struct so a mid-run env mutation does
/// not split-brain the fixture.
#[derive(Debug, Clone)]
struct FixtureConfig {
    action_kind: String,
    confidence: f32,
    label_value: String,
    policy_identifier: String,
    model_name: String,
    model_version: String,
    prompt_template_id: String,
}

impl FixtureConfig {
    /// Read the env vars once at startup. Invalid values fall back to
    /// the documented defaults with a `tracing::warn!` so the operator
    /// sees the bad input named.
    fn from_env() -> Self {
        let action_kind =
            env::var("FIXTURE_RECOMMEND_ACTION_KIND").unwrap_or_else(|_| DEFAULT_ACTION_KIND.into());
        // Validate the action kind against the proto's documented set
        // so a typo is caught at boot, not inferred from a 400 a
        // downstream test produced.
        let action_kind = match action_kind.as_str() {
            "label" | "warn" | "takedown" | "no_action" | "escalate" | "mute" => action_kind,
            other => {
                tracing::warn!(
                    invalid = %other,
                    "FIXTURE_RECOMMEND_ACTION_KIND not in {{label,warn,takedown,no_action,escalate,mute}}; falling back to default `{DEFAULT_ACTION_KIND}`",
                );
                DEFAULT_ACTION_KIND.into()
            }
        };
        let confidence = env::var("FIXTURE_RECOMMEND_CONFIDENCE")
            .ok()
            .and_then(|s| s.parse::<f32>().ok())
            .filter(|c| (0.0..=1.0).contains(c))
            .unwrap_or(DEFAULT_CONFIDENCE);
        let label_value = env::var("FIXTURE_RECOMMEND_LABEL_VALUE").unwrap_or_default();
        let policy_identifier = env::var("FIXTURE_RECOMMEND_POLICY_IDENT")
            .unwrap_or_else(|_| DEFAULT_POLICY_IDENT.into());
        let model_name = env::var("FIXTURE_MODEL_NAME").unwrap_or_else(|_| DEFAULT_MODEL_NAME.into());
        let model_version =
            env::var("FIXTURE_MODEL_VERSION").unwrap_or_else(|_| DEFAULT_MODEL_VERSION.into());
        let prompt_template_id = env::var("FIXTURE_PROMPT_TEMPLATE_ID")
            .unwrap_or_else(|_| DEFAULT_PROMPT_TEMPLATE_ID.into());
        Self {
            action_kind,
            confidence,
            label_value,
            policy_identifier,
            model_name,
            model_version,
            prompt_template_id,
        }
    }
}

/// The fixture's `Classifier` implementation. Cloning is cheap — the
/// config is owned by value and tonic's server clones it per
/// connection.
#[derive(Debug, Clone)]
struct FixtureClassifier {
    config: FixtureConfig,
}

#[tonic::async_trait]
impl Classifier for FixtureClassifier {
    /// Server-streaming type used by `classify_stream`. Required by
    /// the generated trait; the fixture's `classify_stream`
    /// short-circuits to `unimplemented` so the stream type's value
    /// is never produced.
    type ClassifyStreamStream =
        tokio_stream::wrappers::ReceiverStream<Result<ClassifyResponse, Status>>;

    /// Recommend — the only RPC the fixture implements with a real
    /// payload. Constructs a single [`RecommendedAction`] from the
    /// configured action_kind / confidence / label / cited policy
    /// and echoes the request's `event_id` so the dispatcher's
    /// trace correlation keeps working.
    async fn recommend(
        &self,
        request: Request<RecommendRequest>,
    ) -> Result<Response<RecommendResponse>, Status> {
        let req = request.into_inner();
        tracing::info!(
            event_id = %req.event_id,
            subject_did = %req.subject_did,
            subject_kind = %req.subject_kind,
            incident_id = %req.incident_id,
            "fixture: recommend received",
        );

        let action = RecommendedAction {
            action_kind: self.config.action_kind.clone(),
            label_value: self.config.label_value.clone(),
            // The dispatcher's REQ-S3 floor requires `post` scope for
            // autonomous takedowns; mirror the request's subject_kind
            // so the floor passes when the incoming subject is a post
            // and the canned action is a takedown. For non-takedown
            // kinds the scope is informational.
            subject_scope: req.subject_kind.clone(),
            confidence: self.config.confidence,
            cited_policy_identifiers: vec![self.config.policy_identifier.clone()],
            reasoning: format!(
                "Polaris fixture adapter — canned {kind} recommendation against \
                 the {policy} policy. The fixture does not inspect the case; this \
                 text exists to satisfy the dispatcher's ≥10-char reasoning floor \
                 (REQ-F1) and to make the walkthrough's audit row legible.",
                kind = self.config.action_kind,
                policy = self.config.policy_identifier,
            ),
            caveats: vec![
                "Fixture adapter — recommendation is canned, not model-derived. \
                 Wire a real LLM gRPC adapter before promoting any policy to \
                 autonomous mode in production."
                    .to_owned(),
            ],
        };

        let response = RecommendResponse {
            event_id: req.event_id.clone(),
            model: self.config.model_name.clone(),
            model_version: self.config.model_version.clone(),
            prompt_template_id: self.config.prompt_template_id.clone(),
            recommended_actions: vec![action],
            overall_reasoning: format!(
                "Polaris fixture adapter — canned response for event {event_id}. \
                 See docs/ops/llm-moderation.md for the walkthrough.",
                event_id = req.event_id,
            ),
            // The fixture does no inference so token counts are
            // sentinel zeros. The dispatcher records both fields on
            // the observation evidence regardless.
            input_tokens: 0,
            output_tokens: 0,
        };

        Ok(Response::new(response))
    }

    /// Healthy when the process is up. Polaris's per-classifier
    /// circuit breaker uses this for half-open probes; returning a
    /// success here keeps the breaker `Closed` so `Recommend` calls
    /// reach the fixture.
    async fn health_check(
        &self,
        _request: Request<()>,
    ) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".to_owned(),
            message: Some("polaris llm-fixture-adapter is up; Recommend only".to_owned()),
        }))
    }

    /// `Classify` is not implemented by the fixture. Operators
    /// running this binary alongside the real classifier substrate
    /// should route `Classify` to a separate adapter.
    async fn classify(
        &self,
        _request: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        Err(Status::unimplemented(
            "polaris llm-fixture-adapter is Recommend-only; \
             configure a real classifier for the Classify RPC.",
        ))
    }

    /// `ClassifyStream` is not implemented. Same rationale as
    /// `classify`.
    async fn classify_stream(
        &self,
        _request: Request<Streaming<ClassifyRequest>>,
    ) -> Result<Response<Self::ClassifyStreamStream>, Status> {
        Err(Status::unimplemented(
            "polaris llm-fixture-adapter is Recommend-only; \
             configure a real classifier for the ClassifyStream RPC.",
        ))
    }

    /// `Feedback` is not implemented. The fixture has no model to
    /// teach; an operator wanting to validate the feedback path
    /// should point Polaris at the real classifier adapter (whose
    /// `send_feedback` config is what actually gates this RPC).
    async fn feedback(
        &self,
        _request: Request<FeedbackRequest>,
    ) -> Result<Response<FeedbackResponse>, Status> {
        Err(Status::unimplemented(
            "polaris llm-fixture-adapter is Recommend-only; \
             configure a real classifier for the Feedback RPC.",
        ))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Pretty + env-filter so operators can `RUST_LOG=info` to see
    // every Recommend call without the noise of a debug log.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr: SocketAddr = env::var("FIXTURE_LISTEN_ADDR")
        .unwrap_or_else(|_| DEFAULT_LISTEN_ADDR.to_owned())
        .parse()?;
    let config = FixtureConfig::from_env();
    tracing::info!(
        listen_addr = %addr,
        action_kind = %config.action_kind,
        confidence = config.confidence,
        policy = %config.policy_identifier,
        model = %config.model_name,
        "polaris llm-fixture-adapter starting",
    );

    let service = FixtureClassifier { config };
    Server::builder()
        .add_service(ClassifierServer::new(service))
        .serve_with_shutdown(addr, async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("polaris llm-fixture-adapter: shutdown requested");
        })
        .await?;
    Ok(())
}
