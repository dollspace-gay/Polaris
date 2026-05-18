//! `GET /metrics` — Prometheus text-exposition endpoint (REQ-D2 / AC-D2).
//!
//! The recorder is installed once at binary startup via
//! [`metrics_exporter_prometheus::PrometheusBuilder::install_recorder`]
//! (NOT `.install()`, which spawns its own HTTP server — wrong shape
//! for our layered router). The returned [`PrometheusHandle`] is
//! threaded onto [`crate::api::state::ApiState::metrics_handle`]; this
//! handler renders the handle's text-format output verbatim.
//!
//! # Surface
//!
//! Automatic (from `axum-prometheus`'s tower layer applied to the
//! merged router in `main.rs`):
//!
//! - `axum_http_requests_total{method,endpoint,status}` counter
//! - `axum_http_requests_duration_seconds{method,endpoint,status}` histogram
//! - `axum_http_requests_pending{method,endpoint}` gauge
//!
//! Hand-emitted via `metrics::counter!` / `metrics::gauge!` /
//! `metrics::histogram!` at the relevant code sites (one site per
//! series):
//!
//! - `polaris_actions_total{kind}` — `cases::submit_action`
//! - `polaris_labels_emitted_total{val,neg}` — `LabelEmitter::emit`
//! - `polaris_subscribe_labels_subscribers` —
//!   `labeler::server::run_subscription` (gauge ±1 on
//!   connect/disconnect)
//! - `polaris_plc_operations_total{status}` —
//!   `setup::submit_plc_operation`
//! - `polaris_setup_wizard_steps_total{step,status}` — every
//!   `setup::*` handler
//!
//! # LLM moderation-assist series (REQ-I1 — issue #241 / LLM-12)
//!
//! Seven Prometheus series cover the LLM dispatcher and its safety
//! floors. Stable label vocabulary — operators write Grafana alerts
//! off these names, so renaming breaks dashboards.
//!
//! - `polaris_llm_recommend_total{model, policy, kind}` — counter.
//!   Bumped once per [`RecommendedAction`] the dispatcher routes.
//!   Emitted from
//!   [`crate::llm::recommend_dispatcher::RecommendDispatcher::route_recommended_action`].
//! - `polaris_llm_recommend_duration_seconds{model}` — histogram of
//!   classifier-recommend RPC latency. Emitted around the
//!   `ClassifierClient::recommend` call site in
//!   [`crate::llm::recommend_dispatcher::RecommendDispatcher::dispatch_case_inner`].
//! - `polaris_llm_recommend_confidence{policy, kind}` — histogram of
//!   per-recommendation confidence. Emitted alongside
//!   `polaris_llm_recommend_total`.
//! - `polaris_llm_autonomous_action_total{policy, kind}` — counter.
//!   Bumped after a successful autonomous-mode action insert.
//!   Emitted from
//!   [`crate::llm::recommend_dispatcher::RecommendDispatcher::route_recommended_action`].
//! - `polaris_llm_autonomous_reversal_total{policy, kind}` — counter.
//!   Bumped by [`crate::api::reversal::reverse_action`] when the
//!   reversal targets an `actor_kind = 'autonomous_agent'` row.
//!   Ratio of this counter to `polaris_llm_autonomous_action_total`
//!   is the agent's per-policy misfire rate.
//! - `polaris_llm_safety_floor_tripped_total{policy, floor}` —
//!   counter of *evaluations* per floor (both pass and fail bump
//!   the same series; the rate-of-trip is computed by the operator
//!   as a fraction). Floor labels: `confidence | kind_gate |
//!   account_takedown_block | cooldown | rate_limit |
//!   circuit_breaker | global_pause | csam_block`. Emitted from
//!   [`crate::llm::safety_floors::evaluate`].
//! - `polaris_llm_assisted_queue_depth{policy}` — gauge. Sampled
//!   every 30 s by
//!   [`crate::llm::recommend_dispatcher::spawn_assisted_queue_depth_sampler`]
//!   (started from the binary entrypoint).
//!
//! [`RecommendedAction`]: polaris_classifier_proto::v1::RecommendedAction
//!
//! # Authorization
//!
//! `/metrics` is mounted on the **public** subtree (alongside
//! `/healthz` and `/readyz`) so a Prometheus scrape job does not need
//! a moderator session. Operators who want to gate scraping by IP do
//! it at the ingress / mesh layer; the handler itself trusts the
//! reverse proxy.

use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;

use crate::api::state::ApiState;

/// Content-type Prometheus servers (and Grafana scrape jobs) expect
/// when fetching a `text` exposition target. The `version=0.0.4`
/// suffix is the canonical Prometheus text-format version; clients
/// fall back to the default mapping when it's absent but we send it
/// explicitly so a strict parser does not warn.
const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Handler for `GET /metrics`. Renders the recorder handle's
/// Prometheus text-format output. Returns `503 Service Unavailable`
/// (with an empty body) when the handle is `None` — that posture
/// indicates the binary was built without metrics wired (production
/// paths always install the handle; only a slim integration test
/// would leave it unset).
pub async fn handler(State(state): State<ApiState>) -> impl IntoResponse {
    let Some(handle) = state.metrics_handle.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)],
            String::new(),
        );
    };
    let body = handle.render();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)],
        body,
    )
}
