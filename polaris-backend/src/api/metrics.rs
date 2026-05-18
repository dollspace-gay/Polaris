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
//! Hand-emitted via `metrics::counter!` / `metrics::gauge!` at the
//! relevant code sites (one site per series):
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
