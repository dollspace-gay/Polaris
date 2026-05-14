//! `GET /healthz` — liveness + database reachability probe.
//!
//! Semantics:
//!
//! - `200 OK` with `{"status":"ok","db":"ok"}` when the pool can hand out a
//!   connection.
//! - `503 Service Unavailable` with `{"status":"degraded","db":"error: …"}`
//!   when [`Db::ping`] fails.
//!
//! The endpoint deliberately runs **no SQL** — it only verifies pool health.
//! Once #13 lands the first business query, a sibling `/readyz` endpoint may
//! be introduced for schema-aware readiness.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::db::Db;

/// Handler for `GET /healthz`.
///
/// Returns `(StatusCode, Json<serde_json::Value>)` — Axum implements
/// `IntoResponse` for that tuple, so this composes cleanly with the rest of
/// the framework without bespoke response types.
pub async fn handler(State(db): State<Db>) -> impl IntoResponse {
    match db.ping().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "db": "ok",
            })),
        ),
        Err(err) => {
            tracing::warn!(error = %err, "healthz: database ping failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({
                    "status": "degraded",
                    "db": format!("error: {err}"),
                })),
            )
        }
    }
}
