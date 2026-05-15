//! Serve the operator's OAuth client metadata JSON at `/oauth/client-metadata.json` (#81).
//!
//! ATProto OAuth requires the `client_id` URL to return the
//! client-metadata document. The operator hosts this file at the path
//! their `client_id` declares (commonly `/oauth/client-metadata.json` on
//! their public domain). For self-contained deployments — where Polaris
//! is the only public process — this handler serves the file Polaris
//! reads at startup, so the same `polaris.toml` line drives both the
//! ATProto-OAuth verifier and the public document.
//!
//! The path is fixed at `/oauth/client-metadata.json` to match the
//! `client_id` value most operators choose. Operators that prefer a
//! different path can host the file behind their reverse proxy and
//! point `client_id` there; this route stays as a no-op default.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use polaris_types::oauth_config::ClientMetadata;
use serde_json::Value;
use tracing::warn;

/// Cached client-metadata payload.
///
/// Loaded at startup from the path the operator configured under
/// `[auth.atproto] client_metadata_path` and exposed read-only here.
/// `None` means the operator hasn't enabled the ATProto backend (or
/// hasn't pointed the loader at a real file); the handler returns 404
/// so callers can distinguish "Polaris is up" from "Polaris is up *and*
/// has OAuth client metadata."
#[derive(Debug, Clone, Default)]
pub struct ClientMetadataState {
    payload: Option<Arc<Value>>,
}

impl ClientMetadataState {
    /// Construct the cache from a loaded `ClientMetadata`. The metadata
    /// is serialised once at startup so each request avoids
    /// re-serialisation cost.
    #[must_use]
    pub fn from_metadata(metadata: &ClientMetadata) -> Self {
        match serde_json::to_value(metadata) {
            Ok(v) => Self {
                payload: Some(Arc::new(v)),
            },
            Err(err) => {
                warn!(?err, "failed to serialise ClientMetadata at startup");
                Self::default()
            }
        }
    }

    /// Empty cache — the handler returns 404 until [`Self::from_metadata`]
    /// installs a payload.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Inspect the cached payload without cloning.
    #[must_use]
    pub fn payload(&self) -> Option<Arc<Value>> {
        self.payload.clone()
    }
}

/// `GET /oauth/client-metadata.json` handler.
///
/// Returns the cached client-metadata JSON when configured, 404 with a
/// plain-text body otherwise. The handler is intentionally unauthed —
/// the AS that calls it has no Polaris session.
#[allow(
    clippy::unused_async,
    reason = "axum route handlers must be async even when the body is purely synchronous"
)]
pub async fn serve(State(state): State<ClientMetadataState>) -> impl IntoResponse {
    match state.payload() {
        Some(payload) => Json((*payload).clone()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "OAuth client metadata not configured on this Polaris instance",
        )
            .into_response(),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic per rust-quality §7"
)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_has_no_payload() {
        let s = ClientMetadataState::empty();
        assert!(s.payload().is_none());
    }

    #[test]
    fn from_metadata_caches_serialised_value() {
        let metadata: ClientMetadata = serde_json::from_value(serde_json::json!({
            "client_id": "https://example.com/oauth/client-metadata.json",
            "application_type": "web",
            "grant_types": ["authorization_code"],
            "scope": "atproto",
            "response_types": ["code"],
            "redirect_uris": ["https://example.com/auth/atproto/callback"],
            "token_endpoint_auth_method": "none",
            "dpop_bound_access_tokens": true,
        }))
        .unwrap();
        let s = ClientMetadataState::from_metadata(&metadata);
        let payload = s.payload().expect("payload populated");
        assert_eq!(
            payload["client_id"],
            "https://example.com/oauth/client-metadata.json"
        );
    }
}
