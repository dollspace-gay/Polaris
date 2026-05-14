//! Frontend error types.
//!
//! [`FrontendError`] is the umbrella error the UI layer renders against.
//! It wraps the two transport-level error types that the client modules
//! own:
//!
//! - [`ApiError`](crate::api_client::ApiError) — Polaris first-party HTTP
//!   API failures (network, deserialisation, non-2xx response).
//! - [`AtprotoError`](crate::atproto_client::AtprotoError) — public-ATProto
//!   XRPC failures surfaced by `proto-blue`.
//!
//! Both variants are wired as `#[source]` so the cause chain is preserved
//! when rendered into an `<ErrorBoundary/>` or logged via `tracing`.

use crate::api_client::ApiError;
use crate::atproto_client::AtprotoError;

/// Umbrella error for anything the frontend can fail at.
///
/// The variants are intentionally narrow — each transport owns its own
/// detailed error enum (`ApiError`, `AtprotoError`) and this type only
/// arbitrates between them at view-render sites.
#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    /// Polaris first-party API call failed.
    #[error("Polaris API request failed")]
    Api(#[source] ApiError),
    /// Public-ATProto XRPC call failed.
    #[error("ATProto request failed")]
    Atproto(#[source] AtprotoError),
}

impl From<ApiError> for FrontendError {
    fn from(err: ApiError) -> Self {
        Self::Api(err)
    }
}

impl From<AtprotoError> for FrontendError {
    fn from(err: AtprotoError) -> Self {
        Self::Atproto(err)
    }
}
