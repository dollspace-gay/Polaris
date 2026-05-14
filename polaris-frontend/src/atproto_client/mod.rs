//! Public-ATProto read client.
//!
//! Backed by `proto-blue`'s `XrpcClient`, this module reads strictly
//! *public* ATProto data (profiles, posts, blobs) directly from the
//! AppView. Per `.design/polaris-proto-blue-integration.md` §D, no
//! Polaris-owned state ever flows through this client — all moderator-
//! visible private state lives behind [`PolarisApiClient`].
//!
//! Transport selection is identical to [`crate::api_client`]:
//!
//! - `wasm32-unknown-unknown` → `gloo-net`-driven XRPC client.
//! - native → `reqwest`-driven XRPC client.
//!
//! proto-blue's own `Cargo.toml` has target-conditional dependency tables
//! that pick the right fetcher automatically; calling
//! [`proto_blue::xrpc::XrpcClient::new`] gives us the correct transport
//! per target with no further wiring.
//!
//! [`PolarisApiClient`]: crate::api_client::PolarisApiClient

use serde::{Deserialize, Serialize};

// See `crate::api_client` for the rationale: target conditionals live as
// `#![cfg(...)]` inner attributes at the top of each impl file, not on
// the `pub mod` declarations here. Avoids `clippy::duplicated_attributes`
// while keeping the gate at the module boundary.
pub mod native;
pub mod wasm;

#[cfg(not(target_arch = "wasm32"))]
pub use native::NativePublicAtprotoClient;
#[cfg(target_arch = "wasm32")]
pub use wasm::WasmPublicAtprotoClient;

/// Default AppView the read client points at when the operator has not
/// overridden it. `https://api.bsky.app` is the public Bluesky AppView —
/// every public PDS read resolves through it without authentication.
pub const DEFAULT_APPVIEW: &str = "https://api.bsky.app";

/// Trait every public-ATProto client implementation satisfies.
///
/// Restricted to `getProfile` for issue #10 — the canonical smoke. Later
/// issues extend the surface as the UI exercises more public reads.
#[allow(async_fn_in_trait)] // CSR-only frontend, no Send-bound auto-trait need.
pub trait PublicAtprotoClient {
    /// Fetch a [`PublicProfile`] for the given actor identifier.
    ///
    /// `actor` may be a DID (`did:plc:…`, `did:web:…`) or a handle
    /// (`alice.bsky.social`). proto-blue's `AtIdentifier::new` validates
    /// the shape before the request is sent.
    async fn get_profile(&self, actor: &str) -> Result<PublicProfile, AtprotoError>;
}

/// Strongly-typed slice of `app.bsky.actor.defs::ProfileViewDetailed`.
///
/// Only the fields the Polaris UI actually renders are exposed; the full
/// proto-blue type carries ~20 additional optional fields that would
/// inflate the wasm bundle without paying off in the dashboard view.
/// New fields are added here as new surfaces exercise them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicProfile {
    /// Stable decentralised identifier (`did:plc:…` etc.).
    pub did: String,
    /// Current handle. May change over the account's lifetime; the DID is
    /// the stable identity.
    pub handle: String,
    /// Optional display name set by the account holder.
    pub display_name: Option<String>,
}

/// Errors a public-ATProto call can produce.
///
/// Mirrors [`crate::api_client::ApiError`]'s shape so callers can switch
/// on either transport's variant without learning a different error
/// vocabulary per client.
#[derive(Debug, thiserror::Error)]
pub enum AtprotoError {
    /// Underlying XRPC transport failure (network, TLS, body framing).
    #[error("transport error: {0}")]
    Transport(String),
    /// Identifier validation rejected the actor argument.
    #[error("invalid actor identifier: {0}")]
    InvalidActor(String),
    /// XRPC server returned a structured error.
    #[error("XRPC error: {0}")]
    Xrpc(String),
}
