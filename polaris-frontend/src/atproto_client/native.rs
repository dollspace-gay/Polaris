//! Native (`reqwest`-backed) public-ATProto client.
//!
//! proto-blue's umbrella `Cargo.toml` selects the `fetch-reqwest` feature
//! on this target automatically, so [`proto_blue::xrpc::XrpcClient::new`]
//! produces a reqwest-driven client without any further wiring.

#![cfg(not(target_arch = "wasm32"))]

use proto_blue::api::app::bsky::actor::get_profile;
use proto_blue::syntax::AtIdentifier;
use proto_blue::xrpc::XrpcClient;

use super::{AtprotoError, DEFAULT_APPVIEW, PublicAtprotoClient, PublicProfile};

/// Native impl of [`PublicAtprotoClient`].
///
/// Holds the configured XRPC client. The AppView URL is captured at
/// construction; subsequent calls reuse the underlying `reqwest::Client`
/// connection pool.
#[derive(Clone)]
pub struct NativePublicAtprotoClient {
    inner: XrpcClient,
}

impl NativePublicAtprotoClient {
    /// Construct a client pointed at the configured AppView.
    ///
    /// Use [`Self::default`] to point at the public Bluesky AppView
    /// (`https://api.bsky.app`).
    pub fn new(appview: &str) -> Result<Self, AtprotoError> {
        let inner = XrpcClient::new(appview).map_err(|e| AtprotoError::Transport(e.to_string()))?;
        Ok(Self { inner })
    }
}

impl NativePublicAtprotoClient {
    /// Construct a client pointed at the public Bluesky AppView
    /// ([`DEFAULT_APPVIEW`]).
    ///
    /// `Default` is intentionally not implemented: construction is
    /// fallible (URL parse) and the trait's contract is infallible, so a
    /// dedicated constructor keeps error handling explicit at call sites.
    pub fn with_default_appview() -> Result<Self, AtprotoError> {
        Self::new(DEFAULT_APPVIEW)
    }
}

impl PublicAtprotoClient for NativePublicAtprotoClient {
    async fn get_profile(&self, actor: &str) -> Result<PublicProfile, AtprotoError> {
        let actor =
            AtIdentifier::new(actor).map_err(|e| AtprotoError::InvalidActor(e.to_string()))?;
        let params = get_profile::Params { actor };
        let output = get_profile::call(&self.inner, Some(&params), None)
            .await
            .map_err(map_call_error)?;
        Ok(PublicProfile {
            did: output.did.to_string(),
            handle: output.handle.to_string(),
            display_name: output.display_name,
        })
    }
}

fn map_call_error(err: get_profile::CallError) -> AtprotoError {
    match err {
        get_profile::CallError::Xrpc(x) => AtprotoError::Xrpc(x.to_string()),
        get_profile::CallError::Transport(t) => AtprotoError::Transport(t.to_string()),
        get_profile::CallError::Json(j) => AtprotoError::Transport(j.to_string()),
    }
}
