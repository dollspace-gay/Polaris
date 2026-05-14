//! HTTP middleware.
//!
//! Submodules host individual `tower::Layer` / `axum::middleware::from_fn`
//! implementations. The cookie-driven auth extractor lives in [`auth`].

pub mod auth;
