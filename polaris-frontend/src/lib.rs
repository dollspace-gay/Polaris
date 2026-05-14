//! Polaris frontend library.
//!
//! Leptos application compiled to WASM for the moderation dashboard. The
//! same source tree builds for `cfg(target_arch = "wasm32")` (browser
//! bundle, produced by Trunk) and for native targets (tests, IDE checks,
//! workspace tooling) — the public surface is identical on both.
//!
//! ## Architecture
//!
//! Two HTTP clients carve up the surface:
//!
//! - [`PublicAtprotoClient`](crate::atproto_client::PublicAtprotoClient)
//!   reads *public* ATProto data (profiles, public posts, public blobs)
//!   directly from the configured AppView via `proto-blue`'s
//!   [`XrpcClient`](proto_blue::xrpc::XrpcClient). No Polaris session is
//!   involved — these reads work logged-out.
//! - [`PolarisApiClient`](crate::api_client::PolarisApiClient) reaches
//!   the Axum backend at `/api/*` and `/healthz` for everything Polaris
//!   owns (incidents, actions, audit log, etc.). It carries the Polaris
//!   session cookie via `credentials: "include"` on wasm and a cookie
//!   jar on native.
//!
//! Each client trait has two impls — `wasm.rs` (browser fetch / gloo-net)
//! and `native.rs` (reqwest). The `#[cfg(target_arch = "wasm32")]`
//! gating lives at the module boundary; route and component code is
//! target-agnostic.
//!
//! ## Boundary enforcement
//!
//! AC-7 of `.design/polaris-proto-blue-integration.md` requires that no
//! mutating Polaris endpoint be reachable via XRPC — only through
//! `PolarisApiClient`. Issue #11 wires this as a `cargo xtask
//! check-frontend-boundary` grep; this crate's responsibility is to keep
//! the layout that makes that check tractable.
//!
//! ## Entry point
//!
//! The browser entry point lives in `main.rs`; it sets the
//! `console_error_panic_hook` and calls
//! [`leptos::mount::mount_to_body`] on [`App`]. Native builds compile
//! the same crate as an `rlib` so `cargo check` and IDE tooling work
//! without a wasm toolchain.

pub mod api_client;
pub mod app;
pub mod atproto_client;
pub mod components;
pub mod error;
pub mod pages;
pub mod routes;

pub use app::App;
pub use error::FrontendError;
