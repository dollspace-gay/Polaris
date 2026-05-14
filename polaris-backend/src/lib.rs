//! Polaris backend library.
//!
//! This crate provides the Axum HTTP server, ATProto labeler endpoint
//! (`com.atproto.label.subscribeLabels` / `queryLabels`), firehose ingest
//! workers, label signing and emission, evidence preservation, and moderator
//! authentication (OIDC and ATProto OAuth).
//!
//! The library target exists so that integration tests in `tests/` can import
//! internal modules without duplicating the binary. The binary (`src/main.rs`)
//! is a thin entrypoint that delegates to functions defined here.
//!
//! # Module layout
//!
//! - [`config`] — typed configuration, env loading, defaults.
//! - [`db`] — Postgres pool + migrations + ping primitive.
//! - [`api`] — Axum router and HTTP handlers.
//! - [`auth`] — moderator authentication: OIDC, sessions, refresh-token
//!   encryption.
//! - [`middleware`] — Axum middleware (cookie-driven auth extractor).
//! - [`ingest`] — ATProto firehose ingest worker (#12); replay-safe cursor
//!   persistence and bounded outbound channel.
//! - [`bus`] — event-bus abstraction (#16) with Kafka and NATS backends
//!   selected by Cargo feature; design.md §3.1 dual-profile architecture.
//! - [`pattern`] — stateful pattern detectors (#17 SimHash, #18 MinHash,
//!   #19 anomaly bands). Each detector owns a rolling window and emits
//!   typed cluster values; persistence into [`repo`] is wired by the
//!   pattern-engine driver, not by the detectors themselves.
//! - [`repo`] — typed sqlx-checked repository layer for §4 entities
//!   (Subject, Incident, Action, Report, Observation).
//! - [`routing`] — incident → moderator triage routing engine (#22). Pure
//!   rule cascade in `routing::route`; I/O wrapper in `routing::service`.
//! - [`wellness`] — per-moderator exposure tracking (#23). `record` +
//!   `status_for_me` + `remaining_budget` + consent-gated
//!   `aggregate_for_manager`, all behind a single [`wellness::exposure::ExposureTracker`].

pub mod api;
pub mod audit;
pub mod auth;
pub mod bus;
pub mod config;
pub mod db;
pub mod evidence;
pub mod ingest;
pub mod labeler;
pub mod middleware;
pub mod pattern;
pub mod repo;
pub mod reputation;
pub mod routing;
pub mod wellness;
