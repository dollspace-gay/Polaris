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
/// ML classifier integration (issue #126 / M5 #45 PR 2 foundational).
///
/// Polaris consumes classifier output via gRPC as another Observation
/// source. NEVER an autonomous actor — a human moderator always takes
/// the action. The fan-out worker, circuit breaker, and opt-in feedback
/// path land in #127, #128, #130 respectively.
pub mod classifier;
pub mod config;
pub mod db;
pub mod evidence;
/// Cross-instance federation (issue #107 / M5 PR 1).
///
/// Subscribes to configured peer instances' ATProto Firehose streams,
/// filters commits to `gay.dollspace.polaris.*` NSIDs, verifies commit
/// signatures, and materialises records into `federation_quarantine`.
pub mod federation;
pub mod ingest;
pub mod labeler;
/// LLM moderation-assist subsystem (issue #231 /
/// `.design/llm-moderation-assist.md`).
pub mod llm;
pub mod middleware;
/// Mobile push-notification subsystem (issue #116 / M5 #44 PR 2).
///
/// APNs / FCM / ntfy.sh dispatchers behind the [`notifications::PushProvider`]
/// trait. Push payloads carry NO PII per AC-8 / REQ-8.
pub mod notifications;
pub mod pattern;
pub mod repo;
pub mod reputation;
pub mod routing;
pub mod scheduled_takedown_worker;
pub mod test_support;
pub mod wellness;
