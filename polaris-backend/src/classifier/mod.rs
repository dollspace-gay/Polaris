//! ML classifier integration (issue #126 / M5 #45 PR 2 — foundational).
//!
//! Polaris consumes classifier output as another `Observation` source.
//! Classifier output is NEVER an autonomous actor — a human moderator
//! always takes the action. This module provides the gRPC client surface;
//! the fan-out worker (#127 PR 3), the circuit breaker (#128 PR 4), and
//! the opt-in feedback path (#130 PR 6) build on top.
//!
//! # Architecture
//!
//! - [`client::ClassifierClient`] — the trait. `async_trait`-derived so
//!   both the production tonic-backed impl and the in-memory fixture
//!   impl satisfy the same shape.
//! - [`client::TonicClassifierClient`] — production. Wraps a tonic
//!   channel. Per-call timeout applied via `tokio::time::timeout`.
//! - [`client::FixtureClassifierClient`] — test harness. Returns
//!   pre-baked responses; captures feedback calls so tests can assert
//!   the AC-7 privacy-boundary invariant.
//! - [`error::ClassifierError`] — structured failure variants the
//!   circuit breaker dispatches on.

pub mod budget;
pub mod circuit;
pub mod client;
pub mod error;
pub mod fanout;
pub mod feedback;

pub use budget::{BudgetRegistry, DEFAULT_MAX_IN_FLIGHT};
pub use circuit::{BreakerConfig, BreakerRegistry, BreakerVerdict};
pub use client::{
    ClassifierClient, DEFAULT_RECOMMEND_TIMEOUT, FixtureClassifierClient, TonicClassifierClient,
};
pub use error::ClassifierError;
pub use fanout::{ClassifierFanout, ClassifyEvent, ConfiguredClassifier};
pub use feedback::{action_kind_wire_string, build_feedback, spawn_feedback};
