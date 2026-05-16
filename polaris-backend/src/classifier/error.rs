//! Error type for the [`crate::classifier::ClassifierClient`] trait
//! (issue #126 / M5 #45 PR 2).
//!
//! All fallible operations on the trait return `Result<_, ClassifierError>`.
//! The variants are intentionally narrow so per-classifier counters
//! (introduced in #128 / PR 4 — circuit breaker) can dispatch on the
//! shape of failure without parsing free-text messages.

use thiserror::Error;

/// Error type for classifier client operations.
///
/// Carries enough structured context that the circuit-breaker logic
/// (#128 / PR 4) can decide whether the failure is "the classifier
/// hiccupped, retry" vs "the classifier is unreachable, short-circuit
/// for cooldown."
#[derive(Debug, Error)]
pub enum ClassifierError {
    /// The per-call timeout (default 500 ms; operator-configurable per
    /// classifier in #128 / PR 4) elapsed before the classifier
    /// returned a response.
    ///
    /// Treated by the circuit breaker as a transient failure, contributing
    /// to the consecutive-failure counter.
    #[error("classifier `{classifier}` exceeded the per-call timeout")]
    Timeout {
        /// Operator-allocated classifier name (matches
        /// `[[classifiers.<name>]]` in `polaris.toml`).
        classifier: String,
    },

    /// The classifier reached the per-classifier semaphore's capacity
    /// limit and refused the call rather than queuing in-memory.
    ///
    /// Bounded-concurrency primitive — prevents a misbehaving classifier
    /// from piling up in-flight requests on the polaris-backend side.
    /// AC-4 / AC-5 of the epic.
    #[error("classifier `{classifier}` rate-limited at the semaphore boundary")]
    RateLimited {
        /// Operator-allocated classifier name.
        classifier: String,
    },

    /// The classifier RPC returned a transport-level error (TLS,
    /// connection refused, HTTP/2 frame issue, etc.).
    ///
    /// Wraps the underlying [`tonic::Status`] for diagnostic chaining;
    /// the breaker treats any [`tonic::Status`] as a failure regardless
    /// of the inner code.
    #[error("classifier transport error: {0}")]
    Transport(#[from] tonic::Status),

    /// The classifier returned a response that doesn't satisfy the
    /// wire-shape contract (e.g. empty `labels` vec when the proto
    /// requires at least one, malformed model identifier).
    ///
    /// Treated as a classifier-side bug rather than a transient
    /// failure; the breaker counts it but operator-visible alerting
    /// in #176 surfaces it specifically.
    #[error("classifier `{classifier}` returned malformed response: {reason}")]
    BadResponse {
        /// Operator-allocated classifier name.
        classifier: String,
        /// Human-readable explanation of what was malformed.
        reason: String,
    },

    /// The circuit breaker is open for this classifier; no call was
    /// attempted.
    ///
    /// The promoter / fan-out worker in #127 catches this variant
    /// distinctly so it doesn't increment the consecutive-failure
    /// counter (the call never went out — there's nothing to retry).
    #[error("classifier `{classifier}` circuit breaker is open")]
    CircuitOpen {
        /// Operator-allocated classifier name.
        classifier: String,
    },
}
