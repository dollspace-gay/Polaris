//! Pattern detection layer.
//!
//! Consumes normalized events; emits typed [`polaris_types::Observation`]
//! payloads when a cluster crosses configured thresholds. Detectors are
//! stateful (each owns a rolling window) and run inside a single task —
//! they expose `&mut self` methods rather than `Arc<Mutex<...>>`-shared
//! internals.
//!
//! # Detectors in this layer
//!
//! - [`simhash`] (#17) — perceptual-hash brigade detector. Finds groups of
//!   distinct subjects sharing near-identical image content within a
//!   rolling time window.
//! - [`minhash`] (#18) — MinHash + LSH banding for sock-puppet cohort
//!   detection. Finds groups of accounts whose feature sets (creation
//!   timing, posting cadence, reply-graph fingerprints) collide in any LSH
//!   band within a rolling window.
//! - [`anomaly`] (#19) — report-volume z-score banding. Per
//!   `(category, severity)` bucket, a Welford rolling-mean +
//!   sample-variance detector emits when the most recently closed
//!   bucket's count crosses a configurable z-score threshold.
//!
//! # Persistence boundary
//!
//! Detectors **do not** persist observations. They yield typed cluster
//! values via `observe(...) -> Option<...Observation>`. Wiring those
//! values into the [`crate::repo::ObservationRepo`] is the pattern-engine
//! driver's responsibility (a separate integration concern); the detector
//! stays a pure function of `(rolling state, new event) -> emission`.
//!
//! # Error model
//!
//! Detector constructors return [`PatternError`] for configuration that
//! cannot be expressed in the type system (e.g. a hamming threshold that
//! exceeds the hash width). `NonZero*` arguments push the trivial cases
//! into the type system so the error enum stays small.

pub mod anomaly;
pub mod minhash;
pub mod simhash;

/// Errors raised by the pattern-detection layer.
///
/// Detectors validate their configuration at construction time and return
/// a typed error rather than panicking. The variants are intentionally
/// coarse — the per-detector documentation enumerates the conditions that
/// trigger each one. No `anyhow` here: this enum is part of the library's
/// public surface and consumers (the pattern-engine driver, tests) need to
/// `match` on the cause.
#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    /// A configuration value was rejected by the detector — typically a
    /// hamming threshold that exceeds the underlying hash width (64 bits
    /// for the SimHash detector), or a sentinel state that escaped the
    /// `NonZero*` wrappers.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
}
