#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "The RwLock guards an in-memory breaker registry held for the \
              process lifetime. Poisoning means a tokio task panicked while \
              holding the write guard — recovering would mask a programmer \
              bug in a write block that does no .await (per rust-quality §10). \
              .expect with a structured message is the right shape for the \
              poison branch. missing_panics_doc fires on every public method \
              that internally calls .expect on the poison branch; the panic \
              condition is invariant-violation, not a documented runtime case."
)]

//! Circuit breaker state machine — one per configured classifier
//! (issue #128 / M5 #45 PR 4).
//!
//! # States
//!
//! `Closed` → calls allowed.
//! `Open` → calls short-circuited; `classify()` returns
//! [`crate::classifier::ClassifierError::CircuitOpen`] without going to the wire.
//! `HalfOpen` → a single probe call is allowed; on success → `Closed`,
//! on failure → `Open` with a fresh cooldown.
//!
//! # Transitions
//!
//! - `Closed → Open` after `consecutive_failure_threshold`
//!   back-to-back failures (default 10 per AC-5).
//! - `Open → HalfOpen` after `cooldown` elapses (default 60s per AC-5).
//! - `HalfOpen → Closed` on probe success; resets failure counter.
//! - `HalfOpen → Open` on probe failure; restarts cooldown.
//!
//! State lives in memory under an `Arc<RwLock<HashMap<String, CircuitState>>>`;
//! the design notes this can be flushed to a `classifier_health` Postgres
//! table for operator visibility but the v2 baseline keeps it in-process.
//! Operator visibility for the in-memory state lands via the metrics
//! counters in #176.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

/// Operational state of one classifier's circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerVerdict {
    /// Call is allowed; proceed with the wire request.
    Allowed,
    /// Call is allowed AS A PROBE; the breaker is currently
    /// `HalfOpen` and this is the single probe opportunity.
    Probe,
    /// Call is blocked; the breaker is `Open`. Returner should map
    /// to [`crate::classifier::ClassifierError::CircuitOpen`].
    Blocked,
}

/// In-memory state for one classifier.
#[derive(Debug, Clone)]
struct CircuitState {
    consecutive_failures: u32,
    /// `Some(instant)` if state is `Open`; the breaker may transition
    /// to `HalfOpen` after this instant. `None` if `Closed` or `HalfOpen`.
    open_until: Option<Instant>,
    /// `true` if the next allowed call is a probe (state is `HalfOpen`
    /// AND no probe is currently in flight).
    half_open: bool,
}

impl CircuitState {
    const fn closed() -> Self {
        Self {
            consecutive_failures: 0,
            open_until: None,
            half_open: false,
        }
    }
}

/// Configuration for the breaker behaviour.
#[derive(Debug, Clone, Copy)]
pub struct BreakerConfig {
    /// How many consecutive failures trip the breaker from `Closed`
    /// to `Open`. Default 10 per AC-5.
    pub consecutive_failure_threshold: u32,
    /// How long the breaker stays `Open` before transitioning to
    /// `HalfOpen`. Default 60 seconds per AC-5.
    pub cooldown: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            consecutive_failure_threshold: 10,
            cooldown: Duration::from_secs(60),
        }
    }
}

/// Shared breaker registry — one logical entry per classifier name.
#[derive(Debug, Clone, Default)]
pub struct BreakerRegistry {
    inner: Arc<RwLock<HashMap<String, CircuitState>>>,
    config: BreakerConfig,
}

impl BreakerRegistry {
    /// Construct with custom configuration.
    #[must_use]
    pub fn with_config(config: BreakerConfig) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Construct with [`BreakerConfig::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consult the breaker for `classifier`. Use the wall-clock `now`
    /// the caller provides so tests can drive deterministic timing.
    ///
    /// State transitions caused by this call:
    /// - If `Open` and `now >= open_until` → transitions to `HalfOpen`
    ///   and returns [`BreakerVerdict::Probe`].
    /// - If `HalfOpen` and a probe was already issued → returns
    ///   [`BreakerVerdict::Blocked`] until the probe result arrives.
    /// - If `Closed` → returns [`BreakerVerdict::Allowed`].
    pub fn check(&self, classifier: &str, now: Instant) -> BreakerVerdict {
        let mut guard = self
            .inner
            .write()
            .expect("breaker RwLock poisoned — task panicked while holding write guard");
        let state = guard
            .entry(classifier.to_owned())
            .or_insert_with(CircuitState::closed);

        if let Some(until) = state.open_until {
            if now < until {
                return BreakerVerdict::Blocked;
            }
            // Cooldown elapsed → transition Open → HalfOpen and grant
            // a probe.
            state.open_until = None;
            state.half_open = true;
            info!(
                classifier,
                "circuit breaker cooldown elapsed; entering HalfOpen for probe",
            );
            return BreakerVerdict::Probe;
        }

        if state.half_open {
            // A probe is already in flight; further calls are blocked
            // until the probe result resolves the state.
            return BreakerVerdict::Blocked;
        }

        BreakerVerdict::Allowed
    }

    /// Record a successful call. Resets the consecutive-failure
    /// counter; if the call was a probe, transitions `HalfOpen` → `Closed`.
    pub fn record_success(&self, classifier: &str) {
        let mut guard = self
            .inner
            .write()
            .expect("breaker RwLock poisoned — task panicked while holding write guard");
        let state = guard
            .entry(classifier.to_owned())
            .or_insert_with(CircuitState::closed);
        let was_half_open = state.half_open;
        state.consecutive_failures = 0;
        state.half_open = false;
        state.open_until = None;
        if was_half_open {
            info!(classifier, "circuit breaker probe succeeded; Closed");
        }
    }

    /// Record a failed call. Increments the consecutive-failure
    /// counter; if the threshold is crossed (or a probe failed),
    /// transitions to `Open` with a fresh cooldown.
    pub fn record_failure(&self, classifier: &str, now: Instant) {
        let mut guard = self
            .inner
            .write()
            .expect("breaker RwLock poisoned — task panicked while holding write guard");
        let state = guard
            .entry(classifier.to_owned())
            .or_insert_with(CircuitState::closed);

        if state.half_open {
            // Probe failed — restart cooldown immediately.
            state.half_open = false;
            state.open_until = Some(now + self.config.cooldown);
            warn!(
                classifier,
                cooldown_secs = self.config.cooldown.as_secs(),
                "circuit breaker probe failed; Open with fresh cooldown",
            );
            return;
        }

        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.config.consecutive_failure_threshold {
            state.open_until = Some(now + self.config.cooldown);
            state.consecutive_failures = 0;
            warn!(
                classifier,
                threshold = self.config.consecutive_failure_threshold,
                cooldown_secs = self.config.cooldown.as_secs(),
                "circuit breaker consecutive-failure threshold exceeded; Open",
            );
        } else {
            debug!(
                classifier,
                consecutive_failures = state.consecutive_failures,
                "circuit breaker recorded failure",
            );
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    fn fast_config() -> BreakerConfig {
        BreakerConfig {
            consecutive_failure_threshold: 3,
            cooldown: Duration::from_secs(10),
        }
    }

    #[test]
    fn closed_breaker_allows_calls() {
        let reg = BreakerRegistry::with_config(fast_config());
        let now = Instant::now();
        assert_eq!(reg.check("x", now), BreakerVerdict::Allowed);
    }

    #[test]
    fn threshold_failures_open_the_breaker() {
        let reg = BreakerRegistry::with_config(fast_config());
        let t0 = Instant::now();
        for _ in 0..3 {
            reg.record_failure("x", t0);
        }
        // Now Open — call rejected.
        assert_eq!(reg.check("x", t0), BreakerVerdict::Blocked);
    }

    #[test]
    fn open_breaker_transitions_to_half_open_after_cooldown() {
        let reg = BreakerRegistry::with_config(fast_config());
        let t0 = Instant::now();
        for _ in 0..3 {
            reg.record_failure("x", t0);
        }
        // Just before cooldown elapses → still blocked.
        let t_before = t0 + Duration::from_secs(9);
        assert_eq!(reg.check("x", t_before), BreakerVerdict::Blocked);
        // After cooldown elapses → probe granted.
        let t_after = t0 + Duration::from_secs(11);
        assert_eq!(reg.check("x", t_after), BreakerVerdict::Probe);
    }

    #[test]
    fn half_open_blocks_additional_calls_until_probe_resolves() {
        let reg = BreakerRegistry::with_config(fast_config());
        let t0 = Instant::now();
        for _ in 0..3 {
            reg.record_failure("x", t0);
        }
        let t_after = t0 + Duration::from_secs(11);
        // First check grants the probe.
        assert_eq!(reg.check("x", t_after), BreakerVerdict::Probe);
        // Second check blocks until the probe resolves.
        assert_eq!(reg.check("x", t_after), BreakerVerdict::Blocked);
    }

    #[test]
    fn probe_success_closes_the_breaker() {
        let reg = BreakerRegistry::with_config(fast_config());
        let t0 = Instant::now();
        for _ in 0..3 {
            reg.record_failure("x", t0);
        }
        let t_after = t0 + Duration::from_secs(11);
        assert_eq!(reg.check("x", t_after), BreakerVerdict::Probe);
        reg.record_success("x");
        // Back to Allowed.
        assert_eq!(reg.check("x", t_after), BreakerVerdict::Allowed);
    }

    #[test]
    fn probe_failure_restarts_cooldown() {
        let reg = BreakerRegistry::with_config(fast_config());
        let t0 = Instant::now();
        for _ in 0..3 {
            reg.record_failure("x", t0);
        }
        let t_after = t0 + Duration::from_secs(11);
        assert_eq!(reg.check("x", t_after), BreakerVerdict::Probe);
        // Probe fails → Open again with fresh cooldown.
        reg.record_failure("x", t_after);
        // Still blocked just after probe failure.
        assert_eq!(reg.check("x", t_after), BreakerVerdict::Blocked);
        // Still blocked at original cooldown moment (because probe
        // failure reset the clock).
        let t_check = t_after + Duration::from_secs(9);
        assert_eq!(reg.check("x", t_check), BreakerVerdict::Blocked);
    }

    #[test]
    fn success_in_closed_state_resets_failure_counter() {
        let reg = BreakerRegistry::with_config(fast_config());
        let t0 = Instant::now();
        reg.record_failure("x", t0);
        reg.record_failure("x", t0);
        reg.record_success("x"); // reset counter
        // Two more failures don't trip yet (counter went 0 → 1 → 2).
        reg.record_failure("x", t0);
        reg.record_failure("x", t0);
        assert_eq!(reg.check("x", t0), BreakerVerdict::Allowed);
        // Third failure trips.
        reg.record_failure("x", t0);
        assert_eq!(reg.check("x", t0), BreakerVerdict::Blocked);
    }

    #[test]
    fn distinct_classifiers_have_independent_state() {
        let reg = BreakerRegistry::with_config(fast_config());
        let t0 = Instant::now();
        for _ in 0..3 {
            reg.record_failure("alpha", t0);
        }
        assert_eq!(reg.check("alpha", t0), BreakerVerdict::Blocked);
        assert_eq!(reg.check("beta", t0), BreakerVerdict::Allowed);
    }
}
