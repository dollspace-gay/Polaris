#![allow(
    clippy::expect_used,
    clippy::missing_panics_doc,
    reason = "Same justification as circuit.rs: the Mutex guards an in-memory \
              registry; poisoning means a task panicked while holding the \
              lock — a programmer bug, not a runtime condition to recover from. \
              missing_panics_doc fires on the public methods that internally \
              .expect the poison branch."
)]

//! Per-classifier bounded-concurrency budget (issue #128 / M5 #45 PR 4).
//!
//! Each configured classifier holds a `tokio::sync::Semaphore` with a
//! cap (default 64). A misbehaving classifier accepting events faster
//! than it can process gets rate-limited at this boundary rather than
//! piling up in-memory or in-bus.
//!
//! The fan-out worker (#127) integrates by acquiring a permit before
//! each `classify()` call; failure to acquire within a brief grace
//! window maps to [`crate::classifier::ClassifierError::RateLimited`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{Semaphore, SemaphorePermit, TryAcquireError};

/// Default semaphore size — 64 in-flight classifier calls per
/// classifier. Tunable via `[[classifiers.<name>]] max_in_flight`.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// Registry of per-classifier concurrency budgets.
///
/// Cheap to clone (interior `Arc<Mutex<HashMap<...>>>` over the
/// per-classifier `Arc<Semaphore>`s).
#[derive(Debug, Clone, Default)]
pub struct BudgetRegistry {
    inner: Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
}

impl BudgetRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create the semaphore for `classifier` with `max_in_flight`
    /// permits.
    ///
    /// Subsequent calls return the same `Arc<Semaphore>`; the
    /// `max_in_flight` parameter is ignored after first registration
    /// (config is read once at startup).
    #[must_use]
    pub fn semaphore(&self, classifier: &str, max_in_flight: usize) -> Arc<Semaphore> {
        let mut guard = self
            .inner
            .lock()
            .expect("budget Mutex poisoned — task panicked while holding lock");
        Arc::clone(
            guard
                .entry(classifier.to_owned())
                .or_insert_with(|| Arc::new(Semaphore::new(max_in_flight))),
        )
    }

    /// Try to acquire a permit synchronously. Returns
    /// [`TryAcquireError::NoPermits`] if all permits are checked out.
    ///
    /// The fan-out worker uses this — if the budget is exhausted, the
    /// event is dropped (logged) rather than queued, because queueing
    /// on a slow classifier is the failure mode the budget exists to
    /// prevent.
    ///
    /// The returned permit is bound to the borrowed semaphore; the
    /// caller holds it for the duration of the classifier RPC. Per
    /// rust-quality §10: the permit is dropped on the borrowed
    /// semaphore guard — no `MutexGuard` escapes the borrow.
    pub fn try_acquire<'a>(
        &self,
        classifier: &str,
        max_in_flight: usize,
        semaphore_handle: &'a Arc<Semaphore>,
    ) -> Result<SemaphorePermit<'a>, TryAcquireError> {
        // Ensure the registry entry exists for future lookups.
        let _ = self.semaphore(classifier, max_in_flight);
        semaphore_handle.try_acquire()
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

    #[test]
    fn default_max_in_flight_is_64() {
        assert_eq!(DEFAULT_MAX_IN_FLIGHT, 64);
    }

    #[tokio::test]
    async fn semaphore_persists_across_calls() {
        let reg = BudgetRegistry::new();
        let s1 = reg.semaphore("alpha", 4);
        let s2 = reg.semaphore("alpha", 8);
        // Same Arc — second call's max_in_flight is ignored.
        assert!(Arc::ptr_eq(&s1, &s2));
        assert_eq!(s1.available_permits(), 4);
    }

    #[tokio::test]
    async fn distinct_classifiers_have_distinct_semaphores() {
        let reg = BudgetRegistry::new();
        let alpha = reg.semaphore("alpha", 4);
        let beta = reg.semaphore("beta", 8);
        assert!(!Arc::ptr_eq(&alpha, &beta));
        assert_eq!(alpha.available_permits(), 4);
        assert_eq!(beta.available_permits(), 8);
    }

    #[tokio::test]
    async fn try_acquire_blocks_at_capacity() {
        let reg = BudgetRegistry::new();
        let sem = reg.semaphore("alpha", 2);

        let p1 = sem.try_acquire();
        let p2 = sem.try_acquire();
        assert!(p1.is_ok());
        assert!(p2.is_ok());

        // Third try at-capacity → NoPermits.
        let p3 = sem.try_acquire();
        assert!(matches!(p3, Err(TryAcquireError::NoPermits)));

        // Dropping p1 returns a permit; next try_acquire succeeds.
        drop(p1);
        let p4 = sem.try_acquire();
        assert!(p4.is_ok());
    }
}
