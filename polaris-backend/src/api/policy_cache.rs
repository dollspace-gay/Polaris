//! Per-process LRU-ish cache in front of
//! [`mod_policies::current_by_identifier`] (REQ-B4).
//!
//! The action-create handler hits this on every cited identifier. A
//! deployment with a few dozen policies and bursty action throughput
//! would otherwise issue one round-trip per cited identifier on every
//! submission — the workbook does not change often, so caching the
//! current row for a short TTL keeps the hot path off the network.
//!
//! # Design
//!
//! - Backing store: `tokio::sync::RwLock<HashMap<identifier,
//!   (ModPolicy, Instant)>>`. The `lru` crate is not a workspace dep
//!   today; the design doc allows a hand-rolled cache for the 60 s TTL
//!   and a small key space.
//! - TTL: 60 seconds (REQ-B4). On a stale hit the cache treats the entry
//!   as missing, re-reads, and updates the slot.
//! - Soft size bound: [`MAX_ENTRIES`] keeps the map from growing
//!   unboundedly across a long-lived process serving many identifiers.
//!   When the map reaches the bound, the oldest entry (lowest
//!   `inserted_at`) is evicted. This is an O(N) sweep against a tiny
//!   bound, which is cheaper than threading a real LRU through a
//!   `Mutex` and matches the spec's "keep it simple, no new deps"
//!   instruction.
//! - Read path is `RwLock::read` for the fast hit; a stale or missing
//!   entry escalates to `RwLock::write` for the refresh. Writers do not
//!   re-fetch under lock — the DB call runs without holding the
//!   `RwLock` so concurrent readers of other identifiers are never
//!   blocked.
//!
//! # Invalidation
//!
//! No explicit invalidation API is exposed from this module — the
//! workbook's amend / pause / resume / retire paths run through the
//! admin REST surface (WB-3), and a 60-second tail on a stale read is
//! acceptable per the design doc. If a future code-path needs to bust
//! the cache deterministically, expose an `invalidate(identifier)` here
//! and call it from the writers.
//!
//! # Concurrency
//!
//! All public functions are `async` and acquire the lock via
//! `tokio::sync::RwLock` so the cache is safe to share across
//! `axum` request handlers. The wrapper is `Clone`-friendly because
//! the lock lives behind an `Arc<_>` inside [`PolicyCache::shared`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::repo::mod_policies::{self, ModPolicy, ModPolicyError};

/// Per-entry TTL. Stale hits trigger a re-read.
const TTL: Duration = Duration::from_secs(60);

/// Soft cap on the number of identifiers tracked. Eviction is "drop the
/// oldest" — see the module doc-comment for the rationale on the bound
/// and the eviction strategy.
const MAX_ENTRIES: usize = 256;

/// A cached `(policy, inserted_at)` pair.
#[derive(Debug, Clone)]
struct Entry {
    policy: ModPolicy,
    inserted_at: Instant,
}

/// The cache state, behind an `Arc` so cloning is cheap.
type Inner = Arc<RwLock<HashMap<String, Entry>>>;

/// Module-local singleton. The `OnceLock` is process-wide; tests that
/// need an isolated cache build their own [`PolicyCache`] via
/// [`PolicyCache::new`].
fn shared() -> &'static Inner {
    static SHARED: std::sync::OnceLock<Inner> = std::sync::OnceLock::new();
    SHARED.get_or_init(|| Arc::new(RwLock::new(HashMap::new())))
}

/// Look up the current `mod_policies` row for `identifier`, hitting the
/// process-wide LRU-ish cache when possible.
///
/// On a cache hit younger than [`TTL`], returns the cached value
/// without touching the database. On a miss or stale hit, calls
/// [`mod_policies::current_by_identifier`] and stores the result.
///
/// `Ok(None)` is **not** cached — an unknown identifier today may be
/// created tomorrow, and the action-create path that surfaces
/// `Ok(None)` as `400 unknown_policy_ref` would otherwise misclassify
/// post-create attempts for the duration of the TTL.
///
/// # Errors
///
/// Returns the underlying [`ModPolicyError`] verbatim on DB failure.
///
/// # Example
///
/// ```ignore
/// let current = policy_cache::get_current(&pool, "polaris.spam").await?;
/// if let Some(policy) = current {
///     // snapshot policy.version into the citation insert
/// }
/// ```
pub async fn get_current(
    pool: &PgPool,
    identifier: &str,
) -> Result<Option<ModPolicy>, ModPolicyError> {
    // Fast path: shared read lock, fresh entry.
    if let Some(policy) = read_fresh(shared(), identifier).await {
        return Ok(Some(policy));
    }
    // Slow path: miss or stale. Read from DB without holding the lock,
    // then upsert.
    let fetched = mod_policies::current_by_identifier(pool, identifier).await?;
    if let Some(ref policy) = fetched {
        write_entry(shared(), identifier, policy.clone()).await;
    }
    Ok(fetched)
}

/// Read-only handle bound to a private cache instance. Test helpers
/// construct one of these to avoid leaking state into the shared
/// singleton.
#[derive(Debug, Clone, Default)]
pub struct PolicyCache {
    inner: Inner,
}

impl PolicyCache {
    /// Build an empty cache. Tests use this so their per-test state is
    /// not visible to other tests in the same process.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Read-through lookup against this cache (not the process-wide
    /// singleton). Mirrors [`get_current`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`ModPolicyError`] verbatim on DB failure.
    pub async fn get_current(
        &self,
        pool: &PgPool,
        identifier: &str,
    ) -> Result<Option<ModPolicy>, ModPolicyError> {
        if let Some(policy) = read_fresh(&self.inner, identifier).await {
            return Ok(Some(policy));
        }
        let fetched = mod_policies::current_by_identifier(pool, identifier).await?;
        if let Some(ref policy) = fetched {
            write_entry(&self.inner, identifier, policy.clone()).await;
        }
        Ok(fetched)
    }
}

/// Fast-path helper: return the entry if it's present AND not yet
/// expired. The lock is released on return.
async fn read_fresh(cache: &Inner, identifier: &str) -> Option<ModPolicy> {
    let guard = cache.read().await;
    let entry = guard.get(identifier)?;
    if entry.inserted_at.elapsed() < TTL {
        Some(entry.policy.clone())
    } else {
        None
    }
}

/// Slow-path helper: upsert the freshly-fetched policy, evicting the
/// oldest entry if the map is at the soft cap.
async fn write_entry(cache: &Inner, identifier: &str, policy: ModPolicy) {
    let mut guard = cache.write().await;
    if guard.len() >= MAX_ENTRIES && !guard.contains_key(identifier) {
        // Find the oldest entry by `inserted_at`. The key we evict is
        // computed before the actual remove so we don't hold two
        // borrows on the map.
        let victim_key = guard
            .iter()
            .min_by_key(|(_, e)| e.inserted_at)
            .map(|(k, _)| k.clone());
        if let Some(k) = victim_key {
            guard.remove(&k);
        }
    }
    guard.insert(
        identifier.to_owned(),
        Entry {
            policy,
            inserted_at: Instant::now(),
        },
    );
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    /// A `ModPolicy` fixture for cache-shape tests that don't need DB
    /// integration. The DB-backed path is exercised by the
    /// `policy_version_pinning` integration suite.
    fn fixture(identifier: &str, version: i32) -> ModPolicy {
        ModPolicy {
            id: uuid::Uuid::new_v4(),
            identifier: identifier.to_owned(),
            version,
            name: "name".to_owned(),
            description: "description".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "criteria long enough to satisfy the DB check on workbook rows."
                .to_owned(),
            examples_positive: serde_json::json!([]),
            examples_negative: serde_json::json!([]),
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "manual".to_owned(),
            autonomous_action_kinds: vec![],
            autonomous_confidence_threshold: 0.9,
            assisted_confidence_threshold: 0.7,
            autonomous_paused_until: None,
            is_retired: false,
            created_at: chrono::Utc::now(),
            created_by_moderator_id: uuid::Uuid::new_v4(),
            effective_from: chrono::Utc::now(),
            effective_until: None,
            supersedes_id: None,
            change_summary: None,
        }
    }

    #[tokio::test]
    async fn fresh_entry_round_trips() {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        write_entry(&cache, "polaris.spam", fixture("polaris.spam", 1)).await;
        let hit = read_fresh(&cache, "polaris.spam").await.unwrap();
        assert_eq!(hit.identifier, "polaris.spam");
        assert_eq!(hit.version, 1);
    }

    #[tokio::test]
    async fn missing_entry_returns_none() {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        assert!(read_fresh(&cache, "polaris.spam").await.is_none());
    }

    #[tokio::test]
    async fn evicts_oldest_when_over_soft_cap() {
        // Seed MAX_ENTRIES + 1 distinct identifiers; the first one
        // inserted should fall out.
        let cache = Arc::new(RwLock::new(HashMap::new()));
        for i in 0..=MAX_ENTRIES {
            write_entry(
                &cache,
                &format!("polaris.{i}"),
                fixture(&format!("polaris.{i}"), 1),
            )
            .await;
            // Force the inserted_at to differ so the min_by_key sort
            // is deterministic even on coarse-clock machines.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let guard = cache.read().await;
        assert_eq!(guard.len(), MAX_ENTRIES);
        assert!(
            !guard.contains_key("polaris.0"),
            "oldest insert (polaris.0) must have been evicted; keys = {:?}",
            guard.keys().collect::<Vec<_>>()
        );
    }
}
