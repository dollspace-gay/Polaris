//! Dynamic supervisor for per-labeler subscribeLabels consumers.
//!
//! `crate::ingest::labeler_discovery` writes newly-discovered labelers
//! into `upstream_labelers`. The case-view's local index is only
//! useful if there is a live consumer per enabled row pumping that
//! labeler's firehose into `indexed_labels`. This supervisor keeps
//! that invariant.
//!
//! # Lifecycle
//!
//! On startup the supervisor loads every `upstream_labelers WHERE
//! enabled = TRUE` row and spawns one [`UpstreamLabelerConsumer::run`]
//! task per row. After that it owns a single
//! [`tokio::sync::Notify`] handle shared with the discovery worker:
//!
//! - **Wake on Notify** → the discovery worker just inserted a new
//!   row; rescan the table, diff against the in-memory map of
//!   running tasks, spawn for any new rows.
//! - **Wake on periodic tick** → catches operator-driven changes
//!   that bypassed the Notify (manual SQL, admin UI), and reaps
//!   exited tasks (a consumer that gave up after exhausting its
//!   reconnect budget should NOT silently stay missing).
//! - **Wake on cancellation** → propagate to every child task via
//!   the cloned `CancellationToken` so process shutdown completes
//!   in bounded time.
//!
//! # Why a separate task vs. spawn-on-INSERT in the discovery worker
//!
//! Decoupling lets manual `upstream_labelers` writes (the admin
//! surface, operator SQL, integration tests) also get a consumer
//! spawned, without coupling those code paths to the discovery
//! worker. The supervisor is the single authority for
//! "every enabled row has exactly one consumer task".

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ingest::upstream_labels::{
    self, UpstreamKeyCache, UpstreamLabelerConfig, UpstreamLabelerConsumer,
};
use crate::repo::PgObservationRepo;

/// Tick interval for the supervisor's periodic reconciliation pass.
///
/// Bounded so a row inserted via admin SQL (without firing the
/// discovery `Notify`) still gets its consumer spawned within a
/// minute. Notify-driven wakes happen in milliseconds for the
/// common case.
const RECONCILE_TICK: Duration = Duration::from_secs(60);

/// Run the supervisor for the process lifetime.
///
/// `pool` is the shared Postgres pool. `key_cache` is the shared
/// upstream-key cache (one cache for the whole supervisor; per-task
/// `Arc` clones are cheap). `notify` is the handle the discovery
/// worker fires whenever it inserts a row. `cancel` propagates
/// SIGINT to every spawned consumer.
///
/// Returns when `cancel` is fired. Always reaps in-flight children
/// before returning.
pub async fn run(
    pool: PgPool,
    key_cache: Arc<UpstreamKeyCache>,
    notify: Arc<Notify>,
    cancel: CancellationToken,
) {
    // Map from upstream DID → JoinHandle of the consumer task.
    // We use a plain HashMap (no Mutex): the supervisor task owns
    // this map by value; no other task accesses it.
    let mut running: HashMap<String, JoinHandle<()>> = HashMap::new();

    tracing::info!("labeler supervisor starting; performing initial reconciliation");
    reconcile(&pool, &key_cache, &mut running, &cancel).await;

    loop {
        // Wait for any of: notify, periodic tick, or cancellation.
        // `Notify::notified()` is documented cancel-safe.
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::info!(
                    consumer_count = running.len(),
                    "supervisor cancelled; consumers will shut down via shared CancellationToken",
                );
                // The children share `cancel`, so they're already
                // unwinding. Join them to bound shutdown time.
                for (did, handle) in running.drain() {
                    if let Err(err) = handle.await {
                        tracing::warn!(
                            upstream = %did,
                            error = %err,
                            "consumer task join error during shutdown",
                        );
                    }
                }
                return;
            }
            () = notify.notified() => {
                tracing::debug!("supervisor woke on discovery notify");
            }
            () = tokio::time::sleep(RECONCILE_TICK) => {
                tracing::trace!("supervisor woke on periodic tick");
            }
        }

        reconcile(&pool, &key_cache, &mut running, &cancel).await;
    }
}

/// One reconciliation pass: load enabled rows, prune the running
/// map (reap finished handles + abort consumers whose row has
/// become dormant), then spawn consumers for any eligible DID not
/// currently in the running map.
///
/// Prune step rationale (issue #200): `load_enabled_upstreams`
/// already filters out `dormant_until > now()` rows, so the
/// supervisor sees only eligible DIDs in `configs`. Before this
/// fix, consumers for newly-dormant labelers continued running
/// (each carrying a `WebSocketKeepAlive` with a ~20-attempt
/// reconnect budget against a NXDOMAIN host), generating a
/// sustained DNS storm that starved the backfill worker.
/// We now actively abort any handle in `running` whose DID is
/// no longer in the eligible set; the consumer's select loop is
/// cancel-safe and `JoinHandle::abort` is the canonical drop.
/// Finished handles are reaped in the same pass so the
/// `contains_key` check below correctly treats them as gone and
/// respawns when dormancy lifts.
async fn reconcile(
    pool: &PgPool,
    key_cache: &Arc<UpstreamKeyCache>,
    running: &mut HashMap<String, JoinHandle<()>>,
    cancel: &CancellationToken,
) {
    // `load_enabled_upstreams` already filters out rows whose
    // `dormant_until > now()` — see its docstring. The supervisor
    // therefore relies on the SELECT predicate as the single point
    // of truth for "is this row eligible to be spawned right now".
    // Rows that are dormant simply do not appear in `configs`; on
    // the next reconcile pass after the dormancy expires they will
    // re-appear and a fresh consumer will spawn.
    let configs = match upstream_labels::load_enabled_upstreams(pool).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "supervisor reconcile: failed to load upstream_labelers; will retry next tick",
            );
            return;
        }
    };

    // Build the eligible-DID set BEFORE pruning so the same view
    // of "what should be running" drives both the abort step and
    // the spawn step.
    let eligible: HashSet<&str> = configs.iter().map(|c| c.did.as_str()).collect();

    // Reap finished handles first (order matters: a handle may be
    // both finished AND not in the eligible set, in which case the
    // reap-then-skip path is cheaper than aborting a dead future),
    // then abort consumers whose row is no longer eligible.
    let reaped = reap_finished(running);
    let aborted = prune_running(running, &eligible);

    // Companion read: count rows that ARE dormant right now so an
    // operator looking at the structured log envelope can see how
    // much of the labeler set is currently parked. This is a single
    // SELECT COUNT on the indexed predicate, so the cost stays in
    // the millisecond range even for the full ~300-row table.
    let dormant_count = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) AS "count!"
        FROM upstream_labelers
        WHERE enabled = TRUE
          AND dormant_until IS NOT NULL
          AND dormant_until > now()
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0_i64);

    let mut spawned = 0_usize;
    for cfg in configs {
        if running.contains_key(&cfg.did) {
            continue;
        }
        let handle = spawn_one(pool.clone(), Arc::clone(key_cache), &cfg, cancel.clone());
        running.insert(cfg.did.clone(), handle);
        spawned = spawned.saturating_add(1);
    }
    if spawned > 0 || aborted > 0 || reaped > 0 || dormant_count > 0 {
        tracing::info!(
            spawned,
            aborted,
            reaped,
            running = running.len(),
            dormant = dormant_count,
            "supervisor reconcile",
        );
    }
}

/// Drop any [`JoinHandle`] entries whose task has already
/// completed. Returns the number of entries removed.
///
/// Separated from [`prune_running`] so the abort path doesn't
/// fire on already-finished tasks (cheaper, and keeps the
/// `aborted` log field a faithful count of *new* cancels).
fn reap_finished(running: &mut HashMap<String, JoinHandle<()>>) -> usize {
    let before = running.len();
    running.retain(|did, handle| {
        if handle.is_finished() {
            tracing::warn!(
                upstream = %did,
                "consumer task exited; will respawn on next reconcile if still eligible",
            );
            false
        } else {
            true
        }
    });
    before.saturating_sub(running.len())
}

/// Abort and remove every entry in `running` whose DID is NOT in
/// `eligible`. Returns the number of aborts performed.
///
/// This is the supervisor's enforcement of "every dormant row has
/// zero live consumers": [`upstream_labels::load_enabled_upstreams`]
/// drops dormant rows from `configs`, so any DID present in
/// `running` but absent from the eligible set has either gone
/// dormant or been disabled and should be torn down.
///
/// [`JoinHandle::abort`] is fire-and-forget; we deliberately do
/// not `.await` it. The consumer's own select loop observes the
/// abort via the future-dropping path, which is cancel-safe by
/// construction.
fn prune_running(running: &mut HashMap<String, JoinHandle<()>>, eligible: &HashSet<&str>) -> usize {
    let mut aborted = 0_usize;
    running.retain(|did, handle| {
        if eligible.contains(did.as_str()) {
            true
        } else {
            tracing::info!(
                upstream = %did,
                "aborting consumer for dormant/disabled labeler",
            );
            handle.abort();
            aborted = aborted.saturating_add(1);
            false
        }
    });
    aborted
}

/// Spawn a single consumer task and return its `JoinHandle`.
///
/// The task logs its own clean exit / failure; the supervisor only
/// needs the handle to detect completion and to abort during
/// shutdown via the shared `CancellationToken`.
fn spawn_one(
    pool: PgPool,
    key_cache: Arc<UpstreamKeyCache>,
    cfg: &UpstreamLabelerConfig,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    let observations = Arc::new(PgObservationRepo::new(pool.clone()));
    let consumer = UpstreamLabelerConsumer::new(cfg.clone(), pool, observations, key_cache);
    let did = cfg.did.clone();
    let hostname = cfg.hostname.clone();
    tracing::info!(did = %did, hostname = %hostname, "supervisor spawning consumer");
    tokio::spawn(async move {
        match consumer.run(cancel).await {
            Ok(()) => tracing::info!(upstream = %did, "consumer exited cleanly"),
            Err(err) => tracing::warn!(
                upstream = %did,
                error = %err,
                "consumer exited with error; supervisor will respawn on next reconcile",
            ),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{prune_running, reap_finished};
    use std::collections::{HashMap, HashSet};
    use std::future;
    use tokio::task::JoinHandle;

    /// Spawn a never-resolving task so the returned handle stays
    /// "live" until something aborts it. `future::pending::<()>()`
    /// never returns and is the standard test idiom for a handle
    /// the test fully controls the lifetime of.
    fn spawn_live() -> JoinHandle<()> {
        tokio::spawn(future::pending::<()>())
    }

    #[tokio::test]
    async fn prune_running_aborts_dids_absent_from_eligible_set() {
        // Locks issue #200's invariant: a consumer whose row has
        // gone dormant (and therefore disappeared from the eligible
        // set returned by `load_enabled_upstreams`) must be aborted
        // AND removed from the running map on the next reconcile.
        let mut running: HashMap<String, JoinHandle<()>> = HashMap::new();
        let alive = spawn_live();
        let dormant = spawn_live();
        running.insert("did:plc:alive".to_string(), alive);
        running.insert("did:plc:dormant".to_string(), dormant);

        let eligible: HashSet<&str> = ["did:plc:alive"].into_iter().collect();
        let aborted = prune_running(&mut running, &eligible);

        assert_eq!(aborted, 1, "exactly one DID was outside the eligible set");
        assert!(
            running.contains_key("did:plc:alive"),
            "eligible DID must remain",
        );
        assert!(
            !running.contains_key("did:plc:dormant"),
            "dormant DID must be removed from the running map",
        );

        // After abort, the underlying task should reach a finished
        // state. Yield a few times so the scheduler can observe the
        // cancel; the runtime is single-threaded by default for
        // `#[tokio::test]`, so cooperative yielding suffices.
        for _ in 0..16 {
            tokio::task::yield_now().await;
            if running.get("did:plc:alive").map(JoinHandle::is_finished) != Some(false) {
                break;
            }
        }
        assert!(
            !running["did:plc:alive"].is_finished(),
            "eligible task must not have been aborted",
        );
    }

    #[tokio::test]
    async fn reap_finished_drops_completed_handles_only() {
        // Companion locking: a handle whose task has exited (clean
        // shutdown, panic, or prior abort) must be removed so the
        // `contains_key` guard in `reconcile` does not falsely treat
        // a dead DID as "still running" and skip respawn.
        let mut running: HashMap<String, JoinHandle<()>> = HashMap::new();
        let alive = spawn_live();
        let dead = tokio::spawn(async {}); // resolves immediately
        running.insert("did:plc:alive".to_string(), alive);
        running.insert("did:plc:dead".to_string(), dead);

        // Yield until the immediate task is observably finished.
        for _ in 0..16 {
            tokio::task::yield_now().await;
            if running["did:plc:dead"].is_finished() {
                break;
            }
        }
        assert!(
            running["did:plc:dead"].is_finished(),
            "test precondition: dead task must report finished",
        );

        let reaped = reap_finished(&mut running);
        assert_eq!(reaped, 1);
        assert!(running.contains_key("did:plc:alive"));
        assert!(!running.contains_key("did:plc:dead"));
    }
}
