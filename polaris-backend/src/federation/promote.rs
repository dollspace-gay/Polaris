//! Federation quarantine → escalation promotion worker (issue #108 / M5 PR 2).
//!
//! This module scans `federation_quarantine` for rows whose `signature_status`
//! is `'verified'` and promotes them into `federation_escalations` via
//! [`crate::repo::federation::materialize_from_quarantine`].
//!
//! # Cancel safety
//!
//! The worker uses `tokio::select!` with a `CancellationToken` to race the
//! promotion tick against a shutdown signal. Inside a tick, each quarantine row
//! is promoted inside its own `sqlx::Transaction`; a mid-tick cancellation
//! (drop of the `select!` future) cannot double-write because:
//!
//! 1. `select!` in `biased` mode checks cancellation **before** the tick.
//! 2. The promotion transaction is either committed (row deleted from quarantine)
//!    or rolled back (row stays, will be retried on the next restart).
//! 3. The `ON CONFLICT (original_cid) DO NOTHING` in
//!    [`materialize_from_quarantine`] makes retries idempotent — even if the
//!    tx committed and the DELETE did not yet fire, the next pass is a no-op.
//!
//! # Tick interval
//!
//! The interval is configured via [`PromoteConfig::interval_secs`], defaulting
//! to 10 seconds. Operators can tune it via the
//! `POLARIS_FEDERATION_PROMOTE_INTERVAL_SECS` environment variable (set in
//! `FederationConfig::promote` in `config.rs` — out of scope for this PR;
//! the default value is hardcoded here for now).
//!
//! # Error handling
//!
//! Per-row failures are logged at `WARN` and skipped; they do not abort the
//! worker. A DB-level failure to fetch the batch is logged at `ERROR` and the
//! tick is skipped (the worker retries on the next interval).

use std::time::Duration;

use sqlx::PgPool;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, info_span, warn};

use crate::repo::federation::{self as fed_repo, MaterializeOutcome};

// ── constants ─────────────────────────────────────────────────────────────

/// Default promotion interval.
const DEFAULT_INTERVAL_SECS: u64 = 10;

/// Maximum rows to promote in a single tick (prevents a single tick from
/// monopolising the connection pool on a large backlog).
const BATCH_SIZE: i64 = 50;

// ── public entry point ────────────────────────────────────────────────────

/// Spawn the promotion worker as a background Tokio task.
///
/// The returned `JoinHandle` resolves when `cancel` fires or the worker
/// encounters an unrecoverable error.
///
/// # Cancel safety
///
/// Safe to drop mid-tick: the underlying transaction is either committed
/// (idempotent next-tick) or rolled back (quarantine row untouched).
#[must_use]
pub fn spawn_promote_worker(pool: PgPool, cancel: CancellationToken) -> tokio::task::JoinHandle<()> {
    spawn_promote_worker_with_interval(pool, cancel, DEFAULT_INTERVAL_SECS)
}

/// Spawn with an explicit interval (primarily for tests).
#[must_use]
pub fn spawn_promote_worker_with_interval(
    pool: PgPool,
    cancel: CancellationToken,
    interval_secs: u64,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_promote_worker(pool, cancel, Duration::from_secs(interval_secs)).await;
    })
}

// ── worker loop ───────────────────────────────────────────────────────────

/// Drive the promotion loop until cancelled.
async fn run_promote_worker(pool: PgPool, cancel: CancellationToken, interval: Duration) {
    info!("federation promotion worker starting");

    let mut ticker = tokio::time::interval(interval);
    // The first tick fires immediately; consume it so the first real tick
    // waits the full interval (gives the rest of startup time to settle).
    ticker.tick().await;

    loop {
        // ── biased select: check cancel BEFORE the next tick ─────────────
        // This prevents the worker from starting a new batch after shutdown
        // has been requested.
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                info!("federation promotion worker cancelled; shutting down");
                return;
            }
            _ = ticker.tick() => {}
        }

        run_promote_tick(&pool).await;
    }
}

/// Execute one promotion pass: fetch a batch, materialise each row.
async fn run_promote_tick(pool: &PgPool) {
    // Note: we do NOT use `.entered()` here because the guard is not `Send`
    // across `.await` points. Instead we instrument individual sub-operations.
    let _span = info_span!("federation_promote_tick");

    // Fetch a batch of verified, un-promoted CIDs.
    // Using untyped sqlx::query to avoid the cargo-sqlx-prepare requirement
    // for new tables (consistent with PR 1's federation ingest pattern).
    let cids: Vec<String> = match sqlx::query(
        "SELECT cid \
         FROM   federation_quarantine \
         WHERE  signature_status = 'verified' \
         ORDER  BY received_at ASC \
         LIMIT  $1",
    )
    .bind(BATCH_SIZE)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => {
            use sqlx::Row as _;
            rows.into_iter()
                .filter_map(|r| r.try_get::<String, _>("cid").ok())
                .collect()
        }
        Err(err) => {
            error!(
                error = ?err,
                "failed to fetch quarantine batch; skipping tick",
            );
            return;
        }
    };

    if cids.is_empty() {
        return;
    }

    info!(count = cids.len(), "promoting quarantine batch");

    for cid in &cids {
        promote_one(pool, cid).await;
    }
}

/// Promote a single quarantine row inside its own transaction.
///
/// A failure logs at `WARN` and returns. The quarantine row is left intact
/// for the next tick.
async fn promote_one(pool: &PgPool, cid: &str) {
    let result = async {
        let mut tx = pool.begin().await?;
        let outcome = fed_repo::materialize_from_quarantine(&mut tx, cid).await?;
        tx.commit().await?;
        Ok::<MaterializeOutcome, fed_repo::FederationRepoError>(outcome)
    }
    .await;

    match result {
        Ok(MaterializeOutcome::Created { escalation_id }) => {
            info_span!(
                "federation_materialize",
                cid = %cid,
                escalation_id = %escalation_id,
            )
            .in_scope(|| {
                info!("promoted quarantine row to escalation");
            });
        }
        Ok(MaterializeOutcome::AlreadyMaterialized { escalation_id }) => {
            info!(
                cid = %cid,
                escalation_id = %escalation_id,
                "quarantine row already materialised; skipping",
            );
        }
        Err(fed_repo::FederationRepoError::QuarantineNotFound { .. }) => {
            // Race condition: another worker promoted this row between our
            // SELECT and the materialise call. Treat as success.
            info!(cid = %cid, "quarantine row gone before promotion (race); skipping");
        }
        Err(err) => {
            warn!(
                cid = %cid,
                error = ?err,
                "failed to promote quarantine row; will retry on next tick",
            );
        }
    }
}

// ── unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code — rust-quality §7"
)]
mod tests {
    use super::*;

    /// Verify the promotion worker exits quickly when cancelled before the
    /// first real tick.
    #[tokio::test]
    async fn worker_exits_on_cancel() {
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/nonexistent").unwrap();
        let cancel = CancellationToken::new();

        // Use a very long interval so the test does not block on a real tick.
        let handle =
            spawn_promote_worker_with_interval(pool, cancel.clone(), 3600);

        // Cancel immediately.
        cancel.cancel();

        // The handle must resolve without timeout.
        handle.await.unwrap();
    }
}
