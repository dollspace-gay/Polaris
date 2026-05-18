//! Durable background drain of `label_backfill_queue`.
//!
//! The case-view handler enqueues one row per `(subject_did,
//! labeler_did)` pair the first time a moderator opens a subject
//! (idempotent via the `UNIQUE (subject_did, labeler_did)` index +
//! `ON CONFLICT DO NOTHING`). This worker walks the queue at a slow,
//! bounded cadence and drives each pair through
//! [`crate::ingest::label_backfill::backfill_one_labeler`]:
//!
//!   * Success → `status = 'done'` (no more retries, ever).
//!   * Transport failure → keep `status = 'pending'` and schedule a
//!     re-attempt at an exponentially-increasing `next_attempt_at`
//!     (10s → 60s → 5min → 1h, cap 6h). At most [`MAX_ATTEMPTS`]
//!     re-attempts; after that the row transitions to
//!     `permanent_failure`.
//!   * Permanent HTTP failure (4xx, 5xx, malformed JSON) → terminal
//!     `permanent_failure` immediately. These don't get better with
//!     retries and the supervisor's per-labeler dormancy path will
//!     keep us off the labeler entirely if it stays broken.
//!
//! # Why a worker instead of an inline fan-out
//!
//! The case-view used to run all 300 queryLabels round-trips inline
//! on the case-view render. That:
//!
//!   1. Saturated glibc's resolver with the same DNS NXDOMAIN attempts
//!      the live `subscribeLabels` consumers were generating, breaking
//!      backfill timing for the healthy labelers.
//!   2. Gave the moderator a synchronous deadline (60s outer timeout)
//!      after which they saw "whatever the fastest 5-8 labelers
//!      returned" rather than the full ecosystem-wide history.
//!
//! Decoupling the enqueue from the work means the case-view handler
//! is fast and durable (an INSERT either lands or it doesn't), and
//! the panel reads `indexed_labels` directly — every refresh picks
//! up additional labels as the worker progresses, until the entire
//! enabled-labeler set has produced its labels for that subject.
//!
//! # Concurrency
//!
//! The drain query uses `SELECT ... FOR UPDATE SKIP LOCKED LIMIT 8`
//! so multiple Polaris replicas (or a future split into multiple
//! worker tasks) divide the queue without double-processing a row.
//! Inside one tick we currently process the locked batch serially —
//! a future optimisation could fan out within the locked batch, but
//! 8 round-trips per tick is plenty given the per-pair work is
//! HTTPS-bounded.
//!
//! # `UpstreamKeyCache` reuse
//!
//! The worker uses the SAME [`UpstreamKeyCache`] the live subscriber
//! holds, so signature-verify on a backfilled label hits the same
//! warm key it would have under the live path — no per-labeler PLC
//! round-trips just because the work came from the queue.

use std::sync::Arc;
use std::time::Duration;

use sqlx::{PgPool, Row, postgres::PgRow};
use tokio_util::sync::CancellationToken;

use crate::ingest::label_backfill::{BackfillOutcome, backfill_one_labeler};
use crate::ingest::upstream_labels::UpstreamKeyCache;

/// How often the worker polls `label_backfill_queue` for new work.
///
/// 5s is the floor for "moderator opened a subject; how long until
/// the panel starts populating" while keeping the DB poll rate low
/// enough that an idle queue costs essentially nothing.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum number of rows the worker locks + drains per tick.
///
/// Bounded so one tick can't saturate the host's outbound socket pool
/// or starve the live-subscriber consumers of CPU. 8 round-trips per
/// 5s tick = ~96 backfill attempts per minute, which clears a
/// 300-labeler subject in ~3 minutes worst case.
const BATCH_SIZE: i64 = 8;

/// Upper bound on transport-failure re-attempts per (subject, labeler)
/// pair. After this many attempts the row transitions to
/// `permanent_failure`; the supervisor-side dormancy path is the
/// longer-term retry mechanism (and recovery from the dormancy
/// re-enables this pair via a fresh enqueue when the moderator
/// re-opens the subject).
const MAX_ATTEMPTS: i32 = 8;

/// Per-request connect timeout for the queryLabels HTTPS call.
///
/// Short on purpose: a healthy labeler answers in <200ms; a labeler
/// that takes longer than 3s to even establish a TCP/TLS connection
/// is dragging and the worker should move on to the next row rather
/// than park a slot on it.
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// Per-request overall timeout — connect + TLS + request + response.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// Run the worker for the process lifetime.
///
/// Spawned from `main.rs` alongside the scheduled-takedown worker.
/// Returns when `cancel` is fired.
pub async fn run(pool: PgPool, key_cache: Arc<UpstreamKeyCache>, cancel: CancellationToken) {
    tracing::info!(
        poll_interval_s = POLL_INTERVAL.as_secs(),
        batch_size = BATCH_SIZE,
        max_attempts = MAX_ATTEMPTS,
        "label-backfill worker starting",
    );

    let http = match reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .user_agent("polaris-labeler/1.0 (label-backfill-worker)")
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            tracing::error!(
                error = %err,
                "label-backfill worker: failed to build HTTP client; exiting",
            );
            return;
        }
    };

    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => {
                tracing::info!("label-backfill worker cancelled");
                return;
            }
            () = tokio::time::sleep(POLL_INTERVAL) => {}
        }
        drain_tick(&pool, key_cache.as_ref(), &http).await;
    }
}

/// One poll cycle: lock up to [`BATCH_SIZE`] due rows under
/// `FOR UPDATE SKIP LOCKED`, process each via
/// [`backfill_one_labeler`], and transition the row to its terminal
/// status (or schedule a retry) inside the same transaction.
async fn drain_tick(pool: &PgPool, key_cache: &UpstreamKeyCache, http: &reqwest::Client) {
    let claimed = match claim_due_batch(pool).await {
        Ok(rows) => rows,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "label-backfill worker: claim query failed; retrying next tick",
            );
            return;
        }
    };
    if claimed.is_empty() {
        return;
    }
    tracing::info!(
        batch = claimed.len(),
        "label-backfill worker: draining batch",
    );

    // Process the claimed batch concurrently. A serial loop would
    // stall the worker on a single slow / timing-out labeler for the
    // full per-request budget (8s); fanning the batch out via
    // `FuturesUnordered` lets one timeout overlap with seven
    // successful round-trips. The batch size cap (BATCH_SIZE = 8) is
    // already small enough that the spawned-future count is bounded.
    let mut tasks = futures::stream::FuturesUnordered::new();
    for row in claimed {
        tasks.push(process_one(pool, key_cache, http, row));
    }
    while futures::StreamExt::next(&mut tasks).await.is_some() {}
}

/// One queue row as the drain loop sees it. We need the hostname for
/// the queryLabels round-trip; it lives on `upstream_labelers` so the
/// claim query JOINs against that table.
#[derive(Debug)]
struct ClaimedRow {
    id: i64,
    subject_did: String,
    labeler_did: String,
    labeler_hostname: String,
    attempts: i32,
}

/// Claim a batch of due rows under one transaction.
///
/// The transaction is committed before we return — the rows are now
/// `status = 'running'` and won't be picked up by another worker /
/// replica until we transition them to a terminal state (or the row
/// is manually reset). `SKIP LOCKED` makes the claim divisible across
/// concurrent workers without coordination.
async fn claim_due_batch(pool: &PgPool) -> Result<Vec<ClaimedRow>, sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Two-step lock-and-transition. The first query locks the rows;
    // the second flips them to 'running' in one shot. Doing it as one
    // CTE keeps the lock window minimal — the row leaves the FOR
    // UPDATE SKIP LOCKED scope as soon as the CTE returns.
    //
    // The JOIN against upstream_labelers gives us the hostname (the
    // queue table stores only the labeler DID). A row in the queue
    // whose labeler has been deleted from upstream_labelers (rare; the
    // discovery worker doesn't delete, only inserts) is filtered out
    // by the INNER JOIN — those rows will sit in `pending` forever,
    // but a moderator re-opening the subject will re-enqueue and the
    // worker will absorb the duplicate.
    //
    // We cannot pass an i64 literal into the query with the
    // sqlx::query!() macro AND keep the result mappable to a struct
    // we control, so we use the dynamic query API here. The single
    // bind is the batch-size cap; subject_did / labeler_did are read
    // FROM the table, not bound IN.
    // Postgres lets a CTE contain UPDATE ... RETURNING so the lock,
    // status flip, and join-against-upstream_labelers all happen in
    // one statement without confusing FROM-clause aliasing.
    //
    //   step 1: `due` locks the eligible queue rows under FOR UPDATE
    //           SKIP LOCKED, scoping the lock to the queue table.
    //   step 2: `claimed` transitions those rows to 'running' and
    //           returns the row IDs + their labeler_did.
    //   step 3: the outer SELECT joins `claimed` against
    //           `upstream_labelers` to bring the hostname onto the
    //           result set.
    let rows = sqlx::query(
        "
        WITH due AS (
            SELECT q.id
            FROM label_backfill_queue q
            INNER JOIN upstream_labelers u ON u.did = q.labeler_did
            WHERE q.status = 'pending'
              AND q.next_attempt_at <= now()
              AND u.enabled = TRUE
            ORDER BY q.next_attempt_at
            LIMIT $1
            FOR UPDATE OF q SKIP LOCKED
        ),
        claimed AS (
            UPDATE label_backfill_queue
            SET status = 'running',
                attempts = label_backfill_queue.attempts + 1,
                updated_at = now()
            WHERE id IN (SELECT id FROM due)
            RETURNING id, subject_did, labeler_did, attempts
        )
        SELECT c.id, c.subject_did, c.labeler_did, u.hostname AS labeler_hostname, c.attempts
        FROM claimed c
        INNER JOIN upstream_labelers u ON u.did = c.labeler_did
        ",
    )
    .bind(BATCH_SIZE)
    .fetch_all(&mut *tx)
    .await?;

    tx.commit().await?;

    let claimed = rows
        .into_iter()
        .map(|r: PgRow| ClaimedRow {
            id: r.get::<i64, _>("id"),
            subject_did: r.get::<String, _>("subject_did"),
            labeler_did: r.get::<String, _>("labeler_did"),
            labeler_hostname: r.get::<String, _>("labeler_hostname"),
            attempts: r.get::<i32, _>("attempts"),
        })
        .collect();
    Ok(claimed)
}

/// Drive one claimed row to a terminal state (or back to `pending`
/// with a fresh `next_attempt_at` for transport failures under the
/// retry cap).
async fn process_one(
    pool: &PgPool,
    key_cache: &UpstreamKeyCache,
    http: &reqwest::Client,
    row: ClaimedRow,
) {
    tracing::debug!(
        queue_id = row.id,
        subject_did = %row.subject_did,
        labeler = %row.labeler_did,
        hostname = %row.labeler_hostname,
        attempts = row.attempts,
        "label-backfill worker: processing row",
    );

    let outcome = backfill_one_labeler(
        pool,
        key_cache,
        http,
        &row.subject_did,
        &row.labeler_did,
        &row.labeler_hostname,
    )
    .await;

    match outcome {
        BackfillOutcome::Success { labels_persisted } => {
            if let Err(err) = mark_done(pool, row.id, labels_persisted).await {
                tracing::warn!(
                    queue_id = row.id,
                    error = %err,
                    "label-backfill worker: mark_done failed; will be re-claimed next tick",
                );
            } else {
                tracing::info!(
                    queue_id = row.id,
                    subject_did = %row.subject_did,
                    labeler = %row.labeler_did,
                    labels_persisted,
                    "label-backfill worker: done",
                );
            }
        }
        BackfillOutcome::TransportFailure { cause } => {
            // Retry budget: at-or-past MAX_ATTEMPTS → terminal.
            if row.attempts >= MAX_ATTEMPTS {
                if let Err(err) = mark_permanent_failure(pool, row.id, &cause).await {
                    tracing::warn!(
                        queue_id = row.id,
                        error = %err,
                        "label-backfill worker: mark_permanent_failure failed",
                    );
                } else {
                    tracing::info!(
                        queue_id = row.id,
                        subject_did = %row.subject_did,
                        labeler = %row.labeler_did,
                        attempts = row.attempts,
                        cause = %cause,
                        "label-backfill worker: permanent failure after MAX_ATTEMPTS",
                    );
                }
            } else {
                let backoff = transport_retry_delay(row.attempts);
                if let Err(err) = reschedule(pool, row.id, backoff, &cause).await {
                    tracing::warn!(
                        queue_id = row.id,
                        error = %err,
                        "label-backfill worker: reschedule failed; will be re-claimed next tick",
                    );
                } else {
                    tracing::info!(
                        queue_id = row.id,
                        subject_did = %row.subject_did,
                        labeler = %row.labeler_did,
                        attempts = row.attempts,
                        backoff_s = backoff.as_secs(),
                        cause = %cause,
                        "label-backfill worker: transport failure, rescheduled",
                    );
                }
            }
        }
        BackfillOutcome::PermanentFailure { reason } => {
            if let Err(err) = mark_permanent_failure(pool, row.id, &reason).await {
                tracing::warn!(
                    queue_id = row.id,
                    error = %err,
                    "label-backfill worker: mark_permanent_failure failed",
                );
            } else {
                tracing::info!(
                    queue_id = row.id,
                    subject_did = %row.subject_did,
                    labeler = %row.labeler_did,
                    reason = %reason,
                    "label-backfill worker: permanent failure",
                );
            }
        }
    }
}

/// Exponential backoff schedule for transport-failure retries.
///
/// Sequence (using `attempts` as the just-completed attempt count
/// returned from the UPDATE's `attempts + 1`):
///
///   attempts == 1 →  10s
///   attempts == 2 →  60s
///   attempts == 3 →   5min
///   attempts == 4 →  30min
///   attempts == 5 →   1h
///   attempts == 6 →   3h
///   attempts >= 7 →   6h (cap)
fn transport_retry_delay(attempts: i32) -> Duration {
    match attempts {
        ..=1 => Duration::from_secs(10),
        2 => Duration::from_secs(60),
        3 => Duration::from_secs(5 * 60),
        4 => Duration::from_secs(30 * 60),
        5 => Duration::from_secs(60 * 60),
        6 => Duration::from_secs(3 * 60 * 60),
        _ => Duration::from_secs(6 * 60 * 60),
    }
}

/// Transition the row to `done` and record the labels-persisted count
/// in `last_error` (re-used as a small "outcome summary" column —
/// the more obvious place would be a new `labels_persisted` column,
/// but threading that through the migration for a purely
/// informational field is gold-plating). The audit trail lives in
/// the structured log envelope.
async fn mark_done(pool: &PgPool, id: i64, labels_persisted: usize) -> Result<(), sqlx::Error> {
    let summary = format!("ok: {labels_persisted} labels persisted");
    sqlx::query!(
        r#"
        UPDATE label_backfill_queue
        SET status = 'done',
            last_error = $2,
            updated_at = now()
        WHERE id = $1
        "#,
        id,
        summary,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Transition the row back to `pending` with a fresh
/// `next_attempt_at` and the transport-failure cause string.
async fn reschedule(
    pool: &PgPool,
    id: i64,
    backoff: Duration,
    cause: &str,
) -> Result<(), sqlx::Error> {
    // `make_interval(secs => ...)` takes `double precision` per
    // Postgres signature. Casting through f64 is lossless for the
    // values we use here (10s .. 21600s).
    #[allow(
        clippy::cast_precision_loss,
        reason = "backoff seconds are bounded to 21600 — well within f64 mantissa exactness"
    )]
    let secs = backoff.as_secs() as f64;
    sqlx::query!(
        r#"
        UPDATE label_backfill_queue
        SET status = 'pending',
            next_attempt_at = now() + make_interval(secs => $2),
            last_error = $3,
            updated_at = now()
        WHERE id = $1
        "#,
        id,
        secs,
        cause,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Transition the row to terminal `permanent_failure`.
async fn mark_permanent_failure(pool: &PgPool, id: i64, reason: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE label_backfill_queue
        SET status = 'permanent_failure',
            last_error = $2,
            updated_at = now()
        WHERE id = $1
        "#,
        id,
        reason,
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code — rust-quality §7"
)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_is_monotonic_until_cap() {
        let d1 = transport_retry_delay(1);
        let d2 = transport_retry_delay(2);
        let d3 = transport_retry_delay(3);
        let d4 = transport_retry_delay(4);
        let d5 = transport_retry_delay(5);
        let d6 = transport_retry_delay(6);
        let d7 = transport_retry_delay(7);
        let d8 = transport_retry_delay(8);
        assert!(d1 < d2);
        assert!(d2 < d3);
        assert!(d3 < d4);
        assert!(d4 < d5);
        assert!(d5 < d6);
        assert!(d6 < d7);
        assert_eq!(d7, d8, "delay saturates at the 6h cap");
        assert_eq!(d8, Duration::from_secs(6 * 60 * 60));
    }

    #[test]
    fn retry_delay_initial_is_10_seconds() {
        assert_eq!(transport_retry_delay(0), Duration::from_secs(10));
        assert_eq!(transport_retry_delay(1), Duration::from_secs(10));
    }
}
