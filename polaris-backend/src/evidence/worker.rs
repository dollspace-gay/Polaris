//! Evidence-snapshot worker (issue #33 / REQ-10 / AC-11, issue #69 retry).
//!
//! Drains `evidence_jobs` rows. Each row is a one-off snapshot job:
//! fetch the upstream record + MST proof path via an
//! [`EvidenceFetcher`], package the slice as a CAR file
//! ([`proto_blue::repo::blocks_to_car`]), hash the CAR with SHA-256,
//! and write the bytes under `evidence/{prefix}/{hex-cid}` in the
//! configured [`crate::evidence::blob_store::BlobStore`].
//!
//! # State machine
//!
//! ```text
//!   pending ──► running ──► done
//!                       \─► failed (eligible for retry: next_attempt_at SET)
//!                       \─► failed (permanent: attempt_count >= max_attempts)
//! ```
//!
//! # Retry policy (issue #69)
//!
//! On a per-job failure the worker writes
//! `next_attempt_at = now() + retry_delay(attempt_count)` and
//! `last_attempt_at = now()`. The drain loop reclaims `status='failed'`
//! rows whose `next_attempt_at <= now()` and re-runs them, incrementing
//! `attempt_count` on each new attempt. When a failure brings
//! `attempt_count` up to [`EvidenceWorker::max_attempts`], the failure
//! is permanent: `next_attempt_at` is set to NULL so the row is never
//! re-drained.
//!
//! Backoff: `2^min(attempt_count, 11) * retry_base_secs`, capped at
//! 24 hours, with ±25% jitter so a fleet of workers does not
//! synchronise their retries against a flapping upstream. See
//! [`retry_delay`].
//!
//! # Concurrency
//!
//! The worker is bounded by a [`tokio::sync::Semaphore`]. Each drained
//! job acquires a permit before spawning; the permit drops on task
//! completion. The semaphore is the only thing that prevents an
//! unbounded fan-out under a backlog.
//!
//! # Idempotency
//!
//! `evidence_jobs` carries `UNIQUE(action_id)`; the enqueue path uses
//! `ON CONFLICT (action_id) DO NOTHING` so replayed inserts are
//! no-ops. The worker checks `actions.evidence_car_cid` at job start
//! — when it's already populated, the worker short-circuits to the
//! "mark job done" tail. Re-running the worker over a `done` row is
//! cheap and idempotent.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use proto_blue::lex_data::Cid;
use proto_blue::repo::{BlockMap, blocks_to_car};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

/// Default number of attempts before a job is permanently failed
/// (issue #69). Reached when `attempt_count` rises to this value.
///
/// 8 attempts with the default `retry_base_secs = 30` spreads the
/// retries across ~5 hours of wall-clock under the
/// `2^attempt * 30s` schedule (30s, 1m, 2m, 4m, 8m, 16m, 32m, 64m;
/// the cap is 24h so neither growth nor sum approaches the cap).
pub const DEFAULT_MAX_ATTEMPTS: u32 = 8;

/// Default base for the exponential backoff in seconds (issue #69).
pub const DEFAULT_RETRY_BASE_SECS: u64 = 30;

/// Hard cap on the per-attempt retry delay, in seconds (24h).
const RETRY_DELAY_CAP_SECS: u64 = 86_400;

/// Retry-policy snapshot threaded into [`process_one`] and
/// [`mark_failed`] (issue #69).
///
/// Bundled into a struct so the per-job worker call doesn't exceed
/// clippy's `too_many_arguments` ceiling and so adding a future
/// policy knob (e.g. permanent-failure callback) does not ripple
/// through every call site.
#[derive(Debug, Clone, Copy)]
struct RetryPolicy {
    /// Maximum attempts before failure becomes permanent.
    max_attempts: u32,
    /// Base seconds for the exponential backoff (multiplied by
    /// `2^attempt`).
    base_secs: u64,
}

use crate::evidence::blob_store::{BlobStore, BlobStoreError};

/// Errors raised by the [`EvidenceWorker`] loop.
///
/// Per-job failures are recorded on the `evidence_jobs.last_error`
/// column and do not bubble up here; this variant covers the worker's
/// own infrastructure failures (DB pool dead, semaphore poisoned,
/// blob-store unreachable in a non-recoverable way).
#[derive(Debug, thiserror::Error)]
pub enum EvidenceWorkerError {
    /// Database error.
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    /// Blob-store error that the worker could not classify as
    /// per-job-recoverable.
    #[error("blob-store error: {0}")]
    BlobStore(#[from] BlobStoreError),
}

/// Errors raised by an [`EvidenceFetcher`] implementation.
///
/// Per-job failures are recorded on `evidence_jobs.last_error`. The
/// fetcher trait is the seam between the worker and the network /
/// proto-blue XRPC layer; tests inject a mock that produces typed
/// errors.
#[derive(Debug, thiserror::Error)]
pub enum EvidenceFetcherError {
    /// The supplied AT-URI did not parse into a (did, collection, rkey)
    /// triple.
    #[error("could not parse AT-URI: {message}")]
    BadAtUri {
        /// Diagnostic message.
        message: String,
    },
    /// Upstream service refused the request or returned a no-such-record.
    #[error("upstream rejected the fetch: {message}")]
    Upstream {
        /// Diagnostic message.
        message: String,
    },
    /// The fetched bytes did not parse as a CAR / lex structure.
    #[error("evidence-decode error: {message}")]
    Decode {
        /// Diagnostic message.
        message: String,
    },
}

/// Output of an [`EvidenceFetcher::fetch_record_with_proof`] call.
///
/// `root_cid` is the upstream repo's signed-commit root at the time
/// of the fetch (the answer to `describeRepo` / the `commit` field
/// from `getRecord`). `blocks` is the minimum block-map the verifier
/// needs to reproduce the record + walk the MST proof path.
#[derive(Debug, Clone)]
pub struct FetchedEvidence {
    /// The upstream repo's commit root CID. Embedded in the CAR
    /// header as the single "root" entry.
    pub root_cid: Cid,
    /// Record CID + MST proof-path CIDs + the record block, indexed
    /// by their content hashes. Written into the CAR body.
    pub blocks: BlockMap,
}

/// The seam between the worker and the proto-blue XRPC client.
///
/// The trait is dyn-compatible (uses `Pin<Box<dyn Future>>` rather
/// than AFIT) so the worker can hold the fetcher behind
/// `Arc<dyn EvidenceFetcher>` and tests can inject a mock. The live
/// impl wraps a `proto-blue-api` agent / XRPC client; the trait keeps
/// the worker pure with respect to the network stack.
pub trait EvidenceFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch the upstream record at `subject_uri` together with its
    /// MST proof path. The returned `FetchedEvidence` is enough to
    /// reproduce the record's inclusion-in-a-signed-commit proof.
    fn fetch_record_with_proof<'a>(
        &'a self,
        subject_uri: &'a str,
    ) -> std::pin::Pin<
        Box<dyn Future<Output = Result<FetchedEvidence, EvidenceFetcherError>> + Send + 'a>,
    >;
}

/// Background worker that drains `evidence_jobs`.
///
/// Hold this in `main()` as `Arc<EvidenceWorker>` and call
/// [`EvidenceWorker::run_forever`] on a `tokio::spawn`. The worker
/// runs until the pool is dropped or the task is aborted.
///
/// # Retry policy (issue #69)
///
/// Failed jobs are retried with exponential backoff up to
/// `max_attempts`. The backoff base is `retry_base_secs`, doubling per
/// attempt and capped at 24h with ±25% jitter; see [`retry_delay`].
pub struct EvidenceWorker {
    pool: PgPool,
    blob_store: Arc<dyn BlobStore>,
    fetcher: Arc<dyn EvidenceFetcher>,
    concurrency: Arc<Semaphore>,
    poll_interval: Duration,
    batch_size: i64,
    /// Maximum number of attempts before a failure is permanent. A row
    /// whose `attempt_count` reaches this value after a failed attempt
    /// is left at `status='failed'` with `next_attempt_at = NULL`.
    max_attempts: u32,
    /// Base seconds for the exponential backoff
    /// (`2^attempt_count * retry_base_secs`, capped at 24h, ±25%
    /// jitter).
    retry_base_secs: u64,
}

impl std::fmt::Debug for EvidenceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceWorker")
            .field("concurrency", &self.concurrency.available_permits())
            .field("poll_interval", &self.poll_interval)
            .field("batch_size", &self.batch_size)
            .field("max_attempts", &self.max_attempts)
            .field("retry_base_secs", &self.retry_base_secs)
            .field("blob_store", &self.blob_store)
            .field("fetcher", &self.fetcher)
            .finish_non_exhaustive()
    }
}

impl EvidenceWorker {
    /// Build an [`EvidenceWorker`] with the default retry policy
    /// ([`DEFAULT_MAX_ATTEMPTS`] / [`DEFAULT_RETRY_BASE_SECS`]).
    ///
    /// `worker_concurrency` caps the number of in-flight CAR fetches.
    /// `poll_interval` is the time between drain ticks.
    ///
    /// Use [`Self::with_retry_policy`] to override the retry-policy
    /// defaults.
    #[must_use]
    pub fn new(
        pool: PgPool,
        blob_store: Arc<dyn BlobStore>,
        fetcher: Arc<dyn EvidenceFetcher>,
        worker_concurrency: usize,
        poll_interval: Duration,
    ) -> Self {
        Self::with_retry_policy(
            pool,
            blob_store,
            fetcher,
            worker_concurrency,
            poll_interval,
            DEFAULT_MAX_ATTEMPTS,
            DEFAULT_RETRY_BASE_SECS,
        )
    }

    /// Build an [`EvidenceWorker`] with an explicit retry policy
    /// (issue #69).
    ///
    /// `max_attempts` is the ceiling at which failures become
    /// permanent: a failed attempt that leaves `attempt_count` at this
    /// value sets `next_attempt_at = NULL` and the row is never
    /// re-drained. `retry_base_secs` is the base for the exponential
    /// schedule (`2^attempt_count * retry_base_secs`, capped at 24h,
    /// ±25% jitter; see [`retry_delay`]).
    ///
    /// `max_attempts` is clamped to a minimum of 1 — zero would mean
    /// "never run the job at all," which is not a coherent
    /// configuration for a worker.
    #[must_use]
    pub fn with_retry_policy(
        pool: PgPool,
        blob_store: Arc<dyn BlobStore>,
        fetcher: Arc<dyn EvidenceFetcher>,
        worker_concurrency: usize,
        poll_interval: Duration,
        max_attempts: u32,
        retry_base_secs: u64,
    ) -> Self {
        Self {
            pool,
            blob_store,
            fetcher,
            concurrency: Arc::new(Semaphore::new(worker_concurrency.max(1))),
            poll_interval,
            batch_size: 16,
            max_attempts: max_attempts.max(1),
            retry_base_secs: retry_base_secs.max(1),
        }
    }

    /// Process one batch and return. Returns the number of jobs that
    /// terminated (either successfully or with `failed`). Exposed for
    /// tests so they can drive the worker one tick at a time.
    ///
    /// The claim path drains two row populations under SKIP LOCKED:
    ///
    /// 1. Fresh `pending` rows (the original #33 path).
    /// 2. Retry-eligible `failed` rows — `status='failed'` with
    ///    `next_attempt_at IS NOT NULL AND next_attempt_at <= now()`
    ///    (issue #69). The partial index
    ///    `evidence_jobs_next_attempt_idx` from migration 21 keeps
    ///    this lookup bounded as the queue grows.
    ///
    /// Both populations are flipped to `status='running'` atomically;
    /// the per-job worker decides whether the new attempt succeeds
    /// (→ `done`) or fails again (→ `failed` with the next
    /// `next_attempt_at` set, or permanent failure if `attempt_count`
    /// reached `max_attempts`).
    pub async fn run_once(&self) -> Result<usize, EvidenceWorkerError> {
        // Claim a batch of work — `pending` plus retry-due `failed`
        // rows — under SKIP LOCKED so multiple worker replicas can
        // drain in parallel without stepping on each other.
        let jobs = sqlx::query!(
            r#"
            WITH claimed AS (
                SELECT id
                FROM evidence_jobs
                WHERE status = 'pending'
                   OR (status = 'failed'
                       AND next_attempt_at IS NOT NULL
                       AND next_attempt_at <= now())
                ORDER BY enqueued_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT $1
            )
            UPDATE evidence_jobs
            SET status = 'running'
            WHERE id IN (SELECT id FROM claimed)
            RETURNING id, action_id, subject_uri
            "#,
            self.batch_size,
        )
        .fetch_all(&self.pool)
        .await?;

        if jobs.is_empty() {
            return Ok(0);
        }
        debug!(count = jobs.len(), "claimed evidence-job batch");

        let mut handles = Vec::with_capacity(jobs.len());
        for job in jobs {
            // Acquire the per-job permit. `Semaphore::acquire_owned`
            // returns a permit tied to an Arc so the spawned task can
            // hold it for its full lifetime and drop it on completion;
            // this is how we satisfy the "no unbounded spawn" rule.
            let permit = self
                .concurrency
                .clone()
                .acquire_owned()
                .await
                .map_err(|e| {
                    EvidenceWorkerError::BlobStore(BlobStoreError::Other(format!(
                        "concurrency semaphore closed: {e}"
                    )))
                })?;

            let pool = self.pool.clone();
            let blob_store = self.blob_store.clone();
            let fetcher = self.fetcher.clone();
            let job_id = job.id;
            let action_id = job.action_id;
            let subject_uri = job.subject_uri;
            let policy = RetryPolicy {
                max_attempts: self.max_attempts,
                base_secs: self.retry_base_secs,
            };
            handles.push(tokio::spawn(async move {
                let result = process_one(
                    &pool,
                    &*blob_store,
                    &*fetcher,
                    job_id,
                    action_id,
                    &subject_uri,
                    policy,
                )
                .await;
                drop(permit);
                result
            }));
        }

        let mut finished = 0_usize;
        for handle in handles {
            match handle.await {
                Ok(Ok(())) => finished += 1,
                Ok(Err(e)) => {
                    finished += 1;
                    warn!(error = ?e, "evidence job terminated with error");
                }
                Err(join_err) => {
                    warn!(error = ?join_err, "evidence job task panicked or was cancelled");
                }
            }
        }
        Ok(finished)
    }

    /// Drain the queue forever, sleeping `poll_interval` between
    /// empty batches. Returns only if a non-recoverable error
    /// surfaces from the claim path (DB unreachable, etc.); the
    /// caller (main) should log and restart the worker.
    pub async fn run_forever(self: Arc<Self>) -> Result<(), EvidenceWorkerError> {
        info!(
            poll_interval_ms = u64::try_from(self.poll_interval.as_millis()).unwrap_or(u64::MAX),
            "evidence worker started",
        );
        loop {
            let processed = self.run_once().await?;
            if processed == 0 {
                tokio::time::sleep(self.poll_interval).await;
            }
        }
    }
}

/// Process exactly one evidence job. Catches per-job failures and
/// records them on `evidence_jobs.last_error` so the caller (the
/// per-tick handler) does not need to.
///
/// `policy` drives the retry-with-backoff schedule on the failure
/// path (issue #69). A failure that brings `attempt_count` up to
/// `policy.max_attempts` is permanent; earlier failures schedule a
/// `next_attempt_at` via [`retry_delay`].
async fn process_one(
    pool: &PgPool,
    blob_store: &dyn BlobStore,
    fetcher: &dyn EvidenceFetcher,
    job_id: i64,
    action_id: uuid::Uuid,
    subject_uri: &str,
    policy: RetryPolicy,
) -> Result<(), EvidenceWorkerError> {
    // Idempotency short-circuit: if the action already has a
    // populated `evidence_car_cid`, mark the job done without
    // re-fetching. Pattern recommended by the spec — replays of the
    // worker should be cheap.
    let existing = sqlx::query!(
        "SELECT evidence_car_cid FROM actions WHERE id = $1",
        action_id,
    )
    .fetch_optional(pool)
    .await?;
    if let Some(row) = existing
        && row.evidence_car_cid.is_some()
    {
        mark_done(pool, job_id).await?;
        return Ok(());
    }

    match snapshot_and_store(blob_store, fetcher, subject_uri).await {
        Ok(cid) => {
            commit_success(pool, job_id, action_id, &cid).await?;
            info!(%action_id, cid = %cid, "evidence CAR persisted");
            Ok(())
        }
        Err(reason) => {
            warn!(%action_id, %reason, "evidence snapshot failed");
            mark_failed(pool, job_id, &reason, policy).await?;
            Ok(())
        }
    }
}

async fn snapshot_and_store(
    blob_store: &dyn BlobStore,
    fetcher: &dyn EvidenceFetcher,
    subject_uri: &str,
) -> Result<String, String> {
    let evidence = fetcher
        .fetch_record_with_proof(subject_uri)
        .await
        .map_err(|e| format!("fetcher: {e}"))?;
    let car_bytes = blocks_to_car(Some(&evidence.root_cid), &evidence.blocks)
        .map_err(|e| format!("blocks_to_car: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(&car_bytes);
    let digest = hasher.finalize();
    let cid_hex = hex::encode(digest);
    let key = blob_key_for_cid(&cid_hex);
    blob_store
        .put(&key, Bytes::from(car_bytes))
        .await
        .map_err(|e| format!("blob_store: {e}"))?;
    Ok(cid_hex)
}

async fn commit_success(
    pool: &PgPool,
    job_id: i64,
    action_id: uuid::Uuid,
    cid: &str,
) -> Result<(), EvidenceWorkerError> {
    // Single transaction: update both the action and the job. Each
    // statement uses the macro form so the planner can validate the
    // shape against the live schema.
    //
    // `attempt_count` is incremented here so a retry that finally
    // succeeds reflects "I had to try twice (or more)" in the audit
    // trail. `next_attempt_at` is cleared because the row is no
    // longer eligible for re-drain. `last_attempt_at` is stamped to
    // match the failure path's behaviour — the column documents the
    // most recent processing attempt regardless of outcome.
    let mut tx = pool.begin().await?;
    sqlx::query!(
        "UPDATE actions SET evidence_car_cid = $1 WHERE id = $2",
        cid,
        action_id,
    )
    .execute(&mut *tx)
    .await?;
    sqlx::query!(
        r#"
        UPDATE evidence_jobs
        SET status = 'done',
            completed_at = now(),
            last_error = NULL,
            attempt_count = attempt_count + 1,
            last_attempt_at = now(),
            next_attempt_at = NULL
        WHERE id = $1
        "#,
        job_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Record a per-job failure.
///
/// Atomically increments `attempt_count`, sets `status='failed'`,
/// stamps `last_attempt_at = now()`, and decides whether the failure
/// is retry-eligible:
///
/// - If the new `attempt_count` is strictly less than `max_attempts`,
///   compute `next_attempt_at = now() + retry_delay(attempt_count)`
///   (per [`retry_delay`]) so the next worker tick after that wall
///   clock will reclaim the row.
/// - Otherwise the row reached the ceiling: `next_attempt_at` is left
///   NULL and the row is permanently failed — it surfaces in metrics
///   but is never re-drained.
///
/// `attempt_count` is read before increment to compute the backoff
/// against the just-finished attempt; the SQL increments in the same
/// statement so a racing worker cannot observe the row at the old
/// count.
async fn mark_failed(
    pool: &PgPool,
    job_id: i64,
    reason: &str,
    policy: RetryPolicy,
) -> Result<(), EvidenceWorkerError> {
    // Read the pre-increment attempt_count so we can pick the right
    // backoff bucket. The update below increments atomically so a
    // racing tick cannot misread the count even if this read and the
    // write are not in the same transaction.
    let row = sqlx::query!(
        "SELECT attempt_count FROM evidence_jobs WHERE id = $1",
        job_id,
    )
    .fetch_one(pool)
    .await?;
    let prior_attempts: u32 = u32::try_from(row.attempt_count.max(0)).unwrap_or(u32::MAX);
    let new_attempts = prior_attempts.saturating_add(1);
    let next_at: Option<chrono::DateTime<chrono::Utc>> = if new_attempts >= policy.max_attempts {
        // Ceiling reached. Permanent failure — no next attempt.
        None
    } else {
        // Compute the delay against the just-finished attempt (1-based
        // would be off-by-one against the formula `2^attempt * base`;
        // we use the pre-increment count so attempt_count=0 → first
        // retry waits 2^0 * base = base seconds).
        let delay = retry_delay(prior_attempts, policy.base_secs);
        let delay_chrono = chrono::Duration::from_std(delay)
            .unwrap_or_else(|_| chrono::Duration::seconds(RETRY_DELAY_CAP_SECS_I64));
        Some(chrono::Utc::now() + delay_chrono)
    };
    sqlx::query!(
        r#"
        UPDATE evidence_jobs
        SET status = 'failed',
            last_error = $1,
            attempt_count = attempt_count + 1,
            completed_at = now(),
            last_attempt_at = now(),
            next_attempt_at = $2
        WHERE id = $3
        "#,
        reason,
        next_at,
        job_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// `RETRY_DELAY_CAP_SECS` as `i64` for the `chrono::Duration` fallback.
/// Hard-coded to the same value as [`RETRY_DELAY_CAP_SECS`] to avoid a
/// u64→i64 cast (clippy `cast_possible_wrap`); 24h trivially fits in
/// `i64`. The `const _:` assertion below pins the two literals
/// together so a future change to one is forced to update the other.
const RETRY_DELAY_CAP_SECS_I64: i64 = 86_400;
const _: () = assert!(RETRY_DELAY_CAP_SECS == RETRY_DELAY_CAP_SECS_I64 as u64);

async fn mark_done(pool: &PgPool, job_id: i64) -> Result<(), EvidenceWorkerError> {
    sqlx::query!(
        r#"
        UPDATE evidence_jobs
        SET status = 'done',
            completed_at = now(),
            last_error = NULL
        WHERE id = $1
        "#,
        job_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ── pure helpers (no I/O) ───────────────────────────────────────────────

/// Compute the wall-clock retry delay for the next attempt of a failed
/// evidence job (issue #69).
///
/// Formula (matches the architect's pre-flight verbatim):
///
/// ```text
///   shift     = min(attempt, 11)               // cap so 2^shift fits
///   raw_secs  = (1 << shift) * base_secs
///   capped    = min(raw_secs, 86_400)          // 24h ceiling
///   jitter    = ±25%
///   jittered  = max(1, capped * (100 + jitter) / 100)
/// ```
///
/// `attempt` is the count of completed attempts (so the first retry
/// sees `attempt = 0` → `2^0 * base = base` seconds before jitter).
/// The 24h cap dominates after `2^11 * 30s ≈ 17h`; the shift saturates
/// at 11 so no further growth occurs even for very large `attempt`
/// values.
///
/// The jitter is centred — a fleet of workers reclaiming the same
/// flapping upstream will not synchronise their retries against it.
#[must_use]
pub fn retry_delay(attempt: u32, base_secs: u64) -> Duration {
    let shift = attempt.min(11);
    // `2^shift` for `shift <= 11` is `<= 2048`; multiplied by the
    // default base of 30s the result fits in u64 by miles. We still
    // use saturating arithmetic so a pathologically large `base_secs`
    // cannot overflow.
    let raw = (1u64 << shift).saturating_mul(base_secs);
    let capped = raw.min(RETRY_DELAY_CAP_SECS);

    // ±25% jitter. We compute `jitter_pct ∈ [-25, +25]` then apply it
    // as a per-cent offset: `capped + capped * jitter_pct / 100`. The
    // integer math avoids the cast-precision-loss / cast-sign-loss
    // clippy lints the workspace runs with `-D warnings`.
    let mut rng = rand::thread_rng();
    // Range `0..=50` then subtract 25 to centre on 0.
    let jitter_pct: i64 = rng.gen_range(0_i64..=50) - 25;
    // Saturating ladder: cast to i128 to do the multiply, narrow back
    // with `try_from` and a saturating fallback. Keeps clippy quiet
    // under `-D warnings` without a per-line allow.
    let capped_i128 = i128::from(capped);
    let scaled = capped_i128 + capped_i128 * i128::from(jitter_pct) / 100;
    let jittered_u64 = u64::try_from(scaled.max(1)).unwrap_or(1);
    Duration::from_secs(jittered_u64.max(1))
}

/// Compute the canonical blob-store key for an evidence CID.
///
/// The shape is `evidence/{hex[0..2]}/{hex}` — a two-character prefix
/// directory keeps any one directory bounded to ~256 entries even at
/// billions of CARs. Bug-prone: the prefix is the first two
/// **characters** of the hex form, not the first byte; the result is
/// stable across implementations.
///
/// # Panics
///
/// Never — falls back to `evidence/__/<hex>` when the hex string is
/// shorter than two chars (never expected for SHA-256 but the
/// fallback prevents a substring panic).
#[must_use]
pub fn blob_key_for_cid(cid_hex: &str) -> String {
    let prefix = if cid_hex.len() >= 2 {
        &cid_hex[..2]
    } else {
        "__"
    };
    format!("evidence/{prefix}/{cid_hex}")
}

/// Parse an AT-URI of the shape `at://did:plc:.../<collection>/<rkey>`
/// into its three components.
///
/// Returns [`EvidenceFetcherError::BadAtUri`] when the shape does not
/// match.
///
/// # Errors
///
/// Returns [`EvidenceFetcherError::BadAtUri`] when the AT-URI does
/// not have the canonical `at://<did>/<collection>/<rkey>` shape.
pub fn parse_subject_uri(uri: &str) -> Result<(String, String, String), EvidenceFetcherError> {
    let rest = uri
        .strip_prefix("at://")
        .ok_or_else(|| EvidenceFetcherError::BadAtUri {
            message: format!("missing at:// prefix: {uri}"),
        })?;
    let mut parts = rest.splitn(3, '/');
    let did =
        parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| EvidenceFetcherError::BadAtUri {
                message: format!("missing DID: {uri}"),
            })?;
    let collection =
        parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| EvidenceFetcherError::BadAtUri {
                message: format!("missing collection: {uri}"),
            })?;
    let rkey =
        parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| EvidenceFetcherError::BadAtUri {
                message: format!("missing rkey: {uri}"),
            })?;
    Ok((did.to_owned(), collection.to_owned(), rkey.to_owned()))
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
    use proto_blue::lex_data::LexValue;
    use proto_blue::repo::{BlockMap, read_car};

    #[test]
    fn blob_key_layout() {
        assert_eq!(
            blob_key_for_cid("abcdef0123456789"),
            "evidence/ab/abcdef0123456789",
        );
        // Short string fallback — defensive, not a normal input.
        assert_eq!(blob_key_for_cid("z"), "evidence/__/z");
    }

    #[test]
    fn parse_subject_uri_happy_path() {
        let (did, coll, rkey) =
            parse_subject_uri("at://did:plc:abcdef/app.bsky.feed.post/3kabc123").unwrap();
        assert_eq!(did, "did:plc:abcdef");
        assert_eq!(coll, "app.bsky.feed.post");
        assert_eq!(rkey, "3kabc123");
    }

    #[test]
    fn parse_subject_uri_rejects_malformed() {
        for bad in [
            "did:plc:abc/coll/rkey",                // missing at:// prefix
            "at:///coll/rkey",                      // missing DID
            "at://did:plc:abc/coll",                // missing rkey
            "at://did:plc:abc/",                    // missing collection + rkey
            "at://did:plc:abc/app.bsky.feed.post/", // empty rkey
        ] {
            let res = parse_subject_uri(bad);
            assert!(res.is_err(), "expected error on input {bad:?}");
        }
    }

    #[test]
    fn car_round_trip_identity_via_proto_blue() {
        // Build a synthetic 3-block "record + 2 proof blocks" map,
        // CAR-encode it, decode the CAR, and assert the resulting
        // BlockMap byte-equals the original. This proves the
        // worker's CAR-encoding step (`blocks_to_car`) is byte-stable
        // and read-back-able. It does not exercise the network path.
        let mut blocks = BlockMap::new();
        let root = blocks
            .add_value(&LexValue::String("commit root".into()))
            .unwrap();
        let proof_a = blocks
            .add_value(&LexValue::String("mst proof a".into()))
            .unwrap();
        let proof_b = blocks
            .add_value(&LexValue::String("mst proof b".into()))
            .unwrap();
        let record = blocks
            .add_value(&LexValue::String("record value".into()))
            .unwrap();

        let car = blocks_to_car(Some(&root), &blocks).unwrap();
        let (roots, decoded) = read_car(&car).unwrap();

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].to_string_base32(), root.to_string_base32());
        assert_eq!(decoded.len(), 4);
        for cid in [&root, &proof_a, &proof_b, &record] {
            let original = blocks.get(cid).expect("present in original map");
            let after = decoded.get(cid).expect("present in decoded map");
            assert_eq!(original, after, "byte-identity for cid {cid:?}");
        }
    }

    #[test]
    fn sha256_hex_layout_matches_blob_key_prefix() {
        // The worker's blob_key path uses the first two hex chars of
        // the SHA-256 as the directory prefix. Lock that in: changing
        // the layout is a deliberate operator-visible event.
        let mut hasher = Sha256::new();
        hasher.update(b"some car bytes");
        let hex = hex::encode(hasher.finalize());
        assert_eq!(hex.len(), 64, "SHA-256 produces 32 bytes = 64 hex chars");
        let key = blob_key_for_cid(&hex);
        assert!(key.starts_with("evidence/"));
        let prefix = &hex[..2];
        let expected = format!("evidence/{prefix}/{hex}");
        assert_eq!(key, expected);
    }
}

// ── retry-delay tests (issue #69) ───────────────────────────────────
//
// Pure-function tests for [`retry_delay`]. The integration behaviour
// (failure → schedule → reclaim → done) is covered by
// `tests/evidence_retry.rs`; this module proves the math. Lifted out
// of the parent `tests` module so the deliverable's exact filter
// (`cargo test -p polaris-backend --lib evidence::worker::retry`)
// matches the path of every test in this submodule.
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod retry {
    use super::*;

    /// `retry_delay(0, 30)` should land in `[23s, 38s]` — the raw
    /// value is 30s and the ±25% jitter widens that to `[22.5s,
    /// 37.5s]`. We round outward for the assertion.
    #[test]
    fn retry_delay_first_attempt_inside_jitter_band() {
        for _ in 0..32 {
            let d = retry_delay(0, 30).as_secs();
            assert!(d >= 22, "attempt=0 produced {d}s, below 25% lower jitter");
            assert!(d <= 38, "attempt=0 produced {d}s, above 25% upper jitter");
        }
    }

    /// Growth is monotone in expectation: the lower bound of
    /// `attempt=k+1` must exceed the upper bound of `attempt=k-1`
    /// (i.e. the bands of non-adjacent attempts cannot overlap). We
    /// sample medians across many draws.
    #[test]
    fn retry_delay_monotone_across_non_adjacent_attempts() {
        let median = |attempt: u32| -> u64 {
            let mut samples: Vec<u64> = (0..64)
                .map(|_| retry_delay(attempt, 30).as_secs())
                .collect();
            samples.sort_unstable();
            samples[samples.len() / 2]
        };
        // attempt 0 → ~30s; attempt 2 → ~120s. Lower bound of 2 must
        // be strictly above upper bound of 0.
        assert!(
            median(2) > median(0),
            "attempt=2 median ({}) must exceed attempt=0 median ({})",
            median(2),
            median(0),
        );
        // attempt 4 → ~480s; attempt 6 → ~1920s.
        assert!(median(6) > median(4));
    }

    /// `retry_delay` must cap at 24h regardless of how large
    /// `attempt` grows. With the cap and the +25% jitter the upper
    /// bound is `86_400 * 1.25 = 108_000`s; we let the jitter be
    /// inclusive on both sides.
    #[test]
    fn retry_delay_caps_at_24h_plus_jitter() {
        // 24h * 1.25 = 30h = 108_000s.
        let upper = 86_400_u64 + 86_400_u64 / 4;
        for attempt in [12_u32, 20, 100, u32::MAX] {
            for _ in 0..16 {
                let d = retry_delay(attempt, 30).as_secs();
                assert!(
                    d <= upper,
                    "attempt={attempt} produced {d}s, above 24h+25% cap ({upper}s)",
                );
            }
        }
    }

    /// Jitter bands must stay within ±25% of the deterministic
    /// `2^attempt * base` (or the cap, whichever is smaller). We
    /// check both attempts within the growth band and one at the cap.
    #[test]
    fn retry_delay_jitter_within_25_percent_band() {
        let cases: &[(u32, u64)] = &[(0, 30), (3, 30), (5, 30), (15, 30)];
        for &(attempt, base) in cases {
            let shift = attempt.min(11);
            let raw = (1_u64 << shift).saturating_mul(base);
            let capped = raw.min(86_400);
            let lower = capped.saturating_sub(capped / 4).max(1);
            let upper = capped + capped / 4;
            for _ in 0..32 {
                let d = retry_delay(attempt, base).as_secs();
                assert!(
                    d >= lower && d <= upper,
                    "attempt={attempt} produced {d}s, outside [{lower}, {upper}]",
                );
            }
        }
    }

    /// Zero base seconds is degenerate but must not panic;
    /// `retry_delay` must return a strictly positive duration so the
    /// worker never spins on a zero-delay schedule.
    #[test]
    fn retry_delay_positive_under_zero_base() {
        // The constructor clamps `retry_base_secs` to 1, but the pure
        // function is also defensive.
        for attempt in 0..6 {
            let d = retry_delay(attempt, 0);
            assert!(
                d >= Duration::from_secs(1),
                "attempt={attempt} produced sub-second delay",
            );
        }
    }
}
