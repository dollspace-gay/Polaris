//! Evidence-snapshot worker (issue #33 / REQ-10 / AC-11).
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
//!   pending  ──►  running  ──►  done
//!                        \─►   failed   (one attempt; retries are #70)
//! ```
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
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

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
pub struct EvidenceWorker {
    pool: PgPool,
    blob_store: Arc<dyn BlobStore>,
    fetcher: Arc<dyn EvidenceFetcher>,
    concurrency: Arc<Semaphore>,
    poll_interval: Duration,
    batch_size: i64,
}

impl std::fmt::Debug for EvidenceWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvidenceWorker")
            .field("concurrency", &self.concurrency.available_permits())
            .field("poll_interval", &self.poll_interval)
            .field("batch_size", &self.batch_size)
            .field("blob_store", &self.blob_store)
            .field("fetcher", &self.fetcher)
            .finish_non_exhaustive()
    }
}

impl EvidenceWorker {
    /// Build an [`EvidenceWorker`].
    ///
    /// `worker_concurrency` caps the number of in-flight CAR fetches.
    /// `poll_interval` is the time between drain ticks.
    #[must_use]
    pub fn new(
        pool: PgPool,
        blob_store: Arc<dyn BlobStore>,
        fetcher: Arc<dyn EvidenceFetcher>,
        worker_concurrency: usize,
        poll_interval: Duration,
    ) -> Self {
        Self {
            pool,
            blob_store,
            fetcher,
            concurrency: Arc::new(Semaphore::new(worker_concurrency.max(1))),
            poll_interval,
            batch_size: 16,
        }
    }

    /// Process one batch and return. Returns the number of jobs that
    /// terminated (either successfully or with `failed`). Exposed for
    /// tests so they can drive the worker one tick at a time.
    pub async fn run_once(&self) -> Result<usize, EvidenceWorkerError> {
        // Claim a batch of pending jobs under SKIP LOCKED so multiple
        // worker replicas can drain in parallel without stepping on
        // each other.
        let jobs = sqlx::query!(
            r#"
            WITH claimed AS (
                SELECT id
                FROM evidence_jobs
                WHERE status = 'pending'
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
            handles.push(tokio::spawn(async move {
                let result = process_one(
                    &pool,
                    &*blob_store,
                    &*fetcher,
                    job_id,
                    action_id,
                    &subject_uri,
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
async fn process_one(
    pool: &PgPool,
    blob_store: &dyn BlobStore,
    fetcher: &dyn EvidenceFetcher,
    job_id: i64,
    action_id: uuid::Uuid,
    subject_uri: &str,
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
            mark_failed(pool, job_id, &reason).await?;
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
            last_error = NULL
        WHERE id = $1
        "#,
        job_id,
    )
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn mark_failed(pool: &PgPool, job_id: i64, reason: &str) -> Result<(), EvidenceWorkerError> {
    sqlx::query!(
        r#"
        UPDATE evidence_jobs
        SET status = 'failed',
            last_error = $1,
            attempt_count = attempt_count + 1,
            completed_at = now()
        WHERE id = $2
        "#,
        reason,
        job_id,
    )
    .execute(pool)
    .await?;
    Ok(())
}

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
