//! Periodic external attestation of the audit-log head hash
//! (issue #35; design.md §6 + §9).
//!
//! The audit-log chain hash detects internal tampering up to the
//! capability of the actor: a non-superuser cannot bypass the
//! append-only triggers, so a row-level rewrite is detected by
//! [`crate::audit::log::verify_chain`]. The attestation worker is the
//! defence against a *privileged* writer who escalates to bypass the
//! triggers — by streaming the chain head to object storage with
//! object-lock (compliance-mode WORM) on a fixed cadence, an external
//! auditor can detect a tampered chain even when every in-band guard
//! has been suborned.
//!
//! # Cadence and shape
//!
//! Every `interval` the worker:
//!
//! 1. Reads the current chain head's `seq` and `this_hash`.
//! 2. PUTs a small text blob to the configured [`BlobStore`] under
//!    `audit-attestation/{iso8601-ts}.txt`. The body is exactly
//!    `{seq}\n{this_hash_hex}\n` so an auditor can `cat` it without
//!    parsing.
//!
//! The worker NEVER calls `BlobStore::delete` (and the trait has no
//! such method). The S3 object-lock policy is operator-side; the
//! worker assumes the bucket is configured to refuse deletes.
//!
//! # No-head case
//!
//! When the chain is empty (no rows yet), the worker skips the tick
//! and waits for the next `interval`. This avoids writing an
//! attestation blob with a meaningless "no rows" sentinel that an
//! auditor might mistake for "rows were deleted".

use std::sync::Arc;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use sqlx::PgPool;
use tracing::{debug, info, warn};

use crate::audit::log::current_head;
use crate::evidence::blob_store::{BlobStore, BlobStoreError};

/// Errors emitted by the attestation worker's tick loop.
///
/// The `run` loop turns each per-tick failure into a `warn!` log line
/// and continues so a transient blob-store outage does not crash the
/// worker. The typed enum exists so the single-tick test path can
/// match on the failure category.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Database error during head lookup.
    #[error("attestation database error")]
    Db(#[source] sqlx::Error),
    /// Blob-store error during head PUT.
    #[error("attestation blob-store error")]
    BlobStore(#[source] BlobStoreError),
}

impl From<sqlx::Error> for AttestationError {
    fn from(err: sqlx::Error) -> Self {
        Self::Db(err)
    }
}

impl From<BlobStoreError> for AttestationError {
    fn from(err: BlobStoreError) -> Self {
        Self::BlobStore(err)
    }
}

/// Periodic attestation worker.
///
/// Hold-`Arc`-of-trait-object so the same backend can be shared with
/// the evidence worker (#33) without a second factory plumbing pass.
#[derive(Debug, Clone)]
pub struct AttestationWorker {
    pool: PgPool,
    blob_store: Arc<dyn BlobStore>,
    interval: Duration,
}

impl AttestationWorker {
    /// Build a new attestation worker.
    #[must_use]
    pub fn new(pool: PgPool, blob_store: Arc<dyn BlobStore>, interval: Duration) -> Self {
        Self {
            pool,
            blob_store,
            interval,
        }
    }

    /// Run forever, attesting the chain head every `interval`.
    ///
    /// Per-tick failures are logged at `warn!` and swallowed so the
    /// loop survives a transient outage. This call returns only if the
    /// process exits.
    pub async fn run(self) {
        info!(
            interval_secs = self.interval.as_secs(),
            "audit attestation worker starting"
        );
        let mut ticker = tokio::time::interval(self.interval);
        // We deliberately do NOT fire the first tick immediately —
        // `Interval::tick` fires at `t=0` by default, which would
        // attest an empty chain on every fresh process start.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match self.attest_once().await {
                Ok(Some((seq, hash_hex))) => {
                    debug!(seq, this_hash = %hash_hex, "audit attestation tick wrote head");
                }
                Ok(None) => {
                    debug!("audit attestation tick: chain empty, skipping");
                }
                Err(err) => {
                    warn!(error = ?err, "audit attestation tick failed");
                }
            }
        }
    }

    /// Run exactly one attestation tick. Returns the seq + hex hash
    /// that was attested, or `None` when the chain was empty.
    ///
    /// Public-but-`pub(crate)` for the single-tick integration test in
    /// `tests/audit_chain.rs`.
    ///
    /// # Errors
    ///
    /// - [`AttestationError::Db`] if the head lookup query fails.
    /// - [`AttestationError::BlobStore`] if the PUT fails.
    pub async fn attest_once(&self) -> Result<Option<(i64, String)>, AttestationError> {
        let Some((seq, head_bytes)) = current_head(&self.pool).await? else {
            return Ok(None);
        };
        let hash_hex = hex::encode(&head_bytes);
        let body = format!("{seq}\n{hash_hex}\n");
        let key = format!(
            "audit-attestation/{}.txt",
            Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
        );
        self.blob_store
            .put(&key, bytes::Bytes::from(body.into_bytes()))
            .await?;
        Ok(Some((seq, hash_hex)))
    }
}
