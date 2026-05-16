//! Cross-instance federation (issue #107 / M5 PR 1).
//!
//! Polaris federation allows a network of trusted Polaris instances to share
//! case data. This module implements the **ingestion** half: subscribing to a
//! configured peer's ATProto Firehose, filtering commits to Polaris NSIDs,
//! verifying commit signatures, and materialising records into the
//! `federation_quarantine` table.
//!
//! Promotion of quarantined records into the active case store is handled by
//! PR 2 (#108).
//!
//! # Module layout
//!
//! - [`peer_subscribe`] — per-peer Firehose worker with cancel-safe pump/
//!   consume split.
//! - [`verify`] — commit-signature verifier and `PeerKeyResolver`.
//!
//! # Startup
//!
//! Call [`spawn_federation_worker`] from `main.rs` (conditionally, when
//! `config.federation.enabled = true`). It creates one `JoinSet` for the
//! federation supervisor and one child task per configured peer.

pub mod peer_subscribe;
pub mod verify;

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use sqlx::PgPool;

use crate::config::FederationConfig;
pub use crate::config::PeerConfig;

// Re-export FederationDirection so peer_subscribe can use it.
pub use crate::config::FederationDirection;

// ── error type ────────────────────────────────────────────────────────────

/// Errors that can arise during federation ingestion.
///
/// Per the brief: `thiserror`-derived, structured variants, no `unwrap`.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    /// A peer DID that is not in the operator's `[[federation_peers]]` list
    /// was passed to the worker spawner.
    #[error("peer DID {0} is not in the configured federation peers list")]
    PeerNotConfigured(String),

    /// The commit's ECDSA signature did not verify against the peer's
    /// declared public key.
    #[error("signature verification failed for cid={cid} from peer did={did}")]
    SignatureVerifyFailed {
        /// CID of the commit that failed verification.
        cid: String,
        /// DID of the peer that emitted the commit.
        did: String,
    },

    /// The peer's DID document or `app.bsky.labeler.service` record could
    /// not be fetched.
    #[error("failed to fetch repo data for peer did={did}: {message}")]
    RepoFetchFailed {
        /// Peer DID.
        did: String,
        /// Human-readable error description.
        message: String,
    },

    /// Writing to `federation_quarantine` failed.
    #[error("failed to write to federation_quarantine")]
    QuarantineWriteFailed(#[from] sqlx::Error),

    /// The peer has no `app.bsky.labeler.service` record (or it is missing
    /// the `signingKey` field).
    #[error("labeler service record not found for peer did={did}")]
    LabelerServiceNotFound {
        /// Peer DID.
        did: String,
    },
}

// ── worker startup ────────────────────────────────────────────────────────

/// Spawn the federation worker supervisor.
///
/// Creates one `JoinSet` for peer workers; each peer gets an independent
/// child task so a single peer failure does not affect the others. The
/// returned [`JoinHandle`] resolves when all peer tasks have exited (either
/// via cancellation or a fatal error).
///
/// The caller must hold the handle for the process lifetime so SIGINT
/// propagates through the cancellation token.
///
/// # Errors
///
/// Individual peer task errors are logged at `WARN`; the supervisor task
/// itself does not return them — it runs until `cancel` fires.
#[must_use]
pub fn spawn_federation_worker(
    cfg: FederationConfig,
    pool: PgPool,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        run_federation_supervisor(cfg, pool, cancel).await;
    })
}

/// Drive all peer workers inside a `JoinSet`.
async fn run_federation_supervisor(cfg: FederationConfig, pool: PgPool, cancel: CancellationToken) {
    if cfg.peers.is_empty() {
        info!("federation enabled but no peers configured; supervisor exiting");
        return;
    }

    info!(
        peer_count = cfg.peers.len(),
        "federation supervisor starting",
    );

    let ttl = Duration::from_secs(cfg.public_key_cache_ttl_secs);
    let fetcher: Box<dyn verify::LabelerServiceFetcher> =
        Box::new(verify::LiveLabelerServiceFetcher::new());
    let resolver = Arc::new(verify::PeerKeyResolver::new(ttl, fetcher));

    let mut set = JoinSet::new();

    for peer in cfg.peers {
        let peer_clone = peer.clone();
        let pool_clone = pool.clone();
        let resolver_clone = resolver.clone();
        let cancel_clone = cancel.clone();

        info!(peer_did = %peer.did, direction = ?peer.direction, "spawning federation peer worker");

        set.spawn(async move {
            peer_subscribe::run_peer_worker(peer_clone, pool_clone, resolver_clone, cancel_clone)
                .await
        });
    }

    // Drain the JoinSet. Each task runs until cancelled or fatal error.
    while let Some(outcome) = set.join_next().await {
        match outcome {
            Ok(Ok(())) => {
                // Peer worker exited cleanly (cancellation or graceful stop).
            }
            Ok(Err(err)) => {
                warn!(error = ?err, "federation peer worker exited with error");
            }
            Err(join_err) => {
                warn!(error = ?join_err, "federation peer worker task panicked");
            }
        }
    }

    info!("federation supervisor: all peer workers exited");
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

    /// Verify `FederationError` variants produce readable Display output.
    #[test]
    fn federation_error_display() {
        let e = FederationError::PeerNotConfigured("did:plc:abc".to_owned());
        assert!(e.to_string().contains("did:plc:abc"));

        let e = FederationError::SignatureVerifyFailed {
            cid: "bafybeiabc".to_owned(),
            did: "did:plc:xyz".to_owned(),
        };
        let s = e.to_string();
        assert!(s.contains("bafybeiabc"));
        assert!(s.contains("did:plc:xyz"));

        let e = FederationError::RepoFetchFailed {
            did: "did:plc:peer".to_owned(),
            message: "connection refused".to_owned(),
        };
        let s = e.to_string();
        assert!(s.contains("did:plc:peer"));
        assert!(s.contains("connection refused"));

        let e = FederationError::LabelerServiceNotFound {
            did: "did:plc:nolabeler".to_owned(),
        };
        assert!(e.to_string().contains("did:plc:nolabeler"));
    }

    /// Verify `QuarantineWriteFailed` is constructible from a `sqlx::Error`
    /// via the `#[from]` derive.
    #[test]
    fn quarantine_write_failed_from_sqlx() {
        // Construct a sqlx::Error via the RowNotFound variant (always available).
        let sqlx_err = sqlx::Error::RowNotFound;
        let fed_err: FederationError = FederationError::QuarantineWriteFailed(sqlx_err);
        assert!(fed_err.to_string().contains("federation_quarantine"));
    }

    /// Verify the supervisor exits promptly when cancellation fires with no
    /// peers configured (degenerate case — zero child tasks).
    #[tokio::test]
    async fn supervisor_exits_on_empty_peers() {
        let cfg = FederationConfig {
            enabled: true,
            public_key_cache_ttl_secs: 21600,
            peers: vec![],
        };
        let pool = sqlx::PgPool::connect_lazy("postgres://localhost/nonexistent").unwrap();
        let cancel = CancellationToken::new();

        // Should return immediately since there are no peers.
        let handle = spawn_federation_worker(cfg, pool, cancel.clone());
        handle.await.unwrap();
    }
}
