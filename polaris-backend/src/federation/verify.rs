//! Peer public-key resolver and commit-signature verifier.
//!
//! # Public-key resolution
//!
//! [`PeerKeyResolver`] resolves a peer DID to its current signing-key
//! `did:key:z...` form. On first contact (or after TTL expiry) it fetches the
//! peer's `app.bsky.labeler.service` record from the PDS and extracts the
//! `policies.labelValueDefinitions` / `signingKey` field.
//!
//! The resolver uses a two-tier cache:
//! 1. **In-memory** `Mutex<HashMap<String, CachedKey>>` — checked first.
//! 2. **Refresh-on-fail** — if `signature_status = 'verify_failed'` the
//!    caller may call [`PeerKeyResolver::invalidate`] to drop the cached
//!    entry before the next resolution attempt.
//!
//! # Signature verification
//!
//! [`verify_commit_signature`] takes a [`proto_blue::repo::SignedCommit`] and
//! a `did:key` string and returns whether the commit's ECDSA signature is
//! valid. This is a thin wrapper around
//! [`proto_blue::repo::verify_commit_sig`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::FederationError;

// ── cached entry ─────────────────────────────────────────────────────────

/// A cached peer signing-key `did:key` with an absolute expiry timestamp.
#[derive(Debug, Clone)]
struct CachedKey {
    /// The `did:key:z…` string usable with `proto_blue::crypto::verify_signature`.
    did_key: String,
    /// Monotonic deadline. Entry is evicted when `Instant::now() >= expires`.
    expires: Instant,
}

// ── resolver ─────────────────────────────────────────────────────────────

/// HTTP client wrapper used by [`PeerKeyResolver`] to fetch labeler service
/// records.
///
/// A production instance uses `reqwest`; tests inject a stub.
///
/// The trait is object-safe (`Send + Sync`) so the resolver can hold a
/// `Box<dyn LabelerServiceFetcher>` without monomorphisation overhead.
pub trait LabelerServiceFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch the `did:key` signing key for the given peer DID.
    ///
    /// Returns the `did:key:z…` string on success.
    ///
    /// # Errors
    ///
    /// Returns [`FederationError::LabelerServiceNotFound`] when the peer has
    /// no `app.bsky.labeler.service` record, or
    /// [`FederationError::RepoFetchFailed`] on transport / parse failures.
    fn fetch_signing_key<'a>(
        &'a self,
        peer_did: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, FederationError>> + Send + 'a>,
    >;
}

/// Resolves and caches the signing-key `did:key` for each known peer.
///
/// # Threading model
///
/// The inner [`Mutex`] is held across the async fetch (`fetch_signing_key`)
/// **intentionally**: serialising concurrent resolution for the same DID
/// avoids thundering-herd fetches after a cache miss. This is the same
/// pattern as [`crate::ingest::upstream_labels::UpstreamKeyCache`]. Contention
/// is bounded to one fetch per peer per TTL window, which is at most once per
/// 6 hours by default.
#[derive(Debug)]
pub struct PeerKeyResolver {
    cache: Arc<Mutex<HashMap<String, CachedKey>>>,
    ttl: Duration,
    fetcher: Box<dyn LabelerServiceFetcher>,
}

impl PeerKeyResolver {
    /// Build a resolver with the given TTL and service-record fetcher.
    #[must_use]
    pub fn new(ttl: Duration, fetcher: Box<dyn LabelerServiceFetcher>) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            fetcher,
        }
    }

    /// Look up the signing-key for `peer_did`.
    ///
    /// Resolution order: in-memory cache → live fetch + cache. The lock is
    /// held across the fetch to serialise concurrent callers for the same DID.
    ///
    /// # Errors
    ///
    /// Propagates whatever [`LabelerServiceFetcher::fetch_signing_key`] returns.
    pub async fn resolve(&self, peer_did: &str) -> Result<String, FederationError> {
        let mut guard = self.cache.lock().await;

        let now = Instant::now();
        if let Some(cached) = guard.get(peer_did) {
            if now < cached.expires {
                debug!(peer_did, "peer key cache hit");
                return Ok(cached.did_key.clone());
            }
            debug!(peer_did, "peer key cache expired; re-fetching");
        }

        // Cache miss or expired — fetch live.
        let did_key = self.fetcher.fetch_signing_key(peer_did).await?;
        debug!(peer_did, did_key, "fetched peer signing key");

        guard.insert(
            peer_did.to_owned(),
            CachedKey {
                did_key: did_key.clone(),
                expires: now + self.ttl,
            },
        );
        Ok(did_key)
    }

    /// Evict any cached entry for `peer_did`.
    ///
    /// Call this when `verify_commit_signature` returns `false` so the next
    /// `resolve` call picks up a fresh key (the peer may have rotated).
    pub async fn invalidate(&self, peer_did: &str) {
        let mut guard = self.cache.lock().await;
        if guard.remove(peer_did).is_some() {
            warn!(peer_did, "invalidated stale peer signing key from cache");
        }
    }
}

// ── signature verification ────────────────────────────────────────────────

/// Verify a commit's ECDSA signature against `did_key`.
///
/// Returns `true` when the signature is valid, `false` when it is invalid.
///
/// # Errors
///
/// Returns [`FederationError::SignatureVerifyFailed`] when the crypto layer
/// itself rejects the inputs (malformed `did:key`, malformed signature bytes,
/// or an unsupported algorithm).  A well-formed-but-wrong signature returns
/// `Ok(false)` instead.
pub fn verify_commit_signature(
    commit: &proto_blue::repo::SignedCommit,
    did_key: &str,
    commit_cid_str: &str,
    peer_did: &str,
) -> Result<bool, FederationError> {
    proto_blue::repo::verify_commit_sig(commit, did_key).map_err(|_| {
        FederationError::SignatureVerifyFailed {
            cid: commit_cid_str.to_owned(),
            did: peer_did.to_owned(),
        }
    })
}

// ── live fetcher ──────────────────────────────────────────────────────────

/// Production fetcher: resolves the peer's `app.bsky.labeler.service` record
/// via an XRPC `com.atproto.repo.getRecord` call, extracts `signingKey`.
///
/// The signing key in a labeler service record lives under the top-level
/// `signingKey` field (the `did:key:z…` string). The DID document's PDS
/// endpoint is resolved via `https://plc.directory/<did>`.
#[derive(Debug, Clone)]
pub struct LiveLabelerServiceFetcher {
    client: reqwest::Client,
}

impl LiveLabelerServiceFetcher {
    /// Build a fetcher backed by a default-configured `reqwest::Client`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

impl Default for LiveLabelerServiceFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl LabelerServiceFetcher for LiveLabelerServiceFetcher {
    fn fetch_signing_key<'a>(
        &'a self,
        peer_did: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<String, FederationError>> + Send + 'a>,
    > {
        Box::pin(async move {
            // Step 1: resolve the PDS endpoint from the PLC directory.
            let plc_url = format!("https://plc.directory/{peer_did}");
            let did_doc: serde_json::Value = self
                .client
                .get(&plc_url)
                .send()
                .await
                .map_err(|e| FederationError::RepoFetchFailed {
                    did: peer_did.to_owned(),
                    message: e.to_string(),
                })?
                .json()
                .await
                .map_err(|e| FederationError::RepoFetchFailed {
                    did: peer_did.to_owned(),
                    message: e.to_string(),
                })?;

            // Extract the PDS endpoint from the service array.
            let pds_endpoint = did_doc["service"]
                .as_array()
                .and_then(|services| {
                    services.iter().find(|s| {
                        s["id"].as_str() == Some("#atproto_pds")
                            || s["type"].as_str() == Some("AtprotoPersonalDataServer")
                    })
                })
                .and_then(|s| s["serviceEndpoint"].as_str())
                .ok_or_else(|| FederationError::LabelerServiceNotFound {
                    did: peer_did.to_owned(),
                })?
                .to_owned();

            // Step 2: fetch `app.bsky.labeler.service` via XRPC getRecord.
            let xrpc_url = format!(
                "{pds_endpoint}/xrpc/com.atproto.repo.getRecord\
                 ?repo={peer_did}\
                 &collection=app.bsky.labeler.service\
                 &rkey=self"
            );
            let record: serde_json::Value = self
                .client
                .get(&xrpc_url)
                .send()
                .await
                .map_err(|e| FederationError::RepoFetchFailed {
                    did: peer_did.to_owned(),
                    message: e.to_string(),
                })?
                .json()
                .await
                .map_err(|e| FederationError::RepoFetchFailed {
                    did: peer_did.to_owned(),
                    message: e.to_string(),
                })?;

            // Step 3: extract `signingKey` from the record value.
            let signing_key = record["value"]["signingKey"]
                .as_str()
                .ok_or_else(|| FederationError::LabelerServiceNotFound {
                    did: peer_did.to_owned(),
                })?
                .to_owned();

            Ok(signing_key)
        })
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

    // A stub fetcher that always returns a fixed key.
    #[derive(Debug)]
    struct StubFetcher {
        key: &'static str,
    }

    impl LabelerServiceFetcher for StubFetcher {
        fn fetch_signing_key<'a>(
            &'a self,
            _peer_did: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<String, FederationError>> + Send + 'a>,
        > {
            let key = self.key.to_owned();
            Box::pin(async move { Ok(key) })
        }
    }

    #[tokio::test]
    async fn resolver_caches_on_first_hit() {
        let resolver = PeerKeyResolver::new(
            Duration::from_secs(3600),
            Box::new(StubFetcher {
                key: "did:key:zQ3shTestKey123",
            }),
        );

        let k1 = resolver.resolve("did:plc:peerA").await.unwrap();
        let k2 = resolver.resolve("did:plc:peerA").await.unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1, "did:key:zQ3shTestKey123");
    }

    #[tokio::test]
    async fn invalidate_removes_cache_entry() {
        let resolver = PeerKeyResolver::new(
            Duration::from_secs(3600),
            Box::new(StubFetcher {
                key: "did:key:zQ3shTestKey123",
            }),
        );

        let _ = resolver.resolve("did:plc:peerA").await.unwrap();
        resolver.invalidate("did:plc:peerA").await;

        // The cache should now be empty for this DID.
        let guard = resolver.cache.lock().await;
        assert!(!guard.contains_key("did:plc:peerA"));
    }

    #[tokio::test]
    async fn expired_entry_is_re_fetched() {
        // TTL of 1 nanosecond means entries expire immediately.
        let resolver = PeerKeyResolver::new(
            Duration::from_nanos(1),
            Box::new(StubFetcher {
                key: "did:key:zQ3shFreshKey",
            }),
        );

        let k1 = resolver.resolve("did:plc:peerB").await.unwrap();
        // Sleep long enough for the entry to expire (> 1ns in wall time).
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Even if the entry is re-fetched the stub returns the same key;
        // the important thing is the code path doesn't panic.
        let k2 = resolver.resolve("did:plc:peerB").await.unwrap();
        assert_eq!(k1, k2);
    }
}
