//! Object-storage abstraction for evidence CARs (issue #33).
//!
//! [`BlobStore`] is the trait the [`crate::evidence::worker::EvidenceWorker`]
//! depends on. The trait keeps the worker pure with respect to storage —
//! tests run against [`InMemoryBlobStore`], the labeler-profile binary
//! runs against [`LocalFsBlobStore`], and the Bluesky-profile binary
//! runs against [`S3BlobStore`] (feature-gated; #69 wires the
//! end-to-end S3 plumbing with minio tests).
//!
//! # Key shape
//!
//! Callers compute the blob key from the CAR's SHA-256 hex with
//! [`crate::evidence::worker::blob_key_for_cid`]; the shape
//! `evidence/{first-two-hex}/{full-hex}` keeps any one directory
//! bounded to ~256 entries even at billions of evidence CARs.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::AsyncWriteExt as _;
use tokio::sync::RwLock;

/// Errors returned by [`BlobStore`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum BlobStoreError {
    /// The requested key does not exist.
    #[error("blob not found")]
    NotFound,
    /// Local filesystem I/O failure.
    #[error("local-fs I/O error: {0}")]
    Io(#[from] io::Error),
    /// S3 SDK error (feature-gated).
    ///
    /// Falls through to [`BlobStoreError::Other`] for unrecognised
    /// failure modes; the variant exists so structured logging can
    /// route the S3 error chain.
    #[cfg(feature = "s3-blob-store")]
    #[error("S3 error: {0}")]
    S3(String),
    /// Anything not covered by the above. Used by the in-memory store
    /// (which has no real I/O surface) and as the residual variant for
    /// the S3 stub.
    #[error("blob-store error: {0}")]
    Other(String),
}

/// Content-addressed object storage.
///
/// Implementations are `Send + Sync + Debug`; the worker holds them as
/// `Arc<dyn BlobStore>` so the spawn-under-semaphore tasks can share a
/// single backend without per-task cloning.
///
/// The trait is `#[async_trait]`-decorated so it stays dyn-compatible
/// (each method's future becomes a `Pin<Box<dyn Future + Send>>`).
/// The per-call `Box<Future>` allocation is negligible at evidence-CAR
/// rates (one per moderator action on a record); the workspace
/// already pays this cost for the repo traits via the same
/// `async-trait` macro.
#[async_trait]
pub trait BlobStore: Send + Sync + std::fmt::Debug {
    /// Store `bytes` at `key`. Idempotent — writing the same key with
    /// the same content is a no-op. Writing the same key with
    /// different content is implementation-defined; the in-memory and
    /// local-fs impls overwrite.
    async fn put(&self, key: &str, bytes: Bytes) -> Result<(), BlobStoreError>;

    /// Retrieve the bytes at `key`. Returns `Ok(None)` when no blob
    /// exists at `key`.
    async fn get(&self, key: &str) -> Result<Option<Bytes>, BlobStoreError>;

    /// `true` when a blob exists at `key`.
    async fn exists(&self, key: &str) -> Result<bool, BlobStoreError>;
}

/// In-memory blob store, for tests.
///
/// Backed by `Arc<tokio::sync::RwLock<HashMap<_, _>>>`. We use the
/// tokio async lock rather than `Arc<Mutex<_>>` (forbidden by the
/// rust-quality workspace lints) so the lock can be held across
/// `.await` points without risk of blocking the runtime.
///
/// `DashMap` would be lock-free, but adding it as a workspace
/// dependency for an in-memory test fake is disproportionate to the
/// value. The contention here is bounded by the worker's semaphore
/// concurrency (default 4), so a fair-readers `RwLock` is fine.
#[derive(Debug, Default, Clone)]
pub struct InMemoryBlobStore {
    inner: Arc<RwLock<HashMap<String, Bytes>>>,
}

impl InMemoryBlobStore {
    /// Build an empty in-memory blob store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Count of keys currently stored (test helper).
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Snapshot the current set of stored keys (test helper).
    ///
    /// The production [`BlobStore`] trait intentionally omits a list
    /// operation — the production backends (S3, local FS) treat
    /// enumeration as out-of-band. Integration tests in
    /// `tests/audit_chain.rs` (issue #35) need to enumerate keys
    /// written by the attestation worker because the key suffix is a
    /// `Utc::now()` timestamp the test cannot reproduce; the snapshot
    /// is the minimum-surface accessor.
    pub async fn snapshot_keys(&self) -> Vec<String> {
        self.inner.read().await.keys().cloned().collect()
    }

    /// `true` when no blobs are stored (test helper).
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}

#[async_trait]
impl BlobStore for InMemoryBlobStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<(), BlobStoreError> {
        self.inner.write().await.insert(key.to_owned(), bytes);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, BlobStoreError> {
        Ok(self.inner.read().await.get(key).cloned())
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobStoreError> {
        Ok(self.inner.read().await.contains_key(key))
    }
}

/// Filesystem-backed blob store.
///
/// Default for the labeler deployment profile. Writes atomically by
/// writing to `{root}/{key}.tmp` then `rename`-ing into place; an
/// interrupted write leaves only the `.tmp` file (invisible to
/// `get`/`exists`).
///
/// `key` may contain `/` separators (the canonical shape is
/// `evidence/{prefix}/{full-hex}`); the impl creates intermediate
/// directories with `create_dir_all`.
#[derive(Debug, Clone)]
pub struct LocalFsBlobStore {
    root: PathBuf,
}

impl LocalFsBlobStore {
    /// Build a [`LocalFsBlobStore`] rooted at `root`.
    ///
    /// The directory is created lazily on the first `put`; callers do
    /// not need to ensure it exists.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn path_for(&self, key: &str) -> PathBuf {
        self.root.join(key)
    }
}

#[async_trait]
impl BlobStore for LocalFsBlobStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<(), BlobStoreError> {
        let final_path = self.path_for(key);
        if let Some(parent) = final_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        // Atomic write: tmp file → rename. An interrupted process
        // leaves only the .tmp shard, which `get`/`exists` ignore.
        let mut tmp_path = final_path.clone();
        let mut tmp_name = tmp_path
            .file_name()
            .map(std::ffi::OsStr::to_os_string)
            .unwrap_or_default();
        tmp_name.push(".tmp");
        tmp_path.set_file_name(tmp_name);
        {
            let mut file = tokio::fs::File::create(&tmp_path).await?;
            file.write_all(&bytes).await?;
            file.sync_all().await?;
        }
        tokio::fs::rename(&tmp_path, &final_path).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, BlobStoreError> {
        match tokio::fs::read(self.path_for(key)).await {
            Ok(bytes) => Ok(Some(Bytes::from(bytes))),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(BlobStoreError::Io(err)),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobStoreError> {
        match tokio::fs::metadata(self.path_for(key)).await {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(BlobStoreError::Io(err)),
        }
    }
}

// ── S3 stub ─────────────────────────────────────────────────────────────
//
// Feature-gated behind `s3-blob-store` so a stock build does not pull
// the AWS SDK tree. The body intentionally calls real `aws-sdk-s3`
// methods — `put_object`, `get_object`, `head_object` — against the
// SDK's default credential chain, but end-to-end wiring (minio tests,
// retry policy, error-class routing) is filed as #69 follow-up. The
// stub returns `BlobStoreError::Other("not yet wired")` for any code
// path it does not yet implement so a misconfigured Bluesky-profile
// deployment fails closed rather than silently dropping CARs.
//
// Credentials handling: we use the SDK's `from_env` default chain
// (env > shared config > IMDS > SSO). Plaintext credentials never
// appear in this code path; the SDK reads them from process env.

/// S3-backed blob store (feature-gated, skeleton).
///
/// **Not production-ready.** Issue #69 covers end-to-end wiring,
/// minio integration tests, and the retry / error-class routing
/// against the AWS SDK error tree. The skeleton exists so the
/// Bluesky-profile binary's startup can pick between
/// `LocalFsBlobStore` and `S3BlobStore` without paying for a
/// half-wired backend — the methods below call real SDK ops, and
/// failures surface as typed [`BlobStoreError::S3`] strings the
/// operator can act on.
#[cfg(feature = "s3-blob-store")]
#[derive(Debug, Clone)]
pub struct S3BlobStore {
    client: aws_sdk_s3::Client,
    bucket: String,
}

#[cfg(feature = "s3-blob-store")]
impl S3BlobStore {
    /// Build an [`S3BlobStore`] against `bucket` using the supplied
    /// SDK client (which carries the credential chain).
    #[must_use]
    pub fn new(client: aws_sdk_s3::Client, bucket: impl Into<String>) -> Self {
        Self {
            client,
            bucket: bucket.into(),
        }
    }
}

#[cfg(feature = "s3-blob-store")]
#[async_trait]
impl BlobStore for S3BlobStore {
    async fn put(&self, key: &str, bytes: Bytes) -> Result<(), BlobStoreError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes.to_vec()))
            .send()
            .await
            .map_err(|e| BlobStoreError::S3(format!("{e}")))?;
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<Bytes>, BlobStoreError> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => {
                let data = out
                    .body
                    .collect()
                    .await
                    .map_err(|e| BlobStoreError::S3(format!("body: {e}")))?
                    .into_bytes();
                Ok(Some(Bytes::from(data.to_vec())))
            }
            Err(e) => {
                let s = format!("{e}");
                if s.contains("NoSuchKey") || s.contains("404") {
                    Ok(None)
                } else {
                    Err(BlobStoreError::S3(s))
                }
            }
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, BlobStoreError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let s = format!("{e}");
                if s.contains("NotFound") || s.contains("404") {
                    Ok(false)
                } else {
                    Err(BlobStoreError::S3(s))
                }
            }
        }
    }
}

// ── helpers ─────────────────────────────────────────────────────────────

/// `true` when `path` is a regular file (test-friendly form of
/// `LocalFsBlobStore::exists` that does not consult tokio).
#[must_use]
#[doc(hidden)]
pub fn is_file_sync(path: &Path) -> bool {
    path.is_file()
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

    #[tokio::test]
    async fn in_memory_round_trip() {
        let store = InMemoryBlobStore::new();
        assert!(store.is_empty().await);

        let key = "evidence/ab/abcd";
        let payload = Bytes::from_static(b"hello evidence");
        store.put(key, payload.clone()).await.unwrap();
        assert_eq!(store.len().await, 1);
        assert!(store.exists(key).await.unwrap());
        assert_eq!(store.get(key).await.unwrap(), Some(payload));
        assert!(!store.exists("evidence/zz/missing").await.unwrap());
        assert_eq!(store.get("evidence/zz/missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn local_fs_round_trip_and_atomic_write() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = LocalFsBlobStore::new(tmp.path());
        let key = "evidence/ab/abcd";
        let payload = Bytes::from_static(b"local fs evidence bytes");

        store.put(key, payload.clone()).await.unwrap();
        assert!(store.exists(key).await.unwrap());
        assert_eq!(store.get(key).await.unwrap(), Some(payload.clone()));

        // No stray `.tmp` shard left behind by a successful write.
        let tmp_shard = tmp.path().join("evidence/ab/abcd.tmp");
        assert!(
            !is_file_sync(&tmp_shard),
            ".tmp shard must be renamed away on success",
        );

        // Simulate an interrupted write by manually creating a .tmp
        // file. `exists`/`get` must still report the original payload
        // as the canonical bytes.
        tokio::fs::write(&tmp_shard, b"partial corrupt write")
            .await
            .unwrap();
        assert!(store.exists(key).await.unwrap());
        assert_eq!(store.get(key).await.unwrap(), Some(payload));
    }

    #[tokio::test]
    async fn local_fs_put_is_idempotent_for_identical_payload() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = LocalFsBlobStore::new(tmp.path());
        let key = "evidence/ab/abcd";
        let payload = Bytes::from_static(b"idempotent write");
        store.put(key, payload.clone()).await.unwrap();
        // Second put with the same bytes must succeed without error.
        store.put(key, payload.clone()).await.unwrap();
        assert_eq!(store.get(key).await.unwrap(), Some(payload));
    }

    #[tokio::test]
    async fn local_fs_get_missing_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = LocalFsBlobStore::new(tmp.path());
        assert_eq!(store.get("never/written").await.unwrap(), None);
        assert!(!store.exists("never/written").await.unwrap());
    }
}
