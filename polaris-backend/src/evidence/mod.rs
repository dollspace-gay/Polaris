//! Evidence preservation (issue #33 / REQ-10 / AC-11).
//!
//! When a moderator commits an action against a record-shaped subject
//! (post / list / feed — anything other than an account), the action
//! repo enqueues an `evidence_jobs` row inside the same transaction as
//! the action's INSERT (see [`crate::repo::action`]). The
//! [`worker::EvidenceWorker`] drains that table with bounded
//! concurrency, fetches the upstream record + MST proof path through an
//! [`worker::EvidenceFetcher`] (the live impl wraps a `proto-blue-api`
//! XRPC client; tests inject a mock), packages the slice as a CAR file
//! via [`proto_blue::repo::blocks_to_car`], hashes it with SHA-256, and
//! stores the bytes in object storage via a [`blob_store::BlobStore`].
//!
//! See `.design/polaris-proto-blue-integration.md` §H and the inline
//! rustdoc on [`worker::EvidenceWorker`] for the state machine.
//!
//! # Module layout
//!
//! - [`blob_store`] — [`BlobStore`] trait plus three impls (in-memory
//!   for tests, local-fs for the labeler profile, S3 stub for the
//!   Bluesky profile under the `s3-blob-store` Cargo feature).
//! - [`worker`] — [`EvidenceWorker`] plus the [`EvidenceFetcher`]
//!   abstraction the tests mock around.

pub mod blob_store;
pub mod live_fetcher;
pub mod worker;

#[cfg(feature = "s3-blob-store")]
pub use blob_store::S3BlobStore;
pub use blob_store::{BlobStore, BlobStoreError, InMemoryBlobStore, LocalFsBlobStore};
pub use live_fetcher::LiveEvidenceFetcher;
pub use worker::{
    DEFAULT_MAX_ATTEMPTS, DEFAULT_RETRY_BASE_SECS, EvidenceFetcher, EvidenceFetcherError,
    EvidenceWorker, EvidenceWorkerError, FetchedEvidence, blob_key_for_cid, parse_subject_uri,
    retry_delay,
};
