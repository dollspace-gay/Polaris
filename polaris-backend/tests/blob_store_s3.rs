//! Integration test for [`polaris_backend::evidence::S3BlobStore`] against
//! a minio testcontainer (issue #68 / REQ-10 / AC-11).
//!
//! Boots an S3-compatible minio container via
//! [`testcontainers_modules::minio::MinIO`], creates a bucket, then
//! drives the production `S3BlobStore` through its `BlobStore` trait
//! contract: put/get round-trip on a known key returns the original
//! bytes, `exists` on a missing key is `Ok(false)`, `get` on a missing
//! key is `Ok(None)`, and a second `put` with identical bytes is a
//! no-op (S3 default semantics).
//!
//! # Skip behaviour
//!
//! If Docker is not reachable on the host, the test prints a clear
//! skip message and returns successfully. The compile-time requirement
//! (`cargo test -p polaris-backend --features s3-blob-store --no-run
//! --test blob_store_s3`) ALWAYS passes — only the runtime is
//! environment-dependent. This matches the workspace pattern set by
//! `tests/db_smoke.rs` and the bus integration tests.
//!
//! # Feature gating
//!
//! The entire file is `#[cfg(feature = "s3-blob-store")]`: without
//! the feature, the AWS SDK is not in the build graph and the
//! `S3BlobStore` type is invisible. The default `cargo test -p
//! polaris-backend` invocation simply skips this file.

#![cfg(feature = "s3-blob-store")]
#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use bytes::Bytes;
use polaris_backend::evidence::{BlobStore, S3BlobStore};
use testcontainers_modules::minio::MinIO;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// Default minio credentials baked into the upstream container image.
///
/// The container exposes these as the root credentials; the test
/// creates a bucket under them and then drives the
/// [`S3BlobStore::from_endpoint`] constructor with the same pair.
/// Real deployments do **not** use these — production paths go through
/// the SDK's default credential chain (`main.rs::build_s3_blob_store`).
const MINIO_ACCESS_KEY: &str = "minioadmin";
const MINIO_SECRET_KEY: &str = "minioadmin";
const TEST_REGION: &str = "us-east-1";
const TEST_BUCKET: &str = "polaris-evidence-test";

/// Probe for a working Docker daemon. We deliberately avoid pulling
/// in a Docker client crate just for this — the `docker info` exit
/// code is the canonical signal.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Create the test bucket on the running minio. Uses the raw
/// `aws_sdk_s3::Client` (not the `S3BlobStore` wrapper) because bucket
/// creation is out-of-band of the `BlobStore` trait.
async fn create_bucket(endpoint_url: &str) {
    let creds = aws_sdk_s3::config::Credentials::new(
        MINIO_ACCESS_KEY,
        MINIO_SECRET_KEY,
        None,
        None,
        "polaris-test-bucket-bootstrap",
    );
    let region = aws_sdk_s3::config::Region::new(TEST_REGION);
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region)
        .endpoint_url(endpoint_url)
        .credentials_provider(creds)
        .load()
        .await;
    let s3_cfg = aws_sdk_s3::config::Builder::from(&sdk_config)
        .force_path_style(true)
        .build();
    let client = aws_sdk_s3::Client::from_conf(s3_cfg);
    client
        .create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create_bucket against minio");
}

/// Full round-trip: put/get/exists, plus missing-key and idempotency
/// invariants. One test rather than four so we pay the container
/// startup cost (~3 s) exactly once.
#[tokio::test]
async fn s3_blob_store_round_trip_against_minio() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP blob_store_s3: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test."
        );
        return Ok(());
    }

    // Boot the minio container. The module image exposes port 9000 for
    // the S3-compatible API; `get_host_port_ipv4` resolves the local
    // port the container engine forwarded to.
    let minio = MinIO::default().start().await?;
    let host_port = minio.get_host_port_ipv4(9000).await?;
    let endpoint_url = format!("http://127.0.0.1:{host_port}");

    // Provision a bucket up front. `S3BlobStore` never creates
    // buckets (production deployments treat buckets as
    // operator-managed) so the test drives the SDK directly.
    create_bucket(&endpoint_url).await;

    // Construct the production `S3BlobStore` exactly as a deployment
    // pointing at a non-AWS endpoint would.
    let store = S3BlobStore::from_endpoint(
        &endpoint_url,
        TEST_BUCKET,
        TEST_REGION,
        MINIO_ACCESS_KEY,
        MINIO_SECRET_KEY,
    )
    .await?;

    // ── (1) put + get round-trip ────────────────────────────────────
    let key = "evidence/ab/abcd1234deadbeef";
    let payload = Bytes::from_static(b"polaris evidence-CAR round-trip payload");
    store.put(key, payload.clone()).await?;
    let fetched = store.get(key).await?;
    assert_eq!(
        fetched,
        Some(payload.clone()),
        "round-trip get must return the original payload",
    );

    // ── (2) exists on a known key is true ───────────────────────────
    assert!(
        store.exists(key).await?,
        "exists on a key we just wrote must be true",
    );

    // ── (3) exists on a missing key is Ok(false) ────────────────────
    let missing_key = "evidence/zz/never-written-key";
    assert!(
        !store.exists(missing_key).await?,
        "exists on a never-written key must collapse to Ok(false)",
    );

    // ── (4) get on a missing key is Ok(None) ────────────────────────
    let missing = store.get(missing_key).await?;
    assert_eq!(
        missing, None,
        "get on a never-written key must collapse to Ok(None) via the \
         NoSuchKey discriminant in SdkError",
    );

    // ── (5) idempotent put with identical bytes ─────────────────────
    // S3 default semantics: a second PUT of the same key overwrites
    // with the same content, which is observationally a no-op. We
    // assert the post-state is unchanged.
    store.put(key, payload.clone()).await?;
    let fetched_again = store.get(key).await?;
    assert_eq!(
        fetched_again,
        Some(payload),
        "second put with identical bytes must leave the object identical",
    );

    Ok(())
}
