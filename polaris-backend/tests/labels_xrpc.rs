//! Labeler XRPC endpoint integration test (issue #26).
//!
//! Spins up Postgres 16 via testcontainers, applies every migration
//! through `db::connect`, seeds three label rows via raw `sqlx::query!`,
//! and drives the `queryLabels` HTTP handler against the live router /
//! repo to verify:
//!
//! 1. `GET /xrpc/com.atproto.label.queryLabels?uris=at://...` returns
//!    `200 OK` with the labels that match the queried URI.
//! 2. `GET /xrpc/com.atproto.label.queryLabels` with an empty / missing
//!    `uris` parameter returns `400 Bad Request`.
//!
//! Per the architect's pre-flight, the WebSocket subscription path is
//! covered by unit tests in the module itself (CBOR-frame encoding,
//! broadcaster delivery) — the full WS-client integration test is
//! deferred to a follow-up because the CBOR-framing fixture is complex
//! and the bytes-on-the-wire shape is verifiable from the unit tests in
//! combination with the broadcaster's persistence path.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message and
//! returns successfully — same pattern as the other repo-flavoured
//! integration tests in this crate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::labeler;
use serde_json::Value;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Insert a fake label via raw `sqlx::query!`. Bypasses the repo's insert
/// path (which #28 populates with signed labels); for #26's HTTP-layer
/// tests we only need rows to back the queryLabels SELECT path.
///
/// Migration 13 added a 64-byte CHECK on `sig` and NOT NULL columns for
/// `subject_did` / `label_cbor` / `signing_did`. We seed minimum-viable
/// fixtures: a 64-byte zero signature and empty-string DIDs / empty CBOR.
/// The HTTP layer never inspects those columns; #28's emitter is the path
/// that produces cryptographically meaningful values.
async fn insert_fake_label(
    pool: &sqlx::PgPool,
    src: &str,
    uri: &str,
    val: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query!(
        r#"
        INSERT INTO labels (
            src, uri, val, sig,
            subject_did, label_cbor, signing_did
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
        src,
        uri,
        val,
        vec![0_u8; 64], // 64-byte zero signature — satisfies `labels_signature_len`
        "did:plc:fake-subject",
        Vec::<u8>::new(),
        src, // signing_did = same as src in the fixture
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Build the labeler router with a fresh `ApiState` over `pool`.
fn build_labeler_router(pool: sqlx::PgPool) -> Router {
    let crypto = Crypto::new([0u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool, sessions);
    labeler::server::router(state)
}

#[tokio::test]
async fn query_labels_returns_matching_rows() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP labels_xrpc::query_labels_returns_matching_rows: docker daemon not reachable.",
        );
        return Ok(());
    }

    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();

    let uri_a = "at://did:plc:user-a/app.bsky.feed.post/aaa";
    let uri_b = "at://did:plc:user-b/app.bsky.feed.post/bbb";
    insert_fake_label(&pool, "did:plc:labeler", uri_a, "spam").await?;
    insert_fake_label(&pool, "did:plc:labeler", uri_a, "harassment").await?;
    insert_fake_label(&pool, "did:plc:labeler", uri_b, "spam").await?;

    let router = build_labeler_router(pool);

    // URL-encode the at:// URI per RFC 3986.
    let encoded = urlencoding(uri_a);
    let request = Request::builder()
        .uri(format!(
            "/xrpc/com.atproto.label.queryLabels?uris={encoded}"
        ))
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "queryLabels should 200");

    let bytes = response.into_body().collect().await?.to_bytes();
    let body: Value = serde_json::from_slice(&bytes)?;
    let labels = body["labels"].as_array().expect("labels array");
    assert_eq!(
        labels.len(),
        2,
        "two labels target uri_a; labels = {labels:?}",
    );
    for l in labels {
        assert_eq!(l["uri"], uri_a);
        assert_eq!(l["src"], "did:plc:labeler");
    }
    Ok(())
}

#[tokio::test]
async fn query_labels_rejects_missing_uris() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP labels_xrpc::query_labels_rejects_missing_uris: docker daemon not reachable.",
        );
        return Ok(());
    }

    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();

    let router = build_labeler_router(pool);
    let request = Request::builder()
        .uri("/xrpc/com.atproto.label.queryLabels")
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "missing uris must produce 400",
    );
    Ok(())
}

/// Minimal `application/x-www-form-urlencoded`-style percent encoding
/// for an at:// URI. The test crate doesn't pull in `urlencoding` /
/// `percent-encoding` as direct deps; we hand-roll the small alphabet
/// the at:// scheme needs so we don't introduce a workspace-level dep
/// for a single test.
fn urlencoding(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                // `write!` into a String never fails — the `_ =` discards
                // the `fmt::Result` so clippy's format_push_string doesn't
                // flag the buffer-grow + `format!` allocation.
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}
