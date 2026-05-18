//! Integration test for `POST /xrpc/com.atproto.moderation.createReport`.
//!
//! Drives the production router against a testcontainers Postgres and
//! verifies the route ingests both account-level (`repoRef`) and post-
//! level (`strongRef`) reports, persisting them to the partitioned
//! `reports` table with the reporter DID extracted from the inbound
//! Authorization JWT.
//!
//! This is the runtime check that the user-visible "something went
//! wrong, please try again" failure mode (a 404 from a missing route)
//! is fixed: bsky.app's reporter flow now reaches a handler that
//! materialises a `reports` row.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::net::SocketAddr;
use std::process::Command;

use axum::body::{Body, to_bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use base64::Engine as _;
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use sqlx::PgPool;
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

async fn boot() -> Result<(axum::Router, PgPool), Box<dyn std::error::Error>> {
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
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions);
    // `ConnectInfo<SocketAddr>` is normally injected by axum's TCP
    // listener; the `oneshot` driver here bypasses that, so we install
    // a [`MockConnectInfo`] layer that pre-fills the extractor with
    // a deterministic loopback peer. Without this, the
    // `ConnectInfo` extractor in `create_report` would fail and
    // surface as a 500 ahead of the handler's own validation.
    let router = api::router_with_state(db, state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))));
    std::mem::forget(container);
    Ok((router, pool))
}

/// Build a JWT with the supplied `iss` claim. The signature is bogus —
/// the handler currently does not verify (see
/// `polaris-backend/src/api/moderation.rs::extract_reporter_did_unverified`).
fn build_jwt(iss: &str) -> String {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header = engine.encode(br#"{"alg":"ES256K","typ":"JWT"}"#);
    let payload_json = format!(r#"{{"iss":"{iss}","aud":"did:plc:polaris","exp":9999999999}}"#);
    let payload = engine.encode(payload_json.as_bytes());
    let sig = "dummy-signature-not-verified";
    format!("{header}.{payload}.{sig}")
}

async fn send_create_report(
    router: &axum::Router,
    auth: Option<&str>,
    body: serde_json::Value,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/xrpc/com.atproto.moderation.createReport")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = auth {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = builder
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .expect("build request");
    router.clone().oneshot(req).await.expect("oneshot")
}

async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        panic!(
            "body not JSON: {err}; raw: {}",
            String::from_utf8_lossy(&bytes)
        );
    })
}

async fn read_body_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("to_bytes")
        .to_vec()
}

/// Account-level report: `subject` is a `repoRef`. The handler must
/// extract the reporter DID from the JWT iss claim, find-or-create
/// the account subject, and insert a `reports` row.
#[tokio::test]
async fn create_report_account_subject_persists_row() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP moderation_create_report::account: docker daemon not reachable");
        return Ok(());
    }
    let (router, pool) = boot().await?;
    let reporter_did = "did:plc:reporter-account-test";
    let target_did = "did:plc:target-account-test";
    let jwt = build_jwt(reporter_did);

    let body = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "reason": "consistent spammy promo links",
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": target_did,
        },
    });

    let response = send_create_report(&router, Some(&jwt), body).await;
    assert_eq!(response.status(), StatusCode::OK, "createReport must 200");
    let output = read_json(response).await;

    assert_eq!(
        output["reportedBy"].as_str(),
        Some(reporter_did),
        "Output.reportedBy must echo the JWT iss",
    );
    assert_eq!(
        output["reasonType"].as_str(),
        Some("com.atproto.moderation.defs#reasonSpam"),
    );
    assert_eq!(
        output["reason"].as_str(),
        Some("consistent spammy promo links"),
    );
    assert!(output["id"].as_i64().is_some(), "id must be an i64");
    assert!(
        output["createdAt"].as_str().is_some(),
        "createdAt must be RFC3339",
    );
    assert_eq!(
        output["subject"]["$type"].as_str(),
        Some("com.atproto.admin.defs#repoRef"),
        "subject echo must round-trip the $type discriminator",
    );
    assert_eq!(output["subject"]["did"].as_str(), Some(target_did));

    // The reports row must be visible via SQL with the captured reporter DID.
    let count = sqlx::query!(
        "SELECT COUNT(*) AS cnt FROM reports WHERE reporter_did = $1",
        reporter_did,
    )
    .fetch_one(&pool)
    .await?
    .cnt
    .unwrap_or(0);
    assert_eq!(
        count, 1,
        "exactly one report row must exist for this reporter"
    );

    // And the matching subjects row was created as kind=account.
    let row = sqlx::query!(
        "SELECT kind, did FROM subjects WHERE did = $1 AND kind = 'account'",
        target_did,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.kind, "account");
    assert_eq!(row.did.as_deref(), Some(target_did));
    Ok(())
}

/// Record-level report: `subject` is a `strongRef` carrying an AT-URI
/// for a post. The authoring DID is extracted from the URI and the
/// subjects row materialises as `kind = 'post'`.
#[tokio::test]
async fn create_report_post_subject_extracts_uri_authority()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP moderation_create_report::post: docker daemon not reachable");
        return Ok(());
    }
    let (router, pool) = boot().await?;
    let reporter_did = "did:plc:reporter-post-test";
    let target_did = "did:plc:target-post-test";
    let post_uri = format!("at://{target_did}/app.bsky.feed.post/3labcdef12");
    let jwt = build_jwt(reporter_did);

    let body = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonRude",
        "subject": {
            "$type": "com.atproto.repo.strongRef",
            "uri": post_uri,
            "cid": "bafyreigh2akiscaildc2hzfbttbnnzsslnnhpqznfjngrjnj4hsnkqkqha",
        },
    });

    let response = send_create_report(&router, Some(&jwt), body).await;
    assert_eq!(response.status(), StatusCode::OK);
    let output = read_json(response).await;
    assert_eq!(
        output["subject"]["$type"].as_str(),
        Some("com.atproto.repo.strongRef"),
    );
    assert_eq!(output["subject"]["uri"].as_str(), Some(post_uri.as_str()));

    let row = sqlx::query!(
        "SELECT kind, did, uri FROM subjects WHERE uri = $1",
        post_uri,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.kind, "post");
    assert_eq!(row.did.as_deref(), Some(target_did));

    let report_count = sqlx::query!(
        "SELECT COUNT(*) AS cnt FROM reports WHERE reporter_did = $1",
        reporter_did,
    )
    .fetch_one(&pool)
    .await?
    .cnt
    .unwrap_or(0);
    assert_eq!(report_count, 1);
    Ok(())
}

/// Missing Authorization header → 400. The handler must refuse to
/// persist a report without an identifiable reporter.
#[tokio::test]
async fn create_report_rejects_missing_authorization() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP moderation_create_report::missing_auth: docker not reachable");
        return Ok(());
    }
    let (router, pool) = boot().await?;
    let body = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonOther",
        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:anyone"},
    });
    let response = send_create_report(&router, None, body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_body_bytes(response).await;
    assert!(
        String::from_utf8_lossy(&body).contains("Authorization"),
        "error body must mention the missing Authorization header",
    );
    // No row may have been inserted.
    let count = sqlx::query!("SELECT COUNT(*) AS cnt FROM reports")
        .fetch_one(&pool)
        .await?
        .cnt
        .unwrap_or(0);
    assert_eq!(count, 0);
    Ok(())
}

/// Bearer token that is not a 3-segment JWT → 400.
#[tokio::test]
async fn create_report_rejects_non_jwt_bearer() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP moderation_create_report::non_jwt: docker not reachable");
        return Ok(());
    }
    let (router, _pool) = boot().await?;
    let body = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonOther",
        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": "did:plc:anyone"},
    });
    let response = send_create_report(&router, Some("not-a-jwt"), body).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

/// Muted reporter — issue #192: a DID present in `muted_reporters`
/// with `until IS NULL` (permanent) must see its inbound reports
/// silently dropped. The handler returns 200 with a fabricated Output
/// (so the muted reporter can't detect the drop) but NO row lands
/// in `reports`.
#[tokio::test]
async fn create_report_silently_drops_muted_reporter() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP moderation_create_report::muted: docker not reachable");
        return Ok(());
    }
    let (router, pool) = boot().await?;
    let muted_did = "did:plc:muted-reporter-test";
    let target_did = "did:plc:target-of-muted";
    let jwt = build_jwt(muted_did);

    // Mint a moderator the FK on muted_reporters.muted_by needs.
    let mod_row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        format!("mute-test-{}", uuid::Uuid::new_v4()),
    )
    .fetch_one(&pool)
    .await?;

    // Mute the reporter directly via SQL.
    sqlx::query!(
        r"INSERT INTO muted_reporters (reporter_did, muted_by, reason, until)
          VALUES ($1, $2, $3, NULL)",
        muted_did,
        mod_row.id,
        "test-suite: muted reporter regression",
    )
    .execute(&pool)
    .await?;

    let body = serde_json::json!({
        "reasonType": "com.atproto.moderation.defs#reasonSpam",
        "reason": "would-be report from muted DID",
        "subject": {"$type": "com.atproto.admin.defs#repoRef", "did": target_did},
    });
    let response = send_create_report(&router, Some(&jwt), body).await;
    // Silent drop: 200 to the caller (so they can't detect the mute).
    assert_eq!(response.status(), StatusCode::OK);
    let _output = read_json(response).await;

    // But NO row may have been persisted.
    let count = sqlx::query!(
        "SELECT COUNT(*) AS cnt FROM reports WHERE reporter_did = $1",
        muted_did,
    )
    .fetch_one(&pool)
    .await?
    .cnt
    .unwrap_or(0);
    assert_eq!(
        count, 0,
        "muted reporter's reports must be silently dropped"
    );
    Ok(())
}
