//! `GET /api/labeler/policies` integration tests
//! (issue #96 / mod-workstation feature #6).
//!
//! Pins the wire contract of the new authed-but-not-admin-gated
//! `policies` handler:
//!
//! 1. **404 when `polaris_setup_state` carries no `label_values`** —
//!    a fresh deployment has not yet completed the
//!    `publish-labeler-record` step; the preview is unavailable.
//! 2. **200 with the full payload when `label_values` AND
//!    `label_value_definitions` are populated** — the standard happy
//!    path the moderator's frontend exercises during composer use.
//! 3. **200 with empty-array `label_value_definitions` when only
//!    `label_values` is populated** — defends against the migration
//!    edge case where a partial row exists.
//!
//! The fixture pattern is the same testcontainers-Postgres shape the
//! `case_api.rs` suite uses: a moderator with `Role::Moderator` is
//! seeded with a session cookie and the endpoint is driven via
//! `tower::ServiceExt::oneshot` so the auth middleware participates
//! in the path under test.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::middleware::auth::SESSION_COOKIE;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors the rest of the
/// integration suite so the skip behaviour is uniform.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + run migrations + return the
/// `(db, pool)` pair. Same shape every other integration test uses.
async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();
    // Leak the container handle so its Drop runs at process exit,
    // not at this function's stack frame.
    std::mem::forget(container);
    Ok((database, pool))
}

/// Insert a moderator + grant the `moderator` role + mint a session
/// cookie. Returns the session cookie the test injects into the
/// `polaris_session` header.
async fn seed_moderator_with_session(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<String, Box<dyn std::error::Error>> {
    let external_id = format!("label-policies-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    let moderator_id = row.id;

    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id)
    .bind(Role::Moderator.as_db_str())
    .execute(pool)
    .await?;

    let new_session = sessions
        .create(AuthModeratorId(moderator_id), b"test-refresh-token")
        .await?;
    Ok(new_session.token.as_str().to_owned())
}

/// Build the full router + the API state. The policies endpoint
/// doesn't need atproto OAuth wiring — it reads from the local DB
/// and serves the response.
async fn boot_fixture() -> Result<(Router, PgPool), Box<dyn std::error::Error>> {
    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(database, state);
    // Pre-seed a moderator with a session cookie. The cookie is
    // returned through a side-channel because the test bodies all
    // want it.
    Ok((router, pool))
}

/// Pull the response body into a `serde_json::Value`.
async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        let snippet = String::from_utf8_lossy(&bytes);
        panic!("response body was not valid JSON: {err}; body was: {snippet}")
    })
}

// ── Case 1: empty `polaris_setup_state` → 404 ────────────────────────

#[tokio::test]
async fn policies_returns_404_when_label_values_unset() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP label_policies_endpoint::policies_returns_404_when_label_values_unset: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (router, pool) = boot_fixture().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let cookie = seed_moderator_with_session(&pool, &sessions).await?;

    // The migration inserts an empty `polaris_setup_state` singleton row
    // by default; `label_values` is NULL. Hit the endpoint without
    // populating it and assert 404.
    let request = Request::builder()
        .method("GET")
        .uri("/api/labeler/policies")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "an unconfigured deployment must surface 404 from the policies endpoint",
    );
    Ok(())
}

// ── Case 2: populated row → 200 with payload ─────────────────────────

#[tokio::test]
async fn policies_returns_200_with_payload_when_setup_state_populated()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP label_policies_endpoint::policies_returns_200_with_payload_when_setup_state_populated: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (router, pool) = boot_fixture().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let cookie = seed_moderator_with_session(&pool, &sessions).await?;

    // Populate `polaris_setup_state` with values + definitions the
    // wizard's publish step would have written. Using the same shape
    // as `polaris_publish_labeler_record::default_definitions_for` so
    // the round-trip mirrors production.
    let label_values: Vec<String> = vec!["spam".to_owned(), "porn".to_owned()];
    let definitions = serde_json::json!([
        {
            "identifier": "spam",
            "severity": "inform",
            "blurs": "none",
            "defaultSetting": "warn",
            "adultOnly": false,
            "locales": [{
                "lang": "en",
                "name": "spam",
                "description": "Label 'spam' as advertised by this labeler."
            }]
        },
        {
            "identifier": "porn",
            "severity": "inform",
            "blurs": "none",
            "defaultSetting": "warn",
            "adultOnly": false,
            "locales": [{
                "lang": "en",
                "name": "porn",
                "description": "Label 'porn' as advertised by this labeler."
            }]
        }
    ]);
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET label_values = $1, label_value_definitions = $2, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(&label_values)
    .bind(&definitions)
    .execute(&pool)
    .await?;

    let request = Request::builder()
        .method("GET")
        .uri("/api/labeler/policies")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "populated setup state must surface 200",
    );
    let body = read_json_body(response).await;

    // Field-by-field assertions — the wire shape must match what the
    // frontend's `LabelerPoliciesResponse` DTO expects.
    let returned_values = body["label_values"]
        .as_array()
        .expect("label_values must be an array")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect::<Vec<String>>();
    assert_eq!(returned_values, label_values);

    let returned_defs = body["label_value_definitions"]
        .as_array()
        .expect("label_value_definitions must be an array");
    assert_eq!(returned_defs.len(), 2);
    assert_eq!(returned_defs[0]["identifier"], "spam");
    assert_eq!(returned_defs[0]["severity"], "inform");
    assert_eq!(returned_defs[0]["defaultSetting"], "warn");

    // v1 always returns null for subscriber_likes — the frontend
    // renders percentages only when this is null.
    assert!(
        body["subscriber_likes"].is_null(),
        "v1 must return null for subscriber_likes; got {:?}",
        body["subscriber_likes"],
    );
    Ok(())
}

// ── Case 3: definitions-NULL with values populated → 200 + empty defs ─

#[tokio::test]
async fn policies_returns_empty_definitions_when_only_values_populated()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP label_policies_endpoint::policies_returns_empty_definitions_when_only_values_populated: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (router, pool) = boot_fixture().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let cookie = seed_moderator_with_session(&pool, &sessions).await?;

    // Edge case: `label_values` populated but `label_value_definitions`
    // NULL. Production never writes this shape (the publish step
    // stamps both together), but the policies endpoint must degrade
    // gracefully to an empty-array response so the frontend can
    // surface a usable "no definitions declared" UX rather than 500.
    let label_values: Vec<String> = vec!["spam".to_owned()];
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET label_values = $1, label_value_definitions = NULL, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(&label_values)
    .execute(&pool)
    .await?;

    let request = Request::builder()
        .method("GET")
        .uri("/api/labeler/policies")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "values-but-no-definitions row must still surface 200",
    );
    let body = read_json_body(response).await;
    assert_eq!(
        body["label_value_definitions"]
            .as_array()
            .expect("definitions must be an array even when NULL")
            .len(),
        0,
        "NULL definitions must round-trip as the empty array",
    );
    assert!(body["subscriber_likes"].is_null());
    Ok(())
}
