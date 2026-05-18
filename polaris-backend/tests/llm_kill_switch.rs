//! Integration tests for the LLM kill-switch endpoints
//! (`.design/llm-moderation-assist.md` REQ-S7; issue #241 / LLM-12).
//!
//! Hermetic per test: each test boots a fresh testcontainers Postgres
//! 16-alpine, runs migrations via [`db::connect`], wires an
//! [`ApiState`] + full [`api::router_with_state`] composition, and
//! drives the router with `tower::ServiceExt::oneshot` so the
//! cookie-driven auth middleware participates in the request path.
//!
//! # What's covered
//!
//! 1. `pause_sets_until_timestamp` — POST with `{"until": "..."}`
//!    writes the column.
//! 2. `pause_without_body_pauses_forever_until_9999` — empty body
//!    sentinel.
//! 3. `non_admin_gets_403` — RBAC.
//! 4. `delete_clears_pause_column` — DELETE → NULL.
//! 5. `paused_state_makes_safety_floors_s7_block` — the kill switch
//!    actually causes [`safety_floors::evaluate`] to return
//!    `EffectiveMode::Manual` with the `GlobalPause` trip when the
//!    column carries a future timestamp.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{DateTime, Utc};
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::llm::safety_floors::{self, EffectiveMode};
use polaris_backend::middleware::auth::SESSION_COOKIE;
use polaris_backend::repo::mod_policies::{self, NewModPolicy};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

// ── Test-fixture scaffolding ─────────────────────────────────────────

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn boot_db() -> (db::Db, PgPool) {
    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .unwrap();
    let host_port = pg.get_host_port_ipv4(5432).await.unwrap();
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.unwrap();
    let pool = database.pool().clone();
    std::mem::forget(pg);
    (database, pool)
}

async fn seed_moderator_with_session(
    pool: &PgPool,
    sessions: &SessionStore,
    external_id: &str,
    role: Role,
) -> (Uuid, String) {
    let row: (Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, pinned_admin)
          VALUES ($1, 'atproto', FALSE)
          RETURNING id",
    )
    .bind(external_id)
    .fetch_one(pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO moderator_roles (moderator_id, role) VALUES ($1, $2)")
        .bind(row.0)
        .bind(role.as_db_str())
        .execute(pool)
        .await
        .unwrap();
    let session = sessions
        .create(AuthModeratorId(row.0), b"kill-switch-test-refresh-token")
        .await
        .unwrap();
    (row.0, session.token.as_str().to_owned())
}

struct Fixture {
    router: Router,
    pool: PgPool,
    admin_cookie: String,
    moderator_cookie: String,
}

async fn boot_fixture() -> Fixture {
    let (database, pool) = boot_db().await;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let (_admin_id, admin_cookie) =
        seed_moderator_with_session(&pool, &sessions, "did:plc:kill-switch-admin", Role::Admin)
            .await;
    let (_mod_id, moderator_cookie) = seed_moderator_with_session(
        &pool,
        &sessions,
        "did:plc:kill-switch-moderator",
        Role::Moderator,
    )
    .await;
    let state = ApiState::new(pool.clone(), sessions);
    let router = api::router_with_state(database, state);
    Fixture {
        router,
        pool,
        admin_cookie,
        moderator_cookie,
    }
}

async fn post_pause(
    router: &Router,
    cookie: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/admin/llm/pause")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    router.clone().oneshot(req).await.unwrap()
}

async fn delete_pause(router: &Router, cookie: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/admin/llm/pause")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(req).await.unwrap()
}

async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("body not JSON: {err}; bytes: {bytes:?}"))
}

async fn read_pause_column(pool: &PgPool) -> Option<DateTime<Utc>> {
    let row: (Option<DateTime<Utc>>,) = sqlx::query_as(
        "SELECT global_autonomous_pause_until FROM polaris_setup_state WHERE id = TRUE",
    )
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

// ── Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn pause_sets_until_timestamp() {
    if !docker_available() {
        eprintln!("skipping pause_sets_until_timestamp: docker not available");
        return;
    }
    let f = boot_fixture().await;
    // Pause until a known future timestamp.
    let until = Utc::now() + chrono::Duration::hours(4);
    let body = serde_json::json!({ "until": until });
    let resp = post_pause(&f.router, &f.admin_cookie, body).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = read_json(resp).await;
    assert!(payload["paused_until"].is_string());
    // Column should hold the timestamp we set (round-tripped through
    // Postgres microsecond precision; assert within 1 second).
    let column = read_pause_column(&f.pool).await.expect("column was written");
    let delta = (column - until).num_milliseconds().abs();
    assert!(delta < 1000, "column timestamp drifted: {delta}ms");
}

#[tokio::test]
async fn pause_without_body_pauses_forever_until_9999() {
    if !docker_available() {
        eprintln!("skipping pause_without_body_pauses_forever_until_9999: docker not available");
        return;
    }
    let f = boot_fixture().await;
    // Empty JSON body. The handler interprets missing `until` as the
    // forever sentinel.
    let resp = post_pause(&f.router, &f.admin_cookie, serde_json::json!({})).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payload = read_json(resp).await;
    let paused_until = payload["paused_until"]
        .as_str()
        .expect("paused_until is a string");
    assert!(
        paused_until.starts_with("9999-"),
        "expected forever sentinel, got {paused_until}",
    );
    let column = read_pause_column(&f.pool).await.expect("column was written");
    assert_eq!(column.format("%Y").to_string(), "9999");
}

#[tokio::test]
async fn non_admin_gets_403() {
    if !docker_available() {
        eprintln!("skipping non_admin_gets_403: docker not available");
        return;
    }
    let f = boot_fixture().await;
    // POST as a moderator-tier user.
    let resp = post_pause(&f.router, &f.moderator_cookie, serde_json::json!({})).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // DELETE as a moderator-tier user.
    let resp = delete_pause(&f.router, &f.moderator_cookie).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // Column must remain NULL — no write happened.
    assert!(read_pause_column(&f.pool).await.is_none());
}

#[tokio::test]
async fn delete_clears_pause_column() {
    if !docker_available() {
        eprintln!("skipping delete_clears_pause_column: docker not available");
        return;
    }
    let f = boot_fixture().await;
    // Pause first.
    let until = Utc::now() + chrono::Duration::hours(1);
    let _ = post_pause(
        &f.router,
        &f.admin_cookie,
        serde_json::json!({ "until": until }),
    )
    .await;
    assert!(read_pause_column(&f.pool).await.is_some());

    // Clear.
    let resp = delete_pause(&f.router, &f.admin_cookie).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(read_pause_column(&f.pool).await.is_none());

    // Idempotent — second DELETE is still 204.
    let resp = delete_pause(&f.router, &f.admin_cookie).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(read_pause_column(&f.pool).await.is_none());
}

#[tokio::test]
async fn paused_state_makes_safety_floors_s7_block() {
    if !docker_available() {
        eprintln!("skipping paused_state_makes_safety_floors_s7_block: docker not available");
        return;
    }
    let f = boot_fixture().await;

    // Seed a moderator + an `autonomous` policy. The mod_policies row
    // requires a `created_by_moderator_id` FK; reuse the admin row
    // (look it up by external_id).
    let admin_row: (Uuid,) = sqlx::query_as(
        "SELECT id FROM moderators WHERE external_id = $1 AND auth_backend = 'atproto'",
    )
    .bind("did:plc:kill-switch-admin")
    .fetch_one(&f.pool)
    .await
    .unwrap();
    let admin_id = admin_row.0;

    let mut tx = f.pool.begin().await.unwrap();
    let policy = mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: "polaris.kill-switch-test".to_owned(),
            name: "Kill-switch test policy".to_owned(),
            description: "Used by the kill-switch integration tests.".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria:
                "Apply when the kill-switch integration test exercises this policy.".to_owned(),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "autonomous".to_owned(),
            autonomous_action_kinds: vec!["label".to_owned(), "warn".to_owned()],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.7,
            autonomous_rate_limit_per_hour: None,
            autonomous_reversal_breaker_threshold: None,
            change_summary: None,
        },
        admin_id,
    )
    .await
    .expect("policy seeded");
    tx.commit().await.unwrap();

    // Sanity: without the pause, an above-threshold confidence + an
    // allowed kind + a `post` subject route as `Autonomous`.
    let subject_id = Uuid::new_v4();
    let mode = safety_floors::evaluate(&f.pool, &policy, "label", 0.99, subject_id, "post")
        .await
        .expect("evaluate succeeds");
    assert_eq!(
        mode,
        EffectiveMode::Autonomous,
        "baseline must be autonomous",
    );

    // Engage the pause via direct write (mirroring what the POST
    // handler does internally — the round-trip through the router is
    // covered by the earlier tests).
    let until = Utc::now() + chrono::Duration::hours(1);
    sqlx::query(
        "UPDATE polaris_setup_state SET global_autonomous_pause_until = $1 WHERE id = TRUE",
    )
    .bind(until)
    .execute(&f.pool)
    .await
    .unwrap();

    // Now the same evaluation must downgrade to `Manual` with the S7
    // floor's GlobalPause cause.
    let mode = safety_floors::evaluate(&f.pool, &policy, "label", 0.99, subject_id, "post")
        .await
        .expect("evaluate succeeds under pause");
    assert!(
        matches!(mode, EffectiveMode::Manual),
        "expected Manual under pause; got {mode:?}",
    );

    // Past timestamps must NOT pause — sanity check the predicate is
    // `column > now()`.
    sqlx::query(
        "UPDATE polaris_setup_state SET global_autonomous_pause_until = $1 WHERE id = TRUE",
    )
    .bind(Utc::now() - chrono::Duration::hours(1))
    .execute(&f.pool)
    .await
    .unwrap();
    let mode = safety_floors::evaluate(&f.pool, &policy, "label", 0.99, subject_id, "post")
        .await
        .expect("evaluate succeeds with past pause");
    assert_eq!(
        mode,
        EffectiveMode::Autonomous,
        "expired pause must not block",
    );
}
