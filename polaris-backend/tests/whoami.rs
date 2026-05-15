//! Integration tests for `GET /api/whoami` (issue #83b).
//!
//! The handler returns the authenticated moderator's id, external
//! identifier, auth backend, role set, plus a `first_run` flag the
//! frontend uses to land on `/setup` rather than `/`. These tests drive
//! the production router via `tower::ServiceExt::oneshot` so the
//! cookie-driven auth middleware participates in the request path under
//! test — same idiom `tests/case_api.rs` uses.
//!
//! Three behaviours are pinned:
//!
//! 1. No cookie → 401 short-circuit at the auth middleware.
//! 2. Valid session + empty database → 200 with `first_run = true` and
//!    the moderator's role set (including `admin` for the seeded user).
//! 3. Valid session + at least one row in `actions` → 200 with
//!    `first_run = false`. The flag is durable: once `actions` is
//!    non-empty (or `labels` is non-empty), the wizard never re-fires.
//!
//! The seed helper is copied locally (rather than re-exported from
//! `case_api.rs`) because integration tests are separate binaries — the
//! pattern the existing suite follows is to keep each `tests/<name>.rs`
//! self-contained.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    reason = "integration test code — rust-quality §7 convention"
)]

use std::process::Command;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::middleware::auth::SESSION_COOKIE;
use polaris_backend::repo::{self, IncidentRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo};
use polaris_types::{Did, IncidentStatus, ModeratorId, Severity, SubjectKind};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors `case_api.rs` so the skip
/// behaviour is uniform across the suite.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the (`db`, pool)
/// pair. The container is leaked so its `Drop` runs at process exit
/// rather than at the helper's stack frame — same idiom case_api uses.
async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
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
    std::mem::forget(container);
    Ok((db, pool))
}

/// Insert a moderator row directly. Auth-repo upsert is exercised by
/// `oidc_login_flow.rs` / `atproto_login.rs`; here we just need a
/// moderator id for the FK in `sessions`. Dynamic `sqlx::query` (not
/// `query!`) so this test binary does not require a fresh `.sqlx/`
/// cache entry — same idiom `oidc_login_flow.rs` and `session_expiry.rs`
/// use for ad-hoc fixture inserts.
#[allow(dead_code, reason = "kept for parity with case_api.rs's helper shape")]
async fn insert_moderator(pool: &PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("whoami-test-{}", Uuid::new_v4());
    let row: (Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'atproto')
          RETURNING id",
    )
    .bind(&external_id)
    .fetch_one(pool)
    .await?;
    Ok(ModeratorId(row.0))
}

/// Grant the supplied role to the moderator. Uses dynamic
/// `sqlx::query` (not `query!`) so this test binary does not require a
/// fresh `.sqlx/` cache entry — same idiom `case_api.rs` and
/// `oidc_login_flow.rs` use for ad-hoc test-fixture inserts.
async fn grant_role(
    pool: &PgPool,
    moderator_id: ModeratorId,
    role: Role,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id.0)
    .bind(role.as_db_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Mint a session for `moderator_id` via [`SessionStore::create`] — the
/// production code path that seals the refresh token at rest. Returns
/// the opaque cookie value the test injects in `polaris_session`.
async fn mint_session(
    sessions: &SessionStore,
    moderator_id: ModeratorId,
) -> Result<String, Box<dyn std::error::Error>> {
    let new_session = sessions
        .create(AuthModeratorId(moderator_id.0), b"test-refresh-token-plain")
        .await?;
    Ok(new_session.token.as_str().to_owned())
}

/// Tuple returned by [`seed_admin_session`]: the moderator id, the
/// external_id we inserted, and the session cookie.
struct AdminFixture {
    moderator_id: ModeratorId,
    external_id: String,
    session_cookie: String,
}

/// Seed an `admin`-roled moderator with an active session. The
/// resulting cookie value is what the test injects in
/// `polaris_session=…`.
async fn seed_admin_session(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<AdminFixture, Box<dyn std::error::Error>> {
    let external_id = format!("whoami-admin-{}", Uuid::new_v4());
    let row: (Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'atproto')
          RETURNING id",
    )
    .bind(&external_id)
    .fetch_one(pool)
    .await?;
    let moderator_id = ModeratorId(row.0);
    grant_role(pool, moderator_id, Role::Admin).await?;
    let session_cookie = mint_session(sessions, moderator_id).await?;
    Ok(AdminFixture {
        moderator_id,
        external_id,
        session_cookie,
    })
}

/// Build the (router, pool, sessions) triple shared by every test.
async fn boot_fixture() -> Result<(Router, PgPool, SessionStore), Box<dyn std::error::Error>> {
    let (db, pool) = boot_db().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(db, state);
    Ok((router, pool, sessions))
}

/// Read the response body into a `serde_json::Value`. Same helper
/// shape `case_api.rs` uses.
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

// ── 1. GET /api/whoami without auth → 401 ─────────────────────────────

#[tokio::test]
async fn whoami_without_session_returns_401() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP whoami::whoami_without_session_returns_401: docker daemon not reachable");
        return Ok(());
    }
    let (router, _pool, _sessions) = boot_fixture().await?;

    let request = Request::builder()
        .method("GET")
        .uri("/api/whoami")
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "missing cookie must short-circuit at the auth middleware",
    );
    let body = read_json_body(response).await;
    // The middleware's canonical 401 body is `{"error":"unauthorized"}`
    // (no `code` field; the structured ApiError shape is for
    // handler-raised errors only). Same shape `case_api.rs` asserts
    // against the AC-7 binding.
    assert_eq!(body["error"], "unauthorized", "body was {body}");
    Ok(())
}

// ── 2. GET /api/whoami with valid session, empty DB → first_run = true ─

#[tokio::test]
async fn whoami_with_valid_session_returns_first_run_true_on_empty_db()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP whoami::whoami_with_valid_session_returns_first_run_true_on_empty_db: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fx = seed_admin_session(&pool, &sessions).await?;

    let request = Request::builder()
        .method("GET")
        .uri("/api/whoami")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fx.session_cookie),
        )
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "authed whoami against an empty DB must surface 200 OK",
    );
    let body = read_json_body(response).await;
    assert_eq!(
        body["moderator_id"],
        fx.moderator_id.0.to_string(),
        "moderator_id must echo the session-bound moderator; body was {body}",
    );
    assert_eq!(body["external_id"], fx.external_id);
    assert_eq!(body["auth_backend"], "atproto");
    assert_eq!(
        body["first_run"], true,
        "fresh DB (empty actions + empty labels) must yield first_run = true; body was {body}",
    );
    // The roles list must contain "admin"; the wire order is stable
    // (sorted by the handler) but asserting membership decouples this
    // test from any future expansion of the seeded role set.
    let roles = body["roles"]
        .as_array()
        .expect("roles must be a JSON array");
    assert!(
        roles.iter().any(|r| r == "admin"),
        "roles array must contain 'admin'; got {roles:?}",
    );
    Ok(())
}

// ── 3. GET /api/whoami after an action row exists → first_run = false ─

#[tokio::test]
async fn whoami_with_action_row_returns_first_run_false() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!(
            "SKIP whoami::whoami_with_action_row_returns_first_run_false: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fx = seed_admin_session(&pool, &sessions).await?;

    // Seed one subject + one incident + one committed action so the
    // first-run probe in `whoami::is_first_run` reads `count > 0` on
    // the actions table. We go through the production repo writers
    // (not raw SQL) so the action row carries the same shape an
    // OAuth-completed submit-action would write.
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new(format!(
                "did:plc:whoami-{}",
                Uuid::new_v4().simple()
            ))),
            uri: None,
            created_at: Utc::now(),
        })
        .await?;
    let incident = incident_repo
        .insert(repo::NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await?;

    sqlx::query(
        r"INSERT INTO actions
          (incident_id, subject_id, moderator_id, kind, reasoning, policy_refs, reversible_until)
          VALUES ($1, $2, $3, 'label', 'whoami-first-run-flip-probe', $4, now() + interval '1 day')",
    )
    .bind(incident.id.0)
    .bind(subject.id.0)
    .bind(fx.moderator_id.0)
    .bind(vec!["polaris.spam".to_owned()])
    .execute(&pool)
    .await?;

    // Sanity: at least one action row now exists so the heuristic
    // fires. The assertion below is a defensive pre-condition so a
    // future schema change that rejects the INSERT (e.g. a new CHECK
    // constraint) surfaces here as a fixture failure rather than as
    // a confusing `first_run` assertion mismatch.
    let action_count: (i64,) = sqlx::query_as("SELECT count(*) FROM actions")
        .fetch_one(&pool)
        .await?;
    assert!(
        action_count.0 >= 1,
        "fixture must have inserted at least one action row; count = {}",
        action_count.0,
    );

    let request = Request::builder()
        .method("GET")
        .uri("/api/whoami")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fx.session_cookie),
        )
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = read_json_body(response).await;
    assert_eq!(
        body["first_run"], false,
        "actions table non-empty must yield first_run = false; body was {body}",
    );
    // The moderator identity fields are unchanged by the action seed.
    assert_eq!(body["moderator_id"], fx.moderator_id.0.to_string());
    assert_eq!(body["external_id"], fx.external_id);

    Ok(())
}
