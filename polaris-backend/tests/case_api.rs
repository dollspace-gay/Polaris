//! Case API integration tests (#52, AC-7 binding).
//!
//! Hermetic per test: each test boots a fresh testcontainers Postgres 16-alpine,
//! applies all migrations via `db::connect`, builds an [`ApiState`] + full
//! [`api::router_with_state`] composition, and drives the router via
//! `tower::ServiceExt::oneshot` so the cookie-driven auth middleware (issue #9)
//! participates in the request path under test.
//!
//! Session rows are minted through [`SessionStore::create`] — the same code
//! path the production OIDC callback handler uses, which seals the refresh
//! token at rest via [`Crypto::seal`] (AES-256-GCM). Going through the public
//! API here keeps the test resilient to schema drift on `sessions` while
//! still exercising the seal/open contract.
//!
//! # AC-7 runtime proof
//!
//! Two tests in this file are the runtime half of AC-7 (xtask provides the
//! static enforcement in #11):
//!
//! 1. [`get_case_without_auth_returns_401`] — the GET case-view endpoint
//!    rejects an unauthenticated request at the middleware boundary with
//!    `401`. The body shape is the canonical `{"error":"unauthorized"}`
//!    short-circuit from `middleware/auth.rs`.
//! 2. [`post_action_without_auth_returns_401`] — the POST submit-action
//!    endpoint (the most security-sensitive write in #14) rejects an
//!    unauthenticated request the same way.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::collections::HashSet;
use std::process::Command;

use axum::Router;
use axum::body::{Body, to_bytes};
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
use polaris_types::{
    Did, IncidentId, IncidentStatus, ModeratorId, Severity, SubjectId, SubjectKind,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors the other integration tests
/// in this crate (`repo_roundtrip`, `session_expiry`, `oidc_login_flow`) so
/// the skip behaviour is uniform across the suite.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the (`db`, pool) pair.
///
/// The container handle is leaked so its `Drop` impl (which stops the
/// container) runs at process exit rather than at this function's stack
/// frame — the test would otherwise tear the database down before the
/// router has a chance to use the pool. Same trick the `appeals_workflow`
/// integration test uses.
async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
    // Pin Postgres 16-alpine: migration 11 needs generated columns (PG ≥ 12)
    // and the auth migration uses the built-in `gen_random_uuid()` that
    // ships with PG 13+.
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

/// Build the full Axum router (auth middleware included) around the supplied
/// state. Returns the same shape the production binary entrypoint
/// constructs in `main.rs`.
fn build_router(db: db::Db, state: ApiState) -> Router {
    api::router_with_state(db, state)
}

/// Insert a moderator row directly. The auth-repo upsert path is exercised
/// by `oidc_login_flow.rs`; here we just need a moderator id to satisfy the
/// sessions / actions foreign keys.
async fn insert_moderator(pool: &PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("case-api-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(ModeratorId(row.id))
}

/// Grant a moderator the [`Role::Moderator`] role so the session-lookup
/// path returns a non-empty role set (matches the wire-shape that the
/// OIDC handshake produces for a freshly-onboarded moderator with a base
/// role assignment).
async fn grant_moderator_role(
    pool: &PgPool,
    moderator_id: ModeratorId,
) -> Result<(), Box<dyn std::error::Error>> {
    // Dynamic `sqlx::query` (not the `query!` macro) so this test binary
    // does not require a fresh `.sqlx/` cache entry — the same idiom
    // `oidc_login_flow.rs` and `session_expiry.rs` use for ad-hoc
    // test-fixture inserts.
    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id.0)
    .bind(Role::Moderator.as_db_str())
    .execute(pool)
    .await?;
    Ok(())
}

/// Mint a session for `moderator_id` via [`SessionStore::create`] — the
/// production code path that seals the refresh token at rest. Returns the
/// opaque cookie value that the test injects in the `polaris_session`
/// cookie.
async fn mint_session(
    sessions: &SessionStore,
    moderator_id: ModeratorId,
) -> Result<String, Box<dyn std::error::Error>> {
    let new_session = sessions
        .create(AuthModeratorId(moderator_id.0), b"test-refresh-token-plain")
        .await?;
    Ok(new_session.token.as_str().to_owned())
}

/// Seed one subject + one moderator + one open incident. Returns the
/// inserted ids so the caller can reference them in path / body params.
struct Fixture {
    subject_id: SubjectId,
    incident_id: IncidentId,
    moderator_id: ModeratorId,
    session_cookie: String,
}

async fn seed_fixture(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());

    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new(format!(
                "did:plc:case-api-{}",
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

    let moderator_id = insert_moderator(pool).await?;
    grant_moderator_role(pool, moderator_id).await?;
    let session_cookie = mint_session(sessions, moderator_id).await?;

    Ok(Fixture {
        subject_id: subject.id,
        incident_id: incident.id,
        moderator_id,
        session_cookie,
    })
}

/// Build the (`router`, `pool`, `sessions`) triple shared by every test.
async fn boot_fixture() -> Result<(Router, PgPool, SessionStore), Box<dyn std::error::Error>> {
    let (db, pool) = boot_db().await?;
    // Deterministic test key — never used outside `#[cfg(test)]`. Distinct
    // per-test by re-booting the container per test; the constant here
    // is fine.
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = build_router(db, state);
    Ok((router, pool, sessions))
}

/// Read the response body into a `serde_json::Value`. Helper so the
/// per-test assertion path stays one line.
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

/// Convenience: read the response body, asserting the JSON Value shape
/// later. Mirrors `axum::body::to_bytes` for the rare case we want raw
/// bytes (none today, but kept for future expansion).
#[allow(dead_code)]
async fn read_body_bytes(response: axum::response::Response) -> Vec<u8> {
    to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("to_bytes")
        .to_vec()
}

// ── 1. GET /api/cases/:id without auth → 401 ───────────────────────────

#[tokio::test]
async fn get_case_without_auth_returns_401() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP case_api::get_case_without_auth_returns_401: docker daemon not reachable");
        return Ok(());
    }
    let (router, _pool, _sessions) = boot_fixture().await?;

    // A random subject id — it does not matter whether the subject exists:
    // the auth middleware short-circuits before the handler runs.
    let subject_id = SubjectId(Uuid::new_v4());
    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/cases/{}", subject_id.0))
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "missing cookie must short-circuit at the auth middleware (AC-7)",
    );
    let body = read_json_body(response).await;
    // The middleware's canonical 401 body is `{"error":"unauthorized"}`.
    // The `code` field is deliberately omitted by the middleware — the
    // ApiError shape (`{"error":..,"code":..}`) is for handler-raised
    // errors, not middleware short-circuits. Asserting the middleware
    // contract verbatim is the AC-7 binding.
    assert_eq!(
        body["error"], "unauthorized",
        "middleware 401 body shape changed; AC-7 contract regression: {body}",
    );
    Ok(())
}

// ── 2. GET /api/cases/:id with valid session → 200 ─────────────────────

#[tokio::test]
async fn get_case_with_valid_session_returns_200() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP case_api::get_case_with_valid_session_returns_200: docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fixture = seed_fixture(&pool, &sessions).await?;

    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/cases/{}", fixture.subject_id.0))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fixture.session_cookie),
        )
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "valid session + existing subject must surface 200 OK"
    );
    let body = read_json_body(response).await;
    // CaseView contract: `subject` is the row keyed on the path id;
    // `history`, `reports`, `observations`, `reporter_contexts` are arrays
    // (empty in the freshly-seeded fixture); `network_context` is null
    // until M2.
    assert_eq!(
        body["subject"]["id"],
        fixture.subject_id.0.to_string(),
        "subject.id in body must match the path id; body was {body}",
    );
    assert!(body["history"].is_array());
    assert!(body["reports"].is_array());
    assert!(body["observations"].is_array());
    assert!(body["reporter_contexts"].is_array());
    Ok(())
}

// ── 3. GET /api/cases/:id with valid session + unknown subject → 404 ───

#[tokio::test]
async fn get_case_with_valid_session_unknown_subject_returns_404()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP case_api::get_case_with_valid_session_unknown_subject_returns_404: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    // Mint a session but do NOT seed the subject row.
    let moderator_id = insert_moderator(&pool).await?;
    grant_moderator_role(&pool, moderator_id).await?;
    let cookie = mint_session(&sessions, moderator_id).await?;

    // The all-zeros UUID is a well-formed UUID that will never collide with
    // a real `gen_random_uuid()` row. Path parsing succeeds; the repo
    // surfaces `NotFound`.
    let request = Request::builder()
        .method("GET")
        .uri("/api/cases/00000000-0000-0000-0000-000000000000")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::NOT_FOUND,
        "authed lookup of a non-existent subject must surface 404"
    );
    let body = read_json_body(response).await;
    assert_eq!(
        body["code"], "not_found",
        "404 body must carry code=not_found per ApiError contract; body was {body}",
    );
    Ok(())
}

// ── 4. POST /api/cases/:id/actions without auth → 401 ──────────────────

#[tokio::test]
async fn post_action_without_auth_returns_401() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP case_api::post_action_without_auth_returns_401: docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, _pool, _sessions) = boot_fixture().await?;

    let subject_id = SubjectId(Uuid::new_v4());
    // Body is intentionally empty — the auth middleware short-circuits
    // before any body parsing happens, so the wire shape does not matter.
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "POST without cookie must short-circuit at the auth middleware (AC-7)",
    );
    let body = read_json_body(response).await;
    assert_eq!(body["error"], "unauthorized", "body was {body}");
    Ok(())
}

// ── 5. POST /api/cases/:id/actions, reasoning < 10 chars → 400 ─────────

#[tokio::test]
async fn post_action_with_short_reasoning_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP case_api::post_action_with_short_reasoning_returns_400: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fixture = seed_fixture(&pool, &sessions).await?;

    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "tooshort",
        "policy_refs": ["polaris.spam"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", fixture.subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fixture.session_cookie),
        )
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "reasoning < 10 chars must surface 400"
    );
    let body = read_json_body(response).await;
    assert_eq!(
        body["code"], "bad_request",
        "400 body must carry code=bad_request; body was {body}",
    );
    let err_msg = body["error"].as_str().unwrap_or_default();
    assert!(
        err_msg.contains("reasoning"),
        "error message must name the offending field; got {err_msg}",
    );
    Ok(())
}

// ── 6. POST /api/cases/:id/actions, unknown policy_ref → 400 ───────────

#[tokio::test]
async fn post_action_with_unknown_policy_ref_returns_400() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!(
            "SKIP case_api::post_action_with_unknown_policy_ref_returns_400: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fixture = seed_fixture(&pool, &sessions).await?;

    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "this reasoning is sufficiently long to pass length validation",
        "policy_refs": ["polaris.does-not-exist"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", fixture.subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fixture.session_cookie),
        )
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "unknown policy_ref must surface 400"
    );
    let body = read_json_body(response).await;
    assert_eq!(
        body["code"], "bad_request",
        "body must carry code=bad_request; body was {body}",
    );
    Ok(())
}

// ── 7. POST /api/cases/:id/actions, happy path → 201 + row in DB ───────

#[tokio::test]
async fn post_action_happy_path_returns_201_and_persists_row()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP case_api::post_action_happy_path_returns_201_and_persists_row: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fixture = seed_fixture(&pool, &sessions).await?;

    let reasoning = "this reasoning is sufficiently long to pass validation";
    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": reasoning,
        "policy_refs": ["polaris.spam"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", fixture.subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fixture.session_cookie),
        )
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "happy-path submit-action must surface 201 Created"
    );
    let body_json = read_json_body(response).await;
    // The handler echoes the inserted Action — assert the fields the
    // wire contract pins.
    assert_eq!(body_json["incident_id"], fixture.incident_id.0.to_string());
    assert_eq!(body_json["subject_id"], fixture.subject_id.0.to_string());
    assert_eq!(
        body_json["moderator_id"],
        fixture.moderator_id.0.to_string(),
        "moderator_id MUST be the session-bound moderator, NOT a body field (AC-7 attribution)",
    );
    assert_eq!(body_json["kind"], "label");
    assert_eq!(body_json["reasoning"], reasoning);

    // The action row was persisted under the session-bound moderator id.
    let count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM actions WHERE moderator_id = $1 AND incident_id = $2")
            .bind(fixture.moderator_id.0)
            .bind(fixture.incident_id.0)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        count.0, 1,
        "exactly one action row must be persisted for the (moderator, incident) tuple",
    );

    // Cross-check the reasoning column to prove the body round-tripped.
    let row: (String,) =
        sqlx::query_as("SELECT reasoning FROM actions WHERE moderator_id = $1 LIMIT 1")
            .bind(fixture.moderator_id.0)
            .fetch_one(&pool)
            .await?;
    assert_eq!(row.0, reasoning);
    Ok(())
}

// ── 8. POST /api/cases/:id/escalate happy path → 200 + status updated ──

#[tokio::test]
async fn post_escalate_happy_path_returns_200_and_updates_status()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP case_api::post_escalate_happy_path_returns_200_and_updates_status: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fixture = seed_fixture(&pool, &sessions).await?;

    // Sanity: the seeded incident is in status `Open`.
    let pre: (String,) = sqlx::query_as("SELECT status FROM incidents WHERE id = $1")
        .bind(fixture.incident_id.0)
        .fetch_one(&pool)
        .await?;
    assert_eq!(pre.0, "open");

    let body = serde_json::json!({
        "reasoning": "escalation reasoning is sufficiently long",
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/escalate", fixture.incident_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fixture.session_cookie),
        )
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "escalate happy path must surface 200 OK"
    );
    let body_json = read_json_body(response).await;
    assert_eq!(body_json["id"], fixture.incident_id.0.to_string());
    assert_eq!(body_json["status"], "escalated");

    // Cross-check the DB row was flipped to `escalated`.
    let post: (String,) = sqlx::query_as("SELECT status FROM incidents WHERE id = $1")
        .bind(fixture.incident_id.0)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        post.0, "escalated",
        "incidents.status row must be flipped to 'escalated' after the handler returns",
    );
    Ok(())
}

/// Compile-time anchor: keep [`HashSet`] reachable in this file (used
/// transitively by `seed_fixture`'s session-mint path through the auth
/// types). Without an explicit reference clippy would flag the import as
/// unused when the dependency arrives transitively.
#[allow(dead_code)]
const _SET_ANCHOR: fn() -> HashSet<Role> = HashSet::new;
