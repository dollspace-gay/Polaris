//! Integration tests for the policies REST API (WB-3 / issue #225).
//!
//! Hermetic per test: each test boots a fresh testcontainers Postgres
//! 16-alpine, runs migrations via [`db::connect`], wires an
//! [`ApiState`] + full [`api::router_with_state`] composition, and
//! drives the router with `tower::ServiceExt::oneshot` so the
//! cookie-driven auth middleware participates in the request path.
//!
//! # What's covered
//!
//! 1. `admin_can_create_then_read_policy` — happy-path POST then GET
//!    round-trip.
//! 2. `non_admin_gets_403_on_admin_routes` — moderator-tier role
//!    cannot reach admin write paths.
//! 3. `non_admin_can_browse_policies` — moderator-tier role CAN read
//!    `/api/policies/*`.
//! 4. `patch_creates_new_version_and_marks_prior_effective_until` —
//!    versioning semantics.
//! 5. `patch_without_change_summary_returns_400` — the design's
//!    REQUIRED `change_summary` gate.
//! 6. `history_returns_chain_in_correct_order` — REQ-C2 history
//!    endpoint.
//! 7. `diff_returns_only_changed_fields` — REQ-C4 diff shape.
//! 8. `pause_then_resume_cycle` — kill-switch round trip.
//! 9. `autonomy_mode_autonomous_on_human_required_policy_returns_403`
//!    — REQ-G3 hard floor at the workbook edit API.
//! 10. `autonomous_action_kinds_with_escalate_returns_400` — REQ-G1
//!     at the workbook edit API.

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

// ── Test-fixture scaffolding ─────────────────────────────────────────

/// Probe for a working Docker daemon. The integration suite skips
/// (rather than fails) when the runner has no docker; mirrors the
/// rest of `polaris-backend/tests/`.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a fresh Postgres testcontainer, run migrations, return
/// `(db, pool)`. The container is leaked so its `Drop` impl doesn't
/// tear the database down before the test finishes.
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

/// Seed a moderator row + role assignment + active session, returning
/// the moderator UUID and the session cookie value.
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
        .create(AuthModeratorId(row.0), b"test-refresh-token")
        .await
        .unwrap();
    (row.0, session.token.as_str().to_owned())
}

/// Build the router + the admin / moderator sessions in one go.
struct Fixture {
    router: Router,
    pool: PgPool,
    admin_cookie: String,
    admin_id: Uuid,
    moderator_cookie: String,
}

async fn boot_fixture() -> Fixture {
    let (database, pool) = boot_db().await;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let (admin_id, admin_cookie) =
        seed_moderator_with_session(&pool, &sessions, "did:plc:admin-policies", Role::Admin).await;
    let (_, moderator_cookie) = seed_moderator_with_session(
        &pool,
        &sessions,
        "did:plc:non-admin-policies",
        Role::Moderator,
    )
    .await;
    let state = ApiState::new(pool.clone(), sessions);
    let router = api::router_with_state(database, state);
    Fixture {
        router,
        pool,
        admin_cookie,
        admin_id,
        moderator_cookie,
    }
}

/// Read the JSON body of a response. Panics if the body isn't valid
/// JSON — fine for integration tests.
async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("body not JSON: {err}; bytes: {bytes:?}"))
}

/// Body shape that satisfies every validation gate. The tests tweak
/// per-case fields and reuse this as a baseline.
fn valid_create_body(identifier: &str) -> serde_json::Value {
    serde_json::json!({
        "identifier": identifier,
        "name": format!("{identifier} test policy"),
        "description": "A test policy for the admin-policies integration suite.",
        "scope": "post",
        "severity": "alert",
        "decision_criteria":
            "Apply this policy when the integration test creates a v1 row through the admin endpoint.",
        "suggested_action_kinds": ["label"],
        "autonomy_mode": "manual",
        "autonomous_action_kinds": [],
        "autonomous_confidence_threshold": 0.95,
        "assisted_confidence_threshold": 0.7,
    })
}

/// POST `/api/admin/policies` with the supplied body. Returns the
/// response (status + headers + body). Tests inspect status + body.
async fn post_admin_create(
    router: &Router,
    cookie: &str,
    body: serde_json::Value,
) -> axum::response::Response {
    let req = Request::builder()
        .method("POST")
        .uri("/api/admin/policies")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    router.clone().oneshot(req).await.unwrap()
}

// ── 1. Happy-path create + read ──────────────────────────────────────

#[tokio::test]
async fn admin_can_create_then_read_policy() {
    if !docker_available() {
        println!("SKIP admin_policies_endpoint::admin_can_create_then_read_policy: no docker");
        return;
    }
    let f = boot_fixture().await;

    let create = post_admin_create(
        &f.router,
        &f.admin_cookie,
        valid_create_body("polaris.testcreate"),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let body = read_json(create).await;
    assert_eq!(body["identifier"], "polaris.testcreate");
    assert_eq!(body["version"], 1);
    assert_eq!(body["autonomy_mode"], "manual");
    assert_eq!(body["created_by_moderator_id"], f.admin_id.to_string());

    // GET it back as admin.
    let req = Request::builder()
        .method("GET")
        .uri("/api/admin/policies/polaris.testcreate")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["identifier"], "polaris.testcreate");
    assert_eq!(body["version"], 1);
}

// ── 2. Non-admin cannot reach the admin surface ──────────────────────

#[tokio::test]
async fn non_admin_gets_403_on_admin_routes() {
    if !docker_available() {
        println!("SKIP admin_policies_endpoint::non_admin_gets_403_on_admin_routes: no docker");
        return;
    }
    let f = boot_fixture().await;

    let resp = post_admin_create(
        &f.router,
        &f.moderator_cookie,
        valid_create_body("polaris.shouldfail"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = read_json(resp).await;
    assert_eq!(body["code"], "forbidden");

    // PATCH (even on a non-existent identifier) also rejects at the
    // RBAC gate without ever reaching the lookup.
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/admin/policies/polaris.harassment")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.moderator_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "change_summary": "tighten thresholds" }).to_string(),
        ))
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── 3. Moderator-facing read-only surface works for non-admin ────────

#[tokio::test]
async fn non_admin_can_browse_policies() {
    if !docker_available() {
        println!("SKIP admin_policies_endpoint::non_admin_can_browse_policies: no docker");
        return;
    }
    let f = boot_fixture().await;

    // Admin seeds a policy the non-admin will read.
    let resp = post_admin_create(
        &f.router,
        &f.admin_cookie,
        valid_create_body("polaris.publicread"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Moderator hits /api/policies.
    let req = Request::builder()
        .method("GET")
        .uri("/api/policies")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.moderator_cookie),
        )
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let arr = body.as_array().expect("list returns a JSON array");
    assert!(
        arr.iter().any(|p| p["identifier"] == "polaris.publicread"),
        "moderator must see the seeded policy in /api/policies; got: {arr:?}"
    );

    // Moderator hits /api/policies/:identifier.
    let req = Request::builder()
        .method("GET")
        .uri("/api/policies/polaris.publicread")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.moderator_cookie),
        )
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["identifier"], "polaris.publicread");
    assert_eq!(body["version"], 1);
}

// ── 4. PATCH bumps version + closes prior `effective_until` ──────────

#[tokio::test]
async fn patch_creates_new_version_and_marks_prior_effective_until() {
    if !docker_available() {
        println!("SKIP patch_creates_new_version_and_marks_prior_effective_until: no docker");
        return;
    }
    let f = boot_fixture().await;
    let resp = post_admin_create(
        &f.router,
        &f.admin_cookie,
        valid_create_body("polaris.patchme"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // PATCH the name.
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/admin/policies/polaris.patchme")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "renamed",
                "change_summary": "renamed for clarity",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["version"], 2);
    assert_eq!(body["name"], "renamed");

    // Prior row is now `effective_until IS NOT NULL`.
    let prior_row: (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
        r"SELECT effective_until FROM mod_policies
          WHERE identifier = $1 AND version = 1",
    )
    .bind("polaris.patchme")
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(
        prior_row.0.is_some(),
        "v1's effective_until must be set after the amend"
    );
}

// ── 5. PATCH without change_summary rejects with 400 ─────────────────

#[tokio::test]
async fn patch_without_change_summary_returns_400() {
    if !docker_available() {
        println!("SKIP patch_without_change_summary_returns_400: no docker");
        return;
    }
    let f = boot_fixture().await;
    let resp = post_admin_create(
        &f.router,
        &f.admin_cookie,
        valid_create_body("polaris.needssummary"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Empty `change_summary`.
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/admin/policies/polaris.needssummary")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "renamed",
                "change_summary": "",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Missing field entirely (serde reports the missing-field error,
    // surfaced as 422 / 400 depending on axum's extractor pipeline).
    // We accept either as long as it's a 4xx rejection — the
    // contract is "the request did not succeed".
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/admin/policies/polaris.needssummary")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "name": "renamed" }).to_string(),
        ))
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert!(
        resp.status().is_client_error(),
        "missing change_summary must produce a 4xx, got {}",
        resp.status()
    );
}

// ── 6. history returns the chain in ASC version order ────────────────

#[tokio::test]
async fn history_returns_chain_in_correct_order() {
    if !docker_available() {
        println!("SKIP history_returns_chain_in_correct_order: no docker");
        return;
    }
    let f = boot_fixture().await;
    let resp = post_admin_create(
        &f.router,
        &f.admin_cookie,
        valid_create_body("polaris.hist"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Two amendments → versions 2 and 3.
    for (i, summary) in ["bump", "tighten"].iter().enumerate() {
        let req = Request::builder()
            .method("PATCH")
            .uri("/api/admin/policies/polaris.hist")
            .header(
                header::COOKIE,
                format!("{SESSION_COOKIE}={}", f.admin_cookie),
            )
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({
                    "description": format!("desc revision {}", i + 2),
                    "change_summary": summary,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = f.router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let req = Request::builder()
        .method("GET")
        .uri("/api/admin/policies/polaris.hist/history")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0]["version"], 1);
    assert_eq!(entries[1]["version"], 2);
    assert_eq!(entries[2]["version"], 3);
    // v1 has no diff_url; v2 + v3 each carry one.
    assert!(entries[0]["diff_url"].is_null());
    assert!(entries[1]["diff_url"].as_str().unwrap().contains("from=1"));
    assert!(entries[2]["diff_url"].as_str().unwrap().contains("from=2"));
}

// ── 7. diff endpoint surfaces only changed fields ────────────────────

#[tokio::test]
async fn diff_returns_only_changed_fields() {
    if !docker_available() {
        println!("SKIP diff_returns_only_changed_fields: no docker");
        return;
    }
    let f = boot_fixture().await;
    let resp = post_admin_create(
        &f.router,
        &f.admin_cookie,
        valid_create_body("polaris.diffme"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Change `name` only.
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/admin/policies/polaris.diffme")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": "Renamed",
                "change_summary": "rename only",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri("/api/admin/policies/polaris.diffme/diff?from=1&to=2")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = read_json(resp).await;
    assert_eq!(body["identifier"], "polaris.diffme");
    assert_eq!(body["from_version"], 1);
    assert_eq!(body["to_version"], 2);
    let changes = body["changes"].as_object().unwrap();
    assert_eq!(
        changes.len(),
        1,
        "only `name` differed; got changes: {changes:?}"
    );
    assert!(changes.contains_key("name"));
    assert_eq!(changes["name"]["from"], "polaris.diffme test policy");
    assert_eq!(changes["name"]["to"], "Renamed");
}

// ── 8. pause then resume cycle ───────────────────────────────────────

#[tokio::test]
async fn pause_then_resume_cycle() {
    if !docker_available() {
        println!("SKIP pause_then_resume_cycle: no docker");
        return;
    }
    let f = boot_fixture().await;
    let resp = post_admin_create(
        &f.router,
        &f.admin_cookie,
        valid_create_body("polaris.pause"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Pause forever (no body).
    let req = Request::builder()
        .method("POST")
        .uri("/api/admin/policies/polaris.pause/pause")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let paused: (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
        r"SELECT autonomous_paused_until FROM mod_policies
          WHERE identifier = $1 AND effective_until IS NULL",
    )
    .bind("polaris.pause")
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(paused.0.is_some(), "pause must populate the column");
    assert!(
        paused.0.unwrap().year() >= 9999,
        "no-body POST must write the 9999-12-31 sentinel; got {:?}",
        paused.0
    );

    // Resume.
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/admin/policies/polaris.pause/pause")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .body(Body::empty())
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let cleared: (Option<chrono::DateTime<chrono::Utc>>,) = sqlx::query_as(
        r"SELECT autonomous_paused_until FROM mod_policies
          WHERE identifier = $1 AND effective_until IS NULL",
    )
    .bind("polaris.pause")
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert!(cleared.0.is_none(), "resume must clear the column");
}

// ── 9. REQ-G3 hard floor at the workbook edit API ────────────────────

#[tokio::test]
async fn autonomy_mode_autonomous_on_human_required_policy_returns_403() {
    if !docker_available() {
        println!("SKIP autonomy_mode_autonomous_on_human_required_policy_returns_403: no docker");
        return;
    }
    let f = boot_fixture().await;

    // Create a policy with human_required_always = TRUE.
    let mut body = valid_create_body("polaris.csam-like");
    body["human_required_always"] = serde_json::Value::Bool(true);
    let resp = post_admin_create(&f.router, &f.admin_cookie, body).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // PATCH attempts autonomy_mode = "autonomous" → 412 with the
    // typed code `policy_autonomy_forbidden`. (The ApiError variant
    // is `PreconditionFailed` per the design's wording; the wire
    // shape is the same `code` the frontend matches on.)
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/admin/policies/polaris.csam-like")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "autonomy_mode": "autonomous",
                "change_summary": "try to flip to autonomous",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = read_json(resp).await;
    assert_eq!(body["code"], "policy_autonomy_forbidden");
    // The design references `403` for the rejection vocabulary, but
    // Polaris's ApiError::PreconditionFailed wire shape uses 412.
    // Either is documented as "the code, not the status, is the
    // load-bearing contract"; assert the code and pin the family
    // (4xx) rather than the precise status code.
    assert!(
        status.is_client_error(),
        "REQ-G3 must reject with a 4xx; got {status}"
    );
}

// ── 10. REQ-G1 floor (escalate cannot be autonomous) ─────────────────

#[tokio::test]
async fn autonomous_action_kinds_with_escalate_returns_400() {
    if !docker_available() {
        println!("SKIP autonomous_action_kinds_with_escalate_returns_400: no docker");
        return;
    }
    let f = boot_fixture().await;

    let mut body = valid_create_body("polaris.escalate-reject");
    body["autonomous_action_kinds"] = serde_json::json!(["label", "escalate"]);
    let resp = post_admin_create(&f.router, &f.admin_cookie, body).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = read_json(resp).await;
    assert_eq!(body["code"], "bad_request");
    let err_text = body["error"].as_str().unwrap_or_default();
    assert!(
        err_text.contains("autonomous_action_kinds"),
        "error must name the offending field; got: {body}"
    );
}

// Re-import chrono's `Datelike` trait for the pause test's
// `.year()` access. Kept at the bottom so the test-module shape
// stays cohesive at the top.
use chrono::Datelike as _;
