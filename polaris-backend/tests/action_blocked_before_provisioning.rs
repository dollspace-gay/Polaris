//! AC-A3: emit-shaped actions submitted before the labeler's signing
//! key is provisioned must surface `412 Precondition Failed` with
//! `code = "labeler_not_provisioned"`, and the action row must NOT
//! land in `actions` (the precondition fires BEFORE the insert).
//!
//! The fixture pattern mirrors `tests/case_api.rs` and
//! `tests/threats_common/mod.rs`: a testcontainer Postgres + the
//! production router, driven over `tower::ServiceExt::oneshot`.
//!
//! # What this test pins
//!
//! - Label / Takedown actions are rejected 412 when
//!   `polaris_setup_state.signing_pubkey_did IS NULL`. The
//!   `actions` table stays empty.
//! - `Mute`, `Warn`, `Escalate`, `NoAction` (non-emit kinds) pass through:
//!   the precondition does not gate them, the insert returns 201.
//! - When the operator later seeds `signing_pubkey_did`, Label
//!   submissions begin to succeed without a process restart.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7"
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
use polaris_types::{
    Did, IncidentId, IncidentStatus, ModeratorId, Severity, SubjectId, SubjectKind,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// `did:key:z…` form of a fresh K-256 public half. Used as the
/// "labeler is provisioned" seed value. The bytes are not load-
/// bearing — the precondition check only asserts non-NULL.
const PROVISIONED_DID_KEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";

/// Probe for a working Docker daemon. Mirrors every other
/// integration test in this crate so the skip behaviour is uniform.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the
/// `(db, pool)` pair. The container handle is leaked so its Drop
/// runs at process exit, not at this helper's stack frame.
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
    std::mem::forget(container);
    Ok((database, pool))
}

/// Single shared fixture: subject, incident, moderator-with-session.
struct Fixture {
    subject_id: SubjectId,
    incident_id: IncidentId,
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
                "did:plc:not-yet-provisioned-{}",
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

    let external_id = format!("provisioning-gate-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    let moderator_id = ModeratorId(row.id);

    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id.0)
    .bind(Role::Moderator.as_db_str())
    .execute(pool)
    .await?;

    let new_session = sessions
        .create(AuthModeratorId(moderator_id.0), b"test-refresh-token")
        .await?;
    let cookie = new_session.token.as_str().to_owned();

    // CRITICAL: do NOT seed `polaris_setup_state.signing_pubkey_did` —
    // the whole point of this test is the missing-key gate.

    // WB-2 (#224): seed the placeholder policy set so the cited
    // `polaris.spam` identifier resolves; the missing-key gate runs
    // BEFORE policy resolution for Label/Takedown but AFTER for Mute,
    // so the Mute subtests would otherwise reject as
    // `unknown_policy_ref` instead of hitting the labeler-key path.
    polaris_backend::test_support::seed_placeholder_policies(pool, moderator_id.0).await?;

    Ok(Fixture {
        subject_id: subject.id,
        incident_id: incident.id,
        session_cookie: cookie,
    })
}

/// Build the production router around a state without any labeler
/// wiring — same shape the real binary serves during the first-run
/// boot window before the wizard has minted a key.
fn build_router(db: db::Db, pool: PgPool, sessions: SessionStore) -> Router {
    let state = ApiState::new(pool, sessions);
    api::router_with_state(db, state)
}

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

// ── AC-A3 primary: Label rejected with 412 + correct code ──────────────

#[tokio::test]
async fn label_action_returns_412_when_signing_key_not_provisioned()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP action_blocked_before_provisioning::label_action_returns_412_when_signing_key_not_provisioned: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let router = build_router(database, pool.clone(), sessions.clone());
    let fixture = seed_fixture(&pool, &sessions).await?;

    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "this reasoning is sufficiently long to pass validation",
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
        StatusCode::PRECONDITION_FAILED,
        "Label action against an unprovisioned labeler must surface 412 Precondition Failed",
    );
    let body_json = read_json_body(response).await;
    assert_eq!(
        body_json["code"], "labeler_not_provisioned",
        "response body must carry the machine-readable code; body was {body_json}",
    );
    assert!(
        body_json["error"]
            .as_str()
            .unwrap_or_default()
            .contains("setup"),
        "response body must point the operator at /setup; body was {body_json}",
    );

    // The precondition fires BEFORE the insert — no row in `actions`.
    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM actions")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        count.0, 0,
        "no action row may be written when the precondition fails",
    );
    Ok(())
}

// ── AC-A3 corollary: Takedown is also gated ────────────────────────────

#[tokio::test]
async fn takedown_action_returns_412_when_signing_key_not_provisioned()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP action_blocked_before_provisioning::takedown_action_returns_412_when_signing_key_not_provisioned: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let router = build_router(database, pool.clone(), sessions.clone());
    let fixture = seed_fixture(&pool, &sessions).await?;

    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "takedown",
        "label": null,
        "reasoning": "takedown reasoning text is sufficiently long for validation",
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
        StatusCode::PRECONDITION_FAILED,
        "Takedown action against an unprovisioned labeler must also surface 412",
    );
    let body_json = read_json_body(response).await;
    assert_eq!(body_json["code"], "labeler_not_provisioned");
    Ok(())
}

// ── AC-A3 negative branch: non-emit kinds bypass the gate ──────────────

#[tokio::test]
async fn mute_action_succeeds_when_signing_key_not_provisioned()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP action_blocked_before_provisioning::mute_action_succeeds_when_signing_key_not_provisioned: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let router = build_router(database, pool.clone(), sessions.clone());
    let fixture = seed_fixture(&pool, &sessions).await?;

    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "mute",
        "label": null,
        "reasoning": "mute action reasoning is sufficiently long for the validator",
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
        "Mute is a non-emit action; the labeler-not-provisioned gate must NOT fire",
    );

    let count: (i64,) = sqlx::query_as("SELECT count(*) FROM actions WHERE kind = 'mute'")
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        count.0, 1,
        "the mute action must have been persisted exactly once",
    );
    Ok(())
}

// ── AC-A3 transition: seeding the DID lifts the gate ───────────────────

#[tokio::test]
async fn label_action_succeeds_after_signing_key_is_provisioned()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP action_blocked_before_provisioning::label_action_succeeds_after_signing_key_is_provisioned: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let router = build_router(database, pool.clone(), sessions.clone());
    let fixture = seed_fixture(&pool, &sessions).await?;

    // Simulate the wizard's `generate_key` DB-side effect: write the
    // signing public DID into `polaris_setup_state`. The router is
    // unchanged — the precondition check re-reads the DB on every
    // call, so no process restart is needed.
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(PROVISIONED_DID_KEY)
    .execute(&pool)
    .await?;

    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "this reasoning is sufficiently long to pass validation",
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
        "after seeding signing_pubkey_did, the same Label submission must succeed (201)",
    );
    Ok(())
}
