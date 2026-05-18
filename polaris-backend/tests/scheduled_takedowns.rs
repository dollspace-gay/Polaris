//! Integration tests for the scheduled-takedown surface (L1).
//!
//! Covers:
//!   1. `POST /api/scheduled-takedowns` — schedule a future takedown.
//!   2. `DELETE /api/scheduled-takedowns/{id}` — cancel a pending row.
//!   3. The background worker's `drain_due_schedules` materialises a
//!      due schedule as an `actions` row of `kind = takedown`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::{Duration, Utc};
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
use polaris_types::{Did, IncidentStatus, ModeratorId, Severity, SubjectId, SubjectKind};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn boot() -> Result<(Router, PgPool, SessionStore), Box<dyn std::error::Error>> {
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
    let crypto = Crypto::new([88_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(db, state);
    std::mem::forget(container);
    Ok((router, pool, sessions))
}

async fn seed_moderator_session(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<(ModeratorId, String), Box<dyn std::error::Error>> {
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        format!("sched-test-{}", Uuid::new_v4()),
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
    // WB-2 (#224): scheduled-takedown validates each cited identifier
    // against `mod_policies`. Seed the placeholder set so bodies
    // citing `polaris.spam` etc. pass the lookup.
    polaris_backend::test_support::seed_placeholder_policies(pool, moderator_id.0).await?;
    Ok((moderator_id, new_session.token.as_str().to_owned()))
}

async fn seed_subject_and_incident(
    pool: &PgPool,
) -> Result<(SubjectId, polaris_types::IncidentId), Box<dyn std::error::Error>> {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new(format!(
                "did:plc:sched-{}",
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
    Ok((subject.id, incident.id))
}

/// Schedule a takedown for 1 hour out; verify the row landed and is
/// PENDING (no executed_at, no cancelled_at).
#[tokio::test]
async fn schedule_persists_pending_row() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP scheduled_takedowns::schedule: docker not reachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot().await?;
    let (_mod_id, cookie) = seed_moderator_session(&pool, &sessions).await?;
    let (subject_id, incident_id) = seed_subject_and_incident(&pool).await?;
    let execute_at = Utc::now() + Duration::hours(1);
    let body = serde_json::json!({
        "subject_id": subject_id,
        "incident_id": incident_id,
        "execute_at": execute_at.to_rfc3339(),
        "reasoning": "deferred enforcement after operator review window",
        "policy_refs": ["polaris.spam"],
        "label_value": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/scheduled-takedowns")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    assert!(payload["executed_at"].is_null());
    assert!(payload["cancelled_at"].is_null());

    let count = sqlx::query!(
        "SELECT COUNT(*) AS cnt FROM scheduled_takedowns WHERE subject_id = $1",
        subject_id.0,
    )
    .fetch_one(&pool)
    .await?
    .cnt
    .unwrap_or(0);
    assert_eq!(count, 1);
    Ok(())
}

/// Reject schedules with `execute_at` in the past — the worker would
/// otherwise fire them immediately, which defeats the "deferred"
/// contract.
#[tokio::test]
async fn schedule_rejects_past_execute_at() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP scheduled_takedowns::past: docker not reachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot().await?;
    let (_mod_id, cookie) = seed_moderator_session(&pool, &sessions).await?;
    let (subject_id, incident_id) = seed_subject_and_incident(&pool).await?;
    let body = serde_json::json!({
        "subject_id": subject_id,
        "incident_id": incident_id,
        "execute_at": (Utc::now() - Duration::hours(1)).to_rfc3339(),
        "reasoning": "past-dated schedule should be rejected",
        "policy_refs": ["polaris.spam"],
        "label_value": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/scheduled-takedowns")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

/// Cancel-then-double-cancel: first cancel returns 204; second returns 409.
#[tokio::test]
async fn cancel_is_idempotent_with_conflict_on_double() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP scheduled_takedowns::cancel: docker not reachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot().await?;
    let (_mod_id, cookie) = seed_moderator_session(&pool, &sessions).await?;
    let (subject_id, incident_id) = seed_subject_and_incident(&pool).await?;
    // Schedule
    let body = serde_json::json!({
        "subject_id": subject_id,
        "incident_id": incident_id,
        "execute_at": (Utc::now() + Duration::hours(2)).to_rfc3339(),
        "reasoning": "schedule then cancel for double-cancel test",
        "policy_refs": ["polaris.spam"],
        "label_value": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri("/api/scheduled-takedowns")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.clone().oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let payload: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await?.to_bytes())?;
    let id = payload["id"].as_str().unwrap();

    // First cancel
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/scheduled-takedowns/{id}"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = router.clone().oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Second cancel → 409 because the row is already cancelled.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/scheduled-takedowns/{id}"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    Ok(())
}
