//! Integration test for `POST /api/bulk-actions` (issue #193).
//!
//! Boots a fresh router + Postgres, mints a moderator session, inserts
//! N subjects sharing one incident, posts a bulk-action body, and
//! asserts:
//!
//! 1. The HTTP status is 200 OK.
//! 2. The response carries `succeeded` with every subject id from
//!    the request and `failed: []`.
//! 3. The `actions` table holds one row per `subject_id` (cardinality N).

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
    let crypto = Crypto::new([99_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(db, state);
    std::mem::forget(container);
    Ok((router, pool, sessions))
}

/// Insert one moderator + grant the Moderator role + mint a session.
async fn seed_moderator_session(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<(ModeratorId, String), Box<dyn std::error::Error>> {
    let external_id = format!("bulk-test-{}", Uuid::new_v4());
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
        .create(AuthModeratorId(moderator_id.0), b"test-refresh-token-plain")
        .await?;
    Ok((moderator_id, new_session.token.as_str().to_owned()))
}

/// Returns 3 subjects sharing one incident.
async fn seed_three_subjects(
    pool: &PgPool,
) -> Result<(polaris_types::IncidentId, Vec<SubjectId>), Box<dyn std::error::Error>> {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let mut ids = Vec::with_capacity(3);
    for _ in 0..3 {
        let s = subject_repo
            .insert(repo::NewSubject {
                kind: SubjectKind::Account,
                did: Some(Did::new(format!(
                    "did:plc:bulk-{}",
                    Uuid::new_v4().simple()
                ))),
                uri: None,
                created_at: Utc::now(),
            })
            .await?;
        ids.push(s.id);
    }
    let incident = incident_repo
        .insert(repo::NewIncident {
            primary_subject: ids[0],
            severity: Severity::Medium,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await?;
    Ok((incident.id, ids))
}

/// Bulk action against 3 subjects with kind = NoAction (the simplest
/// verb that doesn't require labeler-key provisioning).
#[tokio::test]
async fn bulk_action_persists_one_row_per_subject() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP bulk_actions::three_subjects: docker not reachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot().await?;
    let (_moderator_id, cookie) = seed_moderator_session(&pool, &sessions).await?;
    let (incident_id, subject_ids) = seed_three_subjects(&pool).await?;

    let body = serde_json::json!({
        "subject_ids": subject_ids,
        "body": {
            "incident_id": incident_id,
            "kind": "no_action",
            "label": null,
            "reasoning": "bulk acknowledgement of triaged spam reports",
            "policy_refs": ["polaris.spam"],
            "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
            "reverses_action_id": null,
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/bulk-actions")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let bytes = response.into_body().collect().await?.to_bytes();
    let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
    let succeeded = payload["succeeded"].as_array().unwrap();
    let failed = payload["failed"].as_array().unwrap();
    assert_eq!(succeeded.len(), 3, "all 3 subjects must succeed");
    assert_eq!(failed.len(), 0, "no failures expected");

    // Verify actions table.
    let count = sqlx::query!(
        "SELECT COUNT(*) AS cnt FROM actions WHERE incident_id = $1",
        incident_id.0,
    )
    .fetch_one(&pool)
    .await?
    .cnt
    .unwrap_or(0);
    assert_eq!(count, 3, "one actions row per subject must persist");
    Ok(())
}

/// Empty subject_ids → 400.
#[tokio::test]
async fn bulk_action_rejects_empty_subject_ids() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP bulk_actions::empty: docker not reachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot().await?;
    let (_moderator_id, cookie) = seed_moderator_session(&pool, &sessions).await?;
    let (incident_id, _) = seed_three_subjects(&pool).await?;

    let body = serde_json::json!({
        "subject_ids": [],
        "body": {
            "incident_id": incident_id,
            "kind": "no_action",
            "label": null,
            "reasoning": "this should be rejected before iteration",
            "policy_refs": ["polaris.spam"],
            "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
            "reverses_action_id": null,
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/bulk-actions")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

/// Batch above BULK_ACTIONS_MAX_SUBJECTS (50) → 400.
#[tokio::test]
async fn bulk_action_rejects_oversized_batch() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP bulk_actions::oversize: docker not reachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot().await?;
    let (_moderator_id, cookie) = seed_moderator_session(&pool, &sessions).await?;
    let (incident_id, _) = seed_three_subjects(&pool).await?;

    // Fabricate 51 random UUIDs — they won't resolve to real subjects
    // but the 51-element length check fires BEFORE any per-subject
    // resolution, so we expect a 400 with no DB writes.
    let fake_ids: Vec<Uuid> = (0..51).map(|_| Uuid::new_v4()).collect();
    let body = serde_json::json!({
        "subject_ids": fake_ids,
        "body": {
            "incident_id": incident_id,
            "kind": "no_action",
            "label": null,
            "reasoning": "intentionally oversized batch to exercise the cap",
            "policy_refs": ["polaris.spam"],
            "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
            "reverses_action_id": null,
        }
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/bulk-actions")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}
