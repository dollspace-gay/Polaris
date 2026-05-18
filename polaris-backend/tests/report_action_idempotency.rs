//! Per-report action idempotency (issue #202).
//!
//! Tests prove the contract:
//!
//! 1. Two POSTs of the same `submit_action` body with the same
//!    `report_id` record exactly ONE `actions` row, and both responses
//!    return the same `action_id`. Concretely: the first call returns
//!    `201 Created`; the second returns `200 OK` with the same body.
//! 2. After the first call, `reports.actioned_at` is populated and
//!    `reports.actioned_by_action_id` points at the inserted action.
//! 3. The case-view's `reports[]` panel filters the actioned row out so
//!    the report card stops appearing.
//!
//! The fixture pattern mirrors `tests/case_api.rs`: a fresh
//! testcontainers Postgres per test, all migrations applied via
//! `db::connect`, a router built via `api::router_with_state`, and
//! requests driven through `tower::ServiceExt::oneshot` so the
//! cookie-driven auth middleware participates.

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
use polaris_backend::repo::{
    self, IncidentRepo, NewReport, PgIncidentRepo, PgReportRepo, PgSubjectRepo, ReportRepo,
    SubjectRepo,
};
use polaris_types::{
    Did, IncidentId, IncidentStatus, ModeratorId, ReportCategory, ReportId, Severity, SubjectId,
    SubjectKind,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors `case_api`'s skip
/// behaviour so the integration suite is uniform.
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

fn build_router(db: db::Db, state: ApiState) -> Router {
    api::router_with_state(db, state)
}

async fn insert_moderator(pool: &PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("idempotency-test-{}", Uuid::new_v4());
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

async fn grant_moderator_role(
    pool: &PgPool,
    moderator_id: ModeratorId,
) -> Result<(), Box<dyn std::error::Error>> {
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

async fn mint_session(
    sessions: &SessionStore,
    moderator_id: ModeratorId,
) -> Result<String, Box<dyn std::error::Error>> {
    let new_session = sessions
        .create(AuthModeratorId(moderator_id.0), b"test-refresh-token-plain")
        .await?;
    Ok(new_session.token.as_str().to_owned())
}

struct Fixture {
    subject_id: SubjectId,
    incident_id: IncidentId,
    report_id: ReportId,
    moderator_id: ModeratorId,
    session_cookie: String,
}

/// Seed one subject + one open incident + one moderator with role +
/// one un-actioned report. Sets `polaris_setup_state.signing_pubkey_did`
/// so the cold-path emit-precondition check passes for Label/Takedown
/// kinds (though this test uses NoAction-style Dismiss, the wiring
/// matches the production fixture in `case_api.rs`).
async fn seed_fixture(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<Fixture, Box<dyn std::error::Error>> {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let report_repo = PgReportRepo::new(pool.clone());

    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new(format!(
                "did:plc:idempotency-{}",
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
    let report = report_repo
        .insert(NewReport {
            subject_id: subject.id,
            incident_id: Some(incident.id),
            reporter_did: Did::new(format!("did:plc:reporter-{}", Uuid::new_v4().simple())),
            category: ReportCategory::new("spam"),
            body: "duplicate-test report body".to_owned(),
        })
        .await?;

    let moderator_id = insert_moderator(pool).await?;
    grant_moderator_role(pool, moderator_id).await?;
    let session_cookie = mint_session(sessions, moderator_id).await?;

    // Mirror `case_api::seed_fixture`'s setup-state primer so the
    // signing-key gate doesn't gate the cold-path code with a 412 if
    // the test ever flips kind to Label/Takedown.
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
    .execute(pool)
    .await?;

    // WB-2 (#224): action-create now resolves cited identifiers against
    // `mod_policies`. Seed the placeholder set so bodies citing
    // `polaris.spam` continue to land at the 201 / idempotent paths.
    polaris_backend::test_support::seed_placeholder_policies(pool, moderator_id.0).await?;

    Ok(Fixture {
        subject_id: subject.id,
        incident_id: incident.id,
        report_id: report.id,
        moderator_id,
        session_cookie,
    })
}

async fn boot_fixture() -> Result<(Router, PgPool, SessionStore), Box<dyn std::error::Error>> {
    let (db, pool) = boot_db().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = build_router(db, state);
    Ok((router, pool, sessions))
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

/// AC: two POSTs with the same `report_id` → one row, same `action_id`,
/// report flagged `actioned_at`, case-view panel filters the report out.
#[tokio::test]
async fn submit_action_with_report_id_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP report_action_idempotency::submit_action_with_report_id_is_idempotent: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    let fixture = seed_fixture(&pool, &sessions).await?;

    // Use NoAction (Dismiss-shaped) — no signing-key requirement, no
    // emit step to mock. The wire shape matches the report-card's
    // Dismiss button.
    let body = serde_json::json!({
        "incident_id": fixture.incident_id,
        "kind": "no_action",
        "reasoning": "this dismissal reasoning is sufficiently long",
        "policy_refs": ["polaris.spam"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
        "report_id": fixture.report_id,
    });
    let make_request = || -> Result<Request<Body>, Box<dyn std::error::Error>> {
        Ok(Request::builder()
            .method("POST")
            .uri(format!("/api/cases/{}/actions", fixture.subject_id.0))
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                header::COOKIE,
                format!("{SESSION_COOKIE}={}", fixture.session_cookie),
            )
            .body(Body::from(serde_json::to_vec(&body)?))?)
    };

    // First POST: cold path. 201 Created.
    let response = router.clone().oneshot(make_request()?).await?;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "first POST must surface 201 Created (cold path)",
    );
    let first_body = read_json_body(response).await;
    let first_action_id = first_body["id"]
        .as_str()
        .expect("response.id is a string")
        .to_owned();

    // Second POST: idempotent path. 200 OK with the same action_id.
    let response = router.clone().oneshot(make_request()?).await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "second POST must surface 200 OK (idempotent path)",
    );
    let second_body = read_json_body(response).await;
    let second_action_id = second_body["id"]
        .as_str()
        .expect("response.id is a string")
        .to_owned();
    assert_eq!(
        first_action_id, second_action_id,
        "both POSTs must return the same action id; report-card idempotency",
    );

    // Exactly one action row exists for the (subject, moderator) tuple.
    let count: (i64,) =
        sqlx::query_as("SELECT count(*) FROM actions WHERE subject_id = $1 AND moderator_id = $2")
            .bind(fixture.subject_id.0)
            .bind(fixture.moderator_id.0)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        count.0, 1,
        "exactly one action row must exist after the duplicate POST",
    );

    // The report row carries the actioned_at + actioned_by_action_id
    // bookkeeping.
    let row: (Option<chrono::DateTime<Utc>>, Option<Uuid>) =
        sqlx::query_as("SELECT actioned_at, actioned_by_action_id FROM reports WHERE id = $1")
            .bind(fixture.report_id.as_uuid())
            .fetch_one(&pool)
            .await?;
    assert!(
        row.0.is_some(),
        "reports.actioned_at must be populated after the first POST",
    );
    let actioned_by = row
        .1
        .expect("reports.actioned_by_action_id must be populated");
    assert_eq!(
        actioned_by.to_string(),
        first_action_id,
        "actioned_by_action_id must point at the recorded action",
    );

    // Case-view's reports[] panel must NOT include the actioned report.
    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/cases/{}", fixture.subject_id.0))
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", fixture.session_cookie),
        )
        .body(Body::empty())?;
    let response = router.clone().oneshot(request).await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "case-view GET must surface 200 OK after the dismissal",
    );
    let case_body = read_json_body(response).await;
    let reports = case_body["reports"]
        .as_array()
        .expect("case-view reports[] is an array");
    let actioned_id_string = fixture.report_id.as_uuid().to_string();
    let still_visible = reports
        .iter()
        .any(|r| r["id"].as_str() == Some(actioned_id_string.as_str()));
    assert!(
        !still_visible,
        "actioned report must NOT appear in case-view reports[]; body was {case_body}",
    );

    Ok(())
}
