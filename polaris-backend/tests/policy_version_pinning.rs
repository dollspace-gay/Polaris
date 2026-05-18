//! WB-2 (#224) integration tests — action-create + reversal cite the
//! `mod_policies` row currently in force at write time, snapshotted as
//! `(identifier, version)` into `action_policy_citations`.
//!
//! Hermetic per test: each test boots its own testcontainers Postgres
//! 16-alpine, applies all migrations via `db::connect`, builds an
//! [`ApiState`] + full router, and drives the router via
//! `tower::ServiceExt::oneshot`. The session-cookie auth middleware
//! participates in the request path under test so the wire shape
//! matches production.
//!
//! Mirrors the `tests/case_api.rs` boot harness for the docker /
//! migration / session-cookie scaffolding.

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
use polaris_backend::repo::action_policy_citations;
use polaris_backend::repo::mod_policies::{self, ModPolicyPatch, NewModPolicy};
use polaris_backend::repo::{self, IncidentRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo};
use polaris_backend::test_support::seed_placeholder_policies;
use polaris_types::{Did, IncidentId, IncidentStatus, Severity, SubjectId, SubjectKind};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors `case_api.rs`.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the (`db`, `pool`)
/// pair. Mirrors `case_api.rs::boot_db`.
async fn boot_db() -> Result<(polaris_backend::db::Db, PgPool), Box<dyn std::error::Error>> {
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

/// Build the (`router`, `pool`, `sessions`) triple shared by every test.
async fn boot_fixture() -> Result<(Router, PgPool, SessionStore), Box<dyn std::error::Error>> {
    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(database, state);
    Ok((router, pool, sessions))
}

/// Insert a fresh moderator + role + session cookie. The returned
/// `(moderator_id, cookie)` pair is what every action body in this file
/// rides.
async fn seed_session(
    pool: &PgPool,
    sessions: &SessionStore,
) -> Result<(Uuid, String), Box<dyn std::error::Error>> {
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        format!("policy-pin-test-{}", Uuid::new_v4()),
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
        .create(AuthModeratorId(moderator_id), b"test-refresh-token-plain")
        .await?;
    Ok((moderator_id, new_session.token.as_str().to_owned()))
}

/// Seed one subject + one open incident. Returns the ids.
async fn seed_subject_incident(
    pool: &PgPool,
) -> Result<(SubjectId, IncidentId), Box<dyn std::error::Error>> {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new(format!(
                "did:plc:pinning-{}",
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

/// Prime `polaris_setup_state.signing_pubkey_did` so emit-shaped action
/// kinds (Label / Takedown) pass the REQ-A3 precondition.
async fn prime_setup_state(pool: &PgPool) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
    .execute(pool)
    .await?;
    Ok(())
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

// ── happy-path: cited policy resolves + citation snapshot lands ────────

#[tokio::test]
async fn action_with_current_policy_version_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_version_pinning::happy_path: docker unreachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    prime_setup_state(&pool).await?;
    let (moderator_id, cookie) = seed_session(&pool, &sessions).await?;
    let (subject_id, incident_id) = seed_subject_incident(&pool).await?;
    // Seed v1 of polaris.spam.
    seed_placeholder_policies(&pool, moderator_id).await?;

    let body = serde_json::json!({
        "incident_id": incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "happy path: policy resolves to v1 and the citation row mirrors that snapshot",
        "policy_refs": ["polaris.spam"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "valid body with a current placeholder policy must surface 201",
    );
    let body = read_json_body(response).await;
    let action_id = body["id"].as_str().expect("response carries action id");
    let action_uuid = Uuid::parse_str(action_id)?;

    // The citation row carries the snapshot version.
    let citations = action_policy_citations::citations_for_action(&pool, action_uuid).await?;
    assert_eq!(
        citations.len(),
        1,
        "exactly one citation per cited identifier"
    );
    assert_eq!(citations[0].policy_identifier, "polaris.spam");
    assert_eq!(
        citations[0].policy_version, 1,
        "citation must pin to mod_policies.version = 1 at insert time",
    );

    Ok(())
}

// ── unknown identifier → 400 unknown_policy_ref ────────────────────────

#[tokio::test]
async fn action_with_unknown_identifier_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_version_pinning::unknown_identifier: docker unreachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    prime_setup_state(&pool).await?;
    let (moderator_id, cookie) = seed_session(&pool, &sessions).await?;
    let (subject_id, incident_id) = seed_subject_incident(&pool).await?;
    // Intentionally DO NOT seed placeholder policies — we want
    // polaris.does-not-exist to miss.
    let _ = moderator_id;

    let body = serde_json::json!({
        "incident_id": incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "deliberately citing an identifier that has no mod_policies row",
        "policy_refs": ["polaris.does-not-exist"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json_body(response).await;
    assert_eq!(
        body["code"], "unknown_policy_ref",
        "body must carry typed code=unknown_policy_ref; got {body}",
    );
    assert_eq!(
        body["identifier"], "polaris.does-not-exist",
        "body must echo the offending identifier; got {body}",
    );
    Ok(())
}

// ── retired policy → 400 policy_retired ────────────────────────────────

#[tokio::test]
async fn action_with_retired_policy_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_version_pinning::retired_policy: docker unreachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    prime_setup_state(&pool).await?;
    let (moderator_id, cookie) = seed_session(&pool, &sessions).await?;
    let (subject_id, incident_id) = seed_subject_incident(&pool).await?;
    // Use a unique identifier so the process-wide policy cache cannot
    // observe a stale "current and not retired" entry from a sibling
    // test in the same binary.
    let identifier = format!("polaris.pin-retired-{}", Uuid::new_v4().simple());
    let mut tx = pool.begin().await?;
    mod_policies::insert_initial(
        &mut tx,
        new_policy_fixture(identifier.clone()),
        moderator_id,
    )
    .await?;
    tx.commit().await?;
    // Retire via amend.
    let mut tx = pool.begin().await?;
    mod_policies::amend(
        &mut tx,
        &identifier,
        ModPolicyPatch {
            is_retired: Some(true),
            ..ModPolicyPatch::default()
        },
        moderator_id,
        Some("retire under test".to_owned()),
    )
    .await?;
    tx.commit().await?;

    let body = serde_json::json!({
        "incident_id": incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "deliberate citation against a retired policy — must reject",
        "policy_refs": [identifier],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json_body(response).await;
    assert_eq!(
        body["code"], "policy_retired",
        "body must carry typed code=policy_retired; got {body}",
    );
    Ok(())
}

// ── stale read between amend + insert: new citation uses the new version ──

#[tokio::test]
async fn action_with_stale_version_after_amend_uses_new_version()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_version_pinning::stale_version: docker unreachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    prime_setup_state(&pool).await?;
    let (moderator_id, cookie) = seed_session(&pool, &sessions).await?;
    let (subject_id, incident_id) = seed_subject_incident(&pool).await?;

    // Seed a fresh identifier — `policy-version-pin` — to keep the
    // per-process policy_cache singleton from leaking a stale v1 hit
    // into this test from a sibling test in the same binary. Each
    // test uses its own unique identifier so the cache cannot
    // observe a stale entry.
    let identifier = format!("polaris.pin-stale-{}", Uuid::new_v4().simple());
    let mut tx = pool.begin().await?;
    mod_policies::insert_initial(
        &mut tx,
        new_policy_fixture(identifier.clone()),
        moderator_id,
    )
    .await?;
    tx.commit().await?;

    // Amend to v2 BEFORE we submit the action. The cache (if any) is
    // empty for this fresh identifier, so the first lookup must hit
    // the DB and observe v2 directly.
    let mut tx = pool.begin().await?;
    mod_policies::amend(
        &mut tx,
        &identifier,
        ModPolicyPatch {
            description: Some("amended to v2 between read and insert".to_owned()),
            ..ModPolicyPatch::default()
        },
        moderator_id,
        Some("v2 cosmetic amend".to_owned()),
    )
    .await?;
    tx.commit().await?;

    let body = serde_json::json!({
        "incident_id": incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "after v2 amend the action must cite the new current version",
        "policy_refs": [identifier],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = read_json_body(response).await;
    let action_uuid = Uuid::parse_str(body["id"].as_str().unwrap())?;
    let citations = action_policy_citations::citations_for_action(&pool, action_uuid).await?;
    assert_eq!(citations.len(), 1);
    assert_eq!(
        citations[0].policy_version, 2,
        "action must cite v2, the version current at insert time"
    );
    Ok(())
}

// ── reversal cites current version, not original's snapshot ────────────

#[tokio::test]
async fn reversal_cites_current_version_not_original() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_version_pinning::reversal_cites_current: docker unreachable");
        return Ok(());
    }
    let (router, pool, sessions) = boot_fixture().await?;
    prime_setup_state(&pool).await?;
    let (moderator_id, _cookie) = seed_session(&pool, &sessions).await?;
    // Promote the moderator to SeniorModerator so the reversal
    // window-and-author gates pass regardless of timing.
    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id)
    .bind(Role::SeniorModerator.as_db_str())
    .execute(&pool)
    .await?;
    // Re-mint the session so the role set carries SeniorModerator.
    let new_session = sessions
        .create(AuthModeratorId(moderator_id), b"reversal-test-token")
        .await?;
    let cookie = new_session.token.as_str().to_owned();
    let (subject_id, incident_id) = seed_subject_incident(&pool).await?;

    // Unique identifier per test invocation to avoid cross-test
    // cache collisions in the per-process LRU singleton.
    let identifier = format!("polaris.pin-reversal-{}", Uuid::new_v4().simple());
    let mut tx = pool.begin().await?;
    mod_policies::insert_initial(
        &mut tx,
        new_policy_fixture(identifier.clone()),
        moderator_id,
    )
    .await?;
    tx.commit().await?;

    // Original action cites v1.
    let body = serde_json::json!({
        "incident_id": incident_id,
        "kind": "label",
        "label": "spam",
        "reasoning": "original action citing the v1 snapshot of the test identifier",
        "policy_refs": [identifier],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject_id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.clone().oneshot(req).await?;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = read_json_body(response).await;
    let original_action_uuid = Uuid::parse_str(body["id"].as_str().unwrap())?;

    // Confirm the original cites v1.
    let original_citations =
        action_policy_citations::citations_for_action(&pool, original_action_uuid).await?;
    assert_eq!(original_citations.len(), 1);
    assert_eq!(original_citations[0].policy_version, 1);

    // Amend to v2 between the original write and the reversal.
    let mut tx = pool.begin().await?;
    mod_policies::amend(
        &mut tx,
        &identifier,
        ModPolicyPatch {
            description: Some("amended to v2 between original action and reversal".to_owned()),
            ..ModPolicyPatch::default()
        },
        moderator_id,
        Some("v2 cosmetic amend".to_owned()),
    )
    .await?;
    tx.commit().await?;

    // Reverse the original action.
    let reverse_body = serde_json::json!({
        "reasoning": "reversal: the new policy version supersedes the prior wording",
    });
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/actions/{original_action_uuid}/reverse"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&reverse_body)?))?;
    let response = router.oneshot(req).await?;
    assert_eq!(
        response.status(),
        StatusCode::CREATED,
        "reversal must surface 201 Created",
    );
    let body = read_json_body(response).await;
    let reversal_action_uuid = Uuid::parse_str(body["id"].as_str().unwrap())?;

    // Reversal cites v2; original is untouched at v1.
    let reversal_citations =
        action_policy_citations::citations_for_action(&pool, reversal_action_uuid).await?;
    assert_eq!(reversal_citations.len(), 1);
    assert_eq!(
        reversal_citations[0].policy_version, 2,
        "REQ-B5: reversal cites the current policy version at reversal time, not v1",
    );

    // And the original's citations are untouched.
    let original_citations_after =
        action_policy_citations::citations_for_action(&pool, original_action_uuid).await?;
    assert_eq!(original_citations_after.len(), 1);
    assert_eq!(
        original_citations_after[0].policy_version, 1,
        "original's citation snapshot is immutable across the reversal",
    );

    Ok(())
}

// ── private fixture ───────────────────────────────────────────────────

fn new_policy_fixture(identifier: String) -> NewModPolicy {
    NewModPolicy {
        name: format!("{identifier} title"),
        description: format!("placeholder description for {identifier}"),
        scope: "post".to_owned(),
        severity: "alert".to_owned(),
        decision_criteria: "Apply this policy when the integration test fixture exercises it."
            .to_owned(),
        examples_positive: None,
        examples_negative: None,
        suggested_action_kinds: vec!["label".to_owned()],
        linked_label_value: None,
        exceptions: None,
        human_required_always: false,
        autonomy_mode: "manual".to_owned(),
        autonomous_action_kinds: vec![],
        autonomous_confidence_threshold: 0.95,
        assisted_confidence_threshold: 0.70,
        change_summary: None,
        identifier,
    }
}
