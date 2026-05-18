//! WB-7 (#229) cross-layer regression test for the
//! `human_required_always` safety floor (`.design/mod-policy-workbook.md`
//! REQ-G1, REQ-G2, REQ-G3; AC-8).
//!
//! Three enforcement layers, two of which we own here:
//!
//! 1. **Policy edit API** (WB-3, #225) — `PATCH
//!    /api/admin/policies/:identifier` refuses an `autonomy_mode =
//!    'autonomous'` write against a `human_required_always = TRUE`
//!    row (`policy_autonomy_forbidden`) and refuses an
//!    `autonomous_action_kinds` payload that includes any kind
//!    outside `{label, warn, takedown}` (REQ-G1).
//! 2. **Action-create API** (this issue, WB-7) — an action submitted
//!    via [`polaris_backend::api::cases::submit_action_autonomous_for_test`]
//!    with `actor_kind = 'autonomous_agent'` is rejected when any
//!    cited policy carries `human_required_always = TRUE`
//!    (`policy_autonomy_forbidden`) or when the action is a
//!    `takedown` against an `account`-kind subject
//!    (`account_takedown_autonomous_forbidden`, REQ-G2).
//! 3. **LLM dispatcher** (LLM-6, #235) — out of scope; tested under
//!    `tests/llm_safety_floors.rs` per
//!    `.design/llm-moderation-assist.md` AC-6.
//!
//! Per AC-8 the layer-1 + layer-2 floors are regression-pinned
//! together so that a future change to either path that quietly
//! drops the rejection trips this binary. Tests skip cleanly when
//! Docker is unreachable (same convention as the rest of
//! `polaris-backend/tests/`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::panic,
    clippy::missing_panics_doc,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use chrono::Utc;
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::dto::SubmitAction;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorAuthCtx, ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::middleware::auth::SESSION_COOKIE;
use polaris_backend::repo::action::LlmAuditFields;
use polaris_backend::repo::mod_policies::{self, NewModPolicy};
use polaris_backend::repo::{self, IncidentRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo};
use polaris_types::{
    ActionKind, Did, IncidentId, IncidentStatus, ObservationId, PolicyId, Severity, SubjectId,
    SubjectKind,
};
use sqlx::PgPool;
use std::collections::HashSet;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

// ── Test-fixture scaffolding ─────────────────────────────────────────

/// Probe for a working Docker daemon. Mirrors the rest of
/// `polaris-backend/tests/`.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the `(db, pool)`
/// pair. Mirrors `tests/admin_policies_endpoint.rs::boot_db`.
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

/// Seed a moderator + role + active session. Returns the moderator UUID
/// and the bearer cookie value.
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
        .create(AuthModeratorId(row.0), b"wb7-test-refresh-token")
        .await
        .unwrap();
    (row.0, session.token.as_str().to_owned())
}

/// Build the (`router`, `pool`, `sessions`, `admin_cookie`,
/// `admin_id`) tuple every test rides.
struct Fixture {
    router: Router,
    pool: PgPool,
    sessions: SessionStore,
    admin_cookie: String,
    admin_id: Uuid,
}

async fn boot_fixture() -> Fixture {
    let (database, pool) = boot_db().await;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let (admin_id, admin_cookie) =
        seed_moderator_with_session(&pool, &sessions, "did:plc:wb7-admin", Role::Admin).await;
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(database, state);
    Fixture {
        router,
        pool,
        sessions,
        admin_cookie,
        admin_id,
    }
}

/// Read the JSON body of a response. Panics if the body isn't valid
/// JSON — fine for integration tests.
async fn read_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|err| panic!("body not JSON: {err}; bytes: {bytes:?}"))
}

/// Body shape that satisfies every admin-create validation gate.
/// Tests mutate per-case fields and re-use this as a baseline.
fn valid_create_body(identifier: &str) -> serde_json::Value {
    serde_json::json!({
        "identifier": identifier,
        "name": format!("{identifier} test policy"),
        "description": "WB-7 cross-layer regression policy fixture",
        "scope": "post",
        "severity": "alert",
        "decision_criteria":
            "Apply this policy when the WB-7 integration test asserts the safety floor.",
        "suggested_action_kinds": ["label"],
        "autonomy_mode": "manual",
        "autonomous_action_kinds": [],
        "autonomous_confidence_threshold": 0.95,
        "assisted_confidence_threshold": 0.7,
    })
}

/// `POST /api/admin/policies` with the admin cookie.
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

/// Build the typed [`ModeratorAuthCtx`] the test-only autonomous-action
/// helper takes. We compose it locally so the test does not need to
/// thread an HTTP request through the cookie middleware just to
/// fabricate one.
fn ctx_for(moderator_id: Uuid) -> ModeratorAuthCtx {
    ModeratorAuthCtx::new(AuthModeratorId(moderator_id), HashSet::new())
}

/// Prime `polaris_setup_state.signing_pubkey_did` so emit-shaped
/// kinds (Label / Takedown) pass the REQ-A3 precondition gate.
async fn prime_setup_state(pool: &PgPool) {
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
    .execute(pool)
    .await
    .unwrap();
}

/// Insert a subject + an open incident and return their ids. The
/// subject's kind is parameterised so the REQ-G2 (account-kind
/// takedown) test can target an `account` subject while the REQ-G3
/// post-shaped tests target a `post` subject.
async fn seed_subject_incident(pool: &PgPool, kind: SubjectKind) -> (SubjectId, IncidentId) {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let did = Did::new(format!("did:plc:wb7-{}", Uuid::new_v4().simple()));
    let uri = match kind {
        SubjectKind::Account => None,
        _ => Some(polaris_types::AtUri::new(format!(
            "at://{did}/app.bsky.feed.post/3kabc{}",
            Uuid::new_v4().simple()
        ))),
    };
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind,
            did: Some(did),
            uri,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    let incident = incident_repo
        .insert(repo::NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await
        .unwrap();
    (subject.id, incident.id)
}

/// Seed one policy at v1 via the typed repo, with the supplied
/// `human_required_always` / `autonomy_mode` / `autonomous_action_kinds`
/// shape. Returns the identifier (echoed for ergonomic call sites).
async fn seed_policy(
    pool: &PgPool,
    moderator_id: Uuid,
    identifier: &str,
    human_required_always: bool,
    autonomy_mode: &str,
    autonomous_action_kinds: Vec<String>,
) -> String {
    let mut tx = pool.begin().await.unwrap();
    mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: identifier.to_owned(),
            name: format!("{identifier} title"),
            description: format!("WB-7 fixture for {identifier}"),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria:
                "Apply this policy when the WB-7 cross-layer test exercises the action path."
                    .to_owned(),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["label".to_owned(), "takedown".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always,
            autonomy_mode: autonomy_mode.to_owned(),
            autonomous_action_kinds,
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            change_summary: None,
        },
        moderator_id,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    identifier.to_owned()
}

/// Build a stub [`LlmAuditFields`] envelope — every field NOT NULL so
/// the migration-51 CHECK accepts the row when (and if) it reaches
/// the DB. The test asserts on the *pre-DB* rejection in the API
/// layer, so the envelope's specific values are immaterial; they
/// exist only to satisfy the typed contract.
fn stub_audit_envelope() -> LlmAuditFields {
    LlmAuditFields {
        llm_observation_id: ObservationId(Uuid::new_v4()),
        model: "wb7-test-model".to_owned(),
        model_version: "2026-05-18".to_owned(),
        prompt_template_id: "wb7.test.v1".to_owned(),
        recommendation_confidence: 0.99,
        input_hash: "deadbeef".repeat(8),
    }
}

/// Build the wire-shape [`SubmitAction`] body the autonomous test
/// helper takes. Keeps each test concise.
fn submit_action_body(
    incident_id: IncidentId,
    kind: ActionKind,
    policy_identifiers: &[&str],
) -> SubmitAction {
    SubmitAction {
        incident_id,
        kind,
        label: match kind {
            ActionKind::Label => Some(polaris_types::LabelValue::new("spam")),
            _ => None,
        },
        reasoning:
            "WB-7 cross-layer regression: autonomous action through the test-only entry point."
                .to_owned(),
        policy_refs: policy_identifiers
            .iter()
            .map(|p| PolicyId::new(*p))
            .collect(),
        reversible_until: Utc::now() + chrono::Duration::hours(24),
        reverses_action_id: None,
        report_id: None,
    }
}

// ── 1. Policy edit API rejects autonomy flip on human-required policy ──

#[tokio::test]
async fn policy_edit_api_rejects_autonomous_mode_on_human_required_policy() {
    if !docker_available() {
        println!(
            "SKIP policy_human_required_never_autonomous::policy_edit_api_rejects_autonomous_mode_on_human_required_policy: docker unreachable"
        );
        return;
    }
    let f = boot_fixture().await;

    // Seed `polaris.csam` with human_required_always = TRUE through
    // the admin CREATE endpoint (mirrors the
    // `admin_policies_endpoint::autonomy_mode_autonomous_on_human_required_policy_returns_403`
    // test fixture; AC-8 explicitly names polaris.csam).
    let mut body = valid_create_body("polaris.csam");
    body["human_required_always"] = serde_json::Value::Bool(true);
    let resp = post_admin_create(&f.router, &f.admin_cookie, body).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // PATCH attempts to flip autonomy_mode to "autonomous". REQ-G3
    // layer-1 must reject with `code = policy_autonomy_forbidden`.
    // The wire status is currently `412 Precondition Failed`
    // (Polaris's ApiError::PreconditionFailed shape); the load-bearing
    // contract is `code`, not status, so we pin both the code and
    // the 4xx family.
    let req = Request::builder()
        .method("PATCH")
        .uri("/api/admin/policies/polaris.csam")
        .header(
            header::COOKIE,
            format!("{SESSION_COOKIE}={}", f.admin_cookie),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "autonomy_mode": "autonomous",
                "change_summary": "WB-7 test: flip to autonomous on a human-required policy",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = f.router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = read_json(resp).await;
    assert_eq!(
        body["code"], "policy_autonomy_forbidden",
        "policy edit API must reject with code=policy_autonomy_forbidden; got {body}",
    );
    assert!(
        status.is_client_error(),
        "REQ-G3 layer-1 must reject with a 4xx status; got {status}",
    );
}

// ── 2. Action-create API rejects autonomous_agent on human-required policy ──

#[tokio::test]
async fn action_create_rejects_autonomous_agent_citing_human_required_policy() {
    if !docker_available() {
        println!(
            "SKIP policy_human_required_never_autonomous::action_create_rejects_autonomous_agent_citing_human_required_policy: docker unreachable"
        );
        return;
    }
    let f = boot_fixture().await;
    prime_setup_state(&f.pool).await;
    let (moderator_id, _cookie) =
        seed_moderator_with_session(&f.pool, &f.sessions, "did:plc:wb7-mod-1", Role::Moderator)
            .await;

    // Seed `polaris.csam` directly (unique identifier per test to
    // dodge the per-process `policy_cache` singleton's TTL window).
    let identifier = format!("polaris.csam-{}", Uuid::new_v4().simple());
    seed_policy(
        &f.pool,
        f.admin_id,
        &identifier,
        true,     // human_required_always
        "manual", // REQ-G3 layer-1 disallows 'autonomous' here, which is the point
        vec![],
    )
    .await;

    // The subject is a `post` so REQ-G2 (account-takedown gate) does
    // NOT short-circuit ahead of REQ-G3. We want REQ-G3 to fire.
    let (subject_id, incident_id) = seed_subject_incident(&f.pool, SubjectKind::Post).await;

    let body = submit_action_body(incident_id, ActionKind::Label, &[&identifier]);
    let ctx = ctx_for(moderator_id);
    let state = ApiState::new(f.pool.clone(), f.sessions.clone());

    // Route through the autonomous-action test entry point — the
    // only call site that asserts `actor_kind = 'autonomous_agent'`
    // server-side. REQ-G3 layer-2 must reject with 403 +
    // `policy_autonomy_forbidden` BEFORE the action row is inserted.
    let result = polaris_backend::api::cases::submit_action_autonomous_for_test(
        &state,
        &ctx,
        subject_id,
        &body,
        stub_audit_envelope(),
    )
    .await;
    let err = result.expect_err("autonomous action against a human-required policy must reject");
    match err {
        polaris_backend::api::error::ApiError::PolicyAutonomyForbidden { identifier: i } => {
            assert_eq!(
                i, identifier,
                "rejection must name the offending identifier"
            );
        }
        other => panic!("expected PolicyAutonomyForbidden, got {other:?}"),
    }

    // Pin the wire shape too — IntoResponse must surface
    // `403 policy_autonomy_forbidden`.
    let resp = axum::response::IntoResponse::into_response(
        polaris_backend::api::error::ApiError::PolicyAutonomyForbidden {
            identifier: identifier.clone(),
        },
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = read_json(resp).await;
    assert_eq!(body["code"], "policy_autonomy_forbidden");
    assert_eq!(body["identifier"], identifier);
}

// ── 3. Policy edit API rejects escalate in autonomous_action_kinds (REQ-G1) ──

#[tokio::test]
async fn policy_edit_api_rejects_escalate_in_autonomous_action_kinds() {
    if !docker_available() {
        println!(
            "SKIP policy_human_required_never_autonomous::policy_edit_api_rejects_escalate_in_autonomous_action_kinds: docker unreachable"
        );
        return;
    }
    let f = boot_fixture().await;

    // CREATE that includes "escalate" in autonomous_action_kinds is
    // the same gate as PATCH — both go through `validate_*` which
    // calls `check_autonomous_action_kinds`. We exercise CREATE here
    // because the gate runs in the same code path and the failure
    // mode is identical.
    let mut body = valid_create_body("polaris.escalate-reject");
    body["autonomous_action_kinds"] = serde_json::json!(["escalate"]);
    let resp = post_admin_create(&f.router, &f.admin_cookie, body).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "REQ-G1: escalate cannot autonomously fire",
    );
    let body = read_json(resp).await;
    assert_eq!(body["code"], "bad_request");
    let err_text = body["error"].as_str().unwrap_or_default();
    assert!(
        err_text.contains("autonomous_action_kinds"),
        "rejection message must name the offending field; got {body}",
    );
}

// ── 4. Policy edit API rejects mute in autonomous_action_kinds (REQ-G1) ──

#[tokio::test]
async fn policy_edit_api_rejects_mute_in_autonomous_action_kinds() {
    if !docker_available() {
        println!(
            "SKIP policy_human_required_never_autonomous::policy_edit_api_rejects_mute_in_autonomous_action_kinds: docker unreachable"
        );
        return;
    }
    let f = boot_fixture().await;

    let mut body = valid_create_body("polaris.mute-reject");
    body["autonomous_action_kinds"] = serde_json::json!(["mute"]);
    let resp = post_admin_create(&f.router, &f.admin_cookie, body).await;
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "REQ-G1: mute (high blast-radius) cannot autonomously fire",
    );
    let body = read_json(resp).await;
    assert_eq!(body["code"], "bad_request");
    let err_text = body["error"].as_str().unwrap_or_default();
    assert!(
        err_text.contains("autonomous_action_kinds"),
        "rejection message must name the offending field; got {body}",
    );
}

// ── 5. Action-create API rejects autonomous account-kind takedown (REQ-G2) ──

#[tokio::test]
async fn action_create_rejects_autonomous_takedown_on_account_subject() {
    if !docker_available() {
        println!(
            "SKIP policy_human_required_never_autonomous::action_create_rejects_autonomous_takedown_on_account_subject: docker unreachable"
        );
        return;
    }
    let f = boot_fixture().await;
    prime_setup_state(&f.pool).await;
    let (moderator_id, _cookie) =
        seed_moderator_with_session(&f.pool, &f.sessions, "did:plc:wb7-mod-2", Role::Moderator)
            .await;

    // Seed a non-human-required policy in autonomous mode with
    // takedown in autonomous_action_kinds. The REQ-G2 gate kicks in
    // at the action-create layer when the subject is `account`-kind.
    let identifier = format!("polaris.spam-{}", Uuid::new_v4().simple());
    seed_policy(
        &f.pool,
        f.admin_id,
        &identifier,
        false, // not human-required: REQ-G3 stays out of the way
        "autonomous",
        vec!["takedown".to_owned()],
    )
    .await;

    // Critical: the subject is `account`-kind so REQ-G2 fires.
    let (subject_id, incident_id) = seed_subject_incident(&f.pool, SubjectKind::Account).await;

    let body = submit_action_body(incident_id, ActionKind::Takedown, &[&identifier]);
    let ctx = ctx_for(moderator_id);
    let state = ApiState::new(f.pool.clone(), f.sessions.clone());

    let result = polaris_backend::api::cases::submit_action_autonomous_for_test(
        &state,
        &ctx,
        subject_id,
        &body,
        stub_audit_envelope(),
    )
    .await;
    let err = result.expect_err("autonomous account-kind takedown must reject");
    assert!(
        matches!(
            err,
            polaris_backend::api::error::ApiError::AccountTakedownAutonomousForbidden
        ),
        "expected AccountTakedownAutonomousForbidden; got {err:?}",
    );

    // Wire shape pin.
    let resp = axum::response::IntoResponse::into_response(
        polaris_backend::api::error::ApiError::AccountTakedownAutonomousForbidden,
    );
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = read_json(resp).await;
    assert_eq!(body["code"], "account_takedown_autonomous_forbidden");
}
