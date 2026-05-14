//! Pattern-action end-to-end integration test (issue #21).
//!
//! Spins up Postgres 16 via testcontainers, applies every migration through
//! `db::connect`, then drives the propose / cosign handlers directly against
//! the live [`polaris_backend::repo::PgPatternActionRepo`] and Axum extractor
//! surface. The five scenarios mirror the architect's dispatch:
//!
//! 1. **Below-threshold auto-execute** — a proposal whose resolver yields
//!    `affected_subject_count <= threshold` executes inline. Status flips to
//!    `executed` and one `actions` row per affected subject lands.
//! 2. **Above-threshold cosign-required + cosign-completes** — a proposal
//!    above threshold stays at `proposed` with zero `actions` rows; a senior
//!    cosign call from a different moderator materialises the per-subject
//!    Action rows in a single transaction.
//! 3. **Self-cosign 403** — the proposer's own moderator id is rejected at
//!    the cosign endpoint. No signature row, no Action rows.
//! 4. **Non-senior cosign 403** — a plain `Moderator` role hits the cosign
//!    endpoint and is rejected at the role gate.
//! 5. **Failure-injection rollback** — a duplicate `pattern_action_subjects`
//!    row is pre-inserted so the in-transaction `insert_subject_rows` hits a
//!    PK unique-violation. The whole transaction rolls back: zero `actions`
//!    rows for the proposal, header still `proposed`.
//!
//! Each scenario carries an explicit assert on `actions`/`pattern_actions`
//! row counts after the act, so a regression that silently bypasses the
//! transactional boundary fails loudly.
//!
//! # Why drive the handlers, not the full Axum router
//!
//! Wiring the auth middleware here would require minting a session cookie
//! and threading the cookie-shaped `Request<Body>` through `tower::Service`.
//! The behaviour under test is the propose/cosign logic plus the underlying
//! transaction; both are reachable by calling `propose(State, Extension,
//! Json)` and `cosign(State, Extension, Path)` directly with the same
//! extractor wrappers axum would inject. The cookie middleware has its own
//! integration coverage in `tests/oidc_login_flow.rs`.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message and
//! returns successfully — same pattern as `tests/reversal_workflow.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::collections::HashSet;
use std::process::Command;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use polaris_backend::api::pattern_actions::{
    PatternSelector, ProposeBody, cosign as cosign_handler, propose as propose_handler,
};
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorAuthCtx, ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::{DbConfig, PatternActionsConfig};
use polaris_backend::db;
use polaris_backend::repo::{PatternActionRepo, PatternActionStatus, PgPatternActionRepo};
use polaris_types::{ActionKind, LabelValue, PatternActionId, PolicyId, SubjectId};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
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

/// Boot a Postgres testcontainer + migrate + return the (`db`, pool) pair.
async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
    // Postgres 16-alpine: migration 11 needs generated columns (PG ≥ 12).
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
    // Leak the container so it lives for the rest of the test. The Drop
    // impl on `ContainerAsync` stops the container; binding it to a `_`
    // here ties its lifetime to this function's stack frame, which is why
    // we forget it instead — same idiom as `tests/reversal_workflow.rs`.
    std::mem::forget(container);
    Ok((db, pool))
}

/// Insert a moderator row and return its id. The pattern-action header
/// `requested_by` FK references `moderators(id)` so every proposer must
/// exist there first.
async fn insert_moderator(pool: &PgPool) -> Result<AuthModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("pa-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(AuthModeratorId(row.id))
}

/// Build an auth context from a moderator id and a role slice.
fn ctx_for(moderator_id: AuthModeratorId, roles: &[Role]) -> ModeratorAuthCtx {
    let mut role_set = HashSet::new();
    for r in roles {
        role_set.insert(*r);
    }
    ModeratorAuthCtx::new(moderator_id, role_set)
}

/// Insert a fresh `subjects` row and return its id. The pattern-action
/// resolvers select these via the `observations` join, so each test
/// scenario needs its own pool of subjects to act on.
async fn insert_subject(pool: &PgPool) -> Result<SubjectId, Box<dyn std::error::Error>> {
    let did = format!("did:plc:pa-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO subjects (kind, did, created_at) VALUES ('account', $1, now()) RETURNING id",
        did,
    )
    .fetch_one(pool)
    .await?;
    Ok(SubjectId(row.id))
}

/// Attach an `image_hash_cluster` observation to `subject_id` so the
/// `resolve_image_hash` selector picks it up. The evidence object must
/// carry the `hash` key the resolver matches on.
async fn insert_image_hash_observation(
    pool: &PgPool,
    subject_id: SubjectId,
    hash: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    sqlx::query!(
        r#"
        INSERT INTO observations (subject_id, kind, confidence, evidence)
        VALUES ($1, 'image_hash_cluster', 0.95, jsonb_build_object('hash', $2::text, 'distance', 0))
        "#,
        subject_id.0,
        hash,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Build an `ApiState` configured with the test cosign threshold. The
/// `SessionStore` is constructed against a zero key; the cookie crypto
/// path is never exercised because the handlers receive
/// `ModeratorAuthCtx` via the `Extension` extractor, bypassing the
/// cookie middleware.
fn api_state(pool: PgPool, cosign_threshold: usize) -> ApiState {
    let crypto = Crypto::new([0_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let cfg = PatternActionsConfig { cosign_threshold };
    ApiState::with_config(pool, sessions, cfg)
}

/// Count `actions` rows attributable to a pattern action via its subject
/// join table. `pattern_action_subjects` joins to `actions` on
/// `subject_id` since the per-subject Action rows do not carry a direct
/// FK to the header; the proof-of-execution count is the number of
/// `actions` rows whose `subject_id` appears in the join.
async fn count_actions_for(
    pool: &PgPool,
    pattern_action_id: PatternActionId,
) -> Result<i64, Box<dyn std::error::Error>> {
    let row = sqlx::query!(
        r#"
        SELECT COUNT(*) AS "count!"
        FROM actions a
        JOIN pattern_action_subjects pas
          ON pas.subject_id = a.subject_id
        WHERE pas.pattern_action_id = $1
        "#,
        pattern_action_id.0,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count)
}

/// Count `pattern_action_subjects` rows for a given header. Used to assert
/// the failure-injection scenario leaves the join table at exactly the
/// pre-injected row count (i.e., the txn rollback fired).
async fn count_subject_rows_for(
    pool: &PgPool,
    pattern_action_id: PatternActionId,
) -> Result<i64, Box<dyn std::error::Error>> {
    let row = sqlx::query!(
        r#"
        SELECT COUNT(*) AS "count!"
        FROM pattern_action_subjects
        WHERE pattern_action_id = $1
        "#,
        pattern_action_id.0,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.count)
}

/// Build a `ProposeBody` for an `ImageHashCluster` selector on `hash`.
fn propose_body(hash: &str) -> ProposeBody {
    ProposeBody {
        selector: PatternSelector::ImageHashCluster {
            cluster_id: format!("cluster-{hash}"),
            hash: hash.to_owned(),
        },
        action_kind: ActionKind::Label,
        label_value: Some(LabelValue::new("spam")),
        reasoning: "Bulk label on image-hash cluster pattern action.".to_owned(),
        policy_refs: vec![PolicyId::new("polaris.spam")],
    }
}

#[tokio::test]
async fn pattern_actions_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP pattern_actions: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test.",
        );
        return Ok(());
    }

    let (_db, pool) = boot_db().await?;
    // A small threshold of 2 keeps the test seed footprint tiny: any
    // proposal targeting 3+ subjects requires cosign; 1-2 subjects
    // auto-executes.
    let state = api_state(pool.clone(), 2);
    let pattern_actions_repo = PgPatternActionRepo::new(pool.clone());

    // ── Scenario 1: below-threshold auto-execute ────────────────────────
    {
        let proposer = insert_moderator(&pool).await?;
        let s1 = insert_subject(&pool).await?;
        let s2 = insert_subject(&pool).await?;
        let hash = format!("h-below-{}", Uuid::new_v4().simple());
        insert_image_hash_observation(&pool, s1, &hash).await?;
        insert_image_hash_observation(&pool, s2, &hash).await?;

        let ctx = ctx_for(proposer, &[Role::Moderator]);
        let body = propose_body(&hash);
        let (status, Json(resp)) =
            propose_handler(State(state.clone()), Extension(ctx), Json(body))
                .await
                .map_err(|e| format!("propose returned ApiError: {e:?}"))?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp.affected_subject_count, 2);
        assert!(
            !resp.requires_cosign,
            "2 subjects must be at/below threshold of 2"
        );
        assert_eq!(resp.status, "executed");

        // Exactly one Action row per affected subject.
        let n = count_actions_for(&pool, resp.id).await?;
        assert_eq!(
            n, 2,
            "auto-execute must materialise one Action row per affected subject",
        );

        // Header is `executed` and an `executed_at` timestamp is set.
        let row = pattern_actions_repo
            .get(resp.id)
            .await?
            .expect("header row must exist after propose");
        assert_eq!(row.status, PatternActionStatus::Executed);
        assert!(row.executed_at.is_some(), "executed_at must be set");
    }

    // ── Scenario 2: above-threshold → cosign-required → cosign-completes ─
    let scenario2_header_id;
    let scenario2_subjects: Vec<SubjectId>;
    {
        let proposer = insert_moderator(&pool).await?;
        let senior = insert_moderator(&pool).await?;
        let mut subjects = Vec::with_capacity(3);
        let hash = format!("h-above-{}", Uuid::new_v4().simple());
        for _ in 0..3 {
            let s = insert_subject(&pool).await?;
            insert_image_hash_observation(&pool, s, &hash).await?;
            subjects.push(s);
        }
        scenario2_subjects = subjects;

        // Propose — 3 subjects, threshold 2 → must require cosign.
        let ctx_proposer = ctx_for(proposer, &[Role::Moderator]);
        let (status, Json(resp)) = propose_handler(
            State(state.clone()),
            Extension(ctx_proposer),
            Json(propose_body(&hash)),
        )
        .await
        .map_err(|e| format!("propose (scenario 2) returned ApiError: {e:?}"))?;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(resp.affected_subject_count, 3);
        assert!(
            resp.requires_cosign,
            "3 subjects must exceed threshold of 2"
        );
        assert_eq!(resp.status, "proposed");
        scenario2_header_id = resp.id;

        // Before cosign: no Action rows yet.
        let n_pre = count_actions_for(&pool, resp.id).await?;
        assert_eq!(n_pre, 0, "proposed-only header must have zero Action rows");

        // Senior cosign — must execute.
        let ctx_senior = ctx_for(senior, &[Role::SeniorModerator]);
        let Json(result) =
            cosign_handler(State(state.clone()), Extension(ctx_senior), Path(resp.id))
                .await
                .map_err(|e| format!("cosign (scenario 2) returned ApiError: {e:?}"))?;

        assert_eq!(result.status, "executed");
        assert_eq!(result.inserted_count, 3);

        // After cosign: exactly 3 Action rows, header flipped to executed.
        let n_post = count_actions_for(&pool, resp.id).await?;
        assert_eq!(
            n_post, 3,
            "cosign must materialise one Action row per subject"
        );
        let row = pattern_actions_repo
            .get(resp.id)
            .await?
            .expect("header row must exist after cosign");
        assert_eq!(row.status, PatternActionStatus::Executed);
    }

    // ── Scenario 3: self-cosign 403 ─────────────────────────────────────
    {
        let proposer = insert_moderator(&pool).await?;
        // Grant proposer the SeniorModerator role so the role-gate passes
        // and the failure must come from the self-cosign check.
        sqlx::query!(
            r"INSERT INTO moderator_roles (moderator_id, role) VALUES ($1, 'senior_moderator')",
            proposer.0,
        )
        .execute(&pool)
        .await?;
        let mut subjects = Vec::with_capacity(3);
        let hash = format!("h-self-{}", Uuid::new_v4().simple());
        for _ in 0..3 {
            let s = insert_subject(&pool).await?;
            insert_image_hash_observation(&pool, s, &hash).await?;
            subjects.push(s);
        }

        let ctx_proposer = ctx_for(proposer, &[Role::SeniorModerator]);
        let (_status, Json(resp)) = propose_handler(
            State(state.clone()),
            Extension(ctx_proposer.clone()),
            Json(propose_body(&hash)),
        )
        .await
        .map_err(|e| format!("propose (scenario 3) returned ApiError: {e:?}"))?;
        assert!(resp.requires_cosign);

        // Self-cosign: same moderator id → 403 Forbidden.
        let err = cosign_handler(State(state.clone()), Extension(ctx_proposer), Path(resp.id))
            .await
            .expect_err("self-cosign must be rejected");
        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "self-cosign must surface as 403 Forbidden",
        );

        // No Action rows, header still proposed.
        assert_eq!(count_actions_for(&pool, resp.id).await?, 0);
        let row = pattern_actions_repo
            .get(resp.id)
            .await?
            .expect("header row must exist after rejected cosign");
        assert_eq!(row.status, PatternActionStatus::Proposed);
    }

    // ── Scenario 4: non-senior cosign 403 ───────────────────────────────
    {
        let proposer = insert_moderator(&pool).await?;
        let junior = insert_moderator(&pool).await?;
        let mut subjects = Vec::with_capacity(3);
        let hash = format!("h-junior-{}", Uuid::new_v4().simple());
        for _ in 0..3 {
            let s = insert_subject(&pool).await?;
            insert_image_hash_observation(&pool, s, &hash).await?;
            subjects.push(s);
        }

        let ctx_proposer = ctx_for(proposer, &[Role::Moderator]);
        let (_status, Json(resp)) = propose_handler(
            State(state.clone()),
            Extension(ctx_proposer),
            Json(propose_body(&hash)),
        )
        .await
        .map_err(|e| format!("propose (scenario 4) returned ApiError: {e:?}"))?;
        assert!(resp.requires_cosign);

        // Plain `Moderator` cosigner — must fail the role gate.
        let ctx_junior = ctx_for(junior, &[Role::Moderator, Role::Triage]);
        let err = cosign_handler(State(state.clone()), Extension(ctx_junior), Path(resp.id))
            .await
            .expect_err("non-senior cosign must be rejected");
        let response = axum::response::IntoResponse::into_response(err);
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "non-senior cosign must surface as 403 Forbidden",
        );

        assert_eq!(count_actions_for(&pool, resp.id).await?, 0);
        let row = pattern_actions_repo
            .get(resp.id)
            .await?
            .expect("header row must exist after rejected cosign");
        assert_eq!(row.status, PatternActionStatus::Proposed);
    }

    // ── Scenario 5: failure-injection → transactional rollback ──────────
    {
        let proposer = insert_moderator(&pool).await?;
        let senior = insert_moderator(&pool).await?;
        let mut subjects = Vec::with_capacity(3);
        let hash = format!("h-rollback-{}", Uuid::new_v4().simple());
        for _ in 0..3 {
            let s = insert_subject(&pool).await?;
            insert_image_hash_observation(&pool, s, &hash).await?;
            subjects.push(s);
        }

        let ctx_proposer = ctx_for(proposer, &[Role::Moderator]);
        let (_status, Json(resp)) = propose_handler(
            State(state.clone()),
            Extension(ctx_proposer),
            Json(propose_body(&hash)),
        )
        .await
        .map_err(|e| format!("propose (scenario 5) returned ApiError: {e:?}"))?;
        assert!(resp.requires_cosign);

        // Failure injection: pre-insert one of the (pattern_action_id,
        // subject_id) rows so the execute path's `insert_subject_rows`
        // collides with the composite PK on the second iteration and the
        // whole transaction rolls back.
        sqlx::query!(
            r"INSERT INTO pattern_action_subjects (pattern_action_id, subject_id)
              VALUES ($1, $2)",
            resp.id.0,
            subjects[1].0,
        )
        .execute(&pool)
        .await?;

        let ctx_senior = ctx_for(senior, &[Role::SeniorModerator]);
        let err = cosign_handler(State(state.clone()), Extension(ctx_senior), Path(resp.id))
            .await
            .expect_err("duplicate-subject pre-seed must force execute_pattern_action to fail");
        let response = axum::response::IntoResponse::into_response(err);
        // The PK collision surfaces as a unique-violation, which the
        // ApiError::Repo arm renders as 409 conflict. (A 5xx would also be
        // acceptable from the contract's perspective — the load-bearing
        // assertion is the rollback, below — but Polaris specifically
        // classifies SQLSTATE 23505 as a conflict.)
        assert_eq!(
            response.status(),
            StatusCode::CONFLICT,
            "PK collision on pattern_action_subjects must surface as 409",
        );

        // Rollback proof: zero `actions` rows attributable to this header.
        assert_eq!(
            count_actions_for(&pool, resp.id).await?,
            0,
            "transaction must roll back: no per-subject Action rows on failure",
        );
        // The pre-seeded join row is still present (it was committed
        // before the txn started), but no new rows landed.
        assert_eq!(
            count_subject_rows_for(&pool, resp.id).await?,
            1,
            "only the pre-seeded join row should remain; the txn's inserts must roll back",
        );
        // Header is untouched: still `proposed`, no `executed_at`.
        let row = pattern_actions_repo
            .get(resp.id)
            .await?
            .expect("header row must exist after failed cosign");
        assert_eq!(
            row.status,
            PatternActionStatus::Proposed,
            "rolled-back execute must leave the header at `proposed`",
        );
        assert!(
            row.executed_at.is_none(),
            "rolled-back execute must not set executed_at",
        );

        // Sanity: scenario 2's header is still executed (independent
        // proposal, not affected by scenario 5's rollback).
        let scen2 = pattern_actions_repo
            .get(scenario2_header_id)
            .await?
            .expect("scenario 2 header still present");
        assert_eq!(scen2.status, PatternActionStatus::Executed);
        assert_eq!(
            count_actions_for(&pool, scenario2_header_id).await?,
            i64::try_from(scenario2_subjects.len()).expect("subject count fits in i64"),
        );
    }

    Ok(())
}
