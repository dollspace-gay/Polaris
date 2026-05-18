//! Action reversal workflow integration test (issue #36).
//!
//! Spins up Postgres 16 via testcontainers, applies all migrations through
//! `db::connect`, then exercises the reversal authorization rules against
//! the live `ActionRepo` + `actions` table:
//!
//! 1. Original moderator A reverses their action X within the window →
//!    201 with a new `kind = Reverse` row.
//! 2. Original moderator A after the window elapses → 403 (window expired).
//! 3. Senior moderator B reverses X at any time → 201.
//! 4. Non-author non-senior C → 403 (not eligible).
//! 5. Double-reverse: once B has reversed X, A trying again → 409.
//!
//! Each scenario is followed by an append-only proof: the original action
//! row is re-fetched and asserted byte-identical to its pre-reversal state.
//! The reversal must NEVER UPDATE the original.
//!
//! # Why drive the policy through `can_reverse` + the repo, not the
//! Axum router
//!
//! Wiring the full Axum router would require seeding a moderator session
//! cookie (the auth middleware is cookie-only). The policy under test is
//! the pure function plus the repo I/O; both are exercised here without
//! coupling to the cookie middleware, which has its own integration
//! coverage in `tests/oidc_login_flow.rs`. The end-to-end HTTP shape will
//! land alongside the appeals workflow (#24).
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message and
//! returns successfully — same pattern as the other repo-flavoured
//! integration tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::collections::HashSet;
use std::process::Command;

use chrono::{Duration, Utc};
use polaris_backend::api::reversal::{REVERSAL_REVERSIBLE_WINDOW, ReversalAuthError, can_reverse};
use polaris_backend::auth::{ModeratorAuthCtx, ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::{
    self, ActionRepo, IncidentRepo, PgActionRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{
    Action, ActionKind, Did, IncidentStatus, LabelValue, ModeratorId, PolicyId, Severity,
    SubjectKind,
};
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

async fn insert_moderator(pool: &sqlx::PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("test-{}", Uuid::new_v4());
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

/// Build an auth context from a domain `ModeratorId` and a role slice.
fn ctx_for(moderator_id: ModeratorId, roles: &[Role]) -> ModeratorAuthCtx {
    let mut role_set = HashSet::new();
    for r in roles {
        role_set.insert(*r);
    }
    ModeratorAuthCtx::new(AuthModeratorId(moderator_id.0), role_set)
}

/// Fetch the original action's `reasoning` + `created_at` + `kind` for
/// append-only proof — these are the columns a buggy UPDATE would touch.
async fn snapshot_action(
    repo: &PgActionRepo,
    id: polaris_types::ActionId,
) -> Result<Action, Box<dyn std::error::Error>> {
    let action = repo
        .get(id)
        .await?
        .ok_or("original action disappeared after a reversal — append-only violated")?;
    Ok(action)
}

/// Insert an action and return the persisted row. Centralizes the
/// boilerplate so each scenario only spells out what makes it distinct.
async fn insert_original_action(
    action_repo: &PgActionRepo,
    incident_id: polaris_types::IncidentId,
    subject_id: polaris_types::SubjectId,
    moderator_id: ModeratorId,
    reversible_until: chrono::DateTime<Utc>,
) -> Result<Action, Box<dyn std::error::Error>> {
    let action = action_repo
        .insert(repo::NewAction {
            incident_id,
            subject_id,
            moderator_id,
            kind: ActionKind::Label,
            label: Some(LabelValue::new("spam")),
            reasoning: "Original action reasoning, at least ten characters.".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until,
            reverses_action_id: None,
            llm_audit: None,
        })
        .await?;
    Ok(action)
}

/// Bypass the repo to force a `reversible_until` value in the past. The
/// `actions_no_update` trigger forbids ordinary UPDATEs, but the
/// integration scenario "the window has elapsed" needs a row whose
/// `reversible_until` lies in the past. We bypass by disabling the
/// trigger for one statement; the original column data we want to prove
/// unchanged is `reasoning` + `kind` + `created_at`, none of which we
/// mutate here.
async fn force_window_expired(
    pool: &sqlx::PgPool,
    id: polaris_types::ActionId,
) -> Result<(), Box<dyn std::error::Error>> {
    let new_until = Utc::now() - Duration::hours(1);
    // Three separate statements: Postgres' simple-query protocol can chain
    // them, but prepared-statement bindings (which sqlx uses) accept
    // exactly one statement per call. Issue them sequentially.
    sqlx::query("ALTER TABLE actions DISABLE TRIGGER actions_no_update")
        .execute(pool)
        .await?;
    sqlx::query("UPDATE actions SET reversible_until = $1 WHERE id = $2")
        .bind(new_until)
        .bind(id.into_uuid())
        .execute(pool)
        .await?;
    sqlx::query("ALTER TABLE actions ENABLE TRIGGER actions_no_update")
        .execute(pool)
        .await?;
    Ok(())
}

/// Boot a Postgres testcontainer + migrate + return the (db, pool) pair.
async fn boot_db() -> Result<(db::Db, sqlx::PgPool), Box<dyn std::error::Error>> {
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
    // here ties its lifetime to this function's stack frame, which is
    // why we forget it instead.
    std::mem::forget(container);
    Ok((db, pool))
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "five-scenario integration test in one Postgres-startup; \
              suffix-style snapshot bindings (`snapshot_y_before` / \
              `snapshot_y_after`) are deliberate per-scenario notation"
)]
async fn reversal_workflow_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP reversal_workflow: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test.",
        );
        return Ok(());
    }

    let (_db, pool) = boot_db().await?;
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let action_repo = PgActionRepo::new(pool.clone());

    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new("did:plc:reversal-target")),
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

    // Three distinct moderators with three role profiles.
    let moderator_a = insert_moderator(&pool).await?; // original author (Moderator)
    let moderator_b = insert_moderator(&pool).await?; // SeniorModerator
    let moderator_c = insert_moderator(&pool).await?; // Moderator, not author

    // ── Scenario 1: A reverses X within the window ──────────────────
    let action_x = insert_original_action(
        &action_repo,
        incident.id,
        subject.id,
        moderator_a,
        Utc::now() + Duration::hours(24),
    )
    .await?;

    let snapshot_before = snapshot_action(&action_repo, action_x.id).await?;
    let ctx_a = ctx_for(moderator_a, &[Role::Moderator]);
    let existing = action_repo.find_reversal(action_x.id).await?;
    can_reverse(&ctx_a, &action_x, existing.as_ref(), Utc::now())
        .expect("A within window must be eligible");
    let reversal_one = action_repo
        .insert(repo::NewAction {
            incident_id: action_x.incident_id,
            subject_id: action_x.subject_id,
            moderator_id: moderator_a,
            kind: ActionKind::Reverse,
            label: None,
            reasoning: "Reversal by original moderator within window.".to_owned(),
            policy_refs: vec![],
            reversible_until: Utc::now() + REVERSAL_REVERSIBLE_WINDOW,
            reverses_action_id: Some(action_x.id),
            llm_audit: None,
        })
        .await?;
    assert_eq!(reversal_one.kind, ActionKind::Reverse);
    assert_eq!(reversal_one.reverses_action_id, Some(action_x.id));
    assert_eq!(reversal_one.moderator_id, moderator_a);

    // Append-only proof on X.
    let snapshot_after = snapshot_action(&action_repo, action_x.id).await?;
    assert_eq!(snapshot_after.reasoning, snapshot_before.reasoning);
    assert_eq!(snapshot_after.kind, snapshot_before.kind);
    assert_eq!(snapshot_after.created_at, snapshot_before.created_at);
    assert_eq!(snapshot_after.label, snapshot_before.label);

    // ── Scenario 2: A after the window → WindowExpired ─────────────
    let action_y = insert_original_action(
        &action_repo,
        incident.id,
        subject.id,
        moderator_a,
        Utc::now() + Duration::hours(24),
    )
    .await?;
    let snapshot_y_before = snapshot_action(&action_repo, action_y.id).await?;
    force_window_expired(&pool, action_y.id).await?;
    // Re-fetch after the trigger-disabled UPDATE so we have the new
    // `reversible_until`.
    let action_y_refetched = action_repo
        .get(action_y.id)
        .await?
        .expect("forced row should still be present");
    let existing_y = action_repo.find_reversal(action_y.id).await?;
    let err = can_reverse(&ctx_a, &action_y_refetched, existing_y.as_ref(), Utc::now())
        .expect_err("A after window must be rejected");
    assert_eq!(err, ReversalAuthError::WindowExpired);

    let snapshot_y_after = snapshot_action(&action_repo, action_y.id).await?;
    assert_eq!(snapshot_y_after.reasoning, snapshot_y_before.reasoning);
    assert_eq!(snapshot_y_after.kind, snapshot_y_before.kind);
    assert_eq!(snapshot_y_after.created_at, snapshot_y_before.created_at);

    // ── Scenario 3: Senior B reverses X (anytime) ──────────────────
    let action_z = insert_original_action(
        &action_repo,
        incident.id,
        subject.id,
        moderator_a,
        // Window is irrelevant for senior — set far in the past on purpose.
        Utc::now() - Duration::hours(48),
    )
    .await?;
    let snapshot_z_before = snapshot_action(&action_repo, action_z.id).await?;
    let ctx_b = ctx_for(moderator_b, &[Role::SeniorModerator]);
    let existing_z = action_repo.find_reversal(action_z.id).await?;
    can_reverse(&ctx_b, &action_z, existing_z.as_ref(), Utc::now())
        .expect("senior B must succeed even past window");
    let reversal_three = action_repo
        .insert(repo::NewAction {
            incident_id: action_z.incident_id,
            subject_id: action_z.subject_id,
            moderator_id: moderator_b,
            kind: ActionKind::Reverse,
            label: None,
            reasoning: "Reversal by senior moderator B.".to_owned(),
            policy_refs: vec![],
            reversible_until: Utc::now() + REVERSAL_REVERSIBLE_WINDOW,
            reverses_action_id: Some(action_z.id),
            llm_audit: None,
        })
        .await?;
    assert_eq!(reversal_three.kind, ActionKind::Reverse);
    assert_eq!(reversal_three.reverses_action_id, Some(action_z.id));

    let snapshot_z_after = snapshot_action(&action_repo, action_z.id).await?;
    assert_eq!(snapshot_z_after.reasoning, snapshot_z_before.reasoning);
    assert_eq!(snapshot_z_after.kind, snapshot_z_before.kind);
    assert_eq!(snapshot_z_after.created_at, snapshot_z_before.created_at);

    // ── Scenario 4: C (non-author, non-senior) → NotEligible ─────
    let action_w = insert_original_action(
        &action_repo,
        incident.id,
        subject.id,
        moderator_a,
        Utc::now() + Duration::hours(24),
    )
    .await?;
    let snapshot_w_before = snapshot_action(&action_repo, action_w.id).await?;
    let ctx_c = ctx_for(moderator_c, &[Role::Moderator, Role::Triage]);
    let existing_w = action_repo.find_reversal(action_w.id).await?;
    let err = can_reverse(&ctx_c, &action_w, existing_w.as_ref(), Utc::now())
        .expect_err("C without authorship or senior role must be rejected");
    assert_eq!(err, ReversalAuthError::NotEligible);

    let snapshot_w_after = snapshot_action(&action_repo, action_w.id).await?;
    assert_eq!(snapshot_w_after.reasoning, snapshot_w_before.reasoning);
    assert_eq!(snapshot_w_after.kind, snapshot_w_before.kind);

    // ── Scenario 5: Double-reverse → AlreadyReversed ─────────────
    // We already reversed action_z (senior B); A or C trying to reverse
    // it again must fail. We test both for completeness.
    let existing_z2 = action_repo
        .find_reversal(action_z.id)
        .await?
        .expect("scenario 3 inserted a reversal of z; find_reversal must see it");
    assert_eq!(existing_z2.kind, ActionKind::Reverse);
    assert_eq!(existing_z2.reverses_action_id, Some(action_z.id));

    let err_a = can_reverse(&ctx_a, &action_z, Some(&existing_z2), Utc::now())
        .expect_err("A reversing an already-reversed action must fail");
    assert_eq!(err_a, ReversalAuthError::AlreadyReversed);
    let err_c = can_reverse(&ctx_c, &action_z, Some(&existing_z2), Utc::now())
        .expect_err("C reversing an already-reversed action must fail");
    assert_eq!(err_c, ReversalAuthError::AlreadyReversed);
    // Even another senior must be blocked.
    let ctx_b_admin = ctx_for(moderator_b, &[Role::Admin]);
    let err_b = can_reverse(&ctx_b_admin, &action_z, Some(&existing_z2), Utc::now())
        .expect_err("admin reversing an already-reversed action must still fail");
    assert_eq!(err_b, ReversalAuthError::AlreadyReversed);

    Ok(())
}
