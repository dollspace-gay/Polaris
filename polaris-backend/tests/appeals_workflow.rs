//! Appeals workflow end-to-end integration test (issue #24).
//!
//! Spins up Postgres 16 via testcontainers, applies every migration through
//! `db::connect`, then exercises the appeals workflow's five protocol-bearing
//! rules from `design.md` §5.8 against the live API handlers + repos:
//!
//! 1. **Submit + rate-limit.** `POST /api/appeals` returns `201 Created`
//!    on a first submission from a given IP; the sixth submission within
//!    the same hour-window from the same IP returns `429 Too Many
//!    Requests`. The test drives this with a small per-IP quota so the
//!    branch is reachable without sleeping.
//! 2. **State-machine guards.** The `AppealRepo::record_decision` path
//!    rejects an `Open → DecidedReversed` transition that skips
//!    `Assigned`. `AppealStatus::transition_to` is the audit boundary;
//!    this scenario proves it fires through the repo layer.
//! 3. **Routing excludes original author.** A `RoutingSnapshot` carrying
//!    the original action's author in `exclude_moderator` routes to a
//!    different moderator even when the excluded one would otherwise be
//!    the best fit.
//! 4. **Calibration event on `Reversed`.** Driving the `decide_appeal`
//!    handler with `AppealDecision::Reversed` inserts a
//!    `calibration_events` row with `kind = 'appeal_reversal'` referencing
//!    the original moderator.
//! 5. **Original-author 403.** The `decide_appeal` handler returns
//!    `403 Forbidden` (via `ApiError::Forbidden`) when the calling
//!    moderator is the original action's author, regardless of any role
//!    they hold or whether the appeal was somehow routed to them.
//!
//! # Why drive the handlers, not the full Axum router
//!
//! Wiring the full Axum router would require minting a session cookie and
//! threading the cookie-shaped `Request<Body>` through `tower::Service`.
//! The behaviour under test is the appeals handler + repo + state-machine
//! triad; all three are reachable by calling
//! `submit_appeal(State, ConnectInfo, Json)` /
//! `decide_appeal(State, Extension, Path, Json)` directly with the same
//! extractor wrappers axum would inject. The cookie middleware has its
//! own integration coverage in `tests/oidc_login_flow.rs`. This matches
//! the choice already made by `tests/reversal_workflow.rs` and
//! `tests/pattern_actions.rs`.
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
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::Utc;
use polaris_backend::api::appeals::{
    AppealsRateLimiter, DecideBody, SubmitAppealBody, decide_appeal, get_appeal, submit_appeal,
};
use polaris_backend::api::error::ApiError;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{ModeratorAuthCtx, ModeratorId as AuthModeratorId, Role};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::{
    self, ActionRepo, AppealRepo, CalibrationEventRepo, IncidentRepo, PgActionRepo, PgAppealRepo,
    PgCalibrationEventRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_backend::routing::{
    IncidentForRouting, ModeratorForRouting, RoutingDecision, RoutingSnapshot, route,
};
use polaris_types::{
    ActionKind, AppealDecision, AppealStatus, CalibrationEventKind, Did, IncidentStatus,
    LabelValue, ModeratorId, PolicyId, RoutingCategory, Severity, SubjectKind,
};
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

/// Insert a moderator row and return its `polaris_types::ModeratorId`. The
/// appeals workflow's repo + handler paths reference moderators through
/// FK columns; every test moderator must exist in the table first.
async fn insert_moderator(pool: &PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("appeals-test-{}", Uuid::new_v4());
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

/// Build an auth context from a moderator id and a role slice.
fn ctx_for(moderator_id: ModeratorId, roles: &[Role]) -> ModeratorAuthCtx {
    let mut role_set = HashSet::new();
    for r in roles {
        role_set.insert(*r);
    }
    ModeratorAuthCtx::new(AuthModeratorId(moderator_id.0), role_set)
}

/// Boot a Postgres testcontainer + migrate + return the (`db`, pool)
/// pair. The container handle is intentionally leaked so its Drop impl
/// (which stops the container) runs at process exit, not at this
/// function's stack frame.
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
    std::mem::forget(container);
    Ok((db, pool))
}

/// Build an `ApiState` with a tightly-scoped rate-limiter so the
/// `429`-on-quota-exhausted branch is reachable in test time.
fn api_state_with_tiny_quota(pool: PgPool, max: u32) -> ApiState {
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    ApiState::new(pool, sessions).with_appeals_rate_limiter(AppealsRateLimiter::with_policy(
        max,
        Duration::from_secs(60),
    ))
}

/// Insert one original `Action` (the thing being appealed). The actions
/// table has a FK on `incidents` and `subjects`, so the caller threads
/// in the pre-inserted rows.
async fn insert_original_action(
    action_repo: &PgActionRepo,
    incident_id: polaris_types::IncidentId,
    subject_id: polaris_types::SubjectId,
    author: ModeratorId,
) -> Result<polaris_types::Action, Box<dyn std::error::Error>> {
    let action = action_repo
        .insert(repo::NewAction {
            incident_id,
            subject_id,
            moderator_id: author,
            kind: ActionKind::Label,
            label: Some(LabelValue::new("spam")),
            reasoning: "Original action; ten characters minimum.".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            llm_audit: None,
        })
        .await?;
    Ok(action)
}

#[tokio::test]
async fn appeals_workflow_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP appeals_workflow: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test.",
        );
        return Ok(());
    }

    let (_db, pool) = boot_db().await?;
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let action_repo = PgActionRepo::new(pool.clone());
    let appeal_repo = PgAppealRepo::new(pool.clone());
    let calibration_repo = PgCalibrationEventRepo::new(pool.clone());

    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new("did:plc:appeals-target")),
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

    // Original author of every action in this test. A separate reviewer
    // and a non-eligible third moderator are minted below as scenarios
    // demand them.
    let author = insert_moderator(&pool).await?;
    let action = insert_original_action(&action_repo, incident.id, subject.id, author).await?;

    // ── Scenario 1: submit → 201; 2nd submit (over quota) → 429 ──────
    // Tiny quota (1/window) so the second submit immediately trips.
    let state_q1 = api_state_with_tiny_quota(pool.clone(), 1);
    let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)), 1234);

    let body_a = SubmitAppealBody {
        appealed_action_id: action.id,
        appellant_statement: "First submission, please review.".to_owned(),
    };
    let (status_first, Json(submitted)) =
        submit_appeal(State(state_q1.clone()), ConnectInfo(addr), Json(body_a)).await?;
    assert_eq!(status_first, StatusCode::CREATED);
    let appeal_id = submitted.appeal_id;
    // The DB row should exist with status = Open.
    let appeal_row = appeal_repo
        .get(appeal_id)
        .await?
        .expect("appeal row must exist after 201");
    assert_eq!(appeal_row.status, AppealStatus::Open);
    assert_eq!(appeal_row.appealed_action_id, action.id);

    let body_b = SubmitAppealBody {
        appealed_action_id: action.id,
        appellant_statement: "Second submission, should be throttled.".to_owned(),
    };
    let err = submit_appeal(State(state_q1), ConnectInfo(addr), Json(body_b))
        .await
        .expect_err("second submit from same IP must be rate-limited");
    assert!(
        matches!(err, ApiError::TooManyRequests(_)),
        "expected TooManyRequests, got {err:?}",
    );

    // ── Scenario 2: state-machine — Open → DecidedReversed is illegal
    // The appeal is still in `Open` from scenario 1 (it has not been
    // assigned). Driving `record_decision` skipping `Assigned` must
    // surface a Decode error (the typed signal for an invalid
    // transition); the repo never writes the row.
    let err = appeal_repo
        .record_decision(
            appeal_id,
            AppealStatus::DecidedReversed,
            Utc::now(),
            "Skipping Assigned — should be rejected.".to_owned(),
        )
        .await
        .expect_err("Open -> DecidedReversed must be rejected");
    assert!(
        matches!(err, repo::RepoError::Decode { .. }),
        "expected Decode for invalid transition, got {err:?}",
    );
    // The row's status is unchanged.
    let still_open = appeal_repo
        .get(appeal_id)
        .await?
        .expect("row still present");
    assert_eq!(still_open.status, AppealStatus::Open);

    // ── Scenario 3: routing snapshot excludes the original author ────
    // Build the snapshot with `exclude_moderator = Some(author)` and a
    // pool containing the author (would otherwise be picked as the
    // specialty match at zero load) plus another generalist. The router
    // must pick the other moderator.
    let other = insert_moderator(&pool).await?;
    let snap = RoutingSnapshot {
        incident: IncidentForRouting {
            id: incident.id,
            primary_subject: subject.id,
            category: RoutingCategory::Harassment,
            severity: Severity::Medium,
            exclude_moderator: Some(author),
        },
        eligible_moderators: vec![
            // The original author: a specialty match at zero load. Without
            // exclusion this would be the winner.
            ModeratorForRouting {
                id: author,
                csam_trained: false,
                calibration_complete: true,
                specialties: [RoutingCategory::Harassment].into_iter().collect(),
                current_load: 0,
                exposure_budget_remaining: u32::MAX,
                agreement_with_senior_rate: 0.9,
            },
            // The competing generalist with non-zero load.
            ModeratorForRouting {
                id: other,
                csam_trained: false,
                calibration_complete: true,
                specialties: HashSet::new(),
                current_load: 2,
                exposure_budget_remaining: u32::MAX,
                agreement_with_senior_rate: 0.5,
            },
        ],
    };
    let decision = route(&snap);
    assert_eq!(
        decision,
        RoutingDecision::Assigned(other),
        "appeal routing must exclude the original action's author",
    );

    // Persist the assignment so scenario 4's `decide_appeal` finds
    // an `assigned_to` row. This walks the legal Open → Assigned edge,
    // which is the same transition the routing service would write in
    // production.
    appeal_repo.assign(appeal_id, other).await?;
    let assigned_row = appeal_repo.get(appeal_id).await?.expect("row present");
    assert_eq!(assigned_row.status, AppealStatus::Assigned);
    assert_eq!(assigned_row.assigned_to, Some(other));

    // ── Scenario 4: Reversed decision writes a calibration event ─────
    // `other` is the assigned reviewer; they record `Reversed`. The
    // calibration_events table should have a fresh row on `author`'s
    // stream with `kind = 'appeal_reversal'`.
    let state_full = {
        let crypto = Crypto::new([8_u8; 32]);
        let sessions = SessionStore::new(pool.clone(), crypto);
        ApiState::new(pool.clone(), sessions)
    };
    let ctx_reviewer = ctx_for(other, &[Role::Moderator]);
    let decide_body = DecideBody {
        decision: AppealDecision::Reversed,
        reasoning: "Reviewer found the original label inappropriate.".to_owned(),
    };
    let Json(result) = decide_appeal(
        State(state_full.clone()),
        Extension(ctx_reviewer.clone()),
        Path(appeal_id),
        Json(decide_body),
    )
    .await?;
    assert_eq!(result.appeal_id, appeal_id);
    assert_eq!(result.status, AppealStatus::DecidedReversed);
    let reversal_action_id = result
        .reversal_action_id
        .expect("Reversed decision must insert a reversal action row");

    // The reversal-Action row exists and points at the original.
    let reversal = action_repo
        .get(reversal_action_id)
        .await?
        .expect("reversal action row must be persisted");
    assert_eq!(reversal.kind, ActionKind::Reverse);
    assert_eq!(reversal.reverses_action_id, Some(action.id));
    assert_eq!(reversal.moderator_id, other);

    // A calibration event is on `author`'s stream.
    let events = calibration_repo.list_for_moderator(author, 10).await?;
    assert_eq!(
        events.len(),
        1,
        "exactly one calibration event must be written on Reversed decision",
    );
    let event = &events[0];
    assert_eq!(event.moderator_id, author);
    assert_eq!(event.kind, CalibrationEventKind::AppealReversal);
    assert_eq!(event.referenced_action_id, Some(action.id));
    assert_eq!(event.referenced_appeal_id, Some(appeal_id));

    // `GET /api/appeals/:id` returns the full view post-decision.
    let Json(view) = get_appeal(
        State(state_full.clone()),
        Extension(ctx_reviewer),
        Path(appeal_id),
    )
    .await?;
    assert_eq!(view.id, appeal_id);
    assert_eq!(view.status, AppealStatus::DecidedReversed);
    assert_eq!(view.original_action.id, action.id);

    // ── Scenario 5: original author cannot decide their own appeal ───
    // Fresh action by `author`, fresh appeal, assigned to a third
    // moderator. The author then attempts to decide — must 403 even
    // when carrying the Admin role.
    let action2 = insert_original_action(&action_repo, incident.id, subject.id, author).await?;
    let third = insert_moderator(&pool).await?;
    let state_q5 = api_state_with_tiny_quota(pool.clone(), 10);
    let addr_appellant: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)), 4321);
    let (_status, Json(submitted2)) = submit_appeal(
        State(state_q5),
        ConnectInfo(addr_appellant),
        Json(SubmitAppealBody {
            appealed_action_id: action2.id,
            appellant_statement: "Second appeal, by a different appellant.".to_owned(),
        }),
    )
    .await?;
    let appeal2 = submitted2.appeal_id;
    appeal_repo.assign(appeal2, third).await?;

    // Author tries to decide their own appeal, even with Admin role.
    let ctx_author_admin = ctx_for(author, &[Role::Admin]);
    let err = decide_appeal(
        State(state_full),
        Extension(ctx_author_admin),
        Path(appeal2),
        Json(DecideBody {
            decision: AppealDecision::Upheld,
            reasoning: "I'm uphholding my own decision — should be blocked.".to_owned(),
        }),
    )
    .await
    .expect_err("original author must not decide their own appeal");
    assert!(
        matches!(err, ApiError::Forbidden),
        "expected Forbidden, got {err:?}",
    );

    // And no calibration event was written on `author`'s stream as a
    // side effect of the rejected attempt.
    let events_after = calibration_repo.list_for_moderator(author, 10).await?;
    assert_eq!(
        events_after.len(),
        1,
        "rejected decide must not write a calibration event",
    );

    Ok(())
}
