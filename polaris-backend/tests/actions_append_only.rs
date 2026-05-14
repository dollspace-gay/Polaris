//! Append-only invariant test (issue #13).
//!
//! Proves that the BEFORE UPDATE trigger in
//! `00000000000004_actions.sql` rejects any UPDATE against the `actions`
//! table, regardless of who issues it. We deliberately bypass the
//! [`polaris_backend::repo::ActionRepo`] (which doesn't expose `update`)
//! and run a raw `sqlx::query` to PROVE the DB layer holds the line.
//!
//! # What this test asserts
//!
//! 1. Inserting an `Action` succeeds via the repo.
//! 2. A raw `UPDATE actions SET reasoning = $1 WHERE id = $2` fails.
//! 3. The error is a `sqlx::Error::Database` whose SQLSTATE is `P0001`
//!    (PL/pgSQL `RAISE EXCEPTION`).
//! 4. The row's `reasoning` column is byte-identical to the value before
//!    the failed UPDATE — the trigger is BEFORE UPDATE, so the row never
//!    materialises a mutated state.
//!
//! # Why a raw `sqlx::query` rather than `sqlx::query!`?
//!
//! The compile-time `sqlx::query!` macro validates SQL against a live
//! database AT BUILD TIME; if the build-time DB has the trigger installed
//! it would happily compile (the SQL is syntactically valid). We use the
//! runtime-only `sqlx::query("…").bind(…).execute()` form here for two
//! reasons:
//!
//! 1. It surfaces the runtime SQLSTATE we want to assert on, without
//!    adding a new `.sqlx/` entry for SQL that is *intended* to fail.
//! 2. It mirrors the threat model: the trigger has to defend against a
//!    future hand-crafted query path that bypasses the repo. The raw
//!    query is exactly that path.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message and
//! returns successfully — same pattern as `tests/db_smoke.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use chrono::Utc;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::{
    self, ActionRepo, IncidentRepo, PgActionRepo, PgIncidentRepo, PgSubjectRepo, RepoError,
    SubjectRepo,
};
use polaris_types::{
    ActionKind, Did, IncidentStatus, LabelValue, ModeratorId, PolicyId, Severity, SubjectKind,
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

#[tokio::test]
async fn actions_table_rejects_any_update() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP actions_append_only: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test.",
        );
        return Ok(());
    }

    // Postgres 16-alpine — the workspace-wide target. Migration 11
    // (second_opinion) requires `GENERATED ALWAYS AS … STORED` columns
    // which Postgres ≥ 12 supports; the testcontainers-modules default
    // `11-alpine` rejects the migration with SQLSTATE 42601.
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

    // Build the parent rows. The repo path handles the subject + incident.
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let action_repo = PgActionRepo::new(pool.clone());

    let subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new("did:plc:appendonly")),
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
    let moderator_id = insert_moderator(&pool).await?;
    let original_reasoning =
        "Original reasoning text, longer than ten chars to satisfy the CHECK.".to_owned();
    let action = action_repo
        .insert(repo::NewAction {
            incident_id: incident.id,
            subject_id: subject.id,
            moderator_id,
            kind: ActionKind::Label,
            label: Some(LabelValue::new("spam")),
            reasoning: original_reasoning.clone(),
            policy_refs: vec![PolicyId::new("community-guidelines.spam.v1")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
        })
        .await?;
    assert_eq!(action.reasoning, original_reasoning);

    // ── Direct UPDATE attempt — must be rejected ────────────────────
    // Use the runtime-only `sqlx::query(…)` form (NOT the compile-checked
    // macro). The trigger is BEFORE UPDATE, so the row never enters the
    // mutated state.
    let raw_result = sqlx::query("UPDATE actions SET reasoning = $1 WHERE id = $2")
        .bind("Mutated reasoning that must never be persisted.")
        .bind(action.id.into_uuid())
        .execute(&pool)
        .await;
    let err = raw_result.expect_err("UPDATE on actions must be rejected by the trigger");

    // The error must surface as SQLSTATE `P0001` (PL/pgSQL RAISE EXCEPTION).
    match &err {
        sqlx::Error::Database(db_err) => {
            let code = db_err
                .code()
                .map(std::borrow::Cow::into_owned)
                .expect("rejected UPDATE must carry a SQLSTATE");
            assert_eq!(
                code, "P0001",
                "expected PL/pgSQL exception SQLSTATE P0001 (RAISE EXCEPTION), got {code} \
                 with message: {db_err}",
            );
            assert!(
                db_err.message().to_lowercase().contains("append-only"),
                "trigger message should mention append-only; got: {}",
                db_err.message(),
            );
        }
        other => panic!("expected sqlx::Error::Database, got: {other:?}"),
    }

    // The repo's `From<sqlx::Error>` impl must also route this into the
    // typed AppendOnlyViolation variant — that's the contract repo
    // callers depend on.
    let routed: RepoError = err.into();
    assert!(
        matches!(routed, RepoError::AppendOnlyViolation(_)),
        "RepoError must classify SQLSTATE P0001 as AppendOnlyViolation, got: {routed:?}",
    );

    // ── Row must be unchanged ────────────────────────────────────────
    let post_attempt = action_repo
        .get(action.id)
        .await?
        .expect("action should still exist after rejected UPDATE");
    assert_eq!(
        post_attempt.reasoning, original_reasoning,
        "reasoning must be unchanged after the rejected UPDATE",
    );
    assert_eq!(post_attempt.created_at, action.created_at);
    assert_eq!(post_attempt.id, action.id);

    Ok(())
}
