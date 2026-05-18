//! Action-policy-citations integrity tests (#223, WB-1, AC-2b).
//!
//! Hermetic per test: boots a fresh testcontainers Postgres
//! 16-alpine, applies all migrations, seeds a moderator + subject +
//! incident + action, then exercises the typed citation repo's
//! happy path and the composite-FK + composite-PK rejection paths.
//! Mirrors `mod_policies_repo.rs` for the boot harness so the
//! docker-detection / container-leak conventions are uniform.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::action_policy_citations;
use polaris_backend::repo::mod_policies::{self, NewModPolicy};
use polaris_backend::repo::{
    ActionRepo, IncidentRepo, NewAction, NewIncident, NewSubject, PgActionRepo, PgIncidentRepo,
    PgSubjectRepo, RepoError, SubjectRepo,
};
use polaris_types::{
    ActionKind, AtUri, Did, IncidentStatus, ModeratorId, PolicyId, Severity, SubjectKind,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
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

/// Boot a Postgres testcontainer + migrate + return the pool.
async fn boot_pool() -> Result<PgPool, Box<dyn std::error::Error>> {
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
    Ok(pool)
}

/// Insert a moderator row, return its id.
async fn insert_moderator(pool: &PgPool) -> Result<Uuid, Box<dyn std::error::Error>> {
    let external_id = format!("apc-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// Seed a moderator, subject, incident, and a single action; return
/// the action's id and the moderator id (the latter is the policy
/// fixture's `created_by_moderator_id`).
async fn seed_action_and_policy(pool: &PgPool) -> Result<(Uuid, Uuid), Box<dyn std::error::Error>> {
    let mod_id = insert_moderator(pool).await?;

    let subject = PgSubjectRepo::new(pool.clone())
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new(format!("did:plc:apc-{}", Uuid::new_v4().simple()))),
            uri: Some(AtUri::new(format!(
                "at://did:plc:apc-{}/app.bsky.feed.post/x",
                Uuid::new_v4().simple()
            ))),
            created_at: chrono::Utc::now(),
        })
        .await?;

    let incident = PgIncidentRepo::new(pool.clone())
        .insert(NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await?;

    let action = PgActionRepo::new(pool.clone())
        .insert(NewAction {
            incident_id: incident.id,
            subject_id: subject.id,
            moderator_id: ModeratorId(mod_id),
            kind: ActionKind::Warn,
            label: None,
            reasoning: "fixture reasoning text".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.harassment".to_owned())],
            reversible_until: chrono::Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            llm_audit: None,
        })
        .await?;

    // Seed v1 of polaris.harassment so the FK target exists.
    let mut tx = pool.begin().await?;
    mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: "polaris.harassment".to_owned(),
            name: "harassment".to_owned(),
            description: "placeholder".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "Apply when the post is direct, targeted harassment of a \
                                specific identifiable user beyond fair criticism."
                .to_owned(),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["warn".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "manual".to_owned(),
            autonomous_action_kinds: vec![],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            autonomous_rate_limit_per_hour: None,
            autonomous_reversal_breaker_threshold: None,
            change_summary: None,
        },
        mod_id,
    )
    .await?;
    tx.commit().await?;

    Ok((action.id.0, mod_id))
}

// ── 1. insert_for_action round trip ────────────────────────────────────

#[tokio::test]
async fn insert_for_action_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP action_policy_citations::insert_for_action_round_trip: docker unreachable");
        return Ok(());
    }
    let pool = boot_pool().await?;
    let (action_id, _mod_id) = seed_action_and_policy(&pool).await?;

    let mut tx = pool.begin().await?;
    action_policy_citations::insert_for_action(
        &mut tx,
        action_id,
        &[("polaris.harassment".to_owned(), 1)],
    )
    .await?;
    tx.commit().await?;

    let citations = action_policy_citations::citations_for_action(&pool, action_id).await?;
    assert_eq!(citations.len(), 1);
    assert_eq!(citations[0].action_id, action_id);
    assert_eq!(citations[0].policy_identifier, "polaris.harassment");
    assert_eq!(citations[0].policy_version, 1);
    Ok(())
}

// ── 2. composite FK rejects unknown (identifier, version) ──────────────

#[tokio::test]
async fn fk_rejects_unknown_policy_version() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP action_policy_citations::fk_rejects_unknown_policy_version: docker unreachable"
        );
        return Ok(());
    }
    let pool = boot_pool().await?;
    let (action_id, _mod_id) = seed_action_and_policy(&pool).await?;

    // The seed put v1 in place; v999 does NOT exist. The composite
    // FK must reject the insert.
    let mut tx = pool.begin().await?;
    let err = action_policy_citations::insert_for_action(
        &mut tx,
        action_id,
        &[("polaris.harassment".to_owned(), 999)],
    )
    .await
    .expect_err("FK rejects unknown version");
    drop(tx);
    assert!(
        matches!(err, RepoError::ForeignKey(_)),
        "expected ForeignKey violation, got {err:?}",
    );

    // Also reject unknown identifier entirely.
    let mut tx = pool.begin().await?;
    let err = action_policy_citations::insert_for_action(
        &mut tx,
        action_id,
        &[("polaris.does_not_exist".to_owned(), 1)],
    )
    .await
    .expect_err("FK rejects unknown identifier");
    drop(tx);
    assert!(
        matches!(err, RepoError::ForeignKey(_)),
        "expected ForeignKey violation, got {err:?}",
    );
    Ok(())
}

// ── 3. composite PK rejects duplicate citation ─────────────────────────

#[tokio::test]
async fn pk_rejects_duplicate_citation() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP action_policy_citations::pk_rejects_duplicate_citation: docker unreachable");
        return Ok(());
    }
    let pool = boot_pool().await?;
    let (action_id, _mod_id) = seed_action_and_policy(&pool).await?;

    // First insert succeeds.
    let mut tx = pool.begin().await?;
    action_policy_citations::insert_for_action(
        &mut tx,
        action_id,
        &[("polaris.harassment".to_owned(), 1)],
    )
    .await?;
    tx.commit().await?;

    // Second insert of the same triple violates the composite PK.
    let mut tx = pool.begin().await?;
    let err = action_policy_citations::insert_for_action(
        &mut tx,
        action_id,
        &[("polaris.harassment".to_owned(), 1)],
    )
    .await
    .expect_err("PK rejects duplicate");
    drop(tx);
    assert!(
        matches!(err, RepoError::UniqueViolation(_)),
        "expected UniqueViolation, got {err:?}",
    );

    // Empty-slice insert is a no-op and must not error.
    let mut tx = pool.begin().await?;
    action_policy_citations::insert_for_action(&mut tx, action_id, &[]).await?;
    tx.commit().await?;

    Ok(())
}
