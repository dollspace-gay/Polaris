//! `pending_auto_actions` schema invariants (#233, LLM-3 / AC-4 partial).
//!
//! The pending-draft queue table lands in migration 50; the typed
//! CRUD repo lands in LLM-7 (#236). This file pins the schema-level
//! contract the migration must hold before LLM-7 can build on top:
//!
//! 1. **Happy-path insert** with the minimum required columns commits
//!    and the row reads back with the migration's defaults — `state =
//!    'pending'` and `expires_at ≈ now() + 7 days`.
//!
//! 2. **State CHECK constraint** rejects an out-of-vocabulary value.
//!    The lifecycle vocabulary `(pending | approved | rejected |
//!    superseded | expired)` is the source of truth for the future
//!    typed repo's enum decoder; this test pins it at the DB layer
//!    so a typo in either the migration or a future amendment is
//!    caught at insert time.
//!
//! 3. **CASCADE on incident delete** removes the draft. The
//!    moderator-facing case "delete this incident" affordance must
//!    take its pending drafts with it; without CASCADE the FK would
//!    block.
//!
//! Mirrors the docker-detection / container-leak conventions from
//! `action_policy_citations_integrity.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::{
    IncidentRepo, NewIncident, NewObservation, NewSubject, ObservationRepo, PgIncidentRepo,
    PgObservationRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{Did, IncidentStatus, ObservationKind, Severity, SubjectKind};
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

/// Seed a subject + incident + `LlmRecommendation` observation; return
/// `(subject_id, incident_id, observation_id)` so the test can fan out
/// `pending_auto_actions` inserts against them.
async fn seed_world(pool: &PgPool) -> Result<(Uuid, Uuid, Uuid), Box<dyn std::error::Error>> {
    let subject = PgSubjectRepo::new(pool.clone())
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new(format!("did:plc:paa-{}", Uuid::new_v4().simple()))),
            uri: None,
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
    let observation = PgObservationRepo::new(pool.clone())
        .insert(NewObservation {
            subject_id: subject.id,
            kind: ObservationKind::LlmRecommendation {
                model: "claude-sonnet-4-6".to_owned(),
                model_version: "2026-01-15".to_owned(),
                prompt_template_id: "polaris.case-review.v1".to_owned(),
                recommended_action_kind: "label".to_owned(),
                confidence: 0.82,
            },
            confidence: 0.82,
            evidence: serde_json::json!({}),
        })
        .await?;
    Ok((subject.id.0, incident.id.0, observation.id.0))
}

// ── 1. Happy path: insert + defaults ───────────────────────────────────

#[tokio::test]
async fn pending_auto_action_insert_applies_defaults() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP pending_auto_action_insert_applies_defaults: docker unreachable");
        return Ok(());
    }

    let pool = boot_pool().await?;
    let (subject_id, incident_id, observation_id) = seed_world(&pool).await?;

    let recommended = serde_json::json!({
        "action_kind": "label",
        "label_value": "spam",
        "subject_scope": "post",
        "confidence": 0.82,
        "cited_policy_identifiers": ["polaris.spam"],
        "reasoning": "Identical reply text seen on three unrelated threads.",
        "caveats": [],
    });
    let cited = serde_json::json!([{"identifier": "polaris.spam", "version": 1}]);

    let before = chrono::Utc::now();
    let row = sqlx::query!(
        r#"
        INSERT INTO pending_auto_actions
            (incident_id, subject_id, recommended_action,
             llm_observation_id, cited_policy_versions)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, state, expires_at, created_at, resolved_at,
                  claimed_by_moderator_id
        "#,
        incident_id,
        subject_id,
        recommended,
        observation_id,
        cited,
    )
    .fetch_one(&pool)
    .await?;
    let after = chrono::Utc::now();

    assert_eq!(row.state, "pending");
    assert!(row.resolved_at.is_none());
    assert!(row.claimed_by_moderator_id.is_none());
    // expires_at default is `now() + 7 days`. Allow some clock slack
    // around the surrounding `before`/`after`.
    let target = before + chrono::Duration::days(7);
    let drift = (row.expires_at - target).num_seconds().abs();
    assert!(
        drift < 60,
        "expires_at = {:?}, target ~{:?}, drift = {}s",
        row.expires_at,
        target,
        drift,
    );
    // created_at default similarly.
    assert!(row.created_at >= before && row.created_at <= after);

    Ok(())
}

// ── 2. State CHECK constraint ──────────────────────────────────────────

#[tokio::test]
async fn pending_auto_action_state_check_rejects_bad_value()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP pending_auto_action_state_check_rejects_bad_value: docker unreachable");
        return Ok(());
    }

    let pool = boot_pool().await?;
    let (subject_id, incident_id, observation_id) = seed_world(&pool).await?;

    let err = sqlx::query!(
        r#"
        INSERT INTO pending_auto_actions
            (incident_id, subject_id, recommended_action,
             llm_observation_id, cited_policy_versions, state)
        VALUES ($1, $2, '{}'::jsonb, $3, '[]'::jsonb, 'frobnicated')
        "#,
        incident_id,
        subject_id,
        observation_id,
    )
    .execute(&pool)
    .await
    .expect_err("state CHECK must reject 'frobnicated'");
    let sqlstate = err
        .as_database_error()
        .and_then(|e| e.code().map(std::borrow::Cow::into_owned));
    assert_eq!(
        sqlstate.as_deref(),
        Some("23514"),
        "expected check_violation (23514), got {sqlstate:?}: {err}",
    );

    // Every legal value must be accepted.
    for state in ["pending", "approved", "rejected", "superseded", "expired"] {
        sqlx::query!(
            r#"
            INSERT INTO pending_auto_actions
                (incident_id, subject_id, recommended_action,
                 llm_observation_id, cited_policy_versions, state)
            VALUES ($1, $2, '{}'::jsonb, $3, '[]'::jsonb, $4)
            "#,
            incident_id,
            subject_id,
            observation_id,
            state,
        )
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("legal state {state:?} should insert: {e}"));
    }

    Ok(())
}

// ── 3. ON DELETE CASCADE on incident ───────────────────────────────────

#[tokio::test]
async fn pending_auto_action_cascades_on_incident_delete() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!("SKIP pending_auto_action_cascades_on_incident_delete: docker unreachable");
        return Ok(());
    }

    let pool = boot_pool().await?;
    let (subject_id, incident_id, observation_id) = seed_world(&pool).await?;

    sqlx::query!(
        r#"
        INSERT INTO pending_auto_actions
            (incident_id, subject_id, recommended_action,
             llm_observation_id, cited_policy_versions)
        VALUES ($1, $2, '{}'::jsonb, $3, '[]'::jsonb)
        "#,
        incident_id,
        subject_id,
        observation_id,
    )
    .execute(&pool)
    .await?;

    let count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) FROM pending_auto_actions WHERE incident_id = $1"#,
        incident_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(count, Some(1));

    sqlx::query!(r#"DELETE FROM incidents WHERE id = $1"#, incident_id)
        .execute(&pool)
        .await?;

    let count = sqlx::query_scalar!(
        r#"SELECT COUNT(*) FROM pending_auto_actions WHERE incident_id = $1"#,
        incident_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        count,
        Some(0),
        "incident DELETE must cascade-delete its pending_auto_actions rows",
    );

    Ok(())
}
