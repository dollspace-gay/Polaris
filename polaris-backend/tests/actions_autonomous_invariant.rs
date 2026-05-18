//! Autonomous-action audit envelope invariant (#233, LLM-3 / AC-5).
//!
//! Migration 51 adds the `actor_kind` + six LLM audit columns to
//! `actions` plus the named CHECK constraint
//! `actions_autonomous_audit_complete` that enforces:
//!
//! ```text
//! actor_kind = 'autonomous_agent' ⇒
//!     llm_observation_id        IS NOT NULL
//! AND model                     IS NOT NULL
//! AND model_version             IS NOT NULL
//! AND prompt_template_id        IS NOT NULL
//! AND recommendation_confidence IS NOT NULL
//! AND input_hash                IS NOT NULL
//! ```
//!
//! This file proves the invariant at the database boundary three ways:
//!
//! 1. **Autonomous + complete envelope ⇒ accepted.** The dispatcher path
//!    (LLM-5, #242) constructs a `NewAction` with `Some(LlmAuditFields)`;
//!    the insert succeeds, the row reads back `actor_kind =
//!    'autonomous_agent'` and the audit envelope is intact.
//!
//! 2. **Autonomous + partial envelope ⇒ rejected.** Bypassing the typed
//!    repo with a raw SQL INSERT that sets `actor_kind =
//!    'autonomous_agent'` but leaves `model = NULL` must fail with the
//!    CHECK constraint. This is the load-bearing safety property: a
//!    buggy future writer cannot land a half-audited autonomous row.
//!
//! 3. **Human-emitted (None / default) ⇒ accepted with NULL columns.**
//!    Existing call sites pass `llm_audit: None`; the row commits with
//!    `actor_kind = 'human'` and every LLM column NULL — identical to
//!    the pre-LLM-3 schema's behaviour.
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
use polaris_backend::repo::action::LlmAuditFields;
use polaris_backend::repo::{
    ActionRepo, IncidentRepo, NewAction, NewIncident, NewObservation, NewSubject, ObservationRepo,
    PgActionRepo, PgIncidentRepo, PgObservationRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{
    ActionKind, AtUri, Did, IncidentStatus, ModeratorId, ObservationKind, PolicyId, Severity,
    SubjectKind,
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

async fn insert_moderator(pool: &PgPool) -> Result<Uuid, Box<dyn std::error::Error>> {
    let external_id = format!("autonomous-test-{}", Uuid::new_v4());
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

/// Seed a moderator + subject + incident + `LlmRecommendation`
/// observation so the autonomous-action insert has every FK target
/// available.
async fn seed_world(pool: &PgPool) -> Result<(Uuid, Uuid, Uuid, Uuid), Box<dyn std::error::Error>> {
    let mod_id = insert_moderator(pool).await?;

    let subject = PgSubjectRepo::new(pool.clone())
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new(format!(
                "did:plc:autonomous-{}",
                Uuid::new_v4().simple()
            ))),
            uri: Some(AtUri::new(format!(
                "at://did:plc:autonomous-{}/app.bsky.feed.post/x",
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

    let observation = PgObservationRepo::new(pool.clone())
        .insert(NewObservation {
            subject_id: subject.id,
            kind: ObservationKind::LlmRecommendation {
                model: "claude-sonnet-4-6".to_owned(),
                model_version: "2026-01-15".to_owned(),
                prompt_template_id: "polaris.case-review.v1".to_owned(),
                recommended_action_kind: "label".to_owned(),
                confidence: 0.96,
            },
            confidence: 0.96,
            evidence: serde_json::json!({}),
        })
        .await?;

    Ok((mod_id, subject.id.0, incident.id.0, observation.id.0))
}

// ── 1. Autonomous + complete envelope ⇒ accepted ────────────────────────

#[tokio::test]
async fn autonomous_action_with_complete_envelope_is_accepted()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP autonomous_action_with_complete_envelope_is_accepted: docker unreachable");
        return Ok(());
    }

    let pool = boot_pool().await?;
    let (mod_id, subject_id, incident_id, observation_id) = seed_world(&pool).await?;

    let action = PgActionRepo::new(pool.clone())
        .insert(NewAction {
            incident_id: polaris_types::IncidentId(incident_id),
            subject_id: polaris_types::SubjectId(subject_id),
            moderator_id: ModeratorId(mod_id),
            kind: ActionKind::Label,
            label: Some(polaris_types::LabelValue::new("spam")),
            reasoning: "autonomous-test reasoning long enough for the DB check".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: chrono::Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            llm_audit: Some(LlmAuditFields {
                llm_observation_id: polaris_types::ObservationId(observation_id),
                model: "claude-sonnet-4-6".to_owned(),
                model_version: "2026-01-15".to_owned(),
                prompt_template_id: "polaris.case-review.v1".to_owned(),
                recommendation_confidence: 0.96,
                input_hash: "deadbeef".repeat(8),
            }),
        })
        .await?;

    let row = sqlx::query!(
        r#"SELECT actor_kind, llm_observation_id, model, model_version,
                  prompt_template_id, recommendation_confidence, input_hash
             FROM actions WHERE id = $1"#,
        action.id.0,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.actor_kind, "autonomous_agent");
    assert_eq!(row.llm_observation_id, Some(observation_id));
    assert_eq!(row.model.as_deref(), Some("claude-sonnet-4-6"));
    assert_eq!(row.model_version.as_deref(), Some("2026-01-15"));
    assert_eq!(
        row.prompt_template_id.as_deref(),
        Some("polaris.case-review.v1"),
    );
    assert!(
        row.recommendation_confidence
            .is_some_and(|c| (c - 0.96f32).abs() < 1e-6),
    );
    assert_eq!(row.input_hash.as_deref(), Some(&"deadbeef".repeat(8)[..]));
    Ok(())
}

// ── 2. Autonomous + partial envelope ⇒ rejected by CHECK ────────────────

#[tokio::test]
async fn autonomous_action_with_missing_envelope_field_is_rejected()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP autonomous_action_with_missing_envelope_field_is_rejected: docker unreachable"
        );
        return Ok(());
    }

    let pool = boot_pool().await?;
    let (mod_id, subject_id, incident_id, observation_id) = seed_world(&pool).await?;

    // Bypass the typed repo with a raw SQL INSERT that sets actor_kind
    // = 'autonomous_agent' but leaves model = NULL. The CHECK constraint
    // `actions_autonomous_audit_complete` must reject this with SQLSTATE
    // 23514 (check_violation) — a typed `RepoError::Database` in our
    // error-routing scheme, but for this DB-level invariant test we
    // inspect the raw sqlx error so the SQLSTATE assertion is explicit.
    let err = sqlx::query!(
        r#"
        INSERT INTO actions (
            incident_id, subject_id, moderator_id, kind, label_value,
            reasoning, policy_refs, reversible_until, reverses_action_id,
            actor_kind, llm_observation_id, model, model_version,
            prompt_template_id, recommendation_confidence, input_hash
        )
        VALUES ($1, $2, $3, 'label', 'spam',
                'autonomous-test reasoning long enough',
                ARRAY['polaris.spam']::TEXT[],
                now() + INTERVAL '24 hours', NULL,
                'autonomous_agent', $4, NULL, '2026-01-15',
                'polaris.case-review.v1', 0.96, 'deadbeef')
        "#,
        incident_id,
        subject_id,
        mod_id,
        observation_id,
    )
    .execute(&pool)
    .await
    .expect_err("CHECK constraint must reject partial autonomous envelope");
    let sqlstate = err
        .as_database_error()
        .and_then(|e| e.code().map(std::borrow::Cow::into_owned));
    assert_eq!(
        sqlstate.as_deref(),
        Some("23514"),
        "expected check_violation (23514), got {sqlstate:?}: {err}",
    );

    // And the same shape with `prompt_template_id = NULL` while the
    // other fields are populated.
    let err = sqlx::query!(
        r#"
        INSERT INTO actions (
            incident_id, subject_id, moderator_id, kind, label_value,
            reasoning, policy_refs, reversible_until, reverses_action_id,
            actor_kind, llm_observation_id, model, model_version,
            prompt_template_id, recommendation_confidence, input_hash
        )
        VALUES ($1, $2, $3, 'label', 'spam',
                'autonomous-test reasoning long enough',
                ARRAY['polaris.spam']::TEXT[],
                now() + INTERVAL '24 hours', NULL,
                'autonomous_agent', $4, 'claude-sonnet-4-6', '2026-01-15',
                NULL, 0.96, 'deadbeef')
        "#,
        incident_id,
        subject_id,
        mod_id,
        observation_id,
    )
    .execute(&pool)
    .await
    .expect_err("CHECK constraint must reject missing prompt_template_id");
    let sqlstate = err
        .as_database_error()
        .and_then(|e| e.code().map(std::borrow::Cow::into_owned));
    assert_eq!(sqlstate.as_deref(), Some("23514"));

    Ok(())
}

// ── 3. Human-emitted (default) ⇒ accepted with NULL audit columns ──────

#[tokio::test]
async fn human_action_with_no_envelope_is_accepted_with_null_columns()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP human_action_with_no_envelope_is_accepted: docker unreachable");
        return Ok(());
    }

    let pool = boot_pool().await?;
    let (mod_id, subject_id, incident_id, _observation_id) = seed_world(&pool).await?;

    let action = PgActionRepo::new(pool.clone())
        .insert(NewAction {
            incident_id: polaris_types::IncidentId(incident_id),
            subject_id: polaris_types::SubjectId(subject_id),
            moderator_id: ModeratorId(mod_id),
            kind: ActionKind::Warn,
            label: None,
            reasoning: "human-emitted action with no LLM audit envelope".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.harassment")],
            reversible_until: chrono::Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            llm_audit: None,
        })
        .await?;

    let row = sqlx::query!(
        r#"SELECT actor_kind, llm_observation_id, model, model_version,
                  prompt_template_id, recommendation_confidence, input_hash
             FROM actions WHERE id = $1"#,
        action.id.0,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.actor_kind, "human");
    assert!(row.llm_observation_id.is_none());
    assert!(row.model.is_none());
    assert!(row.model_version.is_none());
    assert!(row.prompt_template_id.is_none());
    assert!(row.recommendation_confidence.is_none());
    assert!(row.input_hash.is_none());
    Ok(())
}
