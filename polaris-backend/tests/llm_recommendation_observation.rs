//! `LlmRecommendation` observation round-trip (#233, LLM-3 / AC-3).
//!
//! Spins up a fresh testcontainers Postgres 16-alpine, applies every
//! migration through migration 52, then inserts an
//! `ObservationKind::LlmRecommendation` observation via the typed repo
//! and reads it back. Verifies:
//!
//! * The `kind` CHECK constraint admits the new `'llm_recommendation'`
//!   discriminator (migration 49).
//! * The typed variant's per-variant fields (`model`, `model_version`,
//!   `prompt_template_id`, `recommended_action_kind`, `confidence`)
//!   round-trip through the JSONB `evidence` column.
//! * Caller-supplied free-form evidence keys (REQ-B2: the full
//!   `RecommendResponse` payload plus the request content-hash) are
//!   preserved verbatim on read.
//!
//! Mirrors the docker-detection / container-leak conventions used by
//! `repo_roundtrip.rs` and `action_policy_citations_integrity.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::{NewObservation, ObservationRepo, PgObservationRepo, PgSubjectRepo};
use polaris_backend::repo::{NewSubject, SubjectRepo};
use polaris_types::{Did, ObservationKind, SubjectKind};
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

#[tokio::test]
async fn llm_recommendation_observation_round_trips_through_postgres()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP llm_recommendation_observation_round_trips: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service to exercise this test."
        );
        return Ok(());
    }

    let pool = boot_pool().await?;

    // Seed a subject so the observation FK is satisfiable.
    let subject = PgSubjectRepo::new(pool.clone())
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new(format!("did:plc:llm-{}", Uuid::new_v4().simple()))),
            uri: None,
            created_at: chrono::Utc::now(),
        })
        .await?;

    // Build the full `RecommendResponse`-shaped free-form evidence: this is
    // the REQ-B2 contract — the row's `evidence` JSONB carries the verbatim
    // LLM response plus the request content-hash for replay determinism
    // checks.
    let recommend_response = serde_json::json!({
        "event_id": "01HJ8K9MFAKE0000000000000",
        "input_tokens": 1234,
        "output_tokens": 567,
        "overall_reasoning": "Account exhibits coordinated reply-brigading.",
        "recommended_actions": [{
            "action_kind": "label",
            "label_value": "spam",
            "subject_scope": "account",
            "confidence": 0.91,
            "cited_policy_identifiers": ["polaris.spam"],
            "reasoning": "Repeated identical replies across unrelated threads \
                          within minutes — classic brigading pattern.",
            "caveats": ["Possible scheduled-posting bot rather than human."],
        }],
        "request_content_hash":
            "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
    });

    let observation_repo = PgObservationRepo::new(pool.clone());
    let inserted = observation_repo
        .insert(NewObservation {
            subject_id: subject.id,
            kind: ObservationKind::LlmRecommendation {
                model: "claude-sonnet-4-6".to_owned(),
                model_version: "2026-01-15".to_owned(),
                prompt_template_id: "polaris.case-review.v1".to_owned(),
                recommended_action_kind: "label".to_owned(),
                confidence: 0.91,
            },
            confidence: 0.91,
            evidence: recommend_response.clone(),
        })
        .await?;

    // Round-trip the typed enum.
    match &inserted.kind {
        ObservationKind::LlmRecommendation {
            model,
            model_version,
            prompt_template_id,
            recommended_action_kind,
            confidence,
        } => {
            assert_eq!(model, "claude-sonnet-4-6");
            assert_eq!(model_version, "2026-01-15");
            assert_eq!(prompt_template_id, "polaris.case-review.v1");
            assert_eq!(recommended_action_kind, "label");
            assert!((confidence - 0.91).abs() < 1e-6);
        }
        other => panic!("expected LlmRecommendation, got {other:?}"),
    }

    // The free-form `RecommendResponse` payload must survive verbatim
    // (REQ-B2): list_by_subject reads back what the repo stored.
    let listed = observation_repo.list_by_subject(subject.id).await?;
    assert_eq!(listed.len(), 1);
    let row = &listed[0];
    // The typed fields are merged into the `evidence` object on the
    // write side; the response payload's own keys must still be present.
    assert_eq!(
        row.evidence
            .get("request_content_hash")
            .and_then(serde_json::Value::as_str),
        Some("0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"),
    );
    assert_eq!(
        row.evidence
            .get("recommended_actions")
            .and_then(|v| v.get(0))
            .and_then(|v| v.get("action_kind"))
            .and_then(serde_json::Value::as_str),
        Some("label"),
    );
    assert_eq!(
        row.evidence
            .get("input_tokens")
            .and_then(serde_json::Value::as_i64),
        Some(1234),
    );

    Ok(())
}
