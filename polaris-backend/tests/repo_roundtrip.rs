//! Repo round-trip integration test (issue #13).
//!
//! Spins up Postgres 16 via testcontainers, applies all migrations through
//! `db::connect`, then exercises each of the five repos:
//!
//! 1. `PgSubjectRepo`: insert / get / list, plus a list filter by `kind`.
//! 2. `PgIncidentRepo`: insert against the previously-inserted subject,
//!    then `get` + `list_by_status`.
//! 3. `PgActionRepo`: insert against the previously-inserted incident +
//!    subject + a moderator row (inserted via raw SQL — the auth repo
//!    isn't part of this dispatch). Then `get` + `list_by_incident`.
//! 4. `PgReportRepo`: insert with an attached incident, then `get` +
//!    `list_by_subject`.
//! 5. `PgObservationRepo`: insert each `ObservationKind` variant against
//!    the subject; assert the `subjects.risk_signals` trigger populates
//!    the denormalized column.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message and
//! returns successfully — same pattern as `tests/db_smoke.rs`. The
//! compile-time `cargo test --no-run` check always passes; only the
//! runtime depends on a Docker daemon.

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
    self, ActionRepo, IncidentRepo, ObservationRepo, PgActionRepo, PgIncidentRepo,
    PgObservationRepo, PgReportRepo, PgSubjectRepo, ReportRepo, SubjectRepo,
};
use polaris_types::{
    ActionKind, AtUri, Did, IncidentStatus, LabelValue, ModeratorId, ObservationKind, PolicyId,
    ReportCategory, Severity, SubjectKind,
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

/// Insert a moderator row directly via sqlx. The auth repo isn't part of
/// this dispatch; #13 just needs a `moderator_id` to satisfy the actions
/// FK. Uses raw `sqlx::query!` so the macro still validates the SQL at
/// compile time.
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
#[allow(
    clippy::too_many_lines,
    reason = "linear scenario covering all five repos in one Postgres-startup; \
              splitting into per-repo tests would force five container starts at ~3s each"
)]
async fn each_repo_round_trips_through_postgres() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP repo_roundtrip: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test.",
        );
        return Ok(());
    }

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

    // ── Subject ──────────────────────────────────────────────────────
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let new_subject = repo::NewSubject {
        kind: SubjectKind::Account,
        did: Some(Did::new("did:plc:test1234")),
        uri: None,
        created_at: Utc::now(),
    };
    let inserted_subject = subject_repo.insert(new_subject.clone()).await?;
    assert_eq!(inserted_subject.kind, new_subject.kind);
    assert_eq!(inserted_subject.did, new_subject.did);
    assert_eq!(inserted_subject.uri, new_subject.uri);
    assert!(
        inserted_subject.risk_signals.is_empty(),
        "fresh subject should have empty risk_signals (the trigger only fires \
         on observations insert/delete)",
    );

    // `get` returns the same row.
    let fetched = subject_repo
        .get(inserted_subject.id)
        .await?
        .expect("just-inserted subject should be present");
    assert_eq!(fetched.id, inserted_subject.id);
    assert_eq!(fetched.kind, inserted_subject.kind);
    assert_eq!(fetched.did, inserted_subject.did);

    // `list` (unfiltered + filtered) finds the row.
    let listed = subject_repo.list(None, 10).await?;
    assert!(listed.iter().any(|s| s.id == inserted_subject.id));
    let listed_accounts = subject_repo.list(Some(SubjectKind::Account), 10).await?;
    assert!(listed_accounts.iter().any(|s| s.id == inserted_subject.id));
    let listed_posts = subject_repo.list(Some(SubjectKind::Post), 10).await?;
    assert!(
        !listed_posts.iter().any(|s| s.id == inserted_subject.id),
        "account subject should not appear in a kind=post filter",
    );

    // Also insert a post-kind subject so the AtUri branch is exercised.
    let post_subject = subject_repo
        .insert(repo::NewSubject {
            kind: SubjectKind::Post,
            did: None,
            uri: Some(AtUri::new("at://did:plc:test1234/app.bsky.feed.post/3lab")),
            created_at: Utc::now(),
        })
        .await?;
    assert_eq!(post_subject.kind, SubjectKind::Post);
    assert_eq!(
        post_subject.uri.as_ref().map(AtUri::as_str),
        Some("at://did:plc:test1234/app.bsky.feed.post/3lab"),
    );

    // ── Incident ─────────────────────────────────────────────────────
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let new_incident = repo::NewIncident {
        primary_subject: inserted_subject.id,
        severity: Severity::High,
        status: IncidentStatus::Open,
        assigned_to: None,
    };
    let inserted_incident = incident_repo.insert(new_incident).await?;
    assert_eq!(inserted_incident.primary_subject, inserted_subject.id);
    assert_eq!(inserted_incident.severity, Severity::High);
    assert_eq!(inserted_incident.status, IncidentStatus::Open);
    assert!(inserted_incident.closed_at.is_none());
    assert!(inserted_incident.reports.is_empty());
    assert!(inserted_incident.pattern_observations.is_empty());

    let fetched_incident = incident_repo
        .get(inserted_incident.id)
        .await?
        .expect("just-inserted incident should be present");
    assert_eq!(fetched_incident.id, inserted_incident.id);
    assert_eq!(fetched_incident.severity, Severity::High);

    let open_incidents = incident_repo
        .list_by_status(Some(IncidentStatus::Open), 10)
        .await?;
    assert!(open_incidents.iter().any(|i| i.id == inserted_incident.id));
    let closed_incidents = incident_repo
        .list_by_status(Some(IncidentStatus::Closed), 10)
        .await?;
    assert!(
        !closed_incidents
            .iter()
            .any(|i| i.id == inserted_incident.id),
        "open incident should not appear in a status=closed filter",
    );

    // ── Action ───────────────────────────────────────────────────────
    let moderator_id = insert_moderator(&pool).await?;
    let action_repo = PgActionRepo::new(pool.clone());
    let new_action = repo::NewAction {
        incident_id: inserted_incident.id,
        subject_id: inserted_subject.id,
        moderator_id,
        kind: ActionKind::Label,
        label: Some(LabelValue::new("spam")),
        reasoning: "Account is engaged in coordinated spamming behaviour.".to_owned(),
        policy_refs: vec![PolicyId::new("community-guidelines.spam.v1")],
        reversible_until: Utc::now() + chrono::Duration::hours(24),
        reverses_action_id: None,
    };
    let inserted_action = action_repo.insert(new_action.clone()).await?;
    assert_eq!(inserted_action.incident_id, inserted_incident.id);
    assert_eq!(inserted_action.subject_id, inserted_subject.id);
    assert_eq!(inserted_action.moderator_id, moderator_id);
    assert_eq!(inserted_action.kind, ActionKind::Label);
    assert_eq!(inserted_action.label, new_action.label);
    assert_eq!(inserted_action.reasoning, new_action.reasoning);
    assert_eq!(inserted_action.policy_refs, new_action.policy_refs);
    assert!(inserted_action.reverses_action_id.is_none());
    assert!(inserted_action.emitted_to_atproto.is_none());

    let fetched_action = action_repo
        .get(inserted_action.id)
        .await?
        .expect("just-inserted action should be present");
    assert_eq!(fetched_action.id, inserted_action.id);
    assert_eq!(fetched_action.kind, ActionKind::Label);

    let actions_for_incident = action_repo
        .list_by_incident(inserted_incident.id, 10)
        .await?;
    assert!(
        actions_for_incident
            .iter()
            .any(|a| a.id == inserted_action.id),
        "action should be discoverable by incident_id",
    );

    // Reverse-action insert: writes a new row pointing at the original.
    // The original is NOT mutated (per §5.5 append-only).
    let reverse_action = action_repo
        .insert(repo::NewAction {
            incident_id: inserted_incident.id,
            subject_id: inserted_subject.id,
            moderator_id,
            kind: ActionKind::Reverse,
            label: None,
            reasoning: "Reversing on review — evidence was misclassified.".to_owned(),
            policy_refs: vec![],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: Some(inserted_action.id),
        })
        .await?;
    assert_eq!(reverse_action.kind, ActionKind::Reverse);
    assert_eq!(reverse_action.reverses_action_id, Some(inserted_action.id));

    // Confirm the original action row is byte-identical after the reverse
    // insert — the append-only contract says only the new row is added.
    let original_after = action_repo
        .get(inserted_action.id)
        .await?
        .expect("original action must still exist");
    assert_eq!(original_after.reasoning, inserted_action.reasoning);
    assert_eq!(original_after.created_at, inserted_action.created_at);

    // ── Report ───────────────────────────────────────────────────────
    let report_repo = PgReportRepo::new(pool.clone());
    let new_report = repo::NewReport {
        subject_id: inserted_subject.id,
        incident_id: Some(inserted_incident.id),
        reporter_did: Did::new("did:plc:reporter"),
        category: ReportCategory::new("spam"),
        body: "Account is spamming replies on every popular thread.".to_owned(),
    };
    let inserted_report = report_repo.insert(new_report.clone()).await?;
    assert_eq!(inserted_report.subject_id, inserted_subject.id);
    assert_eq!(inserted_report.incident_id, Some(inserted_incident.id));
    assert_eq!(inserted_report.reporter_did, new_report.reporter_did);
    assert_eq!(inserted_report.category, new_report.category);
    assert_eq!(inserted_report.body, new_report.body);

    let fetched_report = report_repo
        .get(inserted_report.id)
        .await?
        .expect("just-inserted report should be present");
    assert_eq!(fetched_report.id, inserted_report.id);
    assert_eq!(fetched_report.body, inserted_report.body);

    let reports_for_subject = report_repo.list_by_subject(inserted_subject.id, 10).await?;
    assert!(
        reports_for_subject
            .iter()
            .any(|r| r.id == inserted_report.id),
        "report should be discoverable by subject_id",
    );

    // Also exercise unbound (incident_id IS NULL) at insert time.
    let unbound_report = report_repo
        .insert(repo::NewReport {
            subject_id: inserted_subject.id,
            incident_id: None,
            reporter_did: Did::new("did:plc:reporter2"),
            category: ReportCategory::new("harassment"),
            body: "Reply contained personal threats.".to_owned(),
        })
        .await?;
    assert!(unbound_report.incident_id.is_none());

    // ── Observation ──────────────────────────────────────────────────
    let observation_repo = PgObservationRepo::new(pool.clone());
    let obs_inputs = vec![
        repo::NewObservation {
            subject_id: inserted_subject.id,
            kind: ObservationKind::ImageHashCluster {
                hash: "deadbeefcafebabe".to_owned(),
                distance: 2,
            },
            confidence: 0.92,
            evidence: serde_json::json!({}),
        },
        repo::NewObservation {
            subject_id: inserted_subject.id,
            kind: ObservationKind::ExternalLabel {
                source: Did::new("did:plc:labeler"),
                label_value: LabelValue::new("spam"),
                weight: 0.75,
            },
            confidence: 0.6,
            evidence: serde_json::json!({"raw_emitter": "labeler-v1"}),
        },
        repo::NewObservation {
            subject_id: inserted_subject.id,
            kind: ObservationKind::ClassifierSignal {
                model: "csam-v3".to_owned(),
                label: "csam".to_owned(),
                confidence: 0.99,
            },
            confidence: 0.95,
            evidence: serde_json::json!({}),
        },
    ];
    let mut inserted_obs_ids = Vec::new();
    for input in obs_inputs.clone() {
        let inserted = observation_repo.insert(input.clone()).await?;
        assert_eq!(inserted.subject_id, input.subject_id);
        assert_eq!(inserted.kind, input.kind);
        // Confidence is stored as REAL; tolerate the f32 round-trip.
        assert!((inserted.confidence - input.confidence).abs() < f32::EPSILON);
        inserted_obs_ids.push(inserted.id);
    }
    let listed_obs = observation_repo
        .list_by_subject(inserted_subject.id)
        .await?;
    assert_eq!(
        listed_obs.len(),
        obs_inputs.len(),
        "all inserted observations should be returned by list_by_subject",
    );
    for id in &inserted_obs_ids {
        assert!(listed_obs.iter().any(|o| o.id == *id));
    }

    // ── Risk-signals trigger ─────────────────────────────────────────
    // After three observation inserts, `subjects.risk_signals` should have
    // three entries (the trigger preserves up to 20). The repo re-reads
    // the subject and decodes the JSONB.
    let subject_after_obs = subject_repo
        .get(inserted_subject.id)
        .await?
        .expect("subject should still exist");
    assert_eq!(
        subject_after_obs.risk_signals.len(),
        obs_inputs.len(),
        "trigger should have populated risk_signals with one entry per observation",
    );
    // Verify each signal carries a known discriminator.
    let kinds: std::collections::HashSet<&str> = subject_after_obs
        .risk_signals
        .iter()
        .map(|s| s.kind.as_str())
        .collect();
    assert!(kinds.contains("image_hash_cluster"));
    assert!(kinds.contains("external_label"));
    assert!(kinds.contains("classifier_signal"));

    Ok(())
}
