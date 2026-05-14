//! Integration tests for the reporter-reputation subsystem (issue #37,
//! design.md §9.3). Drives a real Postgres via testcontainers — the
//! same pattern as the rest of the integration suite.
//!
//! Coverage:
//!
//! 1. `record_report_filed` upserts a stats row and increments
//!    `reports_filed`.
//! 2. `record_action(Label)` increments `reports_actioned` and refreshes
//!    `cached_score`.
//! 3. `record_action(NoAction)` increments `reports_dismissed`.
//! 4. `score_for` after multiple records returns the expected smoothed
//!    score (within tolerance).
//!
//! Skip behaviour: as with every other integration test in this crate,
//! the suite short-circuits with a `SKIP` line when the Docker daemon is
//! unreachable. CI surfaces the SKIPs without failing the build.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::reputation::{
    PgReputationProvider, ReputationParams, ReputationProvider as _,
};
use polaris_types::ActionKind;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner as _;

/// Returns true when the Docker daemon is reachable.
///
/// Same shape as the helper in `tests/threats_common/mod.rs` — the
/// reputation test sits outside that module's `mod` discovery scope
/// (the suite is keyed on `tests/threat_*.rs` filenames) so it
/// duplicates the helper rather than reaching into the common module.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a freshly-migrated Postgres-16 container + pool.
async fn boot_pool() -> Result<(PgPool, ContainerAsync<Postgres>), Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    Ok((database.pool().clone(), container))
}

#[tokio::test]
async fn record_report_filed_inserts_stats_row() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP record_report_filed_inserts_stats_row: docker daemon not reachable.");
        return Ok(());
    }
    let (pool, _container) = boot_pool().await?;
    let provider = PgReputationProvider::new(pool.clone(), ReputationParams::default())?;

    provider.record_report_filed("did:plc:rep-fresh").await?;

    let row = sqlx::query!(
        "SELECT reports_filed, reports_actioned, reports_dismissed, cached_score
         FROM reporter_stats
         WHERE did = $1",
        "did:plc:rep-fresh",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.reports_filed, 1, "first report_filed should land at 1");
    assert_eq!(row.reports_actioned, 0);
    assert_eq!(row.reports_dismissed, 0);
    // A reporter with `reports_filed = 1, actioned = 0, dismissed = 0`
    // under the default (1.0, 1.0) prior should still score ≈ 0.5 (no
    // signal yet — only the filed-count is set).
    assert!(
        (row.cached_score - 0.5).abs() < 0.01,
        "fresh reporter should score near the prior, got {}",
        row.cached_score
    );

    // A second filed report from the same DID should bump the count to
    // 2 (NOT create a second row).
    provider.record_report_filed("did:plc:rep-fresh").await?;
    let row = sqlx::query!(
        "SELECT reports_filed FROM reporter_stats WHERE did = $1",
        "did:plc:rep-fresh",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.reports_filed, 2);

    Ok(())
}

#[tokio::test]
async fn record_action_label_increments_actioned() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP record_action_label_increments_actioned: docker daemon not reachable.");
        return Ok(());
    }
    let (pool, _container) = boot_pool().await?;
    let provider = PgReputationProvider::new(pool.clone(), ReputationParams::default())?;

    // Seed the reporter with two filed reports first so the cached score
    // has a non-trivial baseline; otherwise the test is degenerate.
    provider.record_report_filed("did:plc:rep-good").await?;
    provider.record_report_filed("did:plc:rep-good").await?;

    // Label = "actioned"
    provider
        .record_action("did:plc:rep-good", ActionKind::Label)
        .await?;
    let row = sqlx::query!(
        "SELECT reports_actioned, reports_dismissed, cached_score
         FROM reporter_stats
         WHERE did = $1",
        "did:plc:rep-good",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.reports_actioned, 1);
    assert_eq!(row.reports_dismissed, 0);
    // (1 actioned + 1 prior) / (1 actioned + 0 dismissed + 1 + 1 prior) = 2/3 ≈ 0.667
    assert!(
        (row.cached_score - (2.0 / 3.0)).abs() < 0.01,
        "1 actioned + (1,1) prior should score ≈ 0.667, got {}",
        row.cached_score
    );

    // Takedown also bumps actioned.
    provider
        .record_action("did:plc:rep-good", ActionKind::Takedown)
        .await?;
    let row = sqlx::query!(
        "SELECT reports_actioned FROM reporter_stats WHERE did = $1",
        "did:plc:rep-good",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.reports_actioned, 2);

    Ok(())
}

#[tokio::test]
async fn record_action_no_action_increments_dismissed() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP record_action_no_action_increments_dismissed: docker daemon not reachable.");
        return Ok(());
    }
    let (pool, _container) = boot_pool().await?;
    let provider = PgReputationProvider::new(pool.clone(), ReputationParams::default())?;

    // NoAction = "dismissed"
    provider
        .record_action("did:plc:rep-bad", ActionKind::NoAction)
        .await?;
    let row = sqlx::query!(
        "SELECT reports_actioned, reports_dismissed, cached_score
         FROM reporter_stats
         WHERE did = $1",
        "did:plc:rep-bad",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.reports_actioned, 0);
    assert_eq!(row.reports_dismissed, 1);
    // (0 actioned + 1 prior) / (0 + 1 dismissed + 1 + 1 prior) = 1/3 ≈ 0.333
    assert!(
        (row.cached_score - (1.0 / 3.0)).abs() < 0.01,
        "1 dismissed + (1,1) prior should score ≈ 0.333, got {}",
        row.cached_score
    );

    Ok(())
}

#[tokio::test]
async fn record_action_neutral_kinds_are_noops() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP record_action_neutral_kinds_are_noops: docker daemon not reachable.");
        return Ok(());
    }
    let (pool, _container) = boot_pool().await?;
    let provider = PgReputationProvider::new(pool.clone(), ReputationParams::default())?;

    // Mute / Warn / Escalate / Reverse don't bump either counter.
    for kind in [
        ActionKind::Mute,
        ActionKind::Warn,
        ActionKind::Escalate,
        ActionKind::Reverse,
    ] {
        provider.record_action("did:plc:rep-neutral", kind).await?;
    }
    let row = sqlx::query!(
        "SELECT reports_actioned, reports_dismissed
         FROM reporter_stats
         WHERE did = $1",
        "did:plc:rep-neutral",
    )
    .fetch_optional(&pool)
    .await?;
    assert!(
        row.is_none(),
        "neutral action kinds should never create a stats row"
    );

    Ok(())
}

#[tokio::test]
async fn score_for_after_multiple_records_returns_smoothed_score()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP score_for_after_multiple_records_returns_smoothed_score: \
             docker daemon not reachable."
        );
        return Ok(());
    }
    let (pool, _container) = boot_pool().await?;
    let provider = PgReputationProvider::new(pool.clone(), ReputationParams::default())?;

    // Build an "established good" reporter: 99 actioned, 1 dismissed.
    for _ in 0..99 {
        provider
            .record_action("did:plc:rep-established", ActionKind::Label)
            .await?;
    }
    provider
        .record_action("did:plc:rep-established", ActionKind::NoAction)
        .await?;

    let score = provider.score_for("did:plc:rep-established").await?;
    // Expected raw_ratio = (99 + 1) / (99 + 1 + 1 + 1) = 100 / 102 ≈ 0.9804
    // last_active is `now()` so no decay; the score should be very close.
    assert!(
        (score.into_inner() - 0.9804).abs() < 0.01,
        "99 actioned / 1 dismissed should score ≈ 0.98, got {}",
        score.into_inner(),
    );

    // Unknown reporter falls back to neutral (no UnknownReporter error).
    let score = provider.score_for("did:plc:never-seen").await?;
    assert!((score.into_inner() - 0.5).abs() < 1e-6);

    Ok(())
}

#[tokio::test]
async fn report_repo_with_reputation_bumps_stats_in_same_tx()
-> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use polaris_backend::repo::{
        IncidentRepo as _, NewIncident, NewReport, NewSubject, PgIncidentRepo, PgReportRepo,
        PgSubjectRepo, ReportRepo as _, SubjectRepo as _,
    };
    use polaris_types::{Did, ReportCategory, Severity};

    if !docker_available() {
        println!(
            "SKIP report_repo_with_reputation_bumps_stats_in_same_tx: \
             docker daemon not reachable."
        );
        return Ok(());
    }

    let (pool, _container) = boot_pool().await?;
    let provider = Arc::new(PgReputationProvider::new(
        pool.clone(),
        ReputationParams::default(),
    )?);

    // Seed a subject + incident so the report-insert FK is satisfied.
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let subject = subject_repo
        .insert(NewSubject {
            kind: polaris_types::SubjectKind::Account,
            did: Some(Did::new("did:plc:subject")),
            uri: None,
            created_at: chrono::Utc::now(),
        })
        .await?;

    let incident_repo = PgIncidentRepo::new(pool.clone());
    let incident = incident_repo
        .insert(NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: polaris_types::IncidentStatus::Open,
            assigned_to: None,
        })
        .await?;

    let reports = PgReportRepo::new(pool.clone()).with_reputation(Arc::clone(&provider));
    reports
        .insert(NewReport {
            subject_id: subject.id,
            incident_id: Some(incident.id),
            reporter_did: Did::new("did:plc:reporter-via-repo"),
            category: ReportCategory::new("spam"),
            body: "wired through the repo".to_owned(),
        })
        .await?;

    let row = sqlx::query!(
        "SELECT reports_filed FROM reporter_stats WHERE did = $1",
        "did:plc:reporter-via-repo",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        row.reports_filed, 1,
        "report-insert side-effect should have bumped reports_filed",
    );

    Ok(())
}
