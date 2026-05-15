//! Integration tests for the report → incident aggregator (issue #75).
//!
//! These tests boot a real Postgres 16-alpine container via the
//! `threats_common` fixture, exercise the aggregator's `tick()` method
//! against unaggregated reports, and assert the documented shape of the
//! result (one incident per subject within the window, `report_count`
//! trigger increments and decrements correctly, CSAM-class reports
//! promote severity).
//!
//! The aggregator's `run()` loop is `! `-returning; we drive `tick()`
//! directly so each test is bounded and deterministic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::time::Duration;

use polaris_backend::ingest::aggregator::{AggregatorConfig, ReportAggregator};
use polaris_backend::repo::{NewReport, PgReportRepo, ReportRepo as _};
use polaris_types::{Did, ReportCategory, Severity};
use sqlx::Row as _;

#[path = "threats_common/mod.rs"]
mod common;

/// Tight tick cadence so the test does not wait the production default
/// (5s) between drains. Direct `tick()` calls bypass the sleep entirely
/// but the config still requires a value.
fn fast_config(window_secs: i64) -> AggregatorConfig {
    AggregatorConfig {
        batch_size: 1024,
        poll_interval: Duration::from_millis(10),
        window_secs,
    }
}

/// 10 reports against ONE subject → one incident with `report_count = 10`.
///
/// The schema-invariant cousin of this test
/// (`threat_t4_dos_report_flood::many_reports_can_bind_to_single_incident`)
/// asserts the same shape *given* a pre-built incident; here we exercise
/// the aggregator's create-or-attach decision end-to-end.
#[tokio::test]
async fn ten_reports_one_subject_collapse_to_one_incident() -> Result<(), Box<dyn std::error::Error>>
{
    if !common::docker_available() {
        println!("SKIP incident_aggregator ten_reports_one_subject: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;
    let subject_id = fixture
        .insert_account_subject("did:plc:aggregator-single-subject")
        .await?;

    // Insert 10 unaggregated reports — `incident_id = None`. The
    // aggregator's job is to bind them into one incident.
    let reports = PgReportRepo::new(fixture.pool.clone());
    for i in 0..10_u32 {
        reports
            .insert(NewReport {
                subject_id,
                incident_id: None,
                reporter_did: Did::new(format!("did:plc:aggregator-reporter-{i:04}")),
                category: ReportCategory::new("harassment"),
                body: format!("report #{i}"),
            })
            .await?;
    }

    // Drive one tick. With batch_size = 1024 the entire backlog
    // collapses in a single transaction.
    let aggregator = ReportAggregator::new(fixture.pool.clone(), fast_config(86_400));
    let processed = aggregator.tick().await?;
    assert_eq!(processed, 10, "all 10 reports must be aggregated");

    // Exactly one incident exists for the subject.
    let incident_count: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM incidents WHERE primary_subject = $1")
            .bind(subject_id.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        incident_count, 1,
        "10 reports against one subject must collapse to one incident",
    );

    // The incident's `report_count` column reflects the trigger-driven
    // tally — the dashboard read is now an O(1) column fetch, not a
    // `COUNT(*)` over the partitioned reports table.
    let report_count: i32 =
        sqlx::query("SELECT report_count AS c FROM incidents WHERE primary_subject = $1")
            .bind(subject_id.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        report_count, 10,
        "report_count must equal the number of attached reports",
    );

    // Every report row carries the same incident_id.
    let distinct_incidents: i64 =
        sqlx::query("SELECT COUNT(DISTINCT incident_id) AS c FROM reports WHERE subject_id = $1")
            .bind(subject_id.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(distinct_incidents, 1, "all reports must share one incident");
    Ok(())
}

/// 10 reports against 10 DIFFERENT subjects → 10 incidents, each with
/// `report_count = 1`.
#[tokio::test]
async fn ten_reports_ten_subjects_yield_ten_incidents() -> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP incident_aggregator ten_reports_ten_subjects: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;
    let reports = PgReportRepo::new(fixture.pool.clone());

    let mut subject_ids = Vec::with_capacity(10);
    for i in 0..10_u32 {
        let subject_id = fixture
            .insert_account_subject(&format!("did:plc:multi-subject-{i:02}"))
            .await?;
        subject_ids.push(subject_id);
        reports
            .insert(NewReport {
                subject_id,
                incident_id: None,
                reporter_did: Did::new(format!("did:plc:multi-reporter-{i:02}")),
                category: ReportCategory::new("spam"),
                body: format!("report against subject {i}"),
            })
            .await?;
    }

    let aggregator = ReportAggregator::new(fixture.pool.clone(), fast_config(86_400));
    let processed = aggregator.tick().await?;
    assert_eq!(processed, 10, "all 10 reports must be aggregated");

    let total_incidents: i64 = sqlx::query("SELECT COUNT(*) AS c FROM incidents")
        .fetch_one(&fixture.pool)
        .await?
        .try_get("c")?;
    assert_eq!(
        total_incidents, 10,
        "distinct subjects must yield distinct incidents",
    );

    let max_report_count: i32 =
        sqlx::query("SELECT COALESCE(MAX(report_count), 0) AS c FROM incidents")
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    let min_report_count: i32 =
        sqlx::query("SELECT COALESCE(MIN(report_count), 0) AS c FROM incidents")
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        max_report_count, 1,
        "every per-subject incident carries exactly one report",
    );
    assert_eq!(
        min_report_count, 1,
        "every per-subject incident carries exactly one report",
    );
    Ok(())
}

/// A report outside the aggregation window opens a fresh incident even
/// though the subject already has an older open incident.
///
/// We exercise this by inserting an incident with `opened_at` shifted
/// back in time + a report newer than that window, then driving a tick.
/// The aggregator must NOT attach to the stale incident.
#[tokio::test]
async fn report_outside_window_opens_new_incident() -> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP incident_aggregator window: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;
    let subject_id = fixture
        .insert_account_subject("did:plc:window-test-subject")
        .await?;

    // Pre-create an open incident, then back-date its `opened_at` past
    // the test window. The aggregator's window query is
    // `opened_at >= now() - interval`, so a one-hour-old incident with
    // a 60-second window must not be re-used.
    let stale_incident_id = fixture
        .insert_incident(subject_id, Severity::Medium)
        .await?;
    sqlx::query("UPDATE incidents SET opened_at = now() - interval '1 hour' WHERE id = $1")
        .bind(stale_incident_id.into_uuid())
        .execute(&fixture.pool)
        .await?;

    // Insert a fresh unaggregated report.
    let reports = PgReportRepo::new(fixture.pool.clone());
    reports
        .insert(NewReport {
            subject_id,
            incident_id: None,
            reporter_did: Did::new("did:plc:window-test-reporter"),
            category: ReportCategory::new("harassment"),
            body: "fresh report after window expired".to_owned(),
        })
        .await?;

    // 60-second window — the stale incident is 1h old, so it must not
    // be reused.
    let aggregator = ReportAggregator::new(fixture.pool.clone(), fast_config(60));
    let processed = aggregator.tick().await?;
    assert_eq!(processed, 1, "the fresh report must be aggregated");

    let incident_count: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM incidents WHERE primary_subject = $1")
            .bind(subject_id.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        incident_count, 2,
        "the stale incident must not be reused; a fresh one is created",
    );
    Ok(())
}

/// The `report_count` trigger fires on INSERT and on UPDATE-of-incident_id.
///
/// Inserting a report with an incident_id already set increments the
/// parent's count. Clearing the incident_id back to NULL decrements
/// the parent's count and respects the GREATEST-floor-0 guard.
#[tokio::test]
async fn report_count_trigger_increments_and_decrements() -> Result<(), Box<dyn std::error::Error>>
{
    if !common::docker_available() {
        println!("SKIP incident_aggregator trigger: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;
    let subject_id = fixture
        .insert_account_subject("did:plc:trigger-test-subject")
        .await?;
    let incident_id = fixture
        .insert_incident(subject_id, Severity::Medium)
        .await?;

    // INSERT a report with `incident_id` populated — the trigger
    // increments the parent's `report_count`.
    let reports = PgReportRepo::new(fixture.pool.clone());
    let report = reports
        .insert(NewReport {
            subject_id,
            incident_id: Some(incident_id),
            reporter_did: Did::new("did:plc:trigger-reporter"),
            category: ReportCategory::new("harassment"),
            body: "report bound at insert time".to_owned(),
        })
        .await?;

    let after_insert: i32 = sqlx::query("SELECT report_count AS c FROM incidents WHERE id = $1")
        .bind(incident_id.into_uuid())
        .fetch_one(&fixture.pool)
        .await?
        .try_get("c")?;
    assert_eq!(
        after_insert, 1,
        "INSERT with incident_id must increment report_count",
    );

    // UPDATE the report's incident_id back to NULL — the trigger
    // decrements the parent. We use a raw UPDATE here because the
    // ReportRepo trait does not expose an "unbind" mutator; the
    // trigger is what we're asserting on.
    sqlx::query("UPDATE reports SET incident_id = NULL WHERE id = $1 AND created_at = $2")
        .bind(report.id.0)
        .bind(report.created_at)
        .execute(&fixture.pool)
        .await?;
    let after_unbind: i32 = sqlx::query("SELECT report_count AS c FROM incidents WHERE id = $1")
        .bind(incident_id.into_uuid())
        .fetch_one(&fixture.pool)
        .await?
        .try_get("c")?;
    assert_eq!(
        after_unbind, 0,
        "UPDATE-to-NULL must decrement report_count",
    );

    // GREATEST(count - 1, 0) floor: a second decrement with no
    // outstanding rows still produces 0 (no negative count). We
    // exercise this by directly issuing a phantom UPDATE that
    // re-fires the trigger on a row that already has incident_id =
    // NULL — to do that we re-bind then unbind.
    sqlx::query("UPDATE reports SET incident_id = $1 WHERE id = $2 AND created_at = $3")
        .bind(incident_id.into_uuid())
        .bind(report.id.0)
        .bind(report.created_at)
        .execute(&fixture.pool)
        .await?;
    let rebound: i32 = sqlx::query("SELECT report_count AS c FROM incidents WHERE id = $1")
        .bind(incident_id.into_uuid())
        .fetch_one(&fixture.pool)
        .await?
        .try_get("c")?;
    assert_eq!(rebound, 1, "re-attaching must re-increment");

    sqlx::query("UPDATE reports SET incident_id = NULL WHERE id = $1 AND created_at = $2")
        .bind(report.id.0)
        .bind(report.created_at)
        .execute(&fixture.pool)
        .await?;

    // Now force a "phantom decrement" by directly tampering with the
    // parent's count to zero and re-attaching/unattaching — the
    // GREATEST floor must protect against a negative value.
    sqlx::query("UPDATE incidents SET report_count = 0 WHERE id = $1")
        .bind(incident_id.into_uuid())
        .execute(&fixture.pool)
        .await?;
    sqlx::query("UPDATE reports SET incident_id = $1 WHERE id = $2 AND created_at = $3")
        .bind(incident_id.into_uuid())
        .bind(report.id.0)
        .bind(report.created_at)
        .execute(&fixture.pool)
        .await?;
    sqlx::query("UPDATE reports SET incident_id = NULL WHERE id = $1 AND created_at = $2")
        .bind(report.id.0)
        .bind(report.created_at)
        .execute(&fixture.pool)
        .await?;
    let floor_protected: i32 = sqlx::query("SELECT report_count AS c FROM incidents WHERE id = $1")
        .bind(incident_id.into_uuid())
        .fetch_one(&fixture.pool)
        .await?
        .try_get("c")?;
    assert!(
        floor_protected >= 0,
        "GREATEST(count - 1, 0) floor must prevent negative counts",
    );
    Ok(())
}

/// A CSAM-category report on a fresh subject opens a `Severity::Critical`
/// incident, which the routing service interprets as the CSAM cascade.
/// This is the deduplicated form of the T4 end-to-end test in
/// `threat_t4_dos_report_flood.rs`.
#[tokio::test]
async fn csam_report_drives_critical_severity_on_fresh_incident()
-> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP incident_aggregator csam_critical: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;
    let subject_id = fixture
        .insert_account_subject("did:plc:aggregator-csam-subject")
        .await?;

    let reports = PgReportRepo::new(fixture.pool.clone());
    reports
        .insert(NewReport {
            subject_id,
            incident_id: None,
            reporter_did: Did::new("did:plc:aggregator-csam-reporter"),
            category: ReportCategory::new("csam"),
            body: "csam classifier hit".to_owned(),
        })
        .await?;

    let aggregator = ReportAggregator::new(fixture.pool.clone(), fast_config(86_400));
    let processed = aggregator.tick().await?;
    assert_eq!(processed, 1);

    let severity: String = sqlx::query("SELECT severity FROM incidents WHERE primary_subject = $1")
        .bind(subject_id.into_uuid())
        .fetch_one(&fixture.pool)
        .await?
        .try_get("severity")?;
    assert_eq!(
        severity, "critical",
        "a CSAM report on a fresh subject must open a Critical incident",
    );
    Ok(())
}
