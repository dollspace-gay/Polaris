//! Threat-model T4 — denial-of-service via report flooding
//! (`design.md` §9 #4; issue #39).
//!
//! # Mitigation under test
//!
//! Per design.md §9 #4: "rate limits at ingest, dedup at ingest (a
//! thousand identical reports become one incident with a thousand
//! reporters), graceful degradation under load (drop low-signal
//! reports first, never drop CSAM-classifier hits)."
//!
//! # Scope as of issue #39
//!
//! The dedup pipeline that maps N reports → 1 incident is not yet
//! wired (no aggregator exists in `polaris-backend/src/`; reports
//! are inserted with `incident_id = None` and the README in
//! `polaris-backend/src/repo/report.rs` notes "a follow-up
//! aggregation pipeline (issue TBD) binds them to subjects' open
//! incidents"). The CSAM-priority bypass under load is part of the
//! same pipeline.
//!
//! What we CAN test as a MUST-pass invariant today:
//!
//! 1. **Many-reports-to-one-incident shape.** The schema permits N
//!    reports to share the same `incident_id`. Insert 100 reports
//!    against one subject + bind them all to one incident; assert
//!    exactly one incident exists for that subject and exactly 100
//!    reports point at it. This pins the *schema invariant* the
//!    aggregator depends on.
//! 2. **Reporter-DID is captured on every report.** The downstream
//!    aggregator counts unique reporter DIDs to decide whether the
//!    incident is a brigade signal or a legitimate flood. Pin the
//!    invariant that every row records its `reporter_did`.
//! 3. **CSAM-class category passes through the routing rule
//!    cascade.** The pure router in `polaris-backend/src/routing/mod.rs`
//!    already enforces the §5.4 rule that CSAM forwards externally
//!    when no trained moderator is on staff, and routes to the
//!    trained moderator otherwise. That logic is tested in
//!    `src/routing/mod.rs::tests`; here we pin the wire-level
//!    invariant that a `category = 'csam'` report carries that
//!    category through to the `reports` row.
//!
//! The full "1M reports → 1 incident + CSAM-priority bypass under
//! load" assertion is left to follow-up #75 (see issue body).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use polaris_backend::repo::{NewReport, PgReportRepo, ReportRepo as _};
use polaris_types::{Did, ReportCategory, Severity};
use sqlx::Row as _;

#[path = "threats_common/mod.rs"]
mod common;

/// T4 MUST-PASS: 100 reports from 100 distinct reporters can all
/// bind to one incident — the schema supports the dedup invariant.
#[tokio::test]
async fn many_reports_can_bind_to_single_incident() -> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t4_dos_report_flood: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let subject_id = fixture.insert_account_subject("did:plc:t4subject1").await?;
    let incident_id = fixture
        .insert_incident(subject_id, Severity::Medium)
        .await?;

    let reports = PgReportRepo::new(fixture.pool.clone());
    let report_count: u32 = 100;
    for i in 0..report_count {
        let reporter_did = format!("did:plc:t4reporter{i:04}");
        reports
            .insert(NewReport {
                subject_id,
                incident_id: Some(incident_id),
                reporter_did: Did::new(reporter_did),
                category: ReportCategory::new("harassment"),
                body: format!("report #{i}"),
            })
            .await?;
    }

    // Invariant: exactly one incident exists for the subject (we never
    // created a second one — the dedup-into-one-incident shape).
    let incident_count: i64 =
        sqlx::query("SELECT COUNT(*) AS c FROM incidents WHERE primary_subject = $1")
            .bind(subject_id.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        incident_count, 1,
        "exactly one incident must exist for the flooded subject",
    );

    // Invariant: all 100 reports point at the same incident.
    let bound_count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM reports WHERE incident_id = $1")
        .bind(incident_id.into_uuid())
        .fetch_one(&fixture.pool)
        .await?
        .try_get("c")?;
    assert_eq!(
        bound_count,
        i64::from(report_count),
        "all flood reports must bind to the single incident",
    );

    // Invariant: 100 distinct reporter DIDs were captured (the
    // anti-brigade signal the aggregator relies on).
    let distinct_dids: i64 =
        sqlx::query("SELECT COUNT(DISTINCT reporter_did) AS c FROM reports WHERE incident_id = $1")
            .bind(incident_id.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        distinct_dids,
        i64::from(report_count),
        "every reporter DID must be captured distinctly so the aggregator can weight them",
    );

    Ok(())
}

/// T4 MUST-PASS: a `category = 'csam'` report's row carries that
/// category verbatim, so the downstream router can apply the §5.4
/// CSAM-priority bypass.
///
/// The full bypass under load (the "never drop CSAM-classifier hits"
/// part of §9 #4) is a follow-up — see issue #75. Here we pin the
/// wire-level invariant that the CSAM-signal IS captured on insert,
/// so the router has the information it needs.
#[tokio::test]
async fn csam_category_is_recorded_verbatim_on_report_row() -> Result<(), Box<dyn std::error::Error>>
{
    if !common::docker_available() {
        println!("SKIP threat_t4_dos_report_flood csam category: docker daemon not reachable.",);
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let subject_id = fixture.insert_account_subject("did:plc:t4csamsubj").await?;
    let incident_id = fixture
        .insert_incident(subject_id, Severity::Critical)
        .await?;
    let reports = PgReportRepo::new(fixture.pool.clone());

    // Insert 100 noisy non-CSAM reports against the same subject — these
    // are the "report flood" backdrop.
    for i in 0..100u32 {
        reports
            .insert(NewReport {
                subject_id,
                incident_id: Some(incident_id),
                reporter_did: Did::new(format!("did:plc:t4flood{i:04}")),
                category: ReportCategory::new("spam"),
                body: format!("flood #{i}"),
            })
            .await?;
    }
    // Insert one CSAM-category report that must be distinguishable.
    let csam_report = reports
        .insert(NewReport {
            subject_id,
            incident_id: Some(incident_id),
            reporter_did: Did::new("did:plc:t4csamreporter"),
            category: ReportCategory::new("csam"),
            body: "csam classifier hit".to_owned(),
        })
        .await?;

    // Invariant: the CSAM row's category is recorded verbatim — the
    // router can match on it.
    assert_eq!(
        csam_report.category.as_str(),
        "csam",
        "CSAM-category report must record its category verbatim",
    );
    let stored_category: String =
        sqlx::query("SELECT category FROM reports WHERE id = $1 AND category = 'csam'")
            .bind(csam_report.id.0)
            .fetch_one(&fixture.pool)
            .await?
            .try_get("category")?;
    assert_eq!(
        stored_category, "csam",
        "the CSAM report must be queryable by category=csam — not buried under \
         the spam backdrop",
    );

    // Invariant: the CSAM signal survives even under a 100:1 spam-to-
    // CSAM ratio. The downstream router gets to see the CSAM row in
    // its query result.
    let csam_count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM reports WHERE incident_id = $1 AND category = 'csam'",
    )
    .bind(incident_id.into_uuid())
    .fetch_one(&fixture.pool)
    .await?
    .try_get("c")?;
    assert_eq!(
        csam_count, 1,
        "exactly one CSAM report must survive on this incident under the flood",
    );

    Ok(())
}

/// T4 MUST-PASS: under a report flood, a CSAM-category report's incident
/// surfaces with `Severity::Critical` regardless of how many
/// non-CSAM reports came before it — i.e. the
/// [`polaris_backend::routing::service::RoutingService`] cascade
/// (Critical → CSAM cascade → trained-moderator queue) gets the CSAM
/// signal at the front of the queue.
///
/// Implemented by issue #75: the aggregator promotes an incident to
/// `Severity::Critical` when a CSAM-category report attaches to it,
/// and opens fresh CSAM incidents at `Critical` directly. This pins
/// "never drop CSAM-classifier hits" (design.md §9 #4) at the data
/// level — the routing engine reads `Severity::Critical` and runs
/// `RoutingCategory::Csam` through its rule cascade, which fires the
/// `csam_trained` filter before the load-cap step.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "end-to-end T4 assertion: backdrop setup + aggregator drain + \
              four severity / report_count assertions read more clearly inline \
              than broken across helpers."
)]
async fn csam_priority_bypasses_general_queue_under_report_flood()
-> Result<(), Box<dyn std::error::Error>> {
    use polaris_backend::ingest::aggregator::{AggregatorConfig, ReportAggregator};
    use std::time::Duration;

    if !common::docker_available() {
        println!("SKIP threat_t4_dos_report_flood csam priority: docker daemon not reachable.",);
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    // ── set up the spam-flood backdrop ────────────────────────────────
    //
    // 1000 spam-category reports against a non-CSAM subject. The
    // aggregator collapses these into a single `Severity::Medium`
    // incident — the routing service maps Medium → `RoutingCategory::Other`,
    // which does not enter the CSAM cascade.
    let spam_subject = fixture
        .insert_account_subject("did:plc:t4-flood-spam-subject")
        .await?;
    let reports = polaris_backend::repo::PgReportRepo::new(fixture.pool.clone());
    // Scale the backdrop to a manageable size for the test runner; the
    // logic is the same as for 1M reports — the aggregator's
    // `SELECT FOR UPDATE SKIP LOCKED` claim path is `O(batch_size)`
    // per tick regardless of total backlog depth.
    let flood_size: u32 = 200;
    for i in 0..flood_size {
        reports
            .insert(polaris_backend::repo::NewReport {
                subject_id: spam_subject,
                incident_id: None,
                reporter_did: Did::new(format!("did:plc:t4-flood-reporter-{i:04}")),
                category: ReportCategory::new("spam"),
                body: format!("spam flood #{i}"),
            })
            .await?;
    }

    // ── inject ONE CSAM report ──────────────────────────────────────
    //
    // The CSAM hit lands AFTER the spam flood (worst-case ordering:
    // the spam reports created their incident first, so the CSAM
    // report has to claw its way to the front of the queue).
    let csam_subject = fixture
        .insert_account_subject("did:plc:t4-flood-csam-subject")
        .await?;
    reports
        .insert(polaris_backend::repo::NewReport {
            subject_id: csam_subject,
            incident_id: None,
            reporter_did: Did::new("did:plc:t4-flood-csam-reporter"),
            category: ReportCategory::new("csam"),
            body: "csam classifier hit under flood".to_owned(),
        })
        .await?;

    // ── drain the aggregator ────────────────────────────────────────
    //
    // batch_size = flood_size + 1 so the entire backlog collapses in
    // a single tick. The 24h window means same-subject reports always
    // collapse to one incident (matching the production default).
    let aggregator = ReportAggregator::new(
        fixture.pool.clone(),
        AggregatorConfig {
            batch_size: i64::from(flood_size) + 4,
            poll_interval: Duration::from_millis(10),
            window_secs: 86_400,
        },
    );
    let processed = aggregator.tick().await?;
    assert_eq!(
        processed,
        i64::from(flood_size) + 1,
        "every report (flood + csam) must be aggregated",
    );

    // ── assert the CSAM incident outranks the spam-flood incident ────
    //
    // The aggregator must have:
    //   - opened ONE incident for the spam subject, with severity
    //     `Medium` (the non-CSAM default);
    //   - opened ONE incident for the CSAM subject, with severity
    //     `Critical` (the CSAM-class promotion).
    //
    // The routing service maps `Severity::Critical` → CSAM cascade →
    // trained-moderator queue, so the CSAM incident strictly outranks
    // the spam flood in the routing decision.
    let csam_severity: String =
        sqlx::query("SELECT severity FROM incidents WHERE primary_subject = $1")
            .bind(csam_subject.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("severity")?;
    assert_eq!(
        csam_severity, "critical",
        "the CSAM incident must surface at Severity::Critical — the routing \
         cascade reads Critical to enter the CSAM-trained queue regardless of \
         spam-flood depth",
    );

    let spam_severity: String =
        sqlx::query("SELECT severity FROM incidents WHERE primary_subject = $1")
            .bind(spam_subject.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("severity")?;
    assert_ne!(
        spam_severity, "critical",
        "the spam-flood incident must NOT be promoted to Critical — only the \
         CSAM signal opens the trained-queue cascade",
    );

    // Severity ordering: Critical strictly outranks Medium / Low /
    // High in `polaris_types::Severity`. We compare via the enum's
    // ordering rather than string comparison so a future severity
    // re-ordering keeps the assertion honest.
    let csam_severity_enum =
        polaris_types::Severity::from_wire(&csam_severity).expect("CSAM severity must decode");
    let spam_severity_enum =
        polaris_types::Severity::from_wire(&spam_severity).expect("spam severity must decode");
    assert!(
        matches!(csam_severity_enum, polaris_types::Severity::Critical),
        "CSAM incident must be Critical (got {csam_severity_enum:?})",
    );
    assert!(
        !matches!(spam_severity_enum, polaris_types::Severity::Critical),
        "spam incident must not be Critical (got {spam_severity_enum:?})",
    );

    // The CSAM incident's `report_count` is exactly 1 — the trigger
    // wired by migration 23 keeps the column in sync.
    let csam_report_count: i32 =
        sqlx::query("SELECT report_count AS c FROM incidents WHERE primary_subject = $1")
            .bind(csam_subject.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        csam_report_count, 1,
        "report_count must reflect the single CSAM report",
    );

    // The spam-flood incident's `report_count` equals the flood size —
    // dashboards reading this column do NOT pay a `COUNT(*)` over the
    // partitioned reports table.
    let spam_report_count: i32 =
        sqlx::query("SELECT report_count AS c FROM incidents WHERE primary_subject = $1")
            .bind(spam_subject.into_uuid())
            .fetch_one(&fixture.pool)
            .await?
            .try_get("c")?;
    assert_eq!(
        spam_report_count,
        i32::try_from(flood_size).expect("flood_size fits in i32"),
        "report_count must reflect the full spam-flood backlog \
         without forcing a COUNT(*)",
    );
    Ok(())
}
