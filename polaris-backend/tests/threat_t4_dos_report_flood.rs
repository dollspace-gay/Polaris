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

/// T4 IGNORED-WITH-FOLLOWUP: the high-priority routing bypass for
/// CSAM-classifier hits under report-flood load (the "never drop
/// CSAM-classifier hits" half of design.md §9 #4) is owned by the
/// aggregator pipeline that does not exist yet.
///
/// See follow-up issue #75 ("Wire incident-aggregation pipeline +
/// report_count column (T4 mitigation)").
///
/// The smaller observable invariant — that the CSAM category is
/// recorded on the row, so the future aggregator has it to match on —
/// is asserted by `csam_category_is_recorded_verbatim_on_report_row`
/// above. This test is the placeholder for the END-TO-END assertion
/// (1M reports → 1 incident with the CSAM signal routed to the
/// CSAM-trained queue ahead of the spam-flood backlog) that lands
/// with #75.
//
// Follow-up #75 owns un-ignoring this test once the aggregator +
// report_count column are wired. The mitigation surface needed is
// in `polaris-backend/src/repo/` (incident aggregator job) and
// `polaris-backend/src/routing/service.rs` (CSAM-priority lookup).
#[tokio::test]
#[ignore = "T4 end-to-end CSAM-priority bypass needs aggregator pipeline — follow-up #75"]
async fn csam_priority_bypasses_general_queue_under_report_flood()
-> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t4_dos_report_flood csam priority: docker daemon not reachable.",);
        return Ok(());
    }
    // Placeholder: the routing pure-function tests in
    // `src/routing/mod.rs` already cover the CSAM-routes-to-trained-
    // moderator rule; the missing piece is the aggregator + queue
    // ordering under load. Spec out the assertion shape so the
    // follow-up issue has a clear acceptance criterion:
    //
    //   given 1M `category = 'spam'` reports + 1 `category = 'csam'` report
    //   on the same subject within a 60-second window,
    //   the CSAM-trained moderator's queue must surface the CSAM
    //   incident with priority strictly higher than every spam-flood
    //   incident — even if the spam-flood incident was inserted first.
    Ok(())
}
