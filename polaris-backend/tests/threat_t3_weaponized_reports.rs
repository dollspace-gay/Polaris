//! Threat-model T3 — adversaries gaming the report system to
//! weaponize moderation against innocents
//! (`design.md` §9 #3; issue #39).
//!
//! # Mitigation under test
//!
//! Per design.md §9 #3: "reporter reputation scoring, false-report
//! tracking, weighting of reports by reporter history in pattern
//! engine."
//!
//! # Scope as of issue #39
//!
//! Reporter-reputation scoring does not exist yet. The
//! `polaris-backend/src/pattern/anomaly.rs` `ReportVolumeAnomaly`
//! detector weights every report equally — it has no signal for
//! "low-reputation reporter" to down-weight against. See follow-up
//! #74 ("Add reporter-reputation weighting (T3 mitigation)").
//!
//! What we CAN test as a MUST-pass invariant today:
//!
//! - **Every report row records the reporter DID.** Reputation
//!   scoring is a function of (reporter DID → historical
//!   false-report rate); the lookup is only possible if the DID is
//!   on every row.
//! - **Reporter DIDs are stored verbatim, not hashed/elided.**
//!   Weighting by reputation needs the actual DID — a one-way hash
//!   would prevent the join the future reputation table requires.
//!
//! The full "N synthetic reports from low-reputation DIDs do NOT
//! produce a high-confidence pattern observation" assertion is the
//! follow-up.

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

/// T3 MUST-PASS: every report row records the reporter DID
/// verbatim. Reporter-reputation weighting is impossible without
/// the per-row DID; pin the invariant.
#[tokio::test]
async fn every_report_records_reporter_did() -> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t3_weaponized_reports: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let subject_id = fixture.insert_account_subject("did:plc:t3innocent").await?;
    let incident_id = fixture
        .insert_incident(subject_id, Severity::Medium)
        .await?;
    let reports = PgReportRepo::new(fixture.pool.clone());

    // Simulate 20 reports from 20 distinct DIDs — the would-be
    // weaponization burst. The reputation system would weight these
    // down to negligible aggregate signal; we cannot assert that yet,
    // but we CAN assert the DIDs survive into the row.
    let mut expected_dids: Vec<String> = Vec::with_capacity(20);
    for i in 0..20u32 {
        let did_str = format!("did:plc:t3lowrep{i:03}");
        expected_dids.push(did_str.clone());
        reports
            .insert(NewReport {
                subject_id,
                incident_id: Some(incident_id),
                reporter_did: Did::new(&did_str),
                category: ReportCategory::new("harassment"),
                body: format!("weaponized report #{i}"),
            })
            .await?;
    }

    // Invariant: every reporter_did is present, verbatim, exactly once.
    let rows = sqlx::query(
        "SELECT reporter_did FROM reports WHERE subject_id = $1 ORDER BY reporter_did ASC",
    )
    .bind(subject_id.into_uuid())
    .fetch_all(&fixture.pool)
    .await?;
    let mut recorded_dids: Vec<String> = rows
        .iter()
        .map(|r| {
            r.try_get::<String, _>("reporter_did")
                .expect("reporter_did")
        })
        .collect();
    recorded_dids.sort();
    expected_dids.sort();
    assert_eq!(
        recorded_dids, expected_dids,
        "every reporter_did must round-trip verbatim — reputation weighting depends on it",
    );

    // Invariant: the DID column is plain text (not hashed). The
    // future reputation table is keyed on the literal DID, so a
    // schema change that swaps `reporter_did TEXT` for a hash would
    // break the join. Pin the DID format: starts with `did:`.
    for did in &recorded_dids {
        assert!(
            did.starts_with("did:"),
            "reporter_did must be stored as the raw DID, not a hash — got {did}",
        );
    }

    Ok(())
}

/// T3 IGNORED-WITH-FOLLOWUP: N low-reputation reports do not produce
/// a high-confidence ReportVolumeAnomaly observation.
///
/// The reputation surface does not exist yet — see follow-up #74.
/// The MUST-pass invariant the future weighting depends on
/// (per-row reporter DID) is asserted by
/// `every_report_records_reporter_did` above.
//
// Follow-up #74 owns un-ignoring this test once reporter-reputation
// scoring lands. The mitigation surface needed is a new
// `reporter_reputation` table + the `anomaly.rs` detector consulting
// it on each `observe()` call.
#[tokio::test]
#[ignore = "T3 reporter-reputation weighting does not exist yet — follow-up #74"]
async fn low_reputation_flood_does_not_trigger_high_confidence_anomaly()
-> Result<(), Box<dyn std::error::Error>> {
    // Spec out the acceptance criterion the follow-up must satisfy:
    //
    //   given 100 reports against an innocent subject from 100
    //   freshly-created reporter DIDs (zero historical credibility),
    //   the pattern engine must EITHER emit no
    //   `ObservationKind::ReportVolumeAnomaly` for that subject, OR
    //   emit one whose detector `confidence` is below the actionable
    //   threshold (today's default is the Welford z-score gate at
    //   z >= 3.0; the follow-up issue chooses the exact value).
    //
    // Equivalent contrapositive: with 100 reports from
    // *long-established, high-credibility* reporter DIDs, the same
    // detector MUST emit a high-confidence observation. This is the
    // load-bearing differentiation the weighting introduces.
    Ok(())
}
