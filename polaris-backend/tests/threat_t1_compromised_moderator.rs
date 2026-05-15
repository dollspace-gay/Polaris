//! Threat-model T1 — compromised moderator account abusing tool access
//! (`design.md` §9 #1; issue #39 + follow-up #73).
//!
//! # Mitigation under test
//!
//! Per design.md §9 #1: "SSO + hardware key required (first-party),
//! action rate limits, anomaly detection on moderator action patterns
//! (a moderator suddenly labeling 1000 accounts at 3am is itself an
//! incident), senior co-sign for high-impact pattern actions."
//!
//! # What this file tests
//!
//! - **Schema MUST-pass.** Every action row records the acting
//!   moderator's id and the action's `created_at`. The anomaly
//!   detector queries exactly these two columns.
//! - **Detector fires on burst.** Issue #73 added the
//!   moderator-behavior-anomaly detector. With a threshold of 5 and
//!   a 3600-second window, a burst of 6+ actions by one moderator
//!   emits a `polaris_types::ObservationKind::ModeratorBehaviorAnomaly`
//!   observation inside the action-insert transaction.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use chrono::{DateTime, Utc};
use polaris_backend::pattern::moderator_anomaly::ModeratorAnomalyConfig;
use polaris_backend::repo::{ActionRepo as _, NewAction, PgActionRepo};
use polaris_types::{ActionKind, LabelValue, ModeratorId, ObservationKind, PolicyId, Severity};
use sqlx::Row as _;

#[path = "threats_common/mod.rs"]
mod common;

/// T1 MUST-PASS: every action row records the acting moderator's id
/// plus the action's `created_at`. The future anomaly detector
/// (follow-up #73) computes over exactly these two columns; without
/// them the mitigation is impossible to wire.
#[tokio::test]
async fn action_rows_record_moderator_id_and_timestamp() -> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t1_compromised_moderator: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    // One moderator submits a burst of N actions on N subjects. The
    // detector's job is to spot exactly this shape.
    let burst_size: usize = 12;
    let moderator: ModeratorId = fixture.insert_moderator().await?;
    let actions = PgActionRepo::new(fixture.pool.clone());

    let started_at = Utc::now();
    let mut action_ids = Vec::with_capacity(burst_size);
    for i in 0..burst_size {
        let subject_id = fixture
            .insert_account_subject(&format!("did:plc:t1burstsubj{i:03}"))
            .await?;
        let incident_id = fixture
            .insert_incident(subject_id, Severity::Medium)
            .await?;
        let action = actions
            .insert(NewAction {
                incident_id,
                subject_id,
                moderator_id: moderator,
                kind: ActionKind::Label,
                label: Some(LabelValue::new("spam")),
                reasoning: format!("burst action #{i} — long enough reasoning for the DB CHECK"),
                policy_refs: vec![PolicyId::new("polaris.spam")],
                reversible_until: Utc::now() + chrono::Duration::hours(24),
                reverses_action_id: None,
            })
            .await?;
        action_ids.push(action.id);
    }
    let ended_at = Utc::now();

    // Invariant: exactly `burst_size` action rows exist for the
    // moderator, all within the burst window. The detector counts
    // exactly this.
    let rows = sqlx::query(
        "SELECT id, moderator_id, created_at
         FROM actions
         WHERE moderator_id = $1
         ORDER BY created_at ASC",
    )
    .bind(moderator.into_uuid())
    .fetch_all(&fixture.pool)
    .await?;

    assert_eq!(
        rows.len(),
        burst_size,
        "every action submitted in the burst must produce a row keyed on the moderator",
    );

    for row in &rows {
        let recorded_mod: uuid::Uuid = row.try_get("moderator_id")?;
        let recorded_ts: DateTime<Utc> = row.try_get("created_at")?;
        assert_eq!(
            recorded_mod,
            moderator.into_uuid(),
            "actions.moderator_id must equal the submitting moderator's id",
        );
        assert!(
            recorded_ts >= started_at && recorded_ts <= ended_at,
            "actions.created_at must fall within the burst window \
             [{started_at:?}, {ended_at:?}], got {recorded_ts:?}",
        );
    }

    Ok(())
}

/// T1 MUST-PASS (issue #73): the moderator-behavior-anomaly detector
/// emits a `ModeratorBehaviorAnomaly` observation when one moderator
/// submits more actions than `threshold` inside the configured
/// rolling window.
///
/// The test wires `PgActionRepo` with a low threshold (`5`) so the
/// burst fires the detector after the sixth action — the assertion
/// shape is "the observation table grew by exactly one
/// `ObservationKind::ModeratorBehaviorAnomaly` row, carrying the
/// moderator id, action count, and window seconds from the
/// configuration." The emission lives inside the action-insert
/// transaction, so the observation must be queryable through the
/// same pool the test has already committed against.
#[tokio::test]
async fn moderator_behavior_anomaly_fires_on_action_burst() -> Result<(), Box<dyn std::error::Error>>
{
    if !common::docker_available() {
        println!("SKIP threat_t1_compromised_moderator: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let moderator: ModeratorId = fixture.insert_moderator().await?;
    // Threshold = 5, window = 3600s. With a 12-action burst the
    // detector must fire on the 6th insert (the first action whose
    // `count(*)` post-insert strictly exceeds the threshold).
    let cfg = ModeratorAnomalyConfig::new(5, 3_600)?;
    let actions = PgActionRepo::new(fixture.pool.clone()).with_moderator_anomaly(cfg);

    let burst_size: usize = 12;
    for i in 0..burst_size {
        let subject_id = fixture
            .insert_account_subject(&format!("did:plc:t1detect{i:03}"))
            .await?;
        let incident_id = fixture
            .insert_incident(subject_id, Severity::Medium)
            .await?;
        actions
            .insert(NewAction {
                incident_id,
                subject_id,
                moderator_id: moderator,
                kind: ActionKind::Label,
                label: Some(LabelValue::new("spam")),
                reasoning: format!("burst action #{i} — long enough reasoning for the DB CHECK"),
                policy_refs: vec![PolicyId::new("polaris.spam")],
                reversible_until: Utc::now() + chrono::Duration::hours(24),
                reverses_action_id: None,
            })
            .await?;
    }

    // The synthetic subject for moderator anomalies is keyed on the
    // deterministic DID `did:polaris:moderator-anomaly:<uuid>`. Fetch
    // the observation rows attached to it and assert (a) at least one
    // emission fired, (b) every emission decodes back to the
    // `ModeratorBehaviorAnomaly` variant carrying the configured
    // window and the matching moderator id.
    let synthetic_did = format!("did:polaris:moderator-anomaly:{}", moderator.into_uuid());
    let rows = sqlx::query(
        "SELECT o.kind, o.evidence
         FROM observations o
         JOIN subjects s ON s.id = o.subject_id
         WHERE s.did = $1
         ORDER BY o.detected_at ASC",
    )
    .bind(&synthetic_did)
    .fetch_all(&fixture.pool)
    .await?;

    assert!(
        !rows.is_empty(),
        "expected at least one ModeratorBehaviorAnomaly observation after a 12-action \
         burst with threshold=5; got 0 rows on synthetic subject {synthetic_did}",
    );
    // First emission must be on the 6th action (5 below threshold, 6
    // strictly above). Once tripped, every subsequent action whose
    // `count(*)` still exceeds the threshold also emits — that
    // matches the architect's "emit-on-every-trip" wording in #73.
    // We assert: exactly `burst_size - threshold` emissions
    // (actions 6..=12).
    assert_eq!(
        rows.len(),
        burst_size - 5,
        "expected {} emissions (one per action whose count strictly exceeds threshold), got {}",
        burst_size - 5,
        rows.len(),
    );
    for row in &rows {
        let kind: String = row.try_get("kind")?;
        let evidence: serde_json::Value = row.try_get("evidence")?;
        assert_eq!(kind, "moderator_behavior_anomaly");
        let envelope = serde_json::json!({ "kind": kind, "data": evidence });
        let typed: ObservationKind = serde_json::from_value(envelope)?;
        match typed {
            ObservationKind::ModeratorBehaviorAnomaly {
                moderator_id,
                action_count,
                window_secs,
            } => {
                assert_eq!(moderator_id, moderator);
                assert_eq!(window_secs, 3_600);
                assert!(
                    action_count > 5,
                    "every emission's action_count must strictly exceed threshold 5, got {action_count}",
                );
            }
            other => panic!("expected ModeratorBehaviorAnomaly, got {other:?}"),
        }
    }

    Ok(())
}
