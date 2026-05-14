//! Threat-model T1 — compromised moderator account abusing tool access
//! (`design.md` §9 #1; issue #39).
//!
//! # Mitigation under test
//!
//! Per design.md §9 #1: "SSO + hardware key required (first-party),
//! action rate limits, anomaly detection on moderator action patterns
//! (a moderator suddenly labeling 1000 accounts at 3am is itself an
//! incident), senior co-sign for high-impact pattern actions."
//!
//! # Scope as of issue #39
//!
//! The "moderator behavioral anomaly" detector that fires when a
//! single moderator submits N actions in T seconds does not exist
//! yet. The `ObservationKind` enum in `polaris-types/src/observation.rs`
//! has six variants (image-hash cluster, account cohort, reply
//! brigade, report-volume anomaly, external label, classifier
//! signal) — but no `ModeratorBehaviorAnomaly` variant. The
//! anomaly detector in `polaris-backend/src/pattern/anomaly.rs`
//! emits over report-volume buckets keyed on `(category, severity)`,
//! not on moderator id.
//!
//! What we CAN test as a MUST-pass invariant today:
//!
//! - **Every action records the moderator id verbatim, plus
//!   `created_at`.** This is what the future anomaly detector
//!   computes over: `count(actions)` grouped by `moderator_id`
//!   filtered to `created_at > now() - interval`. Pin the schema
//!   invariant the detector depends on.
//!
//! The full anomaly-fires-on-N-actions-in-T-seconds assertion is
//! left to follow-up #73 ("Add moderator-behavior-anomaly detector
//! (T1 mitigation)").

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use chrono::{DateTime, Utc};
use polaris_backend::repo::{ActionRepo as _, NewAction, PgActionRepo};
use polaris_types::{ActionKind, LabelValue, ModeratorId, PolicyId, Severity};
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

/// T1 IGNORED-WITH-FOLLOWUP: a moderator-behavior-anomaly observation
/// fires when one moderator submits N actions in T seconds.
///
/// The detector does not exist yet (no
/// `ObservationKind::ModeratorBehaviorAnomaly` variant in
/// `polaris-types/src/observation.rs`; no detector module under
/// `polaris-backend/src/pattern/` keyed on moderator id). See
/// follow-up issue #73.
///
/// The MUST-pass invariant the detector depends on (per-action
/// `moderator_id` + `created_at` recording) is asserted by
/// `action_rows_record_moderator_id_and_timestamp` above; this test
/// is the placeholder for the detector-fires assertion that lands
/// with #73.
//
// Follow-up #73 owns un-ignoring this test once the
// ModeratorBehaviorAnomaly detector lands. The mitigation surface
// needed is a new module under `polaris-backend/src/pattern/`
// (e.g. `moderator_anomaly.rs`) plus the matching
// `ObservationKind::ModeratorBehaviorAnomaly` variant.
#[tokio::test]
#[ignore = "T1 moderator-behavior-anomaly detector does not exist yet — follow-up #73"]
async fn moderator_behavior_anomaly_fires_on_action_burst() -> Result<(), Box<dyn std::error::Error>>
{
    // Spec out the acceptance criterion the follow-up must satisfy:
    //
    //   given moderator M submits 50 ActionKind::Label actions across
    //   50 distinct subjects within 60 seconds,
    //   the pattern-engine driver must emit an observation whose typed
    //   kind is `ObservationKind::ModeratorBehaviorAnomaly` carrying
    //   { moderator_id: M, action_count: 50, window: 60s }.
    //
    // Until that detector exists, this body is a placeholder. The
    // architect's pre-flight permits #[ignore] tests with a docstring
    // + filed follow-up issue + reference to the missing mitigation
    // surface.
    Ok(())
}
