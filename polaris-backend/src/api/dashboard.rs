//! Pattern dashboard API (issue #20).
//!
//! `GET /api/dashboard` returns a [`DashboardSnapshot`] — the four panels
//! of the pattern dashboard described in `design.md` §5.1:
//!
//! 1. Report-volume timeline over the trailing 24h (hourly buckets).
//! 2. Top incident clusters by `severity × reach`.
//! 3. Recent coordinated-action observations (cohort + image-hash bursts).
//! 4. Moderator load (queue depth per category).
//!
//! # Handler-as-orchestrator
//!
//! Per the architect's pre-flight from #14 (still in force for #20), the
//! handler is ≤ 25 lines and delegates each panel's construction to a
//! `build_*` helper. The helpers issue a single compile-time-checked SQL
//! query each so the `.sqlx/` offline cache contains exactly four new
//! entries.
//!
//! # Live-detector integration
//!
//! `report_volume.expected_mean` and `expected_stddev` are placeholders
//! (`0.0`) for #20 — wiring the live anomaly detector (#19) into the
//! handler is a separate concern. The DTO shape is stable so the runtime
//! wiring is purely a populate-the-existing-fields change.

use std::cmp::Reverse;

use axum::extract::State;
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use polaris_types::{IncidentId, IncidentStatus, ObservationKind, Severity, SubjectId};

use crate::api::dto::{
    CoordinatedSignal, CoordinatedSignalKind, DashboardSnapshot, IncidentClusterSummary,
    ModeratorLoad, ReportVolumeBucket,
};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;

/// Upper bound on the number of clusters returned in one snapshot. The
/// dashboard panel scrolls vertically, but rendering more than 32 rows in
/// the default viewport is a UX smell — pagination lands in a follow-up.
const MAX_CLUSTERS: usize = 32;

/// Upper bound on the number of coordinated signals returned in one
/// snapshot. The panel is "recent" — anything older drops off as new
/// signals arrive.
const MAX_COORDINATED_SIGNALS: i64 = 32;

/// Upper bound on the number of incident rows fetched when computing
/// cluster reach. Matches the case-API's `MAX_ROWS_PER_LIST`; pagination
/// is a follow-up concern.
const MAX_INCIDENT_ROWS: i64 = 256;

/// Handler: assemble the dashboard snapshot.
pub async fn handler(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<DashboardSnapshot>, ApiError> {
    let snapshot = build_snapshot(&state).await?;
    Ok(Json(snapshot))
}

/// Compose the four panels into a single [`DashboardSnapshot`].
async fn build_snapshot(state: &ApiState) -> Result<DashboardSnapshot, ApiError> {
    let now = Utc::now();
    let report_volume = build_report_volume(state, now).await?;
    let clusters = build_clusters(state).await?;
    let coordinated_signals = build_coordinated_signals(state).await?;
    let moderator_load = build_moderator_load(state).await?;
    Ok(DashboardSnapshot {
        report_volume,
        clusters,
        coordinated_signals,
        moderator_load,
        fetched_at: now,
    })
}

/// Build the report-volume panel.
///
/// Issues one query that groups reports filed in the trailing 24h into
/// hour-aligned buckets. `expected_mean` / `expected_stddev` are `0.0` —
/// the live anomaly detector (#19) populates them once the integration
/// lands; the DTO shape is stable.
async fn build_report_volume(
    state: &ApiState,
    now: DateTime<Utc>,
) -> Result<Vec<ReportVolumeBucket>, ApiError> {
    let since = now - Duration::hours(24);
    let rows = sqlx::query!(
        r#"
        SELECT
            date_trunc('hour', created_at) AS "bucket!: DateTime<Utc>",
            COUNT(*)                       AS "count!: i64"
        FROM reports
        WHERE created_at >= $1
        GROUP BY 1
        ORDER BY 1
        "#,
        since,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    let buckets = rows
        .into_iter()
        .map(|row| ReportVolumeBucket {
            bucket_start: row.bucket,
            count: row.count,
            expected_mean: 0.0,
            expected_stddev: 0.0,
        })
        .collect();
    Ok(buckets)
}

/// Build the incident-clusters panel.
///
/// Lists incidents in `open` / `in_review` / `escalated` status with their
/// related-subject count joined from `incident_related_subjects`. Sorted
/// by `severity × reach` (computed in Rust because the severity ordering
/// is a typed-enum concern, not a SQL one) and truncated to
/// [`MAX_CLUSTERS`].
async fn build_clusters(state: &ApiState) -> Result<Vec<IncidentClusterSummary>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            i.id                AS "id!: uuid::Uuid",
            i.primary_subject   AS "primary_subject!: uuid::Uuid",
            i.severity          AS "severity!: String",
            i.status            AS "status!: String",
            i.opened_at         AS "opened_at!: DateTime<Utc>",
            COALESCE(
                (SELECT COUNT(*)::bigint
                 FROM incident_related_subjects irs
                 WHERE irs.incident_id = i.id),
                0
            )                   AS "related_subject_count!: i64"
        FROM incidents i
        WHERE i.status IN ('open', 'in_review', 'escalated')
        ORDER BY i.opened_at DESC
        LIMIT $1
        "#,
        MAX_INCIDENT_ROWS,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    let mut clusters: Vec<IncidentClusterSummary> = rows
        .into_iter()
        .map(|row| {
            let severity = Severity::from_wire(&row.severity).unwrap_or(Severity::Low);
            let status = IncidentStatus::from_wire(&row.status).unwrap_or(IncidentStatus::Open);
            IncidentClusterSummary {
                incident_id: IncidentId(row.id),
                primary_subject: SubjectId(row.primary_subject),
                severity,
                status,
                related_subject_count: row.related_subject_count,
                opened_at: row.opened_at,
            }
        })
        .collect();

    // Sort by `severity × reach`. Severity is mapped to a small integer
    // (critical = 4, high = 3, medium = 2, low = 1); reach is the
    // related-subject count + 1 so an isolated incident still ranks above
    // a `low` with zero relateds. Stable sort keeps the secondary key
    // (newest first) intact for ties.
    clusters.sort_by_key(|c| Reverse(severity_weight(c.severity) * (c.related_subject_count + 1)));
    clusters.truncate(MAX_CLUSTERS);
    Ok(clusters)
}

/// Numeric weight for [`Severity`] in the cluster-ranking score.
const fn severity_weight(s: Severity) -> i64 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
    }
}

/// Build the coordinated-signals panel.
///
/// Lists the most recent cohort / image-hash / reply-brigade / report-
/// volume-anomaly observations. The full `evidence` JSONB is loaded so the
/// label can be projected per detector — image-hash observations contribute
/// a hex-hash prefix, account cohorts contribute the cohort id, etc.
/// `subject_count` is `1` per row today (one observation = one subject);
/// once the engine emits multi-subject signals the row will carry the real
/// count from the detector.
async fn build_coordinated_signals(state: &ApiState) -> Result<Vec<CoordinatedSignal>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            kind        AS "kind!: String",
            evidence    AS "evidence!: serde_json::Value",
            detected_at AS "detected_at!: DateTime<Utc>"
        FROM observations
        WHERE kind IN (
            'image_hash_cluster', 'account_cohort',
            'reply_brigade',      'report_volume_anomaly'
        )
        ORDER BY detected_at DESC
        LIMIT $1
        "#,
        MAX_COORDINATED_SIGNALS,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    let signals = rows
        .into_iter()
        .filter_map(|row| {
            let (kind, label) = project_signal(&row.kind, &row.evidence)?;
            Some(CoordinatedSignal {
                kind,
                label,
                subject_count: 1,
                detected_at: row.detected_at,
            })
        })
        .collect();
    Ok(signals)
}

/// Project a `(discriminator, evidence)` pair onto the dashboard's
/// `(kind, label)` summary.
///
/// Returns `None` for kinds outside the coordinated-signal subset
/// ([`ObservationKind::ExternalLabel`] / [`ObservationKind::ClassifierSignal`]
/// are subject-level, not pattern-level; the SQL filter already excludes
/// them but the projection stays defensive).
fn project_signal(
    discriminator: &str,
    evidence: &serde_json::Value,
) -> Option<(CoordinatedSignalKind, String)> {
    let envelope = serde_json::json!({
        "kind": discriminator,
        "data": evidence,
    });
    let typed: ObservationKind = serde_json::from_value(envelope).ok()?;
    Some(match typed {
        ObservationKind::ImageHashCluster { hash, .. } => {
            let prefix: String = hash.chars().take(8).collect();
            (CoordinatedSignalKind::ImageHashCluster, prefix)
        }
        ObservationKind::AccountCohort { cohort_id, .. } => {
            (CoordinatedSignalKind::AccountCohort, cohort_id)
        }
        ObservationKind::ReplyBrigade { thread_uri } => {
            (CoordinatedSignalKind::ReplyBrigade, thread_uri)
        }
        ObservationKind::ReportVolumeAnomaly { category, .. } => {
            (CoordinatedSignalKind::ReportVolumeAnomaly, category)
        }
        ObservationKind::ExternalLabel { .. } | ObservationKind::ClassifierSignal { .. } => {
            return None;
        }
    })
}

/// Build the moderator-load panel.
///
/// Today `incidents` has no `category` column (M2 introduces categorical
/// routing); the handler projects a single `"all"` row with the current
/// open / in-review counts. The DTO is a `Vec<ModeratorLoad>` so once the
/// column lands the response shape is unchanged — the row count just
/// grows.
async fn build_moderator_load(state: &ApiState) -> Result<Vec<ModeratorLoad>, ApiError> {
    let row = sqlx::query!(
        r#"
        SELECT
            COALESCE(SUM(CASE WHEN status = 'open'      THEN 1 ELSE 0 END), 0)::bigint
                AS "open_count!: i64",
            COALESCE(SUM(CASE WHEN status = 'in_review' THEN 1 ELSE 0 END), 0)::bigint
                AS "in_review_count!: i64"
        FROM incidents
        "#,
    )
    .fetch_one(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    Ok(vec![ModeratorLoad {
        category: "all".to_owned(),
        open_count: row.open_count,
        in_review_count: row.in_review_count,
    }])
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use polaris_types::Did;

    #[test]
    fn severity_weight_orders_critical_above_low() {
        assert!(severity_weight(Severity::Critical) > severity_weight(Severity::High));
        assert!(severity_weight(Severity::High) > severity_weight(Severity::Medium));
        assert!(severity_weight(Severity::Medium) > severity_weight(Severity::Low));
    }

    #[test]
    fn project_signal_extracts_image_hash_prefix() {
        let evidence = serde_json::json!({
            "hash": "deadbeefcafebabe",
            "distance": 3,
        });
        let (kind, label) = project_signal("image_hash_cluster", &evidence).expect("project");
        assert_eq!(kind, CoordinatedSignalKind::ImageHashCluster);
        assert_eq!(label, "deadbeef");
    }

    #[test]
    fn project_signal_returns_none_for_external_label() {
        let evidence = serde_json::json!({
            "source": "did:plc:upstream",
            "label_value": "spam",
            "weight": 0.8,
        });
        // External labels are filtered out by the SQL WHERE clause, but the
        // projection stays defensive — it returns None rather than a wrong
        // mapping if a row slipped through.
        assert!(project_signal("external_label", &evidence).is_none());
    }

    #[test]
    fn project_signal_extracts_cohort_id() {
        let evidence = serde_json::json!({
            "cohort_id": "c-42",
            "similarity_score": 0.91,
        });
        let (kind, label) = project_signal("account_cohort", &evidence).expect("project");
        assert_eq!(kind, CoordinatedSignalKind::AccountCohort);
        assert_eq!(label, "c-42");
    }

    #[test]
    fn report_volume_bucket_round_trips_through_serde() {
        let bucket = ReportVolumeBucket {
            bucket_start: Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap(),
            count: 7,
            expected_mean: 4.2,
            expected_stddev: 1.1,
        };
        let json = serde_json::to_string(&bucket).expect("serialize");
        let back: ReportVolumeBucket = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.count, 7);
        // Float comparison via tolerance — the serde round-trip is
        // lossless for finite f64 values but `assert_eq!` on f64 trips
        // `clippy::float_cmp`. Bound the tolerance to `f64::EPSILON` so
        // any future serde-format regression is still caught.
        assert!((back.expected_mean - 4.2).abs() < f64::EPSILON);
    }

    #[test]
    fn coordinated_signal_kind_serializes_snake_case() {
        let kind = CoordinatedSignalKind::ImageHashCluster;
        let json = serde_json::to_string(&kind).expect("serialize");
        assert_eq!(json, "\"image_hash_cluster\"");
        // Suppress the unused-import-in-test warning when no further test
        // touches `Did` directly.
        let _ = Did::new("did:plc:unused");
    }
}
