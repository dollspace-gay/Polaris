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
//!
//! # Faceted filtering (issue #94)
//!
//! `GET /api/dashboard` accepts four optional facet query parameters
//! (`reporter_did`, `category`, `status`, `since`/`until`) that narrow
//! the cluster panel to incidents matching the AND-composed predicate.
//! The default (no params) is identical to the pre-#94 unfiltered
//! shape — backward-compatible by construction. Each facet feeds
//! through a single `$N IS NULL OR …` binding site in the cluster SQL
//! so one compile-time-checked statement handles every combination
//! and the `.sqlx/` offline cache holds exactly one new entry.
//!
//! The filter state is intentionally **not** mirrored in the URL on
//! the frontend side for v1 — it lives in a Leptos signal on the
//! dashboard mount. Promoting it to URL params (shareable filtered
//! dashboards) is a separate workstream.

pub mod filters;

use std::cmp::Reverse;

use axum::extract::{Query, State};
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use polaris_types::{IncidentId, IncidentStatus, ObservationKind, Severity, SubjectId};

use crate::api::dashboard::filters::{DashboardQuery, ParsedFilters};
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
///
/// Accepts optional facet query parameters per issue #94:
/// `?reporter_did=<did>&category=<cat>&status=<state>&since=<rfc3339>&until=<rfc3339>`.
/// Missing parameters keep the pre-#94 behaviour (return all clusters
/// in the default `open` / `in_review` / `escalated` set).
pub async fn handler(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Query(query): Query<DashboardQuery>,
) -> Result<Json<DashboardSnapshot>, ApiError> {
    // Bump the per-facet-combination Prometheus counter at the route
    // entry so the metric records the request shape regardless of
    // whether parsing succeeded. The `filter` label is comma-joined
    // (canonical order) so cardinality stays bounded.
    metrics::counter!(
        "polaris_dashboard_filtered_requests_total",
        "filter" => query.active_facet_label(),
    )
    .increment(1);

    let parsed = filters::parse_query(&query).map_err(|e| ApiError::BadRequest(e.message()))?;
    let snapshot = build_snapshot(&state, &parsed).await?;
    Ok(Json(snapshot))
}

/// Compose the four panels into a single [`DashboardSnapshot`].
async fn build_snapshot(
    state: &ApiState,
    filters: &ParsedFilters,
) -> Result<DashboardSnapshot, ApiError> {
    let now = Utc::now();
    let report_volume = build_report_volume(state, now).await?;
    let clusters = build_clusters(state, filters).await?;
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
/// Two SQL aggregates feed the panel:
///
/// 1. **Rendered window** — the trailing 24 hours, grouped by hour,
///    returns the `count` and `weighted_count` per bucket the
///    sparkline renders.
/// 2. **Baseline window** — the prior 7 days (hours -192 through -24
///    relative to `now`), grouped by hour, used to compute the
///    trailing-baseline `expected_mean` + `expected_stddev` over
///    weighted counts. The baseline excludes the rendered window
///    itself so a fresh spike in the last 24h does not inflate its
///    own anomaly band.
///
/// The anomaly band uses Welford's algorithm in a numerically-stable
/// pass over the baseline weighted-counts; the resulting mean/stddev
/// is applied uniformly to every emitted bucket in the rendered
/// window so the sparkline can render a single band rather than a
/// per-bucket one. When the baseline window is empty (fresh
/// deployment, first day), both fields stay `0.0` and the frontend
/// hides the band — there is no honest signal until ≥ 2 hours of
/// history accumulate (sample-variance requires `n >= 2`).
///
/// Issue #37 wires `weighted_count`: each report contributes its
/// reporter's cached reputation score (default 0.5 for unknown
/// reporters), so a flood from low-rep accounts accumulates with
/// less weight than the same volume from established reporters.
async fn build_report_volume(
    state: &ApiState,
    now: DateTime<Utc>,
) -> Result<Vec<ReportVolumeBucket>, ApiError> {
    let rendered_since = now - Duration::hours(24);
    let baseline_since = now - Duration::hours(24 + 7 * 24);
    let baseline_until = rendered_since;

    // Compute the trailing-baseline first so its result can be applied
    // to every rendered bucket. A failure on the baseline query is NOT
    // fatal — degrade to `(0.0, 0.0)` so the sparkline renders without
    // a band rather than failing the dashboard.
    let (expected_mean, expected_stddev) =
        match baseline_stats(&state.pool, baseline_since, baseline_until).await {
            Ok(baseline) => baseline,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "report-volume baseline aggregate failed; rendering panel without anomaly band",
                );
                (0.0_f64, 0.0_f64)
            }
        };

    let rows = sqlx::query!(
        r#"
        SELECT
            date_trunc('hour', r.created_at)                    AS "bucket!: DateTime<Utc>",
            COUNT(*)                                            AS "count!: i64",
            SUM(COALESCE(rs.cached_score, 0.5)::double precision)
                                                                AS "weighted!: f64"
        FROM reports r
        LEFT JOIN reporter_stats rs ON rs.did = r.reporter_did
        WHERE r.created_at >= $1
        GROUP BY 1
        ORDER BY 1
        "#,
        rendered_since,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    let buckets = rows
        .into_iter()
        .map(|row| ReportVolumeBucket {
            bucket_start: row.bucket,
            count: row.count,
            weighted_count: row.weighted,
            expected_mean,
            expected_stddev,
        })
        .collect();
    Ok(buckets)
}

/// Compute the trailing-baseline `(mean, stddev)` over weighted hourly
/// counts in `[since, until)`.
///
/// Pulls every hour-aligned bucket in the baseline window and feeds the
/// weighted counts through Welford's algorithm (the same numerical
/// recipe [`crate::pattern::anomaly`] uses for streaming). Hours with
/// zero reports do NOT appear in the row stream — we backfill them as
/// `0.0` so the baseline reflects "this is a quiet stretch" rather than
/// "we have no data for these hours."
///
/// Returns `(0.0, 0.0)` when the baseline contains fewer than 2 hours
/// of data — sample variance requires `n >= 2`, and rendering an
/// anomaly band against a single sample would be meaningless.
async fn baseline_stats(
    pool: &sqlx::PgPool,
    since: DateTime<Utc>,
    until: DateTime<Utc>,
) -> Result<(f64, f64), sqlx::Error> {
    // `generate_series` + LEFT JOIN gives us a row per hour-aligned
    // bucket in the window, with `weighted = 0` for hours with no
    // reports. This is the honest representation of the baseline —
    // a quiet hour is a real data point, not missing data.
    let rows = sqlx::query!(
        r#"
        SELECT
            bucket_start                                            AS "bucket!: DateTime<Utc>",
            COALESCE(SUM(COALESCE(rs.cached_score, 0.5)::double precision), 0.0)
                                                                    AS "weighted!: f64"
        FROM generate_series(
            date_trunc('hour', $1::timestamptz),
            date_trunc('hour', $2::timestamptz) - interval '1 hour',
            interval '1 hour'
        ) AS bucket_start
        LEFT JOIN reports r
            ON r.created_at >= bucket_start
           AND r.created_at <  bucket_start + interval '1 hour'
        LEFT JOIN reporter_stats rs ON rs.did = r.reporter_did
        GROUP BY bucket_start
        ORDER BY bucket_start
        "#,
        since,
        until,
    )
    .fetch_all(pool)
    .await?;

    if rows.len() < 2 {
        return Ok((0.0, 0.0));
    }

    // Welford's online algorithm — same recipe as
    // `crate::pattern::anomaly` but applied to the offline baseline.
    // `f64` throughout for numerical stability across hundreds of
    // hourly samples; the DTO narrows to f64 verbatim.
    //
    // `n` is typed `u32` (the window is 168 hours; far inside `u32`)
    // so the `f64::from(u32)` cast is lossless — Welford then divides
    // by it in the running-mean update.
    let mut n: u32 = 0;
    let mut mean: f64 = 0.0;
    let mut m2: f64 = 0.0;
    for row in &rows {
        n += 1;
        let delta = row.weighted - mean;
        mean += delta / f64::from(n);
        let delta2 = row.weighted - mean;
        m2 += delta * delta2;
    }
    // Sample variance: m2 / (n - 1). Guarded above against `n < 2`,
    // so the `n - 1` subtraction never underflows.
    let variance = m2 / f64::from(n - 1);
    let stddev = variance.sqrt();
    Ok((mean, stddev))
}

/// Build the incident-clusters panel.
///
/// Lists incidents matching the AND-composed facet predicate, with
/// their related-subject count joined from `incident_related_subjects`.
/// Sorted by `severity × reach` (computed in Rust because the severity
/// ordering is a typed-enum concern, not a SQL one) and truncated to
/// [`MAX_CLUSTERS`].
///
/// # Filtering (issue #94)
///
/// Each facet binds through a `$N IS NULL OR …` site so a single
/// statement covers every combination of active facets. The
/// `reporter_did` and `category` facets test against the `reports`
/// table via `EXISTS` so the cluster row is kept iff at least one
/// report under the incident matches the predicate. The `status`
/// facet narrows when supplied; the default (no `status` filter)
/// keeps the pre-#94 `open / in_review / escalated` set so AC-6
/// (backward compatibility with the unfiltered shape) holds.
async fn build_clusters(
    state: &ApiState,
    filters: &ParsedFilters,
) -> Result<Vec<IncidentClusterSummary>, ApiError> {
    // Each facet folds onto an optional binding. `None` → SQL sees
    // NULL and the `$N IS NULL OR …` predicate degenerates to TRUE,
    // matching the unfiltered baseline.
    let reporter_did: Option<&str> = filters.reporter_did.as_deref();
    let category: Option<&str> = filters.category.as_deref();
    let status_filter: Option<&str> = filters.status.map(IncidentStatus::as_str);
    let since: Option<DateTime<Utc>> = filters.since;
    let until: Option<DateTime<Utc>> = filters.until;

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
        WHERE
            -- Status filter (issue #94 facet). When omitted, fall
            -- back to the pre-#94 default (open / in_review /
            -- escalated) so the unfiltered shape is preserved.
            (
                ($3::text IS NULL AND i.status IN ('open', 'in_review', 'escalated'))
                OR i.status = $3
            )
            -- Date-range facets (inclusive bounds).
            AND ($4::timestamptz IS NULL OR i.opened_at >= $4)
            AND ($5::timestamptz IS NULL OR i.opened_at <= $5)
            -- Reporter-DID facet: keep the incident iff at least one
            -- report under it was filed by this reporter.
            AND (
                $1::text IS NULL
                OR EXISTS (
                    SELECT 1 FROM reports r
                    WHERE r.incident_id = i.id AND r.reporter_did = $1
                )
            )
            -- Category facet: keep the incident iff at least one
            -- report under it is in this category.
            AND (
                $2::text IS NULL
                OR EXISTS (
                    SELECT 1 FROM reports r
                    WHERE r.incident_id = i.id AND r.category = $2
                )
            )
        ORDER BY i.opened_at DESC
        LIMIT $6
        "#,
        reporter_did,
        category,
        status_filter,
        since,
        until,
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
        ObservationKind::ExternalLabel { .. }
        | ObservationKind::ClassifierSignal { .. }
        | ObservationKind::ModeratorBehaviorAnomaly { .. }
        | ObservationKind::LlmRecommendation { .. } => {
            // ExternalLabel / ClassifierSignal are subject-level (not
            // pattern-level); ModeratorBehaviorAnomaly is a T1 mitigation
            // signal keyed on a synthetic moderator-anomaly subject and
            // surfaces on its own panel, not on the coordinated-signal
            // dashboard. LlmRecommendation is per-case advisory output
            // from the LLM-assist subsystem (`.design/llm-moderation-
            // assist.md`); it surfaces in the case-view sidebar (REQ-J1)
            // and on the autonomous-action audit page (REQ-F4), not on
            // the coordinated-signal dashboard. The SQL filter already
            // excludes these kinds — the projection stays defensive.
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
            weighted_count: 3.5,
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
