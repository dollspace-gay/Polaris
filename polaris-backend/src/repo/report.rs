//! Report repository — CRUD over the partitioned `reports` table.
//!
//! Maps [`polaris_types::Report`] / `NewReport` to and from rows in the
//! `reports` parent table from `00000000000005_reports.sql`. The table is
//! `PARTITION BY RANGE (created_at)`; Postgres routes each INSERT to the
//! correct monthly child partition automatically, so the repo issues a plain
//! `INSERT INTO reports …` against the parent.
//!
//! Reports may be unaggregated (`incident_id IS NULL`) at insert time;
//! [`crate::ingest::aggregator::ReportAggregator`] (issue #75) is the
//! background worker that binds them to subjects' open incidents.

use std::sync::Arc;

use polaris_types::{Did, IncidentId, Report, ReportCategory, ReportId, SubjectId};
use sqlx::PgPool;
use tokio::sync::Mutex;

use super::RepoError;
use crate::pattern::anomaly::{MemoryAnomalyDetector, ReportVolumeIndex};
use crate::reputation::{PgReputationProvider, ReputationProvider, ReputationScore};

/// Caller-supplied fields for inserting a new [`Report`].
///
/// The repo populates `id` and `created_at` via Postgres defaults.
#[derive(Debug, Clone)]
pub struct NewReport {
    /// Subject the report is about.
    pub subject_id: SubjectId,
    /// Incident binding (typically `None` at insert time).
    pub incident_id: Option<IncidentId>,
    /// Reporter DID.
    pub reporter_did: Did,
    /// Category (free-form wire string; see [`ReportCategory`]).
    pub category: ReportCategory,
    /// Body text.
    pub body: String,
}

/// Compile-time contract for the report repository.
pub trait ReportRepo: Send + Sync {
    /// Insert a new report. Returns the materialized [`Report`] including
    /// server-assigned `id` and `created_at`.
    fn insert(
        &self,
        new: NewReport,
    ) -> impl std::future::Future<Output = Result<Report, RepoError>> + Send;

    /// Look up a report by id. Returns `Ok(None)` when no row matches.
    fn get(
        &self,
        id: ReportId,
    ) -> impl std::future::Future<Output = Result<Option<Report>, RepoError>> + Send;

    /// List reports for a subject, newest first, capped at `limit`.
    fn list_by_subject(
        &self,
        subject_id: SubjectId,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Report>, RepoError>> + Send;
}

/// Postgres-backed [`ReportRepo`] implementation.
///
/// Optionally carries a [`PgReputationProvider`] (issue #37) — when
/// present, every successful `insert` also increments
/// `reporter_stats.reports_filed` for the reporter's DID within the same
/// transaction. Existing call sites that construct the repo via
/// [`Self::new`] are unaffected; the hook is opt-in via
/// [`Self::with_reputation`].
///
/// Optionally carries a [`MemoryAnomalyDetector`] (issue #77) — when
/// present and a [`PgReputationProvider`] is also attached, every
/// successful `insert` looks up the reporter's reputation score and
/// feeds the resulting weight into the detector's
/// [`ReportVolumeIndex::observe_report`] hook. Emitted anomalies are
/// logged via `tracing::warn!` for now; the pattern-engine driver that
/// persists them to [`crate::repo::ObservationRepo`] is a separate
/// concern.
#[derive(Debug, Clone)]
pub struct PgReportRepo {
    pool: PgPool,
    reputation: Option<Arc<PgReputationProvider>>,
    anomaly_detector: Option<Arc<Mutex<MemoryAnomalyDetector>>>,
}

impl PgReportRepo {
    /// Build a [`PgReportRepo`] over the given pool. No reputation hook.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            reputation: None,
            anomaly_detector: None,
        }
    }

    /// Attach a reputation provider so successful `insert`s update
    /// `reporter_stats` in the same transaction (issue #37, T3 mitigation).
    #[must_use]
    pub fn with_reputation(mut self, reputation: Arc<PgReputationProvider>) -> Self {
        self.reputation = Some(reputation);
        self
    }

    /// Attach a reputation-weighted anomaly detector so successful
    /// `insert`s feed the reporter's cached reputation score into the
    /// detector's running statistics (issue #77, T3 mitigation
    /// deepening).
    ///
    /// Has no effect unless [`Self::with_reputation`] is also called —
    /// the score lookup goes through the attached provider. A repo
    /// configured with a detector but no provider silently skips the
    /// hook; the report insert itself is unaffected.
    #[must_use]
    pub fn with_anomaly_detector(mut self, detector: Arc<Mutex<MemoryAnomalyDetector>>) -> Self {
        self.anomaly_detector = Some(detector);
        self
    }
}

impl ReportRepo for PgReportRepo {
    async fn insert(&self, new: NewReport) -> Result<Report, RepoError> {
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query!(
            r#"
            INSERT INTO reports (subject_id, incident_id, reporter_did, category, body)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, subject_id, incident_id, reporter_did, category, body, created_at
            "#,
            new.subject_id.0,
            new.incident_id.map(|i| i.0),
            new.reporter_did.as_str(),
            new.category.as_str(),
            new.body,
        )
        .fetch_one(&mut *tx)
        .await?;

        // Issue #37: if a reputation provider is attached, fire the
        // `record_report_filed` hook inside the same transaction so the
        // reports table and the `reporter_stats` row commit atomically.
        // A failure on the stats update rolls back the report insert,
        // mirroring the action / evidence-job atomicity in
        // `PgActionRepo::insert`.
        if let Some(reputation) = self.reputation.as_ref() {
            reputation
                .record_report_filed_with(&mut tx, &row.reporter_did)
                .await
                .map_err(map_reputation_error)?;
        }

        tx.commit().await?;

        let report = Report {
            id: ReportId(row.id),
            subject_id: SubjectId(row.subject_id),
            incident_id: row.incident_id.map(IncidentId),
            reporter_did: Did::new(row.reporter_did),
            category: ReportCategory::new(row.category),
            body: row.body,
            created_at: row.created_at,
        };

        // Issue #77: feed the reputation-weighted volume signal. The
        // detector hook is opt-in and only runs when both a provider
        // and a detector are attached; the score lookup happens after
        // commit so the cached_score read sees the value
        // `record_report_filed_with` just wrote. Lookup failure falls
        // back to the neutral prior — see `score_for_observe`.
        if let (Some(reputation), Some(detector)) =
            (self.reputation.as_ref(), self.anomaly_detector.as_ref())
        {
            let weight = score_for_observe(reputation.as_ref(), report.reporter_did.as_str()).await;
            let emission = {
                let mut guard = detector.lock().await;
                guard.observe_report(report.created_at, weight)
            };
            if let Some(obs) = emission {
                tracing::warn!(
                    weighted_volume = obs.weighted_volume,
                    z_score = obs.z_score,
                    expected_mean = obs.expected_mean,
                    expected_stddev = obs.expected_stddev,
                    confidence = obs.confidence,
                    detected_at = %obs.detected_at,
                    "report-volume anomaly (reputation-weighted)"
                );
            }
        }

        Ok(report)
    }

    async fn get(&self, id: ReportId) -> Result<Option<Report>, RepoError> {
        // `reports` is partitioned by `created_at`; queries without a
        // `created_at` predicate scan every partition. For an `id` lookup
        // this is fine (each partition has its own index on `id` via the
        // composite PK), but at scale the API layer should pass in a date
        // range whenever the request can reasonably constrain it.
        let row = sqlx::query!(
            r#"
            SELECT id, subject_id, incident_id, reporter_did, category, body, created_at
            FROM reports
            WHERE id = $1
            "#,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        Ok(Some(Report {
            id: ReportId(row.id),
            subject_id: SubjectId(row.subject_id),
            incident_id: row.incident_id.map(IncidentId),
            reporter_did: Did::new(row.reporter_did),
            category: ReportCategory::new(row.category),
            body: row.body,
            created_at: row.created_at,
        }))
    }

    async fn list_by_subject(
        &self,
        subject_id: SubjectId,
        limit: i64,
    ) -> Result<Vec<Report>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, subject_id, incident_id, reporter_did, category, body, created_at
            FROM reports
            WHERE subject_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            subject_id.0,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut reports = Vec::with_capacity(rows.len());
        for row in rows {
            reports.push(Report {
                id: ReportId(row.id),
                subject_id: SubjectId(row.subject_id),
                incident_id: row.incident_id.map(IncidentId),
                reporter_did: Did::new(row.reporter_did),
                category: ReportCategory::new(row.category),
                body: row.body,
                created_at: row.created_at,
            });
        }
        Ok(reports)
    }
}

/// Look up the reporter's reputation score for an
/// [`crate::pattern::anomaly::MemoryAnomalyDetector`] feed, defaulting
/// to the neutral prior (`0.5`) on lookup failure or when the reporter
/// has no `reporter_stats` row.
///
/// The fallback matches
/// [`crate::reputation::ReputationScore::neutral`]'s prior so that
/// unknown reporters do not slip through detection entirely (a
/// `0.0`-weight would let an adversary suppress their own contribution
/// to the volume signal). Lookup errors are demoted to the neutral
/// prior rather than failing the insert: the anomaly hook is a
/// best-effort signal, and a transient database hiccup on the cached-
/// score read should not block reporters from filing.
async fn score_for_observe<P>(provider: &P, did: &str) -> f64
where
    P: ReputationProvider + ?Sized,
{
    match provider.score_for(did).await {
        Ok(score) => f64::from(score.into_inner()),
        Err(err) => {
            tracing::warn!(did, error = %err, "reputation lookup failed; falling back to neutral prior");
            f64::from(ReputationScore::neutral().into_inner())
        }
    }
}

/// Route a [`crate::reputation::ReputationError`] into a [`RepoError`].
///
/// The reputation subsystem's `Db` variant wraps a `sqlx::Error`; we
/// unwrap and re-route through the standard `RepoError::from(sqlx::Error)`
/// so SQLSTATE-class detection (unique-violation, FK violation, etc.)
/// still works. Other variants (`OutOfRange`, `UnknownReporter`) map to
/// `RepoError::Decode` because they indicate either a config drift or
/// a schema drift, not a transient DB failure.
fn map_reputation_error(err: crate::reputation::ReputationError) -> RepoError {
    match err {
        crate::reputation::ReputationError::Db(e) => RepoError::from(e),
        crate::reputation::ReputationError::OutOfRange { value } => RepoError::Decode {
            message: format!("reputation score out of range: {value}"),
        },
        crate::reputation::ReputationError::UnknownReporter { did } => RepoError::Decode {
            message: format!("reputation: unknown reporter {did}"),
        },
    }
}
