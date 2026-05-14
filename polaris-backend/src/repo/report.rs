//! Report repository — CRUD over the partitioned `reports` table.
//!
//! Maps [`polaris_types::Report`] / `NewReport` to and from rows in the
//! `reports` parent table from `00000000000005_reports.sql`. The table is
//! `PARTITION BY RANGE (created_at)`; Postgres routes each INSERT to the
//! correct monthly child partition automatically, so the repo issues a plain
//! `INSERT INTO reports …` against the parent.
//!
//! Reports may be unaggregated (`incident_id IS NULL`) at insert time; a
//! follow-up aggregation pipeline (issue TBD) binds them to subjects' open
//! incidents.

use std::sync::Arc;

use polaris_types::{Did, IncidentId, Report, ReportCategory, ReportId, SubjectId};
use sqlx::PgPool;

use super::RepoError;
use crate::reputation::PgReputationProvider;

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
#[derive(Debug, Clone)]
pub struct PgReportRepo {
    pool: PgPool,
    reputation: Option<Arc<PgReputationProvider>>,
}

impl PgReportRepo {
    /// Build a [`PgReportRepo`] over the given pool. No reputation hook.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            reputation: None,
        }
    }

    /// Attach a reputation provider so successful `insert`s update
    /// `reporter_stats` in the same transaction (issue #37, T3 mitigation).
    #[must_use]
    pub fn with_reputation(mut self, reputation: Arc<PgReputationProvider>) -> Self {
        self.reputation = Some(reputation);
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

        Ok(Report {
            id: ReportId(row.id),
            subject_id: SubjectId(row.subject_id),
            incident_id: row.incident_id.map(IncidentId),
            reporter_did: Did::new(row.reporter_did),
            category: ReportCategory::new(row.category),
            body: row.body,
            created_at: row.created_at,
        })
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
