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

use polaris_types::{Did, IncidentId, Report, ReportCategory, ReportId, SubjectId};
use sqlx::PgPool;

use super::RepoError;

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
#[derive(Debug, Clone)]
pub struct PgReportRepo {
    pool: PgPool,
}

impl PgReportRepo {
    /// Build a [`PgReportRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ReportRepo for PgReportRepo {
    async fn insert(&self, new: NewReport) -> Result<Report, RepoError> {
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
        .fetch_one(&self.pool)
        .await?;

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
