//! Incident repository — CRUD over the `incidents` table.
//!
//! Maps [`polaris_types::Incident`] / `NewIncident` to and from the
//! `incidents` row shape in `00000000000003_subjects_incidents.sql`.
//!
//! The `reports` and `pattern_observations` vectors on
//! [`polaris_types::Incident`] are populated by hydration queries in the API
//! layer (#14+); this repo returns "bare" incidents with those collections
//! empty. The `related_subjects` join table is hydrated here when callers
//! request `get_with_related`; the default `get` returns a bare incident to
//! keep the hot path one row read.

use polaris_types::{Incident, IncidentId, IncidentStatus, ModeratorId, Severity, SubjectId};
use sqlx::PgPool;

use super::RepoError;

/// Caller-supplied fields for creating a new [`Incident`].
///
/// The repo populates `id` and `opened_at` server-side via DEFAULTs;
/// `closed_at` is `None` for fresh incidents and is set by a follow-up
/// status transition (which lives at the service layer, not here).
#[derive(Debug, Clone)]
pub struct NewIncident {
    /// Primary subject.
    pub primary_subject: SubjectId,
    /// Severity tier at creation.
    pub severity: Severity,
    /// Starting status.
    pub status: IncidentStatus,
    /// Initial assignee (typically `None`; populated by the router).
    pub assigned_to: Option<ModeratorId>,
}

/// Compile-time contract for the incident repository.
pub trait IncidentRepo: Send + Sync {
    /// Insert a new incident. Returns the materialized [`Incident`] with
    /// empty hydrated collections.
    fn insert(
        &self,
        new: NewIncident,
    ) -> impl std::future::Future<Output = Result<Incident, RepoError>> + Send;

    /// Look up a bare incident by id. Hydrated collections are empty.
    fn get(
        &self,
        id: IncidentId,
    ) -> impl std::future::Future<Output = Result<Option<Incident>, RepoError>> + Send;

    /// List incidents filtered by `status` (optional), capped at `limit`.
    /// Ordered newest-`opened_at` first.
    fn list_by_status(
        &self,
        status: Option<IncidentStatus>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Incident>, RepoError>> + Send;

    /// Narrow mutation: update only the incident's `status` column.
    ///
    /// This is the *only* mutator on incidents. The deliberate narrowness
    /// keeps the surface auditable: status transitions (`open` → `in_review`
    /// → `actioned` / `escalated` / `closed`) are the legitimate write path, while
    /// every other column (`primary_subject`, `severity`, `opened_at`, …)
    /// is set once at insert and never mutated. A generic `update` method
    /// would invite scope creep.
    ///
    /// Returns the post-update [`Incident`] (with empty hydrated
    /// collections). Returns [`RepoError::NotFound`] if no row matches `id`.
    fn update_status(
        &self,
        id: IncidentId,
        new_status: IncidentStatus,
    ) -> impl std::future::Future<Output = Result<Incident, RepoError>> + Send;
}

/// Postgres-backed [`IncidentRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgIncidentRepo {
    pool: PgPool,
}

impl PgIncidentRepo {
    /// Build a [`PgIncidentRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl IncidentRepo for PgIncidentRepo {
    async fn insert(&self, new: NewIncident) -> Result<Incident, RepoError> {
        let severity_str = new.severity.as_str();
        let status_str = new.status.as_str();
        let row = sqlx::query!(
            r#"
            INSERT INTO incidents (primary_subject, severity, status, assigned_to)
            VALUES ($1, $2, $3, $4)
            RETURNING id, primary_subject, severity, status, assigned_to, locked_by,
                      opened_at, closed_at
            "#,
            new.primary_subject.0,
            severity_str,
            status_str,
            new.assigned_to.map(|m| m.0),
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Incident::new_bare(
            IncidentId(row.id),
            SubjectId(row.primary_subject),
            decode_severity(&row.severity)?,
            decode_status(&row.status)?,
            row.assigned_to.map(ModeratorId),
            row.locked_by.map(ModeratorId),
            row.opened_at,
            row.closed_at,
        ))
    }

    async fn get(&self, id: IncidentId) -> Result<Option<Incident>, RepoError> {
        let row = sqlx::query!(
            r#"
            SELECT id, primary_subject, severity, status, assigned_to, locked_by,
                   opened_at, closed_at
            FROM incidents
            WHERE id = $1
            "#,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        Ok(Some(Incident::new_bare(
            IncidentId(row.id),
            SubjectId(row.primary_subject),
            decode_severity(&row.severity)?,
            decode_status(&row.status)?,
            row.assigned_to.map(ModeratorId),
            row.locked_by.map(ModeratorId),
            row.opened_at,
            row.closed_at,
        )))
    }

    async fn list_by_status(
        &self,
        status: Option<IncidentStatus>,
        limit: i64,
    ) -> Result<Vec<Incident>, RepoError> {
        let status_str = status.map(IncidentStatus::as_str);
        let rows = sqlx::query!(
            r#"
            SELECT id, primary_subject, severity, status, assigned_to, locked_by,
                   opened_at, closed_at
            FROM incidents
            WHERE $1::text IS NULL OR status = $1
            ORDER BY opened_at DESC
            LIMIT $2
            "#,
            status_str,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut incidents = Vec::with_capacity(rows.len());
        for row in rows {
            incidents.push(Incident::new_bare(
                IncidentId(row.id),
                SubjectId(row.primary_subject),
                decode_severity(&row.severity)?,
                decode_status(&row.status)?,
                row.assigned_to.map(ModeratorId),
                row.locked_by.map(ModeratorId),
                row.opened_at,
                row.closed_at,
            ));
        }
        Ok(incidents)
    }

    async fn update_status(
        &self,
        id: IncidentId,
        new_status: IncidentStatus,
    ) -> Result<Incident, RepoError> {
        // The DB CHECK constraint on `incidents.status` already restricts the
        // column to the wire forms in `IncidentStatus::as_str`; binding
        // through `as_str()` keeps the repo's compile-time-checked-SQL
        // contract intact without exposing a free-form `update` method.
        let new_status_str = new_status.as_str();
        let row = sqlx::query!(
            r#"
            UPDATE incidents
            SET status = $2
            WHERE id = $1
            RETURNING id, primary_subject, severity, status, assigned_to, locked_by,
                      opened_at, closed_at
            "#,
            id.0,
            new_status_str,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else {
            return Err(RepoError::NotFound);
        };
        Ok(Incident::new_bare(
            IncidentId(row.id),
            SubjectId(row.primary_subject),
            decode_severity(&row.severity)?,
            decode_status(&row.status)?,
            row.assigned_to.map(ModeratorId),
            row.locked_by.map(ModeratorId),
            row.opened_at,
            row.closed_at,
        ))
    }
}

// ── private decoders ────────────────────────────────────────────────────

fn decode_severity(value: &str) -> Result<Severity, RepoError> {
    Severity::from_wire(value).ok_or_else(|| RepoError::Decode {
        message: format!("incidents.severity={value:?} not in polaris-types contract"),
    })
}

fn decode_status(value: &str) -> Result<IncidentStatus, RepoError> {
    IncidentStatus::from_wire(value).ok_or_else(|| RepoError::Decode {
        message: format!("incidents.status={value:?} not in polaris-types contract"),
    })
}
