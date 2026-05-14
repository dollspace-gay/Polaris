//! Subject repository — CRUD over the `subjects` table.
//!
//! Maps [`polaris_types::Subject`] / [`polaris_types::NewSubject`] to and from
//! the `subjects` row shape in migration `00000000000003_subjects_incidents.sql`.
//! The `risk_signals` JSONB column is denormalized by a trigger
//! (`00000000000007_risk_signals_trigger.sql`); this repo reads it back as
//! `Vec<Signal>` but does not write into it directly.

use chrono::{DateTime, Utc};
use polaris_types::{AtUri, Did, Signal, Subject, SubjectId, SubjectKind};
use sqlx::PgPool;

use super::RepoError;

/// Caller-supplied fields for inserting a new [`Subject`].
///
/// `id`, `first_seen_by_mod`, and `risk_signals` are populated server-side
/// by Postgres defaults; the trigger that maintains `risk_signals` will
/// rewrite the column to `[]` initially and then to the latest observation
/// snapshot as observations arrive.
#[derive(Debug, Clone)]
pub struct NewSubject {
    /// Subject kind discriminator.
    pub kind: SubjectKind,
    /// ATProto DID (see [`Subject::did`]).
    pub did: Option<Did>,
    /// ATProto AT-URI (see [`Subject::uri`]).
    pub uri: Option<AtUri>,
    /// Upstream creation time (account creation, post creation, …).
    pub created_at: DateTime<Utc>,
}

/// Compile-time contract for the subject repository.
///
/// Uses `async fn` in trait (AFIT). See the module-level `mod.rs` doc for
/// the dyn-dispatch trade-off.
pub trait SubjectRepo: Send + Sync {
    /// Insert a new subject. Returns the materialized [`Subject`] including
    /// server-assigned `id`, `first_seen_by_mod`, and `risk_signals`.
    fn insert(
        &self,
        new: NewSubject,
    ) -> impl std::future::Future<Output = Result<Subject, RepoError>> + Send;

    /// Look up a subject by id. Returns `Ok(None)` when no row matches.
    fn get(
        &self,
        id: SubjectId,
    ) -> impl std::future::Future<Output = Result<Option<Subject>, RepoError>> + Send;

    /// List subjects, optionally filtered by `kind`, capped at `limit` rows.
    /// Results are ordered newest-`first_seen_by_mod` first.
    fn list(
        &self,
        kind: Option<SubjectKind>,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Subject>, RepoError>> + Send;
}

/// Postgres-backed [`SubjectRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgSubjectRepo {
    pool: PgPool,
}

impl PgSubjectRepo {
    /// Build a [`PgSubjectRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl SubjectRepo for PgSubjectRepo {
    async fn insert(&self, new: NewSubject) -> Result<Subject, RepoError> {
        let kind_str = new.kind.as_str();
        let did_str = new.did.as_ref().map(Did::as_str);
        let uri_str = new.uri.as_ref().map(AtUri::as_str);
        let row = sqlx::query!(
            r#"
            INSERT INTO subjects (kind, did, uri, created_at)
            VALUES ($1, $2, $3, $4)
            RETURNING id, kind, did, uri, created_at, first_seen_by_mod, risk_signals
            "#,
            kind_str,
            did_str,
            uri_str,
            new.created_at,
        )
        .fetch_one(&self.pool)
        .await?;

        let kind = decode_kind(&row.kind)?;
        let risk_signals = decode_signals(&row.risk_signals)?;
        Ok(Subject {
            id: SubjectId(row.id),
            kind,
            did: row.did.map(Did::new),
            uri: row.uri.map(AtUri::new),
            created_at: row.created_at,
            first_seen_by_mod: row.first_seen_by_mod,
            risk_signals,
        })
    }

    async fn get(&self, id: SubjectId) -> Result<Option<Subject>, RepoError> {
        let row = sqlx::query!(
            r#"
            SELECT id, kind, did, uri, created_at, first_seen_by_mod, risk_signals
            FROM subjects
            WHERE id = $1
            "#,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        let kind = decode_kind(&row.kind)?;
        let risk_signals = decode_signals(&row.risk_signals)?;
        Ok(Some(Subject {
            id: SubjectId(row.id),
            kind,
            did: row.did.map(Did::new),
            uri: row.uri.map(AtUri::new),
            created_at: row.created_at,
            first_seen_by_mod: row.first_seen_by_mod,
            risk_signals,
        }))
    }

    async fn list(&self, kind: Option<SubjectKind>, limit: i64) -> Result<Vec<Subject>, RepoError> {
        // The kind filter is expressed as `$1 IS NULL OR kind = $1` so a
        // single compile-checked query covers both the filtered and
        // unfiltered cases. Postgres is smart enough to prune the
        // `IS NULL OR` branch at plan time when a concrete kind is supplied.
        let kind_str = kind.map(SubjectKind::as_str);
        let rows = sqlx::query!(
            r#"
            SELECT id, kind, did, uri, created_at, first_seen_by_mod, risk_signals
            FROM subjects
            WHERE $1::text IS NULL OR kind = $1
            ORDER BY first_seen_by_mod DESC
            LIMIT $2
            "#,
            kind_str,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut subjects = Vec::with_capacity(rows.len());
        for row in rows {
            let kind = decode_kind(&row.kind)?;
            let risk_signals = decode_signals(&row.risk_signals)?;
            subjects.push(Subject {
                id: SubjectId(row.id),
                kind,
                did: row.did.map(Did::new),
                uri: row.uri.map(AtUri::new),
                created_at: row.created_at,
                first_seen_by_mod: row.first_seen_by_mod,
                risk_signals,
            });
        }
        Ok(subjects)
    }
}

// ── private decoders ────────────────────────────────────────────────────
// These keep the DB column shape (raw TEXT / JSONB) out of the public
// surface. A schema-drift surface (e.g. a kind string outside the CHECK
// constraint set) becomes `RepoError::Decode` instead of a runtime panic.

fn decode_kind(value: &str) -> Result<SubjectKind, RepoError> {
    SubjectKind::from_wire(value).ok_or_else(|| RepoError::Decode {
        message: format!("subjects.kind={value:?} not in polaris-types contract"),
    })
}

fn decode_signals(value: &serde_json::Value) -> Result<Vec<Signal>, RepoError> {
    serde_json::from_value(value.clone()).map_err(|e| RepoError::Decode {
        message: format!("subjects.risk_signals JSONB decode failed: {e}"),
    })
}
