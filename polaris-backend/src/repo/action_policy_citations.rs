//! Per-action policy citations (#223, WB-1, REQ-B1).
//!
//! Maps the `action_policy_citations` row shape from migration 48
//! onto typed Rust values. Carries the `(action_id, identifier,
//! version)` triple per cited clause; the composite FK back into
//! `mod_policies (identifier, version)` is enforced at the
//! database, so an attempt to insert a citation pointing at a
//! non-existent policy version surfaces as
//! [`super::RepoError::ForeignKey`] via the workspace's standard
//! `sqlx::Error` routing.
//!
//! # Atomicity contract
//!
//! [`insert_for_action`] takes a caller-supplied transaction so
//! the action INSERT and its per-citation INSERTs land — or
//! roll back — as a single unit (REQ-B3). The WB-2 action-create
//! handler is the production caller.
//!
//! # SQL discipline
//!
//! Every query goes through `sqlx::query!` (compile-time-checked).

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use super::RepoError;

/// A single citation row.
///
/// The `policy_identifier` / `policy_version` pair is a snapshot
/// of the cited policy at action-create time — never re-resolved
/// from `mod_policies` at read time, so historical citations are
/// stable under workbook amendment (REQ-B1).
#[derive(Debug, Clone, PartialEq)]
pub struct Citation {
    /// The action this citation belongs to.
    pub action_id: Uuid,
    /// Snapshot of `mod_policies.identifier`.
    pub policy_identifier: String,
    /// Snapshot of `mod_policies.version`.
    pub policy_version: i32,
    /// When the citation was written (same instant as the action's
    /// `created_at` in normal operation).
    pub created_at: DateTime<Utc>,
}

/// Insert one citation row per `(identifier, version)` pair, all
/// pointed at `action_id`.
///
/// The supplied transaction MUST be the same one that inserted the
/// `actions` row this citation set belongs to — otherwise the
/// `ON DELETE CASCADE` from `actions(id)` would race a rollback
/// of the action insert and leave the citations orphaned.
///
/// Duplicate pairs in the input slice would collide on the
/// composite PK; the repo does not deduplicate — the action-create
/// handler is responsible for filtering its input before calling
/// here.
///
/// # Errors
///
/// - [`RepoError::ForeignKey`] when any cited
///   `(identifier, version)` is not a row in `mod_policies`.
/// - [`RepoError::UniqueViolation`] when the input contains a
///   duplicate `(identifier, version)` against the same action.
/// - [`RepoError::Database`] for any other DB-side failure.
///
/// # Example
///
/// ```ignore
/// let mut tx = pool.begin().await?;
/// action_policy_citations::insert_for_action(
///     &mut tx,
///     action_id,
///     &[("polaris.harassment".into(), 3), ("polaris.spam".into(), 1)],
/// )
/// .await?;
/// tx.commit().await?;
/// ```
pub async fn insert_for_action(
    tx: &mut Transaction<'_, Postgres>,
    action_id: Uuid,
    citations: &[(String, i32)],
) -> Result<(), RepoError> {
    if citations.is_empty() {
        return Ok(());
    }

    // Split into parallel arrays so `sqlx::query!` can bind them
    // as SQL arrays for a single UNNEST-driven INSERT. One round
    // trip regardless of how many clauses an action cites.
    let identifiers: Vec<String> = citations.iter().map(|(i, _)| i.clone()).collect();
    let versions: Vec<i32> = citations.iter().map(|(_, v)| *v).collect();

    sqlx::query!(
        r#"
        INSERT INTO action_policy_citations
            (action_id, policy_identifier, policy_version)
        SELECT $1, ident, ver
        FROM UNNEST($2::TEXT[], $3::INTEGER[]) AS u(ident, ver)
        "#,
        action_id,
        &identifiers,
        &versions,
    )
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Return every citation attached to `action_id`, oldest-first
/// by the policy identifier then version.
///
/// The case-view and the audit-log diff renderer call this when
/// rendering the structured-citation block.
///
/// # Errors
///
/// [`RepoError::Database`] on any DB-side failure.
pub async fn citations_for_action(
    pool: &PgPool,
    action_id: Uuid,
) -> Result<Vec<Citation>, RepoError> {
    let rows = sqlx::query!(
        r#"
        SELECT action_id, policy_identifier, policy_version, created_at
        FROM action_policy_citations
        WHERE action_id = $1
        ORDER BY policy_identifier ASC, policy_version ASC
        "#,
        action_id,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| Citation {
            action_id: row.action_id,
            policy_identifier: row.policy_identifier,
            policy_version: row.policy_version,
            created_at: row.created_at,
        })
        .collect())
}
