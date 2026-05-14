//! Appeal repository + calibration-event repository (issue #24).
//!
//! Maps [`polaris_types::AppealStatus`] / [`polaris_types::CalibrationEvent`]
//! to and from the row shapes in `00000000000010_appeals.sql`.
//!
//! # State machine on writes
//!
//! [`AppealRepo::update_status`] runs the transition through
//! [`polaris_types::AppealStatus::transition_to`] *before* the SQL UPDATE
//! fires. Invalid transitions surface as [`RepoError::Decode`] with the
//! state pair in the message; valid transitions reach the DB. The DB CHECK
//! constraint is defense-in-depth — a bypass at the application layer
//! (direct `sqlx::query`) still cannot persist an out-of-band value.
//!
//! # Append-only stays intact
//!
//! Reversal-on-appeal is written through the existing `actions` insert
//! path (see [`crate::api::appeals`]). This module never `UPDATE`s the
//! `actions` table — the trigger from migration 4 enforces that
//! invariant unconditionally.

use chrono::{DateTime, Utc};
use polaris_types::{
    ActionId, AppealId, AppealStatus, CalibrationEvent, CalibrationEventKind, ModeratorId,
};
use sqlx::PgPool;

use super::RepoError;

/// Caller-supplied fields for inserting a new appeal row.
///
/// `id`, `status`, and `opened_at` are populated server-side via
/// DEFAULTs. `assigned_to`, `decided_at`, `decision_reasoning` are
/// `None` at insert time.
#[derive(Debug, Clone)]
pub struct NewAppeal {
    /// The action this appeal targets.
    pub appealed_action_id: ActionId,
    /// Appellant's free-text statement. Must be in `[1, 4096]` chars;
    /// the API layer validates length, the DB CHECK enforces the same
    /// bound as defense in depth.
    pub appellant_statement: String,
    /// SHA-256 hash of the source IP (32 bytes). The API layer
    /// computes the hash; the repo just stores it.
    pub appellant_ip_hash: [u8; 32],
}

/// A row from the `appeals` table.
///
/// Mirrors the column layout 1:1; `polaris_types` does not own this
/// shape because the calibration view in #24 is a backend-only concept
/// (no frontend surface in this issue).
#[derive(Debug, Clone, PartialEq)]
pub struct AppealRow {
    /// Primary key.
    pub id: AppealId,
    /// The action this appeal targets.
    pub appealed_action_id: ActionId,
    /// Appellant's free-text statement.
    pub appellant_statement: String,
    /// SHA-256 hash of the source IP (32 bytes). Re-emitted on reads
    /// for the rate-limit accounting path even though the API does not
    /// expose it on the wire.
    pub appellant_ip_hash: Vec<u8>,
    /// Workflow state. Already decoded from the DB string.
    pub status: AppealStatus,
    /// Currently-assigned reviewer (`None` while `status = Open`).
    pub assigned_to: Option<ModeratorId>,
    /// When the appeal was decided (`None` until terminal).
    pub decided_at: Option<DateTime<Utc>>,
    /// Reviewer's reasoning on the decision.
    pub decision_reasoning: Option<String>,
    /// When the appeal was submitted.
    pub opened_at: DateTime<Utc>,
}

/// Compile-time contract for the appeal repository.
pub trait AppealRepo: Send + Sync {
    /// Insert a new appeal row.
    fn insert(
        &self,
        new: NewAppeal,
    ) -> impl std::future::Future<Output = Result<AppealId, RepoError>> + Send;

    /// Look up a single appeal by id. `Ok(None)` when no row matches.
    fn get(
        &self,
        id: AppealId,
    ) -> impl std::future::Future<Output = Result<Option<AppealRow>, RepoError>> + Send;

    /// Count appeal submissions from the given IP hash since `since`.
    /// Used by the rate-limit fallback path (the in-memory ledger is the
    /// primary surface; this is the persistent backstop).
    fn count_recent_for_ip(
        &self,
        ip_hash: &[u8],
        since: DateTime<Utc>,
    ) -> impl std::future::Future<Output = Result<i64, RepoError>> + Send;

    /// List appeals waiting on routing — `status = 'open'`. Ordered
    /// oldest-first so the queue drains FIFO.
    fn list_pending_for_routing(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<AppealRow>, RepoError>> + Send;

    /// Assign an appeal to a reviewer.
    ///
    /// Transitions [`AppealStatus::Open`] → [`AppealStatus::Assigned`].
    /// Returns [`RepoError::Decode`] with the offending state pair when
    /// the current status is not `Open`; the same error variant is used
    /// for invalid transitions because that's how
    /// [`AppealStatus::transition_to`] failures surface through the repo.
    fn assign(
        &self,
        id: AppealId,
        reviewer: ModeratorId,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;

    /// Apply a terminal decision to an appeal.
    ///
    /// Transitions [`AppealStatus::Assigned`] → the matching terminal
    /// state (`DecidedReversed` / `DecidedUpheld`). The transition is
    /// validated by [`AppealStatus::transition_to`] *before* the SQL
    /// UPDATE fires; an invalid `current → new` move returns
    /// [`RepoError::Decode`] without writing.
    fn record_decision(
        &self,
        id: AppealId,
        new_status: AppealStatus,
        decided_at: DateTime<Utc>,
        decision_reasoning: String,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;
}

/// Compile-time contract for the calibration-event repository.
pub trait CalibrationEventRepo: Send + Sync {
    /// Record an `AppealReversal` event on `moderator_id`'s stream.
    fn record_appeal_reversal(
        &self,
        moderator_id: ModeratorId,
        original_action_id: ActionId,
        appeal_id: AppealId,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;

    /// List the most recent `limit` calibration events for `moderator_id`,
    /// newest first.
    fn list_for_moderator(
        &self,
        moderator_id: ModeratorId,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<CalibrationEvent>, RepoError>> + Send;
}

/// Postgres-backed [`AppealRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgAppealRepo {
    pool: PgPool,
}

impl PgAppealRepo {
    /// Build a [`PgAppealRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AppealRepo for PgAppealRepo {
    async fn insert(&self, new: NewAppeal) -> Result<AppealId, RepoError> {
        let ip_hash: &[u8] = new.appellant_ip_hash.as_ref();
        let row = sqlx::query!(
            r#"
            INSERT INTO appeals (
                appealed_action_id, appellant_statement, appellant_ip_hash
            )
            VALUES ($1, $2, $3)
            RETURNING id
            "#,
            new.appealed_action_id.0,
            new.appellant_statement,
            ip_hash,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(AppealId(row.id))
    }

    async fn get(&self, id: AppealId) -> Result<Option<AppealRow>, RepoError> {
        let row = sqlx::query!(
            r#"
            SELECT id, appealed_action_id, appellant_statement, appellant_ip_hash,
                   status, assigned_to, decided_at, decision_reasoning, opened_at
            FROM appeals
            WHERE id = $1
            "#,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let status = AppealStatus::from_wire(&row.status).ok_or_else(|| RepoError::Decode {
            message: format!(
                "appeals.status={:?} not in polaris-types contract",
                row.status
            ),
        })?;
        Ok(Some(AppealRow {
            id: AppealId(row.id),
            appealed_action_id: ActionId(row.appealed_action_id),
            appellant_statement: row.appellant_statement,
            appellant_ip_hash: row.appellant_ip_hash,
            status,
            assigned_to: row.assigned_to.map(ModeratorId),
            decided_at: row.decided_at,
            decision_reasoning: row.decision_reasoning,
            opened_at: row.opened_at,
        }))
    }

    async fn count_recent_for_ip(
        &self,
        ip_hash: &[u8],
        since: DateTime<Utc>,
    ) -> Result<i64, RepoError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!"
            FROM appeals
            WHERE appellant_ip_hash = $1
              AND opened_at >= $2
            "#,
            ip_hash,
            since,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row.count)
    }

    async fn list_pending_for_routing(&self) -> Result<Vec<AppealRow>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, appealed_action_id, appellant_statement, appellant_ip_hash,
                   status, assigned_to, decided_at, decision_reasoning, opened_at
            FROM appeals
            WHERE status = 'open'
            ORDER BY opened_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let status = AppealStatus::from_wire(&row.status).ok_or_else(|| RepoError::Decode {
                message: format!("appeals.status={:?}", row.status),
            })?;
            out.push(AppealRow {
                id: AppealId(row.id),
                appealed_action_id: ActionId(row.appealed_action_id),
                appellant_statement: row.appellant_statement,
                appellant_ip_hash: row.appellant_ip_hash,
                status,
                assigned_to: row.assigned_to.map(ModeratorId),
                decided_at: row.decided_at,
                decision_reasoning: row.decision_reasoning,
                opened_at: row.opened_at,
            });
        }
        Ok(out)
    }

    async fn assign(&self, id: AppealId, reviewer: ModeratorId) -> Result<(), RepoError> {
        let current = self.get(id).await?.ok_or(RepoError::NotFound)?;
        // Validate the transition via the state machine before touching
        // the DB. Invalid moves surface as Decode (with the offending
        // pair in the message) so the API layer sees a typed signal.
        let next = current
            .status
            .transition_to(AppealStatus::Assigned)
            .map_err(|e: polaris_types::InvalidTransition| RepoError::Decode {
                message: format!("appeal {id} invalid transition: {e}"),
            })?;
        sqlx::query!(
            r#"
            UPDATE appeals
            SET status = $1, assigned_to = $2
            WHERE id = $3
            "#,
            next.as_str(),
            reviewer.0,
            id.0,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_decision(
        &self,
        id: AppealId,
        new_status: AppealStatus,
        decided_at: DateTime<Utc>,
        decision_reasoning: String,
    ) -> Result<(), RepoError> {
        if !new_status.is_terminal() {
            return Err(RepoError::Decode {
                message: format!(
                    "record_decision called with non-terminal status {new_status}; \
                     terminal states are decided_reversed / decided_upheld",
                ),
            });
        }
        let current = self.get(id).await?.ok_or(RepoError::NotFound)?;
        let next = current.status.transition_to(new_status).map_err(
            |e: polaris_types::InvalidTransition| RepoError::Decode {
                message: format!("appeal {id} invalid transition: {e}"),
            },
        )?;
        sqlx::query!(
            r#"
            UPDATE appeals
            SET status = $1, decided_at = $2, decision_reasoning = $3
            WHERE id = $4
            "#,
            next.as_str(),
            decided_at,
            decision_reasoning,
            id.0,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

/// Postgres-backed [`CalibrationEventRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgCalibrationEventRepo {
    pool: PgPool,
}

impl PgCalibrationEventRepo {
    /// Build a [`PgCalibrationEventRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl CalibrationEventRepo for PgCalibrationEventRepo {
    async fn record_appeal_reversal(
        &self,
        moderator_id: ModeratorId,
        original_action_id: ActionId,
        appeal_id: AppealId,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            INSERT INTO calibration_events (
                moderator_id, kind, referenced_action_id, referenced_appeal_id
            )
            VALUES ($1, 'appeal_reversal', $2, $3)
            "#,
            moderator_id.0,
            original_action_id.0,
            appeal_id.0,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_for_moderator(
        &self,
        moderator_id: ModeratorId,
        limit: i64,
    ) -> Result<Vec<CalibrationEvent>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, moderator_id, kind, referenced_action_id,
                   referenced_appeal_id, created_at
            FROM calibration_events
            WHERE moderator_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
            moderator_id.0,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let kind =
                CalibrationEventKind::from_wire(&row.kind).ok_or_else(|| RepoError::Decode {
                    message: format!("calibration_events.kind={:?}", row.kind),
                })?;
            out.push(CalibrationEvent {
                id: row.id,
                moderator_id: ModeratorId(row.moderator_id),
                kind,
                referenced_action_id: row.referenced_action_id.map(ActionId),
                referenced_appeal_id: row.referenced_appeal_id.map(AppealId),
                created_at: row.created_at,
            });
        }
        Ok(out)
    }
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

    #[test]
    fn new_appeal_struct_is_constructible_with_expected_fields() {
        // Compile-time check that the public field set matches the
        // documented contract; the struct is a transport object and a
        // field rename would break callers without this anchor.
        let na = NewAppeal {
            appealed_action_id: ActionId::new(),
            appellant_statement: "I think this was a mistake.".to_owned(),
            appellant_ip_hash: [0_u8; 32],
        };
        assert_eq!(na.appellant_ip_hash.len(), 32);
        assert!(!na.appellant_statement.is_empty());
    }
}
