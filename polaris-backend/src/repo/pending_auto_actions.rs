//! Repository layer for the assisted-mode draft queue
//! (`pending_auto_actions` table, migration 50).
//!
//! Backs the LLM-7 (#236) queue endpoints. Three flows:
//!
//! 1. **List** — moderator opens the queue: paginated current-pending
//!    drafts (with their backing `LlmRecommendation` observation
//!    reference) keyed on `(created_at DESC, id DESC)`.
//! 2. **Approve** — moderator approves a draft: state transitions
//!    `pending → approved`, `resolved_at = now()`. The action insert
//!    itself is the caller's responsibility (the handler owns the
//!    cross-table transaction; this repo only owns the queue-row
//!    transition).
//! 3. **Reject** — moderator rejects a draft: state transitions
//!    `pending → rejected`, `resolved_at = now()`. The caller fires
//!    the feedback hook (`fire_assisted_reject_feedback`) separately.
//!
//! Plus a fourth maintenance flow:
//!
//! 4. **Expire** — daily sweep transitions stale `pending` rows
//!    whose `expires_at` lapsed to `expired`. Returns the count of
//!    rows transitioned so an observability metric can increment.
//!
//! The state machine + the partial indexes on migration 50 are
//! the contract; if you add a state or relax the lifecycle, the
//! SQL `CHECK` constraint and the index predicates here all need
//! updating in lock-step.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Transaction, postgres::Postgres};
use thiserror::Error;
use uuid::Uuid;

/// Default page size when the operator does not supply `?limit=`.
/// Matches the admin-audit list convention (REQ-F4) so the queue UI
/// and the audit page paginate at the same rate.
pub const DEFAULT_LIMIT: i64 = 50;

/// Hard upper bound on a single page so a runaway query cannot
/// exhaust the connection pool. Same ceiling as the audit list.
pub const MAX_LIMIT: i64 = 200;

/// Lifecycle state of a `pending_auto_actions` row.
///
/// Matches the SQL `CHECK (state IN ('pending', 'approved',
/// 'rejected', 'superseded', 'expired'))` constraint on migration 50.
/// The wire form is the lowercase string the constraint accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingAutoActionState {
    /// Draft waiting for moderator review.
    Pending,
    /// Moderator approved the draft; an action row was committed
    /// against the same transaction.
    Approved,
    /// Moderator rejected the draft. No action emitted.
    Rejected,
    /// Newer recommendation invalidated this draft (dispatcher
    /// rewrites — not used in this issue, reserved for LLM-11
    /// re-recommendation flow).
    Superseded,
    /// `expires_at` lapsed without moderator action.
    Expired,
}

impl PendingAutoActionState {
    /// Wire / SQL string form (`'pending'`, `'approved'`, …).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Expired => "expired",
        }
    }

    /// Parse from the wire / SQL string form. Unknown variants
    /// surface as `PendingAutoActionError::UnknownState` rather
    /// than panic.
    ///
    /// # Errors
    /// Returns `PendingAutoActionError::UnknownState` when `raw`
    /// is not one of the five lifecycle constants.
    pub fn parse(raw: &str) -> Result<Self, PendingAutoActionError> {
        match raw {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "superseded" => Ok(Self::Superseded),
            "expired" => Ok(Self::Expired),
            _ => Err(PendingAutoActionError::UnknownState(raw.to_owned())),
        }
    }
}

/// A row of `pending_auto_actions` as read by the queue handlers.
///
/// `recommended_action` and `cited_policy_versions` are the verbatim
/// JSONB payloads — typed by the caller via `serde_json::from_value`
/// against the appropriate shape. The repo intentionally does not
/// decode them: their schema lives with the LLM dispatcher
/// (#242) and with the workbook citations (#223) respectively, and
/// pinning a decode here would couple this repo to those shapes.
#[derive(Debug, Clone)]
pub struct PendingAutoAction {
    /// Surrogate primary key for the queue row.
    pub id: Uuid,
    /// The incident this draft is suggesting an action against.
    pub incident_id: Uuid,
    /// The subject the proposed action targets (denormalized off the
    /// incident for cheap pagination + cheaper UI rendering).
    pub subject_id: Uuid,
    /// Verbatim JSONB payload describing the LLM's recommended
    /// action. Decoded by the handler against the
    /// `recommend_dispatcher` shape; not interpreted here.
    pub recommended_action: serde_json::Value,
    /// Foreign-key to the `LlmRecommendation` observation that
    /// produced this draft — used to wire approve/reject feedback
    /// back to the LLM substrate.
    pub llm_observation_id: Uuid,
    /// Verbatim JSONB array of `(policy_identifier, version)` pairs
    /// the LLM cited. Frozen at draft-creation time so the moderator
    /// sees exactly what the LLM saw, even if the workbook is edited
    /// between recommendation and review.
    pub cited_policy_versions: serde_json::Value,
    /// Current lifecycle state (`pending`, `approved`, `rejected`,
    /// `superseded`, `expired`).
    pub state: PendingAutoActionState,
    /// Moderator who picked up the draft (claim-on-view). `None`
    /// while it is unclaimed in the queue.
    pub claimed_by_moderator_id: Option<Uuid>,
    /// Wall-clock time the draft was inserted.
    pub created_at: DateTime<Utc>,
    /// Wall-clock time the draft transitioned out of `pending`.
    /// `None` while still pending.
    pub resolved_at: Option<DateTime<Utc>>,
    /// Hard expiry — sweep transitions rows past this to `expired`.
    pub expires_at: DateTime<Utc>,
}

impl std::fmt::Display for PendingAutoActionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors the queue repo emits.
#[derive(Debug, Error)]
pub enum PendingAutoActionError {
    /// Draft not found (already resolved, already expired, or
    /// never existed).
    #[error("pending_auto_actions row not found: {0}")]
    NotFound(Uuid),

    /// State transition refused — the draft is no longer in the
    /// `pending` state the caller expected.
    #[error("pending_auto_actions row {id} is in state {current}, expected {expected}")]
    InvalidTransition {
        /// Primary key of the offending row.
        id: Uuid,
        /// State the row was found in.
        current: PendingAutoActionState,
        /// State the caller required for the transition to be legal.
        expected: PendingAutoActionState,
    },

    /// SQL `state` column held a value not in the lifecycle enum.
    /// Shouldn't happen given the `CHECK` constraint, but the
    /// decoder still maps it explicitly rather than panicking.
    #[error("unknown pending_auto_actions state: {0:?}")]
    UnknownState(String),

    /// Underlying SQL failure (connection / query / decode).
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// List pending drafts, newest-first, paginated by keyset on
/// `(created_at DESC, id DESC)`.
///
/// `limit` is clamped to `[1, MAX_LIMIT]`; the caller is expected to
/// have applied [`DEFAULT_LIMIT`] already if no query param was set.
///
/// # Errors
/// Returns `PendingAutoActionError::Database` on SQL failure.
pub async fn list_pending(
    pool: &PgPool,
    limit: i64,
    cursor: Option<(DateTime<Utc>, Uuid)>,
) -> Result<Vec<PendingAutoAction>, PendingAutoActionError> {
    let limit = limit.clamp(1, MAX_LIMIT);
    let (cur_ts, cur_id) = cursor.unzip();
    let cur_ts_opt = cur_ts;
    let cur_id_opt = cur_id;

    let rows = sqlx::query!(
        r"
        SELECT id, incident_id, subject_id, recommended_action,
               llm_observation_id, cited_policy_versions, state,
               claimed_by_moderator_id, created_at, resolved_at,
               expires_at
          FROM pending_auto_actions
         WHERE state = 'pending'
           AND ($1::timestamptz IS NULL
                OR (created_at, id) < ($1, $2))
         ORDER BY created_at DESC, id DESC
         LIMIT $3
        ",
        cur_ts_opt,
        cur_id_opt,
        limit,
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|r| {
            Ok(PendingAutoAction {
                id: r.id,
                incident_id: r.incident_id,
                subject_id: r.subject_id,
                recommended_action: r.recommended_action,
                llm_observation_id: r.llm_observation_id,
                cited_policy_versions: r.cited_policy_versions,
                state: PendingAutoActionState::parse(&r.state)?,
                claimed_by_moderator_id: r.claimed_by_moderator_id,
                created_at: r.created_at,
                resolved_at: r.resolved_at,
                expires_at: r.expires_at,
            })
        })
        .collect()
}

/// Fetch a single draft by id, regardless of state.
///
/// # Errors
/// Returns `PendingAutoActionError::NotFound` if no row matches.
pub async fn get(pool: &PgPool, id: Uuid) -> Result<PendingAutoAction, PendingAutoActionError> {
    let r = sqlx::query!(
        r"
        SELECT id, incident_id, subject_id, recommended_action,
               llm_observation_id, cited_policy_versions, state,
               claimed_by_moderator_id, created_at, resolved_at,
               expires_at
          FROM pending_auto_actions
         WHERE id = $1
        ",
        id,
    )
    .fetch_optional(pool)
    .await?
    .ok_or(PendingAutoActionError::NotFound(id))?;

    Ok(PendingAutoAction {
        id: r.id,
        incident_id: r.incident_id,
        subject_id: r.subject_id,
        recommended_action: r.recommended_action,
        llm_observation_id: r.llm_observation_id,
        cited_policy_versions: r.cited_policy_versions,
        state: PendingAutoActionState::parse(&r.state)?,
        claimed_by_moderator_id: r.claimed_by_moderator_id,
        created_at: r.created_at,
        resolved_at: r.resolved_at,
        expires_at: r.expires_at,
    })
}

/// Mark a draft `approved` inside the caller's transaction. Returns
/// the prior state on success so the handler can verify nothing
/// raced past it.
///
/// The action-create that landed against this approval is the
/// caller's responsibility — this repo only owns the queue row.
/// The transaction the caller passes should include both the action
/// insert AND this update so they commit atomically (REQ-E3).
///
/// # Errors
/// * `InvalidTransition` if the row is not currently `pending`.
/// * `NotFound` if no row matches.
/// * `Database` on SQL failure.
pub async fn approve_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: Uuid,
) -> Result<PendingAutoAction, PendingAutoActionError> {
    let row = sqlx::query!(
        r"
        SELECT state FROM pending_auto_actions
         WHERE id = $1
         FOR UPDATE
        ",
        id,
    )
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(PendingAutoActionError::NotFound(id))?;

    let current = PendingAutoActionState::parse(&row.state)?;
    if current != PendingAutoActionState::Pending {
        return Err(PendingAutoActionError::InvalidTransition {
            id,
            current,
            expected: PendingAutoActionState::Pending,
        });
    }

    sqlx::query!(
        r"
        UPDATE pending_auto_actions
           SET state = 'approved', resolved_at = now()
         WHERE id = $1
        ",
        id,
    )
    .execute(&mut **tx)
    .await?;

    // Re-read the row so the caller sees the final shape (state +
    // resolved_at populated).
    let r = sqlx::query!(
        r"
        SELECT id, incident_id, subject_id, recommended_action,
               llm_observation_id, cited_policy_versions, state,
               claimed_by_moderator_id, created_at, resolved_at,
               expires_at
          FROM pending_auto_actions
         WHERE id = $1
        ",
        id,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(PendingAutoAction {
        id: r.id,
        incident_id: r.incident_id,
        subject_id: r.subject_id,
        recommended_action: r.recommended_action,
        llm_observation_id: r.llm_observation_id,
        cited_policy_versions: r.cited_policy_versions,
        state: PendingAutoActionState::parse(&r.state)?,
        claimed_by_moderator_id: r.claimed_by_moderator_id,
        created_at: r.created_at,
        resolved_at: r.resolved_at,
        expires_at: r.expires_at,
    })
}

/// Mark a draft `rejected`. Single-shot (no caller-supplied tx) —
/// rejection doesn't require atomicity with another table because
/// the feedback fire-and-forget happens outside the SQL boundary.
///
/// # Errors
/// * `InvalidTransition` if the row is not currently `pending`.
/// * `NotFound` if no row matches.
pub async fn reject(pool: &PgPool, id: Uuid) -> Result<PendingAutoAction, PendingAutoActionError> {
    let mut tx = pool.begin().await?;

    let row = sqlx::query!(
        r"SELECT state FROM pending_auto_actions WHERE id = $1 FOR UPDATE",
        id,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(PendingAutoActionError::NotFound(id))?;

    let current = PendingAutoActionState::parse(&row.state)?;
    if current != PendingAutoActionState::Pending {
        return Err(PendingAutoActionError::InvalidTransition {
            id,
            current,
            expected: PendingAutoActionState::Pending,
        });
    }

    sqlx::query!(
        r"UPDATE pending_auto_actions
             SET state = 'rejected', resolved_at = now()
           WHERE id = $1",
        id,
    )
    .execute(&mut *tx)
    .await?;

    let r = sqlx::query!(
        r"
        SELECT id, incident_id, subject_id, recommended_action,
               llm_observation_id, cited_policy_versions, state,
               claimed_by_moderator_id, created_at, resolved_at,
               expires_at
          FROM pending_auto_actions
         WHERE id = $1
        ",
        id,
    )
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(PendingAutoAction {
        id: r.id,
        incident_id: r.incident_id,
        subject_id: r.subject_id,
        recommended_action: r.recommended_action,
        llm_observation_id: r.llm_observation_id,
        cited_policy_versions: r.cited_policy_versions,
        state: PendingAutoActionState::parse(&r.state)?,
        claimed_by_moderator_id: r.claimed_by_moderator_id,
        created_at: r.created_at,
        resolved_at: r.resolved_at,
        expires_at: r.expires_at,
    })
}

/// Sweep: transition all `pending` rows whose `expires_at` lapsed to
/// `expired`. Returns the count of rows transitioned. Idempotent —
/// re-running is a no-op once every stale row has aged out.
///
/// # Errors
/// Returns `PendingAutoActionError::Database` on SQL failure.
pub async fn expire_old(pool: &PgPool) -> Result<u64, PendingAutoActionError> {
    let result = sqlx::query!(
        r"
        UPDATE pending_auto_actions
           SET state = 'expired', resolved_at = now()
         WHERE state = 'pending'
           AND expires_at < now()
        ",
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7"
)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_via_wire_string() {
        for s in [
            PendingAutoActionState::Pending,
            PendingAutoActionState::Approved,
            PendingAutoActionState::Rejected,
            PendingAutoActionState::Superseded,
            PendingAutoActionState::Expired,
        ] {
            assert_eq!(PendingAutoActionState::parse(s.as_str()).unwrap(), s);
        }
    }

    #[test]
    fn unknown_state_string_surfaces_as_typed_error() {
        let err = PendingAutoActionState::parse("nonsense").unwrap_err();
        assert!(matches!(err, PendingAutoActionError::UnknownState(s) if s == "nonsense"));
    }
}
