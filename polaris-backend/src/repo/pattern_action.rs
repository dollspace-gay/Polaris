//! Pattern-action repository (issue #21).
//!
//! Backs the bulk-on-pattern endpoints (design.md §5.3). The header row in
//! `pattern_actions` carries the selector + action template + workflow
//! state; `pattern_action_signatures` is the co-sign audit trail;
//! `pattern_action_subjects` is the materialised affected-subject set.
//!
//! # Transaction shape
//!
//! Header insertion is a single-statement operation (`insert_header`).
//! The cosign endpoint requires multiple coordinated writes (record
//! signature → insert subjects → insert per-subject Action rows → flip
//! status); that orchestration lives in
//! [`crate::api::pattern_actions::execute_pattern_action`] and is driven
//! through `sqlx::Transaction` directly so the all-or-nothing rollback
//! covers every write. The repo deliberately does NOT take a `&Pool` on
//! the transactional path — see the helper functions in
//! [`crate::api::pattern_actions`].

use chrono::{DateTime, Utc};
use polaris_types::{ActionKind, LabelValue, ModeratorId, PatternActionId, PolicyId};
use sqlx::PgPool;

use super::RepoError;
use crate::auth::ModeratorId as AuthModeratorId;

/// Workflow state for a pattern-action header row.
///
/// Mirrors the `pattern_actions.status` CHECK constraint in migration 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternActionStatus {
    /// Header inserted; awaiting cosign or about-to-auto-execute.
    Proposed,
    /// Transaction is in flight (reserved for future async execution paths).
    Executing,
    /// Per-subject Action rows have been inserted.
    Executed,
    /// The proposal was cancelled before execution.
    Cancelled,
}

impl PatternActionStatus {
    /// Wire/DB string. Matches the CHECK constraint values.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Executing => "executing",
            Self::Executed => "executed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Parse from wire/DB form. Returns `None` on unknown input.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "proposed" => Some(Self::Proposed),
            "executing" => Some(Self::Executing),
            "executed" => Some(Self::Executed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// Caller-supplied fields for inserting a pattern-action header.
///
/// `selector_data` is the JSON-encoded per-variant payload of the typed
/// `PatternSelector` enum (carried as `serde_json::Value` so the repo
/// stays free of the API-layer enum's serde shape).
#[derive(Debug, Clone)]
pub struct NewPatternActionHeader {
    /// Selector kind discriminator (`image_hash_cluster`, `account_cohort`,
    /// `anomaly_bucket`).
    pub selector_kind: &'static str,
    /// Typed JSON payload for the selector.
    pub selector_data: serde_json::Value,
    /// Action template — same set as `ActionKind` minus `Reverse`.
    pub action_kind: ActionKind,
    /// Label value, only meaningful when `action_kind = Label`.
    pub label_value: Option<LabelValue>,
    /// Free-text reasoning (must be ≥ 10 chars; DB CHECK enforces).
    pub reasoning: String,
    /// Policy refs cited.
    pub policy_refs: Vec<PolicyId>,
    /// Snapshot of the propose-time affected-subject count.
    pub affected_subject_count: usize,
    /// Whether this proposal needs a senior co-sign before execution.
    pub requires_cosign: bool,
    /// The moderator who proposed the action.
    pub requested_by: ModeratorId,
}

/// A `pattern_actions` row.
///
/// Returned by [`PatternActionRepo::get`] and the listing methods. The
/// `selector_data` field is the raw JSON; consumers convert back to the
/// typed `PatternSelector` enum at the API layer.
#[derive(Debug, Clone)]
pub struct PatternActionRow {
    /// Primary key.
    pub id: PatternActionId,
    /// Selector kind discriminator.
    pub selector_kind: String,
    /// Typed selector JSON payload.
    pub selector_data: serde_json::Value,
    /// Action verb.
    pub action_kind: ActionKind,
    /// Label value, when `action_kind = Label`.
    pub label_value: Option<LabelValue>,
    /// Reasoning.
    pub reasoning: String,
    /// Policy refs cited.
    pub policy_refs: Vec<PolicyId>,
    /// Propose-time affected-subject count.
    pub affected_subject_count: i32,
    /// Whether the proposal requires a senior co-sign.
    pub requires_cosign: bool,
    /// Workflow state.
    pub status: PatternActionStatus,
    /// Proposer.
    pub requested_by: ModeratorId,
    /// Propose-time timestamp.
    pub requested_at: DateTime<Utc>,
    /// Execute-time timestamp (`None` while `status != Executed`).
    pub executed_at: Option<DateTime<Utc>>,
}

/// Compile-time contract for the pattern-action repository.
///
/// Mutating methods do single-statement work; the multi-statement
/// execute path (subjects + per-subject Actions + status flip) lives in
/// the API helpers and goes through `sqlx::Transaction` directly so the
/// rollback covers every row.
pub trait PatternActionRepo: Send + Sync {
    /// Insert a header row. Returns the assigned [`PatternActionId`].
    fn insert_header(
        &self,
        new: NewPatternActionHeader,
    ) -> impl std::future::Future<Output = Result<PatternActionId, RepoError>> + Send;

    /// Look up a header by id.
    fn get(
        &self,
        id: PatternActionId,
    ) -> impl std::future::Future<Output = Result<Option<PatternActionRow>, RepoError>> + Send;

    /// Record a senior signature against `pattern_action_id`. Duplicate
    /// signatures by the same moderator surface as
    /// [`RepoError::UniqueViolation`] via the composite PK.
    fn record_signature(
        &self,
        pattern_action_id: PatternActionId,
        signer_id: AuthModeratorId,
    ) -> impl std::future::Future<Output = Result<(), RepoError>> + Send;

    /// List proposals waiting on a senior co-sign — the senior dashboard
    /// surface. Ordered oldest-first so the queue drains in FIFO order.
    fn list_pending_cosign(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<PatternActionRow>, RepoError>> + Send;
}

/// Postgres-backed [`PatternActionRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgPatternActionRepo {
    pool: PgPool,
}

impl PgPatternActionRepo {
    /// Build a [`PgPatternActionRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl PatternActionRepo for PgPatternActionRepo {
    async fn insert_header(
        &self,
        new: NewPatternActionHeader,
    ) -> Result<PatternActionId, RepoError> {
        let action_kind_str = new.action_kind.as_str();
        let label_str = new.label_value.as_ref().map(LabelValue::as_str);
        let policy_refs: Vec<String> = new
            .policy_refs
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect();
        let count_i32 =
            i32::try_from(new.affected_subject_count).map_err(|_| RepoError::Decode {
                message: format!(
                    "affected_subject_count={} exceeds i32::MAX",
                    new.affected_subject_count
                ),
            })?;
        let row = sqlx::query!(
            r#"
            INSERT INTO pattern_actions (
                selector_kind, selector_data, action_kind, label_value,
                reasoning, policy_refs, affected_subject_count, requires_cosign,
                requested_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
            "#,
            new.selector_kind,
            new.selector_data,
            action_kind_str,
            label_str,
            new.reasoning,
            &policy_refs,
            count_i32,
            new.requires_cosign,
            new.requested_by.0,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(PatternActionId(row.id))
    }

    async fn get(&self, id: PatternActionId) -> Result<Option<PatternActionRow>, RepoError> {
        let row = sqlx::query!(
            r#"
            SELECT id, selector_kind, selector_data, action_kind, label_value,
                   reasoning, policy_refs, affected_subject_count,
                   requires_cosign, status, requested_by, requested_at,
                   executed_at
            FROM pattern_actions
            WHERE id = $1
            "#,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let action_kind =
            ActionKind::from_wire(&row.action_kind).ok_or_else(|| RepoError::Decode {
                message: format!("pattern_actions.action_kind={:?}", row.action_kind),
            })?;
        let status =
            PatternActionStatus::from_wire(&row.status).ok_or_else(|| RepoError::Decode {
                message: format!("pattern_actions.status={:?}", row.status),
            })?;
        Ok(Some(PatternActionRow {
            id: PatternActionId(row.id),
            selector_kind: row.selector_kind,
            selector_data: row.selector_data,
            action_kind,
            label_value: row.label_value.map(LabelValue::new),
            reasoning: row.reasoning,
            policy_refs: row.policy_refs.into_iter().map(PolicyId::new).collect(),
            affected_subject_count: row.affected_subject_count,
            requires_cosign: row.requires_cosign,
            status,
            requested_by: ModeratorId(row.requested_by),
            requested_at: row.requested_at,
            executed_at: row.executed_at,
        }))
    }

    async fn record_signature(
        &self,
        pattern_action_id: PatternActionId,
        signer_id: AuthModeratorId,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            INSERT INTO pattern_action_signatures (pattern_action_id, signing_moderator_id)
            VALUES ($1, $2)
            "#,
            pattern_action_id.0,
            signer_id.0,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_pending_cosign(&self) -> Result<Vec<PatternActionRow>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, selector_kind, selector_data, action_kind, label_value,
                   reasoning, policy_refs, affected_subject_count,
                   requires_cosign, status, requested_by, requested_at,
                   executed_at
            FROM pattern_actions
            WHERE requires_cosign = TRUE AND status = 'proposed'
            ORDER BY requested_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let action_kind =
                ActionKind::from_wire(&row.action_kind).ok_or_else(|| RepoError::Decode {
                    message: format!("pattern_actions.action_kind={:?}", row.action_kind),
                })?;
            let status =
                PatternActionStatus::from_wire(&row.status).ok_or_else(|| RepoError::Decode {
                    message: format!("pattern_actions.status={:?}", row.status),
                })?;
            out.push(PatternActionRow {
                id: PatternActionId(row.id),
                selector_kind: row.selector_kind,
                selector_data: row.selector_data,
                action_kind,
                label_value: row.label_value.map(LabelValue::new),
                reasoning: row.reasoning,
                policy_refs: row.policy_refs.into_iter().map(PolicyId::new).collect(),
                affected_subject_count: row.affected_subject_count,
                requires_cosign: row.requires_cosign,
                status,
                requested_by: ModeratorId(row.requested_by),
                requested_at: row.requested_at,
                executed_at: row.executed_at,
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
    fn status_round_trips_through_wire() {
        for s in [
            PatternActionStatus::Proposed,
            PatternActionStatus::Executing,
            PatternActionStatus::Executed,
            PatternActionStatus::Cancelled,
        ] {
            assert_eq!(PatternActionStatus::from_wire(s.as_str()), Some(s));
        }
    }

    #[test]
    fn status_from_wire_rejects_unknown() {
        assert_eq!(PatternActionStatus::from_wire("unknown"), None);
        assert_eq!(PatternActionStatus::from_wire(""), None);
    }
}
