//! Action repository — append-only audit substrate.
//!
//! Maps [`polaris_types::Action`] / `NewAction` to and from the `actions`
//! row shape in `00000000000004_actions.sql`.
//!
//! # Append-only contract
//!
//! `ActionRepo` exposes only `insert`, `get`, and `list_by_incident`. There
//! is intentionally no `update` method. The Postgres BEFORE UPDATE trigger
//! in migration `00000000000004_actions.sql` rejects any UPDATE against the
//! `actions` table with a PL/pgSQL `RAISE EXCEPTION`; the repo's `From`
//! impl on [`RepoError`] routes the SQLSTATE `P0001` into
//! [`RepoError::AppendOnlyViolation`]. Tests in
//! `tests/actions_append_only.rs` PROVE the invariant by attempting an
//! UPDATE through a raw `sqlx::query` and asserting it fails.
//!
//! # Evidence-job enqueue (issue #33 / REQ-10 / AC-11)
//!
//! [`PgActionRepo::insert`] runs inside a `BEGIN … COMMIT` transaction so
//! the action row and its `evidence_jobs` row commit together. After the
//! INSERT into `actions`, the repo reads the parent `subjects` row to
//! learn the subject's kind + uri; when the subject is record-shaped
//! (anything other than [`polaris_types::SubjectKind::Account`]) and has
//! a non-NULL `uri`, the repo `INSERT … ON CONFLICT (action_id) DO
//! NOTHING`s into `evidence_jobs`. Account-shaped subjects (or record
//! subjects without an AT-URI) are skipped — no job is enqueued.
//!
//! Atomicity matters: if the action commits but the job enqueue is
//! dropped (e.g. a crash between the two statements), the worker can
//! never recover the evidence — the action is committed but no job
//! row exists to drive a snapshot. The transaction makes both
//! statements visible together or neither.

use chrono::{DateTime, Utc};
use polaris_types::{
    Action, ActionId, ActionKind, IncidentId, LabelValue, ModeratorId, PolicyId, SubjectId,
    SubjectKind,
};
use sqlx::PgPool;

use super::RepoError;
use crate::audit::{AuditEvent, AuditLog};

/// Caller-supplied fields for inserting a new [`Action`].
///
/// The repo populates `id`, `created_at`, and leaves `emitted_to_atproto` as
/// `None`. The `reversible_until` window is set by the caller because the
/// policy on its computation (24h for regular moderators, longer for seniors
/// per `design.md` §5.5) is a service-layer concern.
#[derive(Debug, Clone)]
pub struct NewAction {
    /// Incident this action belongs to.
    pub incident_id: IncidentId,
    /// Subject this action targets.
    pub subject_id: SubjectId,
    /// Moderator recording the action.
    pub moderator_id: ModeratorId,
    /// Action verb.
    pub kind: ActionKind,
    /// Label value, when `kind = Label`.
    pub label: Option<LabelValue>,
    /// Reasoning. Must be at least 10 chars (DB CHECK enforces).
    pub reasoning: String,
    /// Policy clauses cited.
    pub policy_refs: Vec<PolicyId>,
    /// When this action stops being reversible without senior co-sign.
    pub reversible_until: DateTime<Utc>,
    /// When `kind = Reverse`, the action being reversed. The DB does not
    /// CHECK this in 0004 (per the comment in that migration), so the
    /// service layer that calls into the repo is responsible for asserting
    /// the policy. The repo just inserts what it's given.
    pub reverses_action_id: Option<ActionId>,
}

/// Compile-time contract for the action repository.
///
/// Mutators are limited to [`ActionRepo::insert`]. There is no `update`;
/// reversal is a fresh row with `kind = Reverse`. See the module-level
/// "Append-only contract" section for the why.
pub trait ActionRepo: Send + Sync {
    /// Insert a new action.
    fn insert(
        &self,
        new: NewAction,
    ) -> impl std::future::Future<Output = Result<Action, RepoError>> + Send;

    /// Look up an action by id. Returns `Ok(None)` when no row matches.
    ///
    /// The `reverses_action_id` field on the returned [`Action`] is the
    /// in-row direction (this row reverses that row); the reverse direction
    /// (`reversed_by`) is intentionally not modeled — see the
    /// `polaris-types::action` module docs.
    fn get(
        &self,
        id: ActionId,
    ) -> impl std::future::Future<Output = Result<Option<Action>, RepoError>> + Send;

    /// List actions attached to `incident_id`, oldest first, capped at
    /// `limit`. The audit-style ordering (chronological) matches the
    /// case-view UI in `design.md` §5.4.
    fn list_by_incident(
        &self,
        incident_id: IncidentId,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Action>, RepoError>> + Send;

    /// Return the (at most one) reverse-Action that targets `id`, if any.
    ///
    /// Used by the reversal API (`POST /api/actions/:id/reverse`) to enforce
    /// the "double-reverse guard" — once an action has been reversed, further
    /// reversal attempts must surface as `409 Conflict`. The `actions` table
    /// has no application-level unique constraint on `reverses_action_id`
    /// (a future appeals-workflow extension may relax the rule), so the
    /// guard is enforced at the service layer by calling this method and
    /// returning the existing reversal to the authorization function.
    ///
    /// Returns `Ok(None)` when no row reverses `id`. If somehow more than
    /// one reversal exists (which should be impossible given the service
    /// layer's check), this returns the first one encountered — the caller
    /// only needs to know "is this already reversed?"
    fn find_reversal(
        &self,
        id: ActionId,
    ) -> impl std::future::Future<Output = Result<Option<Action>, RepoError>> + Send;
}

/// Postgres-backed [`ActionRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgActionRepo {
    pool: PgPool,
}

impl PgActionRepo {
    /// Build a [`PgActionRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ActionRepo for PgActionRepo {
    async fn insert(&self, new: NewAction) -> Result<Action, RepoError> {
        let kind_str = new.kind.as_str();
        let label_str = new.label.as_ref().map(LabelValue::as_str);
        // `policy_refs` is a TEXT[] in Postgres; sqlx encodes `&[String]` as
        // such directly. Build the owned `Vec<String>` once and bind a slice
        // view to keep the macro's borrow checker happy.
        let policy_refs: Vec<String> = new
            .policy_refs
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect();

        // Wrap the INSERT INTO actions + the evidence-job enqueue in a
        // single transaction so the row and its job materialise (or
        // don't) together. See module-level rustdoc.
        let mut tx = self.pool.begin().await?;

        let row = sqlx::query!(
            r#"
            INSERT INTO actions (
                incident_id, subject_id, moderator_id, kind, label_value,
                reasoning, policy_refs, reversible_until, reverses_action_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, incident_id, subject_id, moderator_id, kind, label_value,
                      reasoning, policy_refs, reversible_until, reverses_action_id,
                      emitted_to_atproto, evidence_car_cid, created_at
            "#,
            new.incident_id.0,
            new.subject_id.0,
            new.moderator_id.0,
            kind_str,
            label_str,
            new.reasoning,
            &policy_refs,
            new.reversible_until,
            new.reverses_action_id.map(|a| a.0),
        )
        .fetch_one(&mut *tx)
        .await?;

        // Look up the parent subject's kind + uri to decide whether to
        // enqueue an evidence job. Account-shaped subjects never carry
        // an AT-URI worth snapshotting; record-shaped subjects with a
        // populated `uri` enqueue one job per action.
        let subject_row = sqlx::query!(
            r#"
            SELECT kind, uri
            FROM subjects
            WHERE id = $1
            "#,
            row.subject_id,
        )
        .fetch_one(&mut *tx)
        .await?;

        if let Some(uri) = subject_row.uri
            && let Some(kind) = SubjectKind::from_wire(&subject_row.kind)
            && !matches!(kind, SubjectKind::Account)
        {
            sqlx::query!(
                r#"
                INSERT INTO evidence_jobs (action_id, subject_uri)
                VALUES ($1, $2)
                ON CONFLICT (action_id) DO NOTHING
                "#,
                row.id,
                uri,
            )
            .execute(&mut *tx)
            .await?;
        }

        // Audit-log append in the same transaction (issue #35;
        // design.md §6 + §9). The action row, its evidence-job row,
        // and the audit row commit atomically — or none of them do.
        // The `kind` flips between `action.commit` and
        // `action.reverse` so dashboards can filter on it without
        // re-parsing the payload.
        let audit_kind = if matches!(new.kind, ActionKind::Reverse) {
            "action.reverse"
        } else {
            "action.commit"
        };
        let audit_payload = serde_json::json!({
            "action_id": row.id,
            "subject_id": row.subject_id,
            "incident_id": row.incident_id,
            "moderator_id": row.moderator_id,
            "kind": row.kind,
            "reverses_action_id": row.reverses_action_id,
        });
        AuditLog::record(
            &mut tx,
            AuditEvent {
                actor: ModeratorId(row.moderator_id).0.to_string(),
                kind: audit_kind.to_owned(),
                payload: audit_payload,
            },
        )
        .await?;

        tx.commit().await?;

        row_to_action(
            row.id,
            row.incident_id,
            row.subject_id,
            row.moderator_id,
            &row.kind,
            row.label_value,
            row.reasoning,
            row.policy_refs,
            row.reversible_until,
            row.reverses_action_id,
            row.emitted_to_atproto,
            row.evidence_car_cid,
            row.created_at,
        )
    }

    async fn get(&self, id: ActionId) -> Result<Option<Action>, RepoError> {
        let row = sqlx::query!(
            r#"
            SELECT id, incident_id, subject_id, moderator_id, kind, label_value,
                   reasoning, policy_refs, reversible_until, reverses_action_id,
                   emitted_to_atproto, evidence_car_cid, created_at
            FROM actions
            WHERE id = $1
            "#,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        row_to_action(
            row.id,
            row.incident_id,
            row.subject_id,
            row.moderator_id,
            &row.kind,
            row.label_value,
            row.reasoning,
            row.policy_refs,
            row.reversible_until,
            row.reverses_action_id,
            row.emitted_to_atproto,
            row.evidence_car_cid,
            row.created_at,
        )
        .map(Some)
    }

    async fn list_by_incident(
        &self,
        incident_id: IncidentId,
        limit: i64,
    ) -> Result<Vec<Action>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, incident_id, subject_id, moderator_id, kind, label_value,
                   reasoning, policy_refs, reversible_until, reverses_action_id,
                   emitted_to_atproto, evidence_car_cid, created_at
            FROM actions
            WHERE incident_id = $1
            ORDER BY created_at ASC
            LIMIT $2
            "#,
            incident_id.0,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut actions = Vec::with_capacity(rows.len());
        for row in rows {
            actions.push(row_to_action(
                row.id,
                row.incident_id,
                row.subject_id,
                row.moderator_id,
                &row.kind,
                row.label_value,
                row.reasoning,
                row.policy_refs,
                row.reversible_until,
                row.reverses_action_id,
                row.emitted_to_atproto,
                row.evidence_car_cid,
                row.created_at,
            )?);
        }
        Ok(actions)
    }

    async fn find_reversal(&self, id: ActionId) -> Result<Option<Action>, RepoError> {
        let row = sqlx::query!(
            r#"
            SELECT id, incident_id, subject_id, moderator_id, kind, label_value,
                   reasoning, policy_refs, reversible_until, reverses_action_id,
                   emitted_to_atproto, evidence_car_cid, created_at
            FROM actions
            WHERE reverses_action_id = $1
            LIMIT 1
            "#,
            id.0,
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(row) = row else { return Ok(None) };
        row_to_action(
            row.id,
            row.incident_id,
            row.subject_id,
            row.moderator_id,
            &row.kind,
            row.label_value,
            row.reasoning,
            row.policy_refs,
            row.reversible_until,
            row.reverses_action_id,
            row.emitted_to_atproto,
            row.evidence_car_cid,
            row.created_at,
        )
        .map(Some)
    }
}

// ── private decoders ────────────────────────────────────────────────────

#[allow(
    clippy::too_many_arguments,
    reason = "row decoder mirrors the SELECT projection 1:1; bundling into a struct \
              would just shadow the sqlx-macro-generated row type"
)]
fn row_to_action(
    id: uuid::Uuid,
    incident_id: uuid::Uuid,
    subject_id: uuid::Uuid,
    moderator_id: uuid::Uuid,
    kind: &str,
    label_value: Option<String>,
    reasoning: String,
    policy_refs: Vec<String>,
    reversible_until: DateTime<Utc>,
    reverses_action_id: Option<uuid::Uuid>,
    emitted_to_atproto: Option<DateTime<Utc>>,
    evidence_car_cid: Option<String>,
    created_at: DateTime<Utc>,
) -> Result<Action, RepoError> {
    let kind = decode_kind(kind)?;
    Ok(Action {
        id: ActionId(id),
        incident_id: IncidentId(incident_id),
        subject_id: SubjectId(subject_id),
        moderator_id: ModeratorId(moderator_id),
        kind,
        label: label_value.map(LabelValue::new),
        reasoning,
        policy_refs: policy_refs.into_iter().map(PolicyId::new).collect(),
        reversible_until,
        reverses_action_id: reverses_action_id.map(ActionId),
        created_at,
        emitted_to_atproto,
        evidence_car_cid,
    })
}

fn decode_kind(value: &str) -> Result<ActionKind, RepoError> {
    ActionKind::from_wire(value).ok_or_else(|| RepoError::Decode {
        message: format!("actions.kind={value:?} not in polaris-types contract"),
    })
}
