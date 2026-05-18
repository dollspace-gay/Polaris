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

use std::sync::Arc;

use chrono::{DateTime, Utc};
use polaris_types::{
    Action, ActionId, ActionKind, IncidentId, LabelValue, ModeratorId, PolicyId, SubjectId,
    SubjectKind,
};
use sqlx::{PgPool, Postgres, Transaction};

use super::RepoError;
use crate::audit::{AuditEvent, AuditLog};
use crate::pattern::moderator_anomaly::{self, ModeratorAnomalyConfig};
use crate::reputation::PgReputationProvider;

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
    /// LLM-assist audit envelope (REQ-F1, migration 51).
    ///
    /// `None` — the default for every caller pre-LLM-5 (#242) — produces
    /// a row with `actor_kind = 'human'` and every LLM column NULL,
    /// identical to the pre-LLM-3 schema's behaviour.
    ///
    /// `Some(fields)` — emitted by the LLM dispatcher when an
    /// autonomous-mode policy fires — sets `actor_kind =
    /// 'autonomous_agent'` and populates the full audit envelope. The
    /// database CHECK `actions_autonomous_audit_complete` (migration
    /// 51) rejects partial envelopes at insert time, so the typed
    /// `Some` shape is the only way to land an autonomous row.
    pub llm_audit: Option<LlmAuditFields>,
}

/// The audit envelope an LLM-emitted (autonomous) action carries
/// (`.design/llm-moderation-assist.md` REQ-F1).
///
/// Every field is load-bearing: a future investigator reading a
/// reversal row needs to know which model produced the bad
/// decision, which prompt template was in force, what input the
/// LLM saw, and which observation backs the action. The database
/// CHECK `actions_autonomous_audit_complete` (migration 51)
/// rejects an autonomous row with any of these missing, so this
/// struct is the typed shape that satisfies that contract.
///
/// Construct via the dispatcher path in LLM-5 (#242); pre-LLM-5
/// call sites pass `llm_audit: None` and never construct an
/// `LlmAuditFields`.
///
/// # Examples
///
/// ```rust,no_run
/// use polaris_backend::repo::action::LlmAuditFields;
/// use polaris_types::ObservationId;
///
/// let envelope = LlmAuditFields {
///     llm_observation_id: ObservationId(uuid::Uuid::new_v4()),
///     model: "claude-sonnet-4-6".to_owned(),
///     model_version: "2026-01-15".to_owned(),
///     prompt_template_id: "polaris.case-review.v1".to_owned(),
///     recommendation_confidence: 0.97,
///     input_hash: "deadbeef".repeat(8),
/// };
/// assert_eq!(envelope.model, "claude-sonnet-4-6");
/// ```
#[derive(Debug, Clone)]
pub struct LlmAuditFields {
    /// The `LlmRecommendation` observation row that produced this
    /// action. The observation's `evidence` JSONB carries the full
    /// `RecommendResponse` payload (REQ-B2) for replay.
    pub llm_observation_id: polaris_types::ObservationId,
    /// Model identifier as reported by the adapter (e.g.
    /// `"claude-sonnet-4-6"`).
    pub model: String,
    /// Model-version string snapshotted from the adapter.
    pub model_version: String,
    /// Opaque adapter-stable identifier for the prompt template the
    /// adapter ran. The adapter owns versioning; Polaris audits it
    /// without interpreting it.
    pub prompt_template_id: String,
    /// 0.0–1.0 confidence reported by the LLM for the action it
    /// recommended. Stored as REAL on the row.
    pub recommendation_confidence: f32,
    /// SHA-256 hex of the canonicalised `RecommendRequest` payload.
    /// Lets a future audit prove determinism: same case bundle ⇒ same
    /// decision.
    pub input_hash: String,
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

    /// List every action ever taken against `subject_id`, across every
    /// incident the subject has been involved in, oldest first, capped
    /// at `limit`. The case-view audit timeline calls this.
    ///
    /// Implemented as a direct filter on `actions.subject_id` rather
    /// than the previous brute-force "walk incidents, then walk each
    /// incident's actions" loop — one SQL pass instead of N+1.
    fn list_by_subject(
        &self,
        subject_id: SubjectId,
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
///
/// Optionally carries a [`PgReputationProvider`] (issue #37) — when
/// present, a successful `insert` looks up every report attached to the
/// incident the action covers and bumps each reporter's `reporter_stats`
/// (actioned for `Label`/`Takedown`, dismissed for `NoAction`) within
/// the same transaction.
#[derive(Debug, Clone)]
pub struct PgActionRepo {
    pool: PgPool,
    reputation: Option<Arc<PgReputationProvider>>,
    /// Issue #73, T1 mitigation. When present, every successful
    /// `insert` runs the moderator-behavior-anomaly detector inside the
    /// same transaction: if the moderator's rolling-window action count
    /// crosses the threshold an `ObservationKind::ModeratorBehaviorAnomaly`
    /// is emitted alongside the action row. Absence of the config
    /// disables the hook entirely.
    moderator_anomaly: Option<ModeratorAnomalyConfig>,
}

impl PgActionRepo {
    /// Build a [`PgActionRepo`] over the given pool. No reputation hook.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            reputation: None,
            moderator_anomaly: None,
        }
    }

    /// Attach a reputation provider so successful `insert`s update
    /// per-reporter `reporter_stats` in the same transaction
    /// (issue #37, T3 mitigation).
    #[must_use]
    pub fn with_reputation(mut self, reputation: Arc<PgReputationProvider>) -> Self {
        self.reputation = Some(reputation);
        self
    }

    /// Attach a [`ModeratorAnomalyConfig`] so successful `insert`s run
    /// the T1 moderator-behavior-anomaly check inside the same
    /// transaction (issue #73). Absence of the config disables the
    /// hook; tests that don't exercise the detector pass `None` by
    /// omitting this builder step.
    #[must_use]
    pub fn with_moderator_anomaly(mut self, config: ModeratorAnomalyConfig) -> Self {
        self.moderator_anomaly = Some(config);
        self
    }

    /// Insert an action inside a caller-supplied transaction. Runs the
    /// same evidence-job enqueue, reporter-reputation update, audit-log
    /// append, and moderator-behavior-anomaly hook as
    /// [`Self::insert`], but does NOT open or commit the transaction —
    /// the caller controls the boundary.
    ///
    /// Issue #202: the `submit_action` handler's per-report idempotency
    /// path holds a `SELECT … FOR UPDATE` lock on the `reports` row and
    /// updates `reports.actioned_at` atomically with the action insert.
    /// Both operations must commit together, so the handler hands its
    /// transaction in here.
    ///
    /// # Errors
    ///
    /// Returns [`RepoError`] for any database-side failure. The caller
    /// is responsible for rolling back (or letting the `Transaction`
    /// drop and auto-rollback) on `Err`.
    pub async fn insert_in_tx(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        new: NewAction,
    ) -> Result<Action, RepoError> {
        insert_action_in_tx(
            tx,
            &new,
            self.reputation.as_deref(),
            self.moderator_anomaly.as_ref(),
        )
        .await
    }
}

impl ActionRepo for PgActionRepo {
    async fn insert(&self, new: NewAction) -> Result<Action, RepoError> {
        // Wrap the action insert + side-effects (evidence-job, reporter
        // reputation, audit log, moderator anomaly) in a single
        // transaction so all of them materialise — or none of them do.
        // See [`insert_action_in_tx`] for the body.
        let mut tx = self.pool.begin().await?;
        let action = insert_action_in_tx(
            &mut tx,
            &new,
            self.reputation.as_deref(),
            self.moderator_anomaly.as_ref(),
        )
        .await?;
        tx.commit().await?;
        Ok(action)
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

    async fn list_by_subject(
        &self,
        subject_id: SubjectId,
        limit: i64,
    ) -> Result<Vec<Action>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, incident_id, subject_id, moderator_id, kind, label_value,
                   reasoning, policy_refs, reversible_until, reverses_action_id,
                   emitted_to_atproto, evidence_car_cid, created_at
            FROM actions
            WHERE subject_id = $1
            ORDER BY created_at ASC
            LIMIT $2
            "#,
            subject_id.0,
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

// ── shared insert helper ────────────────────────────────────────────────

/// Insert an action row inside the caller's transaction, then run the
/// per-insert side-effects: evidence-job enqueue, reporter-reputation
/// update, audit-log append, and moderator-behavior-anomaly check.
///
/// Both [`PgActionRepo::insert`] (which opens its own tx and commits)
/// and [`PgActionRepo::insert_in_tx`] (which threads through a caller-
/// owned tx) delegate here so the action-insert contract stays in one
/// place. The per-report idempotency path in the `submit_action`
/// handler (issue #202) is the caller of the latter.
#[allow(
    clippy::too_many_lines,
    reason = "single-tx orchestration of the action insert + \
              evidence-job enqueue + reputation update + audit-log \
              append. Splitting into sub-helpers would force passing \
              `&mut PgConnection`-backed tx state through several \
              hops and obscure the single-transaction story."
)]
async fn insert_action_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    new: &NewAction,
    reputation: Option<&PgReputationProvider>,
    moderator_anomaly: Option<&ModeratorAnomalyConfig>,
) -> Result<Action, RepoError> {
    let kind_str = new.kind.as_str();
    let label_str = new.label.as_ref().map(LabelValue::as_str);

    // REQ-B5: a reversal action writes its own citations against the
    // *current* policy version at reversal time. The original action's
    // citations stay untouched (the original cites its own snapshot;
    // the reversal cites whatever is in force when the reverse happens).
    //
    // The reversal's `actions.policy_refs TEXT[]` mirror (REQ-B2 legacy
    // column) must match the structured citations, so we resolve the
    // citation set BEFORE the INSERT and use the identifier list both
    // as the legacy `policy_refs` and to drive the
    // `action_policy_citations` write further below. The `actions`
    // table is append-only — UPDATEs are rejected by trigger — so a
    // post-INSERT mutation of `policy_refs` is structurally not an
    // option here.
    let reversal_citations: Option<Vec<(String, i32)>> = match (new.kind, new.reverses_action_id) {
        (ActionKind::Reverse, Some(original_id)) => {
            Some(resolve_reversal_citations(tx, original_id).await?)
        }
        _ => None,
    };

    // `policy_refs` is a TEXT[] in Postgres; sqlx encodes `&[String]` as
    // such directly. Build the owned `Vec<String>` once and bind a slice
    // view to keep the macro's borrow checker happy. For reversal kind
    // we override the caller-supplied (typically empty) refs with the
    // resolved identifier list so the legacy column mirrors the
    // structured citations.
    let policy_refs: Vec<String> = match reversal_citations.as_ref() {
        Some(citations) => citations.iter().map(|(ident, _)| ident.clone()).collect(),
        None => new
            .policy_refs
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect(),
    };

    // REQ-F1: when an LLM audit envelope is present the row is an
    // autonomous-agent emission and the migration-51 CHECK constraint
    // requires every audit column to be NOT NULL. Pulling the fields
    // out into typed `Option<_>` bindings keeps the macro's parameter
    // map readable and routes the `None` default (human-emitted row)
    // through the same INSERT as the LLM dispatcher path. The DB
    // CHECK is the load-bearing invariant: a partial envelope is
    // rejected at the boundary regardless of whether the caller went
    // through this typed struct.
    let actor_kind: &str = if new.llm_audit.is_some() {
        "autonomous_agent"
    } else {
        "human"
    };
    let llm_observation_id = new.llm_audit.as_ref().map(|f| f.llm_observation_id.0);
    let llm_model = new.llm_audit.as_ref().map(|f| f.model.as_str());
    let llm_model_version = new.llm_audit.as_ref().map(|f| f.model_version.as_str());
    let llm_prompt_template_id = new
        .llm_audit
        .as_ref()
        .map(|f| f.prompt_template_id.as_str());
    let llm_recommendation_confidence = new.llm_audit.as_ref().map(|f| f.recommendation_confidence);
    let llm_input_hash = new.llm_audit.as_ref().map(|f| f.input_hash.as_str());

    let row = sqlx::query!(
        r#"
        INSERT INTO actions (
            incident_id, subject_id, moderator_id, kind, label_value,
            reasoning, policy_refs, reversible_until, reverses_action_id,
            actor_kind, llm_observation_id, model, model_version,
            prompt_template_id, recommendation_confidence, input_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16)
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
        actor_kind,
        llm_observation_id,
        llm_model,
        llm_model_version,
        llm_prompt_template_id,
        llm_recommendation_confidence,
        llm_input_hash,
    )
    .fetch_one(&mut **tx)
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
    .fetch_one(&mut **tx)
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
        .execute(&mut **tx)
        .await?;
    }

    // Issue #37: reporter-reputation update. When a reputation
    // provider is attached, walk the reports attached to this
    // action's incident and bump each reporter's stats. The
    // walk happens inside the same tx so reporter_stats commits
    // atomically with the action row. `record_action_with` is a
    // no-op for kinds that don't credit / demerit a reporter
    // (Mute/Warn/Escalate/Reverse), so the call is safe to make
    // for every action kind.
    if let Some(reputation) = reputation {
        // One query for the distinct reporter DIDs on the incident.
        // The `reports` table has `incident_id IS NULL` rows (an
        // unaggregated report); those don't belong to this action,
        // so the WHERE clause filters them out.
        let reporter_rows = sqlx::query!(
            r#"
            SELECT DISTINCT reporter_did
            FROM reports
            WHERE incident_id = $1
            "#,
            row.incident_id,
        )
        .fetch_all(&mut **tx)
        .await?;
        let action_kind = ActionKind::from_wire(&row.kind).ok_or_else(|| RepoError::Decode {
            message: format!("actions.kind={:?} not in polaris-types contract", row.kind),
        })?;
        for reporter in reporter_rows {
            reputation
                .record_action_with(tx, &reporter.reporter_did, action_kind)
                .await
                .map_err(map_reputation_error)?;
        }
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
        tx,
        AuditEvent {
            actor: ModeratorId(row.moderator_id).0.to_string(),
            kind: audit_kind.to_owned(),
            payload: audit_payload,
        },
    )
    .await?;

    // Issue #73 / T1 mitigation. Run the moderator-behavior-anomaly
    // detector inside the same transaction so a tripped detector
    // emits its observation atomically with the action row. The
    // hook is opt-in (`None` skips it) so tests that don't
    // exercise the detector keep the action-insert path lean.
    if let Some(cfg) = moderator_anomaly {
        moderator_anomaly::check_and_emit(tx, ModeratorId(row.moderator_id), cfg).await?;
    }

    // REQ-B5: write the reversal's own citation rows inside the same
    // transaction as the action insert. The originating citations
    // (which point at the *original* action's `id`) are left in
    // place — the reversal cites its own snapshot at the version
    // currently in force. Non-reversal actions take their citation
    // writes from the caller (the `cases::submit_action` path); only
    // the reversal-shaped case fans in here, where the policy
    // identifiers can be derived deterministically from the
    // original action's citations.
    if let Some(citations) = reversal_citations.as_ref()
        && !citations.is_empty()
    {
        crate::repo::action_policy_citations::insert_for_action(tx, row.id, citations).await?;
    }

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

// ── private decoders ────────────────────────────────────────────────────

#[allow(
    clippy::too_many_arguments,
    reason = "row decoder mirrors the SELECT projection 1:1; bundling into a struct \
              would just shadow the sqlx-macro-generated row type"
)]
pub(crate) fn row_to_action(
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

/// Resolve the citation snapshot a reversal action will record (REQ-B5).
///
/// Reads every `(policy_identifier, _)` cited by the *original* action
/// and re-queries each identifier's `mod_policies.current_by_identifier`
/// row to pin the reversal at the version in force at reversal time.
///
/// Edge cases:
///
/// - The original might have zero citations (a pre-WB-2 action or a
///   reversal-of-a-reversal carrying no policy refs). Returns an
///   empty vec — the reversal writes no citations.
/// - A previously-cited policy might have been retired between the
///   original action and the reversal. The retired row still has a
///   `current_by_identifier` hit (the tombstone is a normal row
///   with `is_retired = TRUE`), so the reversal can still pin its
///   version. This is the intended behaviour per the workbook
///   design: an auditor reading the reversal's citation chain wants
///   to see "we reversed under harassment v5, which is the retired
///   version" — not silently drop the cite.
/// - A previously-cited policy might be missing entirely (an
///   operator hard-deleted the workbook rows, which the workbook
///   schema does not normally allow). The repo treats this as a
///   skipped cite rather than an error so the reversal still
///   commits — the audit trail's primary purpose is to record the
///   moderator's decision, and dropping a cite to a vanished policy
///   is preferable to refusing to roll back an action that needs to
///   be rolled back.
async fn resolve_reversal_citations(
    tx: &mut Transaction<'_, Postgres>,
    original_action_id: ActionId,
) -> Result<Vec<(String, i32)>, RepoError> {
    let identifier_rows = sqlx::query!(
        r#"
        SELECT DISTINCT policy_identifier
        FROM action_policy_citations
        WHERE action_id = $1
        ORDER BY policy_identifier ASC
        "#,
        original_action_id.0,
    )
    .fetch_all(&mut **tx)
    .await?;

    let mut snapshots: Vec<(String, i32)> = Vec::with_capacity(identifier_rows.len());
    for row in identifier_rows {
        // `mod_policies.current_by_identifier` is the canonical lookup,
        // but it takes a `PgPool` — using it would require splitting
        // the policy resolve out of this transaction, which defeats
        // the "single tx" atomicity goal. Inline the SELECT against
        // the caller's tx instead so the read participates in the
        // same MVCC snapshot as the action insert.
        let policy_row = sqlx::query!(
            r#"
            SELECT identifier, version
            FROM mod_policies
            WHERE identifier = $1 AND effective_until IS NULL
            "#,
            row.policy_identifier,
        )
        .fetch_optional(&mut **tx)
        .await?;
        if let Some(p) = policy_row {
            snapshots.push((p.identifier, p.version));
        } else {
            // Policy is missing entirely; see the function-level doc
            // comment for why we skip rather than fail.
            tracing::warn!(
                identifier = %row.policy_identifier,
                "reversal: cited identifier has no current mod_policies row; skipping citation"
            );
        }
    }
    Ok(snapshots)
}

/// Route a [`crate::reputation::ReputationError`] into a [`RepoError`].
///
/// See the matching helper in [`crate::repo::report`] for the rationale.
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
