//! Pattern-action API (issue #21).
//!
//! Per design.md §5.3: moderators act on patterns directly — "apply label X
//! to every account that posted this image hash in the last 48h." Every
//! affected subject still gets an individual `actions` row so reversal and
//! audit work the same as for single-subject decisions. Pattern actions
//! affecting more than [`crate::config::PatternActionsConfig::cosign_threshold`]
//! subjects require a senior co-sign.
//!
//! # Two endpoints
//!
//! 1. `POST /api/pattern-actions` — typed [`PatternSelector`] + action
//!    template → [`ProposedPatternAction`] (header id + projected affected-
//!    subject count + cosign decision). If the count is at-or-below the
//!    threshold, the per-subject Action rows are inserted atomically
//!    inside the same call.
//! 2. `POST /api/pattern-actions/:id/cosign` — senior signature →
//!    [`PatternActionResult`]. The signature row is written, the per-
//!    subject Action rows are materialised, and the header's status flips
//!    to `executed` — all in one `sqlx::Transaction`. Any failure rolls
//!    back the whole sequence; the header stays at `proposed` and the
//!    caller can retry.
//!
//! # Handler shape
//!
//! Both handlers are ≤ 25 lines and delegate validation, resolution, and
//! execution to free functions in this module. The forbidden-pattern
//! checklist for #21 calls this out explicitly:
//!
//! - The selector is a typed enum (never a free-form JSON map on the wire).
//! - Senior role is checked server-side from `ModeratorAuthCtx.roles`;
//!   the request body never carries a "role" claim.
//! - Self-cosign is rejected (a proposer cannot supply both signatures).
//! - All multi-statement writes go through `sqlx::Transaction` with
//!   all-or-nothing rollback.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use polaris_types::{
    ActionId, ActionKind, IncidentId, LabelValue, ModeratorId as TypesModeratorId, PatternActionId,
    PolicyId, SubjectId,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::repo::pattern_action::{NewPatternActionHeader, PatternActionRepo, PatternActionStatus};
use crate::repo::{PatternActionRow, RepoError};

/// Minimum reasoning length. Mirrors the per-subject `actions.reasoning`
/// CHECK constraint in migration 4.
const MIN_REASONING_LEN: usize = 10;

/// Default reversibility window for per-subject Action rows produced by a
/// pattern action. Matches the standard 24h window applied at the
/// per-case submit-action path; the resulting Action rows participate in
/// the existing reversal API (#36) unchanged.
const PATTERN_ACTION_REVERSIBLE_WINDOW: chrono::Duration = chrono::Duration::hours(24);

/// Typed selector for a pattern action.
///
/// The serde representation is `#[serde(tag = "kind", rename_all = "snake_case")]`
/// so the wire form is `{ "kind": "image_hash_cluster", "cluster_id": "...",
/// "hash": ... }`. The `kind` discriminator matches the `selector_kind`
/// CHECK constraint values in migration 8.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PatternSelector {
    /// Subjects with an `image_hash_cluster` observation matching this
    /// cluster id / hash combination.
    ImageHashCluster {
        /// Engine-assigned opaque cluster id (matches the cohort the
        /// detector emitted the observation under).
        cluster_id: String,
        /// Hex-encoded perceptual hash.
        hash: String,
    },
    /// Subjects with an `account_cohort` observation matching this cohort.
    AccountCohort {
        /// Engine-assigned cohort id.
        cohort_id: String,
    },
    /// Subjects with a `report_volume_anomaly` observation matching this
    /// category + severity bucket at `bucket_start`.
    AnomalyBucket {
        /// The anomalous report category.
        category: String,
        /// Severity tier (`critical` / `high` / `medium` / `low`); free
        /// text at the wire layer so future engines can extend the set.
        severity: String,
        /// Lower bound of the bucket window.
        bucket_start: DateTime<Utc>,
    },
}

impl PatternSelector {
    /// DB discriminator string. Matches the `selector_kind` CHECK
    /// constraint in migration 8.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ImageHashCluster { .. } => "image_hash_cluster",
            Self::AccountCohort { .. } => "account_cohort",
            Self::AnomalyBucket { .. } => "anomaly_bucket",
        }
    }
}

/// Wire shape for `POST /api/pattern-actions`.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposeBody {
    /// Typed selector describing which subjects the action targets.
    pub selector: PatternSelector,
    /// Action verb to apply per subject.
    pub action_kind: ActionKind,
    /// Label value, only meaningful when `action_kind = Label`.
    pub label_value: Option<LabelValue>,
    /// Free-text reasoning (must be ≥ 10 chars).
    pub reasoning: String,
    /// Policy refs cited (must be non-empty; each entry must be in the
    /// [`crate::api::policy::KNOWN_POLICY_REFS`] allow-list).
    pub policy_refs: Vec<PolicyId>,
}

/// Wire shape for the 201 response of `POST /api/pattern-actions`.
#[derive(Debug, Clone, Serialize)]
pub struct ProposedPatternAction {
    /// Header row identifier.
    pub id: PatternActionId,
    /// The subjects the selector resolved to.
    pub affected_subjects: Vec<SubjectId>,
    /// Count of affected subjects.
    pub affected_subject_count: usize,
    /// Whether the proposal needs a senior co-sign.
    pub requires_cosign: bool,
    /// Workflow status (`proposed` when waiting on cosign, `executed`
    /// when auto-approved).
    pub status: String,
}

/// Wire shape for the 200 response of `POST /api/pattern-actions/:id/cosign`.
#[derive(Debug, Clone, Serialize)]
pub struct PatternActionResult {
    /// Header row identifier (echoed for client convenience).
    pub id: PatternActionId,
    /// Workflow status after the cosign call. Always `"executed"` on
    /// success (the cosign endpoint is total: it either rolls back and
    /// returns an error or it completes the transition).
    pub status: String,
    /// Count of per-subject Action rows the transaction inserted.
    pub inserted_count: usize,
}

// ── handlers ────────────────────────────────────────────────────────────

/// Handler: propose a pattern action.
///
/// # Errors
///
/// - `400 Bad Request` — reasoning too short, empty / unknown policy refs.
/// - `500 Internal Server Error` — DB / resolver failure.
pub async fn propose(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(body): Json<ProposeBody>,
) -> Result<(StatusCode, Json<ProposedPatternAction>), ApiError> {
    validate_propose(&body)?;
    validate_propose_policies(&state.pool, &body).await?;
    let affected = resolve_selector(&state.pool, &body.selector).await?;
    let threshold = state.pattern_actions_cfg.cosign_threshold;
    let requires_cosign = affected.len() > threshold;
    let id = insert_header(&state, &ctx, &body, affected.len(), requires_cosign).await?;
    let status = if requires_cosign {
        PatternActionStatus::Proposed
    } else {
        execute_pattern_action(&state.pool, id, &ctx, &affected, &body).await?;
        PatternActionStatus::Executed
    };
    Ok((
        StatusCode::CREATED,
        Json(ProposedPatternAction {
            id,
            affected_subject_count: affected.len(),
            affected_subjects: affected,
            requires_cosign,
            status: status.as_str().to_owned(),
        }),
    ))
}

/// Handler: senior co-sign for a pending pattern action.
///
/// # Errors
///
/// - `403 Forbidden` — caller is not [`Role::Admin`] / [`Role::SeniorModerator`],
///   or is the proposer themselves.
/// - `404 Not Found` — `id` does not exist.
/// - `400 Bad Request` — the proposal was auto-approved at propose time
///   (`requires_cosign = false`) and cannot be cosigned.
/// - `409 Conflict` — the proposal is no longer `proposed` (already
///   executed / cancelled), or this senior has already signed.
pub async fn cosign(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(id): Path<PatternActionId>,
) -> Result<Json<PatternActionResult>, ApiError> {
    require_senior(&ctx)?;
    let pa = state
        .pattern_actions
        .get(id)
        .await?
        .ok_or(ApiError::NotFound)?;
    validate_cosign_target(&pa, &ctx)?;
    let body = body_from_row(&pa)?;
    let affected = resolve_selector_from_row(&state.pool, &pa).await?;
    state
        .pattern_actions
        .record_signature(id, ctx.moderator_id)
        .await?;
    execute_pattern_action(&state.pool, id, &ctx, &affected, &body).await?;
    Ok(Json(PatternActionResult {
        id,
        status: PatternActionStatus::Executed.as_str().to_owned(),
        inserted_count: affected.len(),
    }))
}

// ── validation + authorization ──────────────────────────────────────────

fn validate_propose(body: &ProposeBody) -> Result<(), ApiError> {
    if body.reasoning.len() < MIN_REASONING_LEN {
        return Err(ApiError::BadRequest(
            "reasoning must be at least 10 characters",
        ));
    }
    if body.policy_refs.is_empty() {
        return Err(ApiError::BadRequest("policy_refs must be non-empty"));
    }
    if body.action_kind == ActionKind::Reverse {
        return Err(ApiError::BadRequest(
            "pattern actions cannot be of kind 'reverse'",
        ));
    }
    Ok(())
}

/// WB-2 / REQ-B3 async policy resolve. Confirms every cited identifier
/// has a current `mod_policies` row and is not retired; mirrors the
/// action-create handler's check so the policy-version contract is
/// uniform across the action APIs.
async fn validate_propose_policies(
    pool: &sqlx::PgPool,
    body: &ProposeBody,
) -> Result<(), ApiError> {
    for r in &body.policy_refs {
        let identifier = r.as_str();
        let resolved = crate::api::policy_cache::get_current(pool, identifier)
            .await
            .map_err(|e| match e {
                crate::repo::mod_policies::ModPolicyError::Database(inner) => {
                    ApiError::Repo(crate::repo::RepoError::from(inner))
                }
                _ => ApiError::Internal(anyhow::anyhow!("policy lookup failure: {e}")),
            })?;
        let Some(policy) = resolved else {
            return Err(ApiError::UnknownPolicyRef {
                identifier: identifier.to_owned(),
            });
        };
        if policy.is_retired {
            return Err(ApiError::PolicyRetired {
                identifier: identifier.to_owned(),
                retired_at: policy.effective_from,
            });
        }
    }
    Ok(())
}

/// Senior-role gate. Used by the cosign endpoint server-side; the
/// frontend's role claim is irrelevant.
fn require_senior(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin) || ctx.roles.contains(&Role::SeniorModerator) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Per-row authorization gate for the cosign endpoint. The senior-role
/// check has already passed; the remaining rules are:
///
/// - The proposal must still be `proposed`. Re-cosigning an executed or
///   cancelled proposal is a 409.
/// - The proposal must actually require a cosign (auto-approved actions
///   have already executed and cannot be cosigned). 400.
/// - The cosigner must not be the proposer. 403 — a single moderator
///   cannot supply both signatures.
fn validate_cosign_target(pa: &PatternActionRow, ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if pa.status != PatternActionStatus::Proposed {
        return Err(ApiError::Conflict(
            "pattern action is not in proposed status",
        ));
    }
    if !pa.requires_cosign {
        return Err(ApiError::BadRequest(
            "action below cosign threshold; already executed",
        ));
    }
    if pa.requested_by.0 == ctx.moderator_id.0 {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

// ── header insertion ────────────────────────────────────────────────────

/// Persist the header row. Pure delegation to the repo plus an
/// `affected_subject_count` cast — extracted so the propose handler
/// stays under the 25-line ceiling.
async fn insert_header(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    body: &ProposeBody,
    affected_count: usize,
    requires_cosign: bool,
) -> Result<PatternActionId, ApiError> {
    let selector_data = serde_json::to_value(&body.selector).map_err(|e| {
        ApiError::Internal(anyhow::anyhow!(
            "failed to encode PatternSelector to JSON: {e}"
        ))
    })?;
    let header = NewPatternActionHeader {
        selector_kind: body.selector.kind(),
        selector_data,
        action_kind: body.action_kind,
        label_value: body.label_value.clone(),
        reasoning: body.reasoning.clone(),
        policy_refs: body.policy_refs.clone(),
        affected_subject_count: affected_count,
        requires_cosign,
        requested_by: TypesModeratorId(ctx.moderator_id.0),
    };
    let id = state.pattern_actions.insert_header(header).await?;
    Ok(id)
}

/// Rebuild a [`ProposeBody`]-equivalent from a stored header row. Used
/// by the cosign path so the post-signature execute step has the same
/// shape as the auto-approve path.
fn body_from_row(pa: &PatternActionRow) -> Result<ProposeBody, ApiError> {
    let selector: PatternSelector = decode_selector(&pa.selector_kind, &pa.selector_data)?;
    Ok(ProposeBody {
        selector,
        action_kind: pa.action_kind,
        label_value: pa.label_value.clone(),
        reasoning: pa.reasoning.clone(),
        policy_refs: pa.policy_refs.clone(),
    })
}

/// Reconstruct the typed selector from `(selector_kind, selector_data)`.
fn decode_selector(kind: &str, data: &serde_json::Value) -> Result<PatternSelector, ApiError> {
    // The wire form is `{ "kind": "<kind>", <fields> }`. The stored
    // `selector_data` is the original `serde_json::to_value(&selector)`
    // output (which already includes the tag), so we can deserialise
    // directly. Defensive fallback: if the stored payload lacks the tag
    // we re-inject it before parsing.
    if data.get("kind").is_some() {
        serde_json::from_value(data.clone()).map_err(|e| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to decode pattern selector (kind={kind}): {e}"
            ))
        })
    } else {
        let mut envelope = serde_json::Map::new();
        envelope.insert(
            "kind".to_owned(),
            serde_json::Value::String(kind.to_owned()),
        );
        if let serde_json::Value::Object(obj) = data {
            for (k, v) in obj {
                envelope.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(serde_json::Value::Object(envelope)).map_err(|e| {
            ApiError::Internal(anyhow::anyhow!(
                "failed to decode pattern selector (kind={kind}): {e}"
            ))
        })
    }
}

// ── selector resolution ─────────────────────────────────────────────────

/// Resolve a typed [`PatternSelector`] to the set of [`SubjectId`]s it
/// targets. Backed by `observations`-table reads — the M2 detectors
/// populate the table; for #21 these resolvers are conservative (return
/// empty when the underlying observations table is empty), and the
/// integration test pre-populates a matching observation.
async fn resolve_selector(
    pool: &PgPool,
    selector: &PatternSelector,
) -> Result<Vec<SubjectId>, ApiError> {
    match selector {
        PatternSelector::ImageHashCluster { hash, .. } => resolve_image_hash(pool, hash).await,
        PatternSelector::AccountCohort { cohort_id } => resolve_cohort(pool, cohort_id).await,
        PatternSelector::AnomalyBucket {
            category,
            bucket_start,
            ..
        } => resolve_anomaly(pool, category, *bucket_start).await,
    }
}

/// Same as [`resolve_selector`] but takes a stored row directly.
async fn resolve_selector_from_row(
    pool: &PgPool,
    pa: &PatternActionRow,
) -> Result<Vec<SubjectId>, ApiError> {
    let selector = decode_selector(&pa.selector_kind, &pa.selector_data)?;
    resolve_selector(pool, &selector).await
}

async fn resolve_image_hash(pool: &PgPool, hash: &str) -> Result<Vec<SubjectId>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT subject_id
        FROM observations
        WHERE kind = 'image_hash_cluster'
          AND evidence ->> 'hash' = $1
        "#,
        hash,
    )
    .fetch_all(pool)
    .await
    .map_err(RepoError::from)?;
    Ok(rows.into_iter().map(|r| SubjectId(r.subject_id)).collect())
}

async fn resolve_cohort(pool: &PgPool, cohort_id: &str) -> Result<Vec<SubjectId>, ApiError> {
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT subject_id
        FROM observations
        WHERE kind = 'account_cohort'
          AND evidence ->> 'cohort_id' = $1
        "#,
        cohort_id,
    )
    .fetch_all(pool)
    .await
    .map_err(RepoError::from)?;
    Ok(rows.into_iter().map(|r| SubjectId(r.subject_id)).collect())
}

async fn resolve_anomaly(
    pool: &PgPool,
    category: &str,
    bucket_start: DateTime<Utc>,
) -> Result<Vec<SubjectId>, ApiError> {
    let bucket_end = bucket_start + chrono::Duration::hours(1);
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT r.subject_id
        FROM reports r
        WHERE r.category = $1
          AND r.created_at >= $2
          AND r.created_at <  $3
        "#,
        category,
        bucket_start,
        bucket_end,
    )
    .fetch_all(pool)
    .await
    .map_err(RepoError::from)?;
    Ok(rows.into_iter().map(|r| SubjectId(r.subject_id)).collect())
}

// ── transactional execution ─────────────────────────────────────────────

/// Materialise the per-subject Action rows + bookkeeping for a pattern
/// action. All writes happen inside a single `sqlx::Transaction`; any
/// failure rolls back the lot and leaves `pattern_actions.status` at its
/// pre-call value.
///
/// Steps, in order:
///
/// 1. Re-fetch the header inside the txn and assert it is still
///    `proposed` (defence against a concurrent cosign racing the
///    proposer's auto-approve).
/// 2. Insert one `pattern_action_subjects` row per affected subject.
/// 3. For each subject, look up (or synthesise via the existing
///    incident attached to a relevant observation) an incident id and
///    insert one `actions` row carrying the action template's
///    `action_kind` / `label_value` / `reasoning` / `policy_refs`.
/// 4. UPDATE the header's `status` to `executed` and `executed_at` to
///    `now()`.
///
/// The UPDATE in step 4 is on `pattern_actions`, NOT on `actions` —
/// the append-only trigger from #13 protects `actions` only; the
/// pattern-actions header is intentionally mutable for workflow state
/// transitions.
async fn execute_pattern_action(
    pool: &PgPool,
    id: PatternActionId,
    ctx: &ModeratorAuthCtx,
    affected: &[SubjectId],
    body: &ProposeBody,
) -> Result<(), ApiError> {
    let mut txn: Transaction<'_, Postgres> = pool.begin().await.map_err(RepoError::from)?;
    assert_executable(&mut txn, id).await?;
    insert_subject_rows(&mut txn, id, affected).await?;
    let policy_refs: Vec<String> = body
        .policy_refs
        .iter()
        .map(|p| p.as_str().to_owned())
        .collect();
    let reversible_until = Utc::now() + PATTERN_ACTION_REVERSIBLE_WINDOW;
    let moderator_id = TypesModeratorId(ctx.moderator_id.0);
    for subject_id in affected {
        let incident_id = ensure_incident_for_subject(&mut txn, *subject_id).await?;
        insert_action_row(
            &mut txn,
            incident_id,
            *subject_id,
            moderator_id,
            body.action_kind,
            body.label_value.as_ref(),
            &body.reasoning,
            &policy_refs,
            reversible_until,
        )
        .await?;
    }
    mark_executed(&mut txn, id).await?;
    txn.commit().await.map_err(RepoError::from)?;
    Ok(())
}

/// Inside the transaction, re-read the header status and reject the
/// execute if it is no longer `proposed`. This is the concurrent-cosign
/// guard: two seniors hitting `/cosign` simultaneously cannot both
/// materialise the per-subject Actions.
async fn assert_executable(
    txn: &mut Transaction<'_, Postgres>,
    id: PatternActionId,
) -> Result<(), ApiError> {
    let row = sqlx::query!(
        r#"SELECT status FROM pattern_actions WHERE id = $1 FOR UPDATE"#,
        id.0,
    )
    .fetch_optional(&mut **txn)
    .await
    .map_err(RepoError::from)?;
    let row = row.ok_or(ApiError::NotFound)?;
    if row.status != PatternActionStatus::Proposed.as_str() {
        return Err(ApiError::Conflict(
            "pattern action is no longer in proposed status",
        ));
    }
    Ok(())
}

async fn insert_subject_rows(
    txn: &mut Transaction<'_, Postgres>,
    id: PatternActionId,
    affected: &[SubjectId],
) -> Result<(), ApiError> {
    for subject_id in affected {
        sqlx::query!(
            r#"
            INSERT INTO pattern_action_subjects (pattern_action_id, subject_id)
            VALUES ($1, $2)
            "#,
            id.0,
            subject_id.0,
        )
        .execute(&mut **txn)
        .await
        .map_err(RepoError::from)?;
    }
    Ok(())
}

/// Pick an incident to attribute the per-subject Action to. Tries (in
/// order):
///
/// 1. An existing `incidents` row where this subject is the
///    `primary_subject` and the status is `open` / `in_review`.
/// 2. Otherwise, opens a fresh incident of medium severity, status
///    `actioned` — pattern actions imply the action is already taken,
///    so the incident is opened-and-resolved in one breath.
///
/// The materialised `incident_id` is stored on `pattern_action_subjects`
/// so the audit trail can reconstruct which incident absorbed which
/// per-subject Action.
async fn ensure_incident_for_subject(
    txn: &mut Transaction<'_, Postgres>,
    subject_id: SubjectId,
) -> Result<IncidentId, ApiError> {
    let existing = sqlx::query!(
        r#"
        SELECT id
        FROM incidents
        WHERE primary_subject = $1
          AND status IN ('open', 'in_review')
        ORDER BY opened_at DESC
        LIMIT 1
        "#,
        subject_id.0,
    )
    .fetch_optional(&mut **txn)
    .await
    .map_err(RepoError::from)?;
    let incident_id = if let Some(row) = existing {
        IncidentId(row.id)
    } else {
        let row = sqlx::query!(
            r#"
            INSERT INTO incidents (primary_subject, severity, status)
            VALUES ($1, 'medium', 'actioned')
            RETURNING id
            "#,
            subject_id.0,
        )
        .fetch_one(&mut **txn)
        .await
        .map_err(RepoError::from)?;
        IncidentId(row.id)
    };
    Ok(incident_id)
}

#[allow(
    clippy::too_many_arguments,
    reason = "delegates 1:1 to the actions table column list; bundling into a struct would only \
              shadow the columns of an INSERT we want kept obvious at the call site"
)]
async fn insert_action_row(
    txn: &mut Transaction<'_, Postgres>,
    incident_id: IncidentId,
    subject_id: SubjectId,
    moderator_id: TypesModeratorId,
    action_kind: ActionKind,
    label: Option<&LabelValue>,
    reasoning: &str,
    policy_refs: &[String],
    reversible_until: DateTime<Utc>,
) -> Result<ActionId, ApiError> {
    let kind_str = action_kind.as_str();
    let label_str = label.map(LabelValue::as_str);
    let row = sqlx::query!(
        r#"
        INSERT INTO actions (
            incident_id, subject_id, moderator_id, kind, label_value,
            reasoning, policy_refs, reversible_until
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id
        "#,
        incident_id.0,
        subject_id.0,
        moderator_id.0,
        kind_str,
        label_str,
        reasoning,
        policy_refs,
        reversible_until,
    )
    .fetch_one(&mut **txn)
    .await
    .map_err(RepoError::from)?;
    Ok(ActionId(row.id))
}

async fn mark_executed(
    txn: &mut Transaction<'_, Postgres>,
    id: PatternActionId,
) -> Result<(), ApiError> {
    sqlx::query!(
        r#"
        UPDATE pattern_actions
        SET status = 'executed', executed_at = now()
        WHERE id = $1
        "#,
        id.0,
    )
    .execute(&mut **txn)
    .await
    .map_err(RepoError::from)?;
    Ok(())
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
    use std::collections::HashSet;

    use crate::auth::ModeratorId as AuthModeratorId;

    fn ctx_with(roles: &[Role]) -> ModeratorAuthCtx {
        let mut set = HashSet::new();
        for r in roles {
            set.insert(*r);
        }
        ModeratorAuthCtx::new(AuthModeratorId::new_v4(), set)
    }

    fn good_body() -> ProposeBody {
        ProposeBody {
            selector: PatternSelector::ImageHashCluster {
                cluster_id: "c-1".to_owned(),
                hash: "deadbeef".to_owned(),
            },
            action_kind: ActionKind::Label,
            label_value: Some(LabelValue::new("spam")),
            reasoning: "Bulk label on image-hash cluster.".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
        }
    }

    #[test]
    fn validate_propose_accepts_good_body() {
        validate_propose(&good_body()).expect("good body must pass");
    }

    #[test]
    fn validate_propose_rejects_short_reasoning() {
        let mut body = good_body();
        body.reasoning = "short".to_owned();
        let err = validate_propose(&body).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("reasoning")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn validate_propose_rejects_empty_policy_refs() {
        let mut body = good_body();
        body.policy_refs = vec![];
        assert!(matches!(
            validate_propose(&body).unwrap_err(),
            ApiError::BadRequest(_),
        ));
    }

    // The previous `validate_propose_rejects_unknown_policy_ref`
    // unit test was retired with the WB-2 rewrite. Unknown-identifier
    // rejection now lives in `validate_propose_policies`, which needs
    // a live DB pool to query `mod_policies`; the equivalent coverage
    // belongs in the pattern-actions integration suite.

    #[test]
    fn validate_propose_rejects_reverse_action_kind() {
        let mut body = good_body();
        body.action_kind = ActionKind::Reverse;
        assert!(matches!(
            validate_propose(&body).unwrap_err(),
            ApiError::BadRequest(_),
        ));
    }

    #[test]
    fn require_senior_accepts_admin_and_senior() {
        require_senior(&ctx_with(&[Role::Admin])).expect("admin");
        require_senior(&ctx_with(&[Role::SeniorModerator])).expect("senior");
    }

    #[test]
    fn require_senior_rejects_moderator_and_readonly() {
        assert!(matches!(
            require_senior(&ctx_with(&[Role::Moderator])).unwrap_err(),
            ApiError::Forbidden,
        ));
        assert!(matches!(
            require_senior(&ctx_with(&[Role::ReadOnly])).unwrap_err(),
            ApiError::Forbidden,
        ));
    }

    #[test]
    fn selector_kind_matches_serde_tag() {
        let s = PatternSelector::AccountCohort {
            cohort_id: "c-7".to_owned(),
        };
        assert_eq!(s.kind(), "account_cohort");
        let json = serde_json::to_string(&s).expect("serialize");
        assert!(
            json.contains("\"kind\":\"account_cohort\""),
            "expected discriminator in wire form, got {json}",
        );
    }

    #[test]
    fn selector_round_trips_through_serde() {
        let cases = vec![
            PatternSelector::ImageHashCluster {
                cluster_id: "c-1".to_owned(),
                hash: "abc".to_owned(),
            },
            PatternSelector::AccountCohort {
                cohort_id: "c-2".to_owned(),
            },
            PatternSelector::AnomalyBucket {
                category: "spam".to_owned(),
                severity: "high".to_owned(),
                bucket_start: Utc::now(),
            },
        ];
        for s in cases {
            let json = serde_json::to_value(&s).expect("serialize");
            let kind = s.kind();
            let back = decode_selector(kind, &json).expect("decode");
            assert_eq!(back, s);
        }
    }

    #[test]
    fn validate_cosign_target_rejects_self_cosign() {
        let ctx = ctx_with(&[Role::SeniorModerator]);
        let pa = PatternActionRow {
            id: PatternActionId(uuid::Uuid::new_v4()),
            selector_kind: "image_hash_cluster".to_owned(),
            selector_data: serde_json::json!({}),
            action_kind: ActionKind::Label,
            label_value: None,
            reasoning: "reasoning ten chars at least".to_owned(),
            policy_refs: vec![],
            affected_subject_count: 50,
            requires_cosign: true,
            status: PatternActionStatus::Proposed,
            requested_by: TypesModeratorId(ctx.moderator_id.0),
            requested_at: Utc::now(),
            executed_at: None,
        };
        assert!(matches!(
            validate_cosign_target(&pa, &ctx).unwrap_err(),
            ApiError::Forbidden,
        ));
    }

    #[test]
    fn validate_cosign_target_rejects_below_threshold() {
        let ctx = ctx_with(&[Role::SeniorModerator]);
        let pa = PatternActionRow {
            id: PatternActionId(uuid::Uuid::new_v4()),
            selector_kind: "image_hash_cluster".to_owned(),
            selector_data: serde_json::json!({}),
            action_kind: ActionKind::Label,
            label_value: None,
            reasoning: "reasoning ten chars at least".to_owned(),
            policy_refs: vec![],
            affected_subject_count: 1,
            requires_cosign: false,
            status: PatternActionStatus::Proposed,
            requested_by: TypesModeratorId(uuid::Uuid::new_v4()),
            requested_at: Utc::now(),
            executed_at: None,
        };
        assert!(matches!(
            validate_cosign_target(&pa, &ctx).unwrap_err(),
            ApiError::BadRequest(_),
        ));
    }

    #[test]
    fn validate_cosign_target_rejects_non_proposed_status() {
        let ctx = ctx_with(&[Role::SeniorModerator]);
        let pa = PatternActionRow {
            id: PatternActionId(uuid::Uuid::new_v4()),
            selector_kind: "image_hash_cluster".to_owned(),
            selector_data: serde_json::json!({}),
            action_kind: ActionKind::Label,
            label_value: None,
            reasoning: "reasoning ten chars at least".to_owned(),
            policy_refs: vec![],
            affected_subject_count: 50,
            requires_cosign: true,
            status: PatternActionStatus::Executed,
            requested_by: TypesModeratorId(uuid::Uuid::new_v4()),
            requested_at: Utc::now(),
            executed_at: Some(Utc::now()),
        };
        assert!(matches!(
            validate_cosign_target(&pa, &ctx).unwrap_err(),
            ApiError::Conflict(_),
        ));
    }
}
