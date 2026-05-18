//! Mod-policies repository — versioned workbook of moderation rules (#223).
//!
//! Maps the `mod_policies` row shape from migration 47 onto typed Rust
//! values that the action API (WB-2, #224) and the admin REST API
//! (WB-3, #225) consume. See `.design/mod-policy-workbook.md` REQ-A1
//! through REQ-A5 for the schema contract; this module is the typed
//! reflection of that contract.
//!
//! # Versioning model
//!
//! Every edit produces a **new row** with `version = prior + 1`; the
//! prior row stays in place with `effective_until = now()`. There is
//! no destructive UPDATE to the cells the operator typed — historical
//! actions resolve, on read, to the exact wording that was binding
//! when they fired (REQ-A1, REQ-F1).
//!
//! Retirement is also a supersession: the new row carries
//! `is_retired = TRUE`. Lookups still find the tombstone row;
//! [`ModPolicyError::RetiredPolicy`] surfaces the retired state to
//! the action-create handler so new citations are rejected.
//!
//! # Concurrency
//!
//! [`amend`] takes a `SELECT … FOR UPDATE` on the current-version
//! row inside the caller's transaction *before* writing the
//! successor. Two concurrent transactions amending the same
//! identifier serialise: the second to acquire the lock sees the
//! first amendment's `effective_until` set, observes that its
//! prior-version snapshot is now stale, and returns
//! [`ModPolicyError::ConcurrentEdit`] so the API layer can map it
//! to a `409 Conflict` (mirrors the design's REQ-A7 disposition).
//!
//! # SQL discipline
//!
//! Every query goes through `sqlx::query!` or `sqlx::query_as!`. The
//! workspace rule (`.crosslink/rules/global.md` "parameterized
//! queries only") is enforced by the absence of any string-built
//! SQL in this file.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Errors raised by the [`mod_policies`](self) repo.
///
/// Distinct from the workspace-wide [`super::RepoError`] because the
/// workbook surface has policy-shaped failure modes (stale version,
/// retired policy, unknown identifier, lock contention) that the
/// action-create and admin-REST handlers need to discriminate on.
/// `Database(sqlx::Error)` is the catch-all for everything the typed
/// variants do not call out.
#[derive(Debug, thiserror::Error)]
pub enum ModPolicyError {
    /// The caller's view of the current version is stale — another
    /// transaction has already amended this identifier. The API
    /// layer surfaces this as `409 Conflict` with
    /// `{ "code": "policy_version_stale", "current_version": N }`
    /// per `.design/mod-policy-workbook.md` AC-7.
    #[error("policy {identifier} version is stale: caller expected v{expected}, current is v{got}")]
    StaleVersion {
        /// The identifier whose current version moved out from under
        /// the caller.
        identifier: String,
        /// The version the caller believed was current.
        expected: i32,
        /// The version currently in force.
        got: i32,
    },

    /// The cited policy was retired (tombstoned) — new citations to
    /// it must be rejected. The action-create handler maps this to
    /// `400 Bad Request` with body
    /// `{ "code": "policy_retired", "identifier": "...", "retired_at": "..." }`.
    #[error("policy {identifier} was retired at {retired_at}")]
    RetiredPolicy {
        /// The identifier of the retired policy.
        identifier: String,
        /// When the tombstone successor version was written.
        retired_at: DateTime<Utc>,
    },

    /// No row matches the requested identifier. The action-create
    /// handler surfaces this as `400 Bad Request` with
    /// `{ "code": "unknown_policy_ref", "identifier": "..." }`.
    #[error("policy {identifier} is not known")]
    UnknownIdentifier {
        /// The identifier the caller tried to look up.
        identifier: String,
    },

    /// A concurrent amendment beat this transaction to the lock and
    /// the second writer's prior-version snapshot is no longer the
    /// current row. Mapped to `409 Conflict` by the admin API.
    #[error("concurrent amendment to policy {identifier}; retry")]
    ConcurrentEdit {
        /// The identifier whose amendment lost the race.
        identifier: String,
    },

    /// Any other database-side failure surfaced verbatim.
    #[error("database error")]
    Database(#[from] sqlx::Error),
}

/// A full `mod_policies` row decoded into typed fields.
///
/// Mirrors the column layout 1:1. The JSONB example arrays are
/// surfaced as `serde_json::Value` so the wasm frontend and the
/// LLM-assist context-builder can deserialize them into their own
/// strongly-typed shape without forcing the repo to re-validate
/// what the admin REST API has already validated on write.
#[derive(Debug, Clone, PartialEq)]
pub struct ModPolicy {
    /// Row identity (primary key).
    pub id: Uuid,
    /// Human-stable identifier (`polaris.harassment` etc.).
    pub identifier: String,
    /// Monotonic edit counter, 1 on initial insert.
    pub version: i32,
    /// Short human-readable title.
    pub name: String,
    /// One-paragraph policy description.
    pub description: String,
    /// `account` | `post` | `both`.
    pub scope: String,
    /// `inform` | `alert` | `hide` | `remove`.
    pub severity: String,
    /// Markdown-formatted decision criteria (≥ 64 chars).
    pub decision_criteria: String,
    /// Worked examples that DO violate the policy.
    pub examples_positive: serde_json::Value,
    /// Worked examples that look like violations but are NOT.
    pub examples_negative: serde_json::Value,
    /// Non-empty subset of `actions.kind` typically applied here.
    pub suggested_action_kinds: Vec<String>,
    /// Optional default label value when the action is `label`.
    pub linked_label_value: Option<String>,
    /// Free-text "when this policy does not apply".
    pub exceptions: Option<String>,
    /// When TRUE, autonomy mode can never be set to `autonomous`
    /// for this policy (REQ-G3).
    pub human_required_always: bool,
    /// `manual` | `assisted` | `autonomous`.
    pub autonomy_mode: String,
    /// Subset of `actions.kind` allowed for auto-fire.
    pub autonomous_action_kinds: Vec<String>,
    /// Confidence floor for autonomous emission. `0.0..=1.0`.
    pub autonomous_confidence_threshold: f32,
    /// Confidence floor for assisted draft creation. `0.0..=1.0`.
    pub assisted_confidence_threshold: f32,
    /// When `Some(t)` and `t > now()`, autonomy is suspended.
    pub autonomous_paused_until: Option<DateTime<Utc>>,
    /// Tombstone marker (retirement).
    pub is_retired: bool,
    /// When this row was inserted.
    pub created_at: DateTime<Utc>,
    /// Moderator who wrote this version.
    pub created_by_moderator_id: Uuid,
    /// When this version started binding decisions.
    pub effective_from: DateTime<Utc>,
    /// When this version stopped being current. `None` while
    /// current.
    pub effective_until: Option<DateTime<Utc>>,
    /// `Some(id)` of the prior version row, `None` for v1.
    pub supersedes_id: Option<Uuid>,
    /// "Why this version was written" — surfaced in history view.
    pub change_summary: Option<String>,
}

/// A slim row for list views. Drops the example arrays and the
/// decision-criteria body so the index list endpoint stays compact.
#[derive(Debug, Clone, PartialEq)]
pub struct ModPolicySummary {
    /// Row identity.
    pub id: Uuid,
    /// Human-stable identifier.
    pub identifier: String,
    /// Current version number.
    pub version: i32,
    /// Short title.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// Scope vocabulary value.
    pub scope: String,
    /// Severity vocabulary value.
    pub severity: String,
    /// Autonomy mode (`manual` / `assisted` / `autonomous`).
    pub autonomy_mode: String,
    /// Tombstone marker.
    pub is_retired: bool,
    /// When this version started binding.
    pub effective_from: DateTime<Utc>,
}

/// Fields the [`amend`] path may change. Every field is optional;
/// `None` means "carry forward from the prior version". The version
/// number itself is computed (`prior + 1`) — callers do not pass it.
#[derive(Debug, Clone, Default)]
pub struct ModPolicyPatch {
    /// New short title.
    pub name: Option<String>,
    /// New description paragraph.
    pub description: Option<String>,
    /// New scope.
    pub scope: Option<String>,
    /// New severity.
    pub severity: Option<String>,
    /// New decision criteria text.
    pub decision_criteria: Option<String>,
    /// Replace positive-example array.
    pub examples_positive: Option<serde_json::Value>,
    /// Replace negative-example array.
    pub examples_negative: Option<serde_json::Value>,
    /// Replace suggested action kinds list.
    pub suggested_action_kinds: Option<Vec<String>>,
    /// Replace linked label value (pass `Some(None)` to clear).
    pub linked_label_value: Option<Option<String>>,
    /// Replace exceptions text (pass `Some(None)` to clear).
    pub exceptions: Option<Option<String>>,
    /// Flip the human-required-always floor.
    pub human_required_always: Option<bool>,
    /// New autonomy mode.
    pub autonomy_mode: Option<String>,
    /// Replace allowed-autonomous-kinds list.
    pub autonomous_action_kinds: Option<Vec<String>>,
    /// New autonomous confidence floor.
    pub autonomous_confidence_threshold: Option<f32>,
    /// New assisted confidence floor.
    pub assisted_confidence_threshold: Option<f32>,
    /// Retire the policy (writes a tombstone successor).
    pub is_retired: Option<bool>,
}

/// Filters for the [`list`] endpoint. All fields are optional; an
/// empty filter is "list everything currently in force".
#[derive(Debug, Clone, Default)]
pub struct ModPolicyFilters {
    /// Restrict to a specific scope vocabulary value.
    pub scope: Option<String>,
    /// Restrict to a specific autonomy mode.
    pub autonomy_mode: Option<String>,
    /// Free-text match against `name`, `description`,
    /// `decision_criteria`. Case-insensitive substring.
    pub q: Option<String>,
}

/// Caller-supplied fields for [`insert_initial`].
///
/// `version`, `effective_from`, `created_at` are populated by the
/// repo (DEFAULT `now()` in the DB, `version` hardcoded to 1).
/// `supersedes_id`, `effective_until`, `is_retired` are not
/// accepted at initial-insert — v1 cannot supersede anything and
/// cannot be born tombstoned.
#[derive(Debug, Clone)]
pub struct NewModPolicy {
    /// Human-stable identifier; must be unique across the table at
    /// version 1 (the `UNIQUE (identifier, version)` constraint
    /// surfaces a collision as [`ModPolicyError::Database`] with a
    /// SQLSTATE 23505 inside).
    pub identifier: String,
    /// Short title.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// Scope vocabulary value.
    pub scope: String,
    /// Severity vocabulary value.
    pub severity: String,
    /// Decision criteria (≥ 64 chars; DB CHECK enforces).
    pub decision_criteria: String,
    /// Positive example array (defaults to `[]` if `None`).
    pub examples_positive: Option<serde_json::Value>,
    /// Negative example array (defaults to `[]` if `None`).
    pub examples_negative: Option<serde_json::Value>,
    /// Non-empty list of suggested action verbs.
    pub suggested_action_kinds: Vec<String>,
    /// Optional linked label value.
    pub linked_label_value: Option<String>,
    /// Optional exceptions free text.
    pub exceptions: Option<String>,
    /// REQ-A2 hard-floor marker.
    pub human_required_always: bool,
    /// `manual` / `assisted` / `autonomous`.
    pub autonomy_mode: String,
    /// Autonomous action kinds (defaults to `{}` if empty Vec).
    pub autonomous_action_kinds: Vec<String>,
    /// Autonomous confidence floor.
    pub autonomous_confidence_threshold: f32,
    /// Assisted confidence floor.
    pub assisted_confidence_threshold: f32,
    /// Optional change-summary note for the seed-loader / admin
    /// create path. Most v1 inserts leave this `None`.
    pub change_summary: Option<String>,
}

/// Insert the initial (v1) row for a brand-new policy identifier.
///
/// `created_by_moderator_id` is required so every row carries an
/// actor; the seed loader uses the bootstrap admin's id. The
/// supplied transaction is what the action-create caller (and the
/// admin create endpoint) carries through; this function never
/// opens or commits its own.
///
/// # Errors
///
/// Returns [`ModPolicyError::Database`] for the DB-side
/// `(identifier, version)` UNIQUE-violation case (operator tried
/// to "create" a policy that already exists) and for any other
/// `sqlx::Error`. Differential mapping to a `409 Conflict` shape
/// lives at the admin REST layer (WB-3) where the wire-error
/// vocabulary lives; the repo just surfaces the raw category.
///
/// # Example
///
/// ```ignore
/// let mut tx = pool.begin().await?;
/// let policy = mod_policies::insert_initial(
///     &mut tx,
///     NewModPolicy { /* ... */ },
///     bootstrap_admin_id,
/// )
/// .await?;
/// tx.commit().await?;
/// ```
pub async fn insert_initial(
    tx: &mut Transaction<'_, Postgres>,
    new: NewModPolicy,
    created_by_moderator_id: Uuid,
) -> Result<ModPolicy, ModPolicyError> {
    let examples_positive = new
        .examples_positive
        .unwrap_or_else(|| serde_json::json!([]));
    let examples_negative = new
        .examples_negative
        .unwrap_or_else(|| serde_json::json!([]));

    let row = sqlx::query!(
        r#"
        INSERT INTO mod_policies (
            identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            created_by_moderator_id, change_summary
        )
        VALUES (
            $1, 1, $2, $3,
            $4, $5, $6,
            $7, $8,
            $9, $10, $11,
            $12,
            $13, $14,
            $15,
            $16,
            $17, $18
        )
        RETURNING
            id, identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            autonomous_paused_until,
            is_retired, created_at, created_by_moderator_id,
            effective_from, effective_until,
            supersedes_id, change_summary
        "#,
        new.identifier,
        new.name,
        new.description,
        new.scope,
        new.severity,
        new.decision_criteria,
        examples_positive,
        examples_negative,
        &new.suggested_action_kinds,
        new.linked_label_value,
        new.exceptions,
        new.human_required_always,
        new.autonomy_mode,
        &new.autonomous_action_kinds,
        new.autonomous_confidence_threshold,
        new.assisted_confidence_threshold,
        created_by_moderator_id,
        new.change_summary,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(ModPolicy {
        id: row.id,
        identifier: row.identifier,
        version: row.version,
        name: row.name,
        description: row.description,
        scope: row.scope,
        severity: row.severity,
        decision_criteria: row.decision_criteria,
        examples_positive: row.examples_positive,
        examples_negative: row.examples_negative,
        suggested_action_kinds: row.suggested_action_kinds,
        linked_label_value: row.linked_label_value,
        exceptions: row.exceptions,
        human_required_always: row.human_required_always,
        autonomy_mode: row.autonomy_mode,
        autonomous_action_kinds: row.autonomous_action_kinds,
        autonomous_confidence_threshold: row.autonomous_confidence_threshold,
        assisted_confidence_threshold: row.assisted_confidence_threshold,
        autonomous_paused_until: row.autonomous_paused_until,
        is_retired: row.is_retired,
        created_at: row.created_at,
        created_by_moderator_id: row.created_by_moderator_id,
        effective_from: row.effective_from,
        effective_until: row.effective_until,
        supersedes_id: row.supersedes_id,
        change_summary: row.change_summary,
    })
}

/// Amend the current version of `identifier`: write a successor
/// row with `version = prior + 1` and set the prior row's
/// `effective_until = now()`.
///
/// # Concurrency
///
/// The function `SELECT … FOR UPDATE`s the prior current-version
/// row inside `tx` before writing the successor, so two concurrent
/// amend transactions on the same identifier serialise cleanly.
/// The loser, on releasing its `FOR UPDATE` wait, observes the
/// new `effective_until` on the row it locked and returns
/// [`ModPolicyError::ConcurrentEdit`].
///
/// # Errors
///
/// - [`ModPolicyError::UnknownIdentifier`] — no current version
///   exists.
/// - [`ModPolicyError::ConcurrentEdit`] — the prior row was
///   superseded while waiting for the lock.
/// - [`ModPolicyError::Database`] — anything else.
///
/// # Example
///
/// ```ignore
/// let mut tx = pool.begin().await?;
/// let v2 = mod_policies::amend(
///     &mut tx,
///     "polaris.harassment",
///     ModPolicyPatch {
///         description: Some("clarified satire carve-out".into()),
///         ..Default::default()
///     },
///     admin_id,
///     Some("clarify satire exception".into()),
/// )
/// .await?;
/// tx.commit().await?;
/// ```
#[allow(
    clippy::too_many_lines,
    reason = "single-tx orchestration: FOR-UPDATE the prior current row, \
              carry-forward each optional patch field, close out the prior \
              row, INSERT the successor, decode. Splitting into helpers \
              would force passing `&mut Transaction` + every prior-row \
              column through several hops and obscure the single-\
              transaction story (mirrors the same allow on \
              `insert_action_in_tx` in `action.rs`)."
)]
pub async fn amend(
    tx: &mut Transaction<'_, Postgres>,
    identifier: &str,
    patch: ModPolicyPatch,
    created_by_moderator_id: Uuid,
    change_summary: Option<String>,
) -> Result<ModPolicy, ModPolicyError> {
    // Lock the current-version row. The `effective_until IS NULL`
    // predicate matches the partial index from migration 47 so the
    // lookup is a single index probe.
    let prior_opt = sqlx::query!(
        r#"
        SELECT
            id, identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            autonomous_paused_until,
            is_retired, created_at, created_by_moderator_id,
            effective_from, effective_until,
            supersedes_id, change_summary
        FROM mod_policies
        WHERE identifier = $1 AND effective_until IS NULL
        FOR UPDATE
        "#,
        identifier,
    )
    .fetch_optional(&mut **tx)
    .await?;

    let Some(prior) = prior_opt else {
        return Err(ModPolicyError::UnknownIdentifier {
            identifier: identifier.to_owned(),
        });
    };

    // If the locked row already has `effective_until` set (race
    // resolution) bail with ConcurrentEdit. In practice, the
    // `effective_until IS NULL` predicate above means we never see
    // a non-null value here; the check is defensive against a
    // future relaxation of the predicate.
    if prior.effective_until.is_some() {
        return Err(ModPolicyError::ConcurrentEdit {
            identifier: identifier.to_owned(),
        });
    }

    let next_version = prior.version + 1;

    let name = patch.name.unwrap_or(prior.name);
    let description = patch.description.unwrap_or(prior.description);
    let scope = patch.scope.unwrap_or(prior.scope);
    let severity = patch.severity.unwrap_or(prior.severity);
    let decision_criteria = patch.decision_criteria.unwrap_or(prior.decision_criteria);
    let examples_positive = patch.examples_positive.unwrap_or(prior.examples_positive);
    let examples_negative = patch.examples_negative.unwrap_or(prior.examples_negative);
    let suggested_action_kinds = patch
        .suggested_action_kinds
        .unwrap_or(prior.suggested_action_kinds);
    let linked_label_value = match patch.linked_label_value {
        Some(v) => v,
        None => prior.linked_label_value,
    };
    let exceptions = match patch.exceptions {
        Some(v) => v,
        None => prior.exceptions,
    };
    let human_required_always = patch
        .human_required_always
        .unwrap_or(prior.human_required_always);
    let autonomy_mode = patch.autonomy_mode.unwrap_or(prior.autonomy_mode);
    let autonomous_action_kinds = patch
        .autonomous_action_kinds
        .unwrap_or(prior.autonomous_action_kinds);
    let autonomous_confidence_threshold = patch
        .autonomous_confidence_threshold
        .unwrap_or(prior.autonomous_confidence_threshold);
    let assisted_confidence_threshold = patch
        .assisted_confidence_threshold
        .unwrap_or(prior.assisted_confidence_threshold);
    let is_retired = patch.is_retired.unwrap_or(prior.is_retired);

    // Close out the prior row. `now()` matches the successor's
    // `effective_from = now()` so the boundary is consistent on
    // both sides.
    sqlx::query!(
        r#"
        UPDATE mod_policies
        SET effective_until = now()
        WHERE id = $1
        "#,
        prior.id,
    )
    .execute(&mut **tx)
    .await?;

    let row = sqlx::query!(
        r#"
        INSERT INTO mod_policies (
            identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            is_retired,
            created_by_moderator_id, change_summary, supersedes_id
        )
        VALUES (
            $1, $2, $3, $4,
            $5, $6, $7,
            $8, $9,
            $10, $11, $12,
            $13,
            $14, $15,
            $16,
            $17,
            $18,
            $19, $20, $21
        )
        RETURNING
            id, identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            autonomous_paused_until,
            is_retired, created_at, created_by_moderator_id,
            effective_from, effective_until,
            supersedes_id, change_summary
        "#,
        identifier,
        next_version,
        name,
        description,
        scope,
        severity,
        decision_criteria,
        examples_positive,
        examples_negative,
        &suggested_action_kinds,
        linked_label_value,
        exceptions,
        human_required_always,
        autonomy_mode,
        &autonomous_action_kinds,
        autonomous_confidence_threshold,
        assisted_confidence_threshold,
        is_retired,
        created_by_moderator_id,
        change_summary,
        prior.id,
    )
    .fetch_one(&mut **tx)
    .await?;

    Ok(ModPolicy {
        id: row.id,
        identifier: row.identifier,
        version: row.version,
        name: row.name,
        description: row.description,
        scope: row.scope,
        severity: row.severity,
        decision_criteria: row.decision_criteria,
        examples_positive: row.examples_positive,
        examples_negative: row.examples_negative,
        suggested_action_kinds: row.suggested_action_kinds,
        linked_label_value: row.linked_label_value,
        exceptions: row.exceptions,
        human_required_always: row.human_required_always,
        autonomy_mode: row.autonomy_mode,
        autonomous_action_kinds: row.autonomous_action_kinds,
        autonomous_confidence_threshold: row.autonomous_confidence_threshold,
        assisted_confidence_threshold: row.assisted_confidence_threshold,
        autonomous_paused_until: row.autonomous_paused_until,
        is_retired: row.is_retired,
        created_at: row.created_at,
        created_by_moderator_id: row.created_by_moderator_id,
        effective_from: row.effective_from,
        effective_until: row.effective_until,
        supersedes_id: row.supersedes_id,
        change_summary: row.change_summary,
    })
}

/// Fetch the current (`effective_until IS NULL`) version of
/// `identifier`, or `None` if no row matches.
///
/// The action-create hot path calls this through the LRU cache
/// (WB-2); the workbook list / detail / history endpoints call it
/// directly. Either way, the query is one index probe via the
/// partial index from migration 47.
///
/// # Errors
///
/// [`ModPolicyError::Database`] on any DB-side failure.
///
/// # Example
///
/// ```ignore
/// let p = mod_policies::current_by_identifier(&pool, "polaris.harassment").await?;
/// assert!(p.is_some());
/// ```
pub async fn current_by_identifier(
    pool: &PgPool,
    identifier: &str,
) -> Result<Option<ModPolicy>, ModPolicyError> {
    let row_opt = sqlx::query!(
        r#"
        SELECT
            id, identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            autonomous_paused_until,
            is_retired, created_at, created_by_moderator_id,
            effective_from, effective_until,
            supersedes_id, change_summary
        FROM mod_policies
        WHERE identifier = $1 AND effective_until IS NULL
        "#,
        identifier,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row_opt.map(|row| ModPolicy {
        id: row.id,
        identifier: row.identifier,
        version: row.version,
        name: row.name,
        description: row.description,
        scope: row.scope,
        severity: row.severity,
        decision_criteria: row.decision_criteria,
        examples_positive: row.examples_positive,
        examples_negative: row.examples_negative,
        suggested_action_kinds: row.suggested_action_kinds,
        linked_label_value: row.linked_label_value,
        exceptions: row.exceptions,
        human_required_always: row.human_required_always,
        autonomy_mode: row.autonomy_mode,
        autonomous_action_kinds: row.autonomous_action_kinds,
        autonomous_confidence_threshold: row.autonomous_confidence_threshold,
        assisted_confidence_threshold: row.assisted_confidence_threshold,
        autonomous_paused_until: row.autonomous_paused_until,
        is_retired: row.is_retired,
        created_at: row.created_at,
        created_by_moderator_id: row.created_by_moderator_id,
        effective_from: row.effective_from,
        effective_until: row.effective_until,
        supersedes_id: row.supersedes_id,
        change_summary: row.change_summary,
    }))
}

/// Fetch a specific historical version of `identifier`.
///
/// Used by the per-version detail endpoint (WB-3) and by the
/// action-create idempotency path, which resolves a cited
/// `(identifier, version)` pair to confirm it existed.
///
/// # Errors
///
/// [`ModPolicyError::Database`] on any DB-side failure.
pub async fn at_version(
    pool: &PgPool,
    identifier: &str,
    version: i32,
) -> Result<Option<ModPolicy>, ModPolicyError> {
    let row_opt = sqlx::query!(
        r#"
        SELECT
            id, identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            autonomous_paused_until,
            is_retired, created_at, created_by_moderator_id,
            effective_from, effective_until,
            supersedes_id, change_summary
        FROM mod_policies
        WHERE identifier = $1 AND version = $2
        "#,
        identifier,
        version,
    )
    .fetch_optional(pool)
    .await?;

    Ok(row_opt.map(|row| ModPolicy {
        id: row.id,
        identifier: row.identifier,
        version: row.version,
        name: row.name,
        description: row.description,
        scope: row.scope,
        severity: row.severity,
        decision_criteria: row.decision_criteria,
        examples_positive: row.examples_positive,
        examples_negative: row.examples_negative,
        suggested_action_kinds: row.suggested_action_kinds,
        linked_label_value: row.linked_label_value,
        exceptions: row.exceptions,
        human_required_always: row.human_required_always,
        autonomy_mode: row.autonomy_mode,
        autonomous_action_kinds: row.autonomous_action_kinds,
        autonomous_confidence_threshold: row.autonomous_confidence_threshold,
        assisted_confidence_threshold: row.assisted_confidence_threshold,
        autonomous_paused_until: row.autonomous_paused_until,
        is_retired: row.is_retired,
        created_at: row.created_at,
        created_by_moderator_id: row.created_by_moderator_id,
        effective_from: row.effective_from,
        effective_until: row.effective_until,
        supersedes_id: row.supersedes_id,
        change_summary: row.change_summary,
    }))
}

/// Return every version of `identifier`, oldest first.
///
/// The history view (WB-3) renders these top-to-bottom with each
/// row's `change_summary` and a per-version diff link. The
/// ordering matches that surface convention.
///
/// # Errors
///
/// [`ModPolicyError::Database`] on any DB-side failure.
pub async fn history(pool: &PgPool, identifier: &str) -> Result<Vec<ModPolicy>, ModPolicyError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            id, identifier, version, name, description,
            scope, severity, decision_criteria,
            examples_positive, examples_negative,
            suggested_action_kinds, linked_label_value, exceptions,
            human_required_always,
            autonomy_mode, autonomous_action_kinds,
            autonomous_confidence_threshold,
            assisted_confidence_threshold,
            autonomous_paused_until,
            is_retired, created_at, created_by_moderator_id,
            effective_from, effective_until,
            supersedes_id, change_summary
        FROM mod_policies
        WHERE identifier = $1
        ORDER BY version ASC
        "#,
        identifier,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ModPolicy {
            id: row.id,
            identifier: row.identifier,
            version: row.version,
            name: row.name,
            description: row.description,
            scope: row.scope,
            severity: row.severity,
            decision_criteria: row.decision_criteria,
            examples_positive: row.examples_positive,
            examples_negative: row.examples_negative,
            suggested_action_kinds: row.suggested_action_kinds,
            linked_label_value: row.linked_label_value,
            exceptions: row.exceptions,
            human_required_always: row.human_required_always,
            autonomy_mode: row.autonomy_mode,
            autonomous_action_kinds: row.autonomous_action_kinds,
            autonomous_confidence_threshold: row.autonomous_confidence_threshold,
            assisted_confidence_threshold: row.assisted_confidence_threshold,
            autonomous_paused_until: row.autonomous_paused_until,
            is_retired: row.is_retired,
            created_at: row.created_at,
            created_by_moderator_id: row.created_by_moderator_id,
            effective_from: row.effective_from,
            effective_until: row.effective_until,
            supersedes_id: row.supersedes_id,
            change_summary: row.change_summary,
        })
        .collect())
}

/// List the current version of every policy, filtered by the
/// supplied criteria.
///
/// The frontend list view (`/admin/policies` and `/policies`)
/// renders [`ModPolicySummary`] rows; the example arrays and the
/// decision-criteria body are intentionally omitted to keep the
/// index payload small.
///
/// `filters.q` does a case-insensitive substring match across
/// `name`, `description`, and `decision_criteria`. Empty filters
/// return every current version in identifier-ASC order.
///
/// # Errors
///
/// [`ModPolicyError::Database`] on any DB-side failure.
pub async fn list(
    pool: &PgPool,
    filters: ModPolicyFilters,
) -> Result<Vec<ModPolicySummary>, ModPolicyError> {
    // Free-text filter is built into a single ILIKE pattern so the
    // query stays a `sqlx::query!` (compile-time-checked) — no
    // dynamic string concatenation. NULL means "no filter".
    let q_pattern = filters.q.as_ref().map(|q| format!("%{q}%"));

    let rows = sqlx::query!(
        r#"
        SELECT
            id, identifier, version, name, description,
            scope, severity, autonomy_mode, is_retired,
            effective_from
        FROM mod_policies
        WHERE effective_until IS NULL
          AND ($1::TEXT IS NULL OR scope = $1)
          AND ($2::TEXT IS NULL OR autonomy_mode = $2)
          AND (
              $3::TEXT IS NULL
              OR name ILIKE $3
              OR description ILIKE $3
              OR decision_criteria ILIKE $3
          )
        ORDER BY identifier ASC
        "#,
        filters.scope,
        filters.autonomy_mode,
        q_pattern,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ModPolicySummary {
            id: row.id,
            identifier: row.identifier,
            version: row.version,
            name: row.name,
            description: row.description,
            scope: row.scope,
            severity: row.severity,
            autonomy_mode: row.autonomy_mode,
            is_retired: row.is_retired,
            effective_from: row.effective_from,
        })
        .collect())
}

/// Set `autonomous_paused_until` on the current version of
/// `identifier`.
///
/// Used by the kill-switch endpoint (WB-3) and by the
/// circuit-breaker that the LLM-assist design writes when its
/// per-moderator anomaly detectors trip. The amend path is NOT
/// used — pausing is not a versioning event (the wording did not
/// change), only an operational annotation; bumping the version
/// for every kill-switch toggle would noise the history view.
///
/// `until` is `None` when the caller wants "pause for the
/// foreseeable future"; pass `Some(t)` with `t = '9999-12-31'`
/// for the "forever" UI affordance.
///
/// # Errors
///
/// - [`ModPolicyError::UnknownIdentifier`] when no current
///   version exists.
/// - [`ModPolicyError::Database`] on any DB-side failure.
pub async fn pause(
    tx: &mut Transaction<'_, Postgres>,
    identifier: &str,
    until: Option<DateTime<Utc>>,
) -> Result<(), ModPolicyError> {
    let result = sqlx::query!(
        r#"
        UPDATE mod_policies
        SET autonomous_paused_until = $2
        WHERE identifier = $1 AND effective_until IS NULL
        "#,
        identifier,
        until,
    )
    .execute(&mut **tx)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ModPolicyError::UnknownIdentifier {
            identifier: identifier.to_owned(),
        });
    }
    Ok(())
}

/// Clear `autonomous_paused_until` on the current version of
/// `identifier`.
///
/// The companion to [`pause`]. Resumes auto-firing immediately on
/// commit — the LLM dispatcher re-reads this column on every
/// recommend call so no cache invalidation is needed.
///
/// # Errors
///
/// - [`ModPolicyError::UnknownIdentifier`] when no current
///   version exists.
/// - [`ModPolicyError::Database`] on any DB-side failure.
pub async fn resume(
    tx: &mut Transaction<'_, Postgres>,
    identifier: &str,
) -> Result<(), ModPolicyError> {
    let result = sqlx::query!(
        r#"
        UPDATE mod_policies
        SET autonomous_paused_until = NULL
        WHERE identifier = $1 AND effective_until IS NULL
        "#,
        identifier,
    )
    .execute(&mut **tx)
    .await?;

    if result.rows_affected() == 0 {
        return Err(ModPolicyError::UnknownIdentifier {
            identifier: identifier.to_owned(),
        });
    }
    Ok(())
}
