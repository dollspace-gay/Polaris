//! Admin-only policy management handlers (WB-3 / #225).
//!
//! Mirrors `crate::api::admin_moderators` in shape: every handler is
//! `pub async fn`, takes `State<ApiState>` + `Extension<ModeratorAuthCtx>`,
//! short-circuits via [`require_admin`], translates DB errors through
//! [`ApiError`], and appends an `audit_log` row inside the same
//! transaction as the write so a failed audit append rolls the write
//! back.
//!
//! # Endpoints
//!
//! - `GET    /api/admin/policies` — list (filters: scope, `autonomy_mode`, q).
//! - `GET    /api/admin/policies/:identifier` — current full version.
//! - `GET    /api/admin/policies/:identifier/history` — full version chain.
//! - `GET    /api/admin/policies/:identifier/diff?from=N&to=M` —
//!   per-field diff.
//! - `GET    /api/admin/policies/:identifier/:version` — historical version.
//! - `POST   /api/admin/policies` — create v1.
//! - `PATCH  /api/admin/policies/:identifier` — amend (new version).
//! - `POST   /api/admin/policies/:identifier/pause` — set kill switch.
//! - `DELETE /api/admin/policies/:identifier/pause` — clear kill switch.
//!
//! # Route ordering note
//!
//! The router registers `:identifier/history` and `:identifier/diff`
//! BEFORE the generic `:identifier/:version` route so axum's matcher
//! does not consume the literal words "history" / "diff" as a
//! `:version` path parameter (see `crate::api::admin_policies::mod`).
//!
//! # Validation discipline
//!
//! Per the issue plan and `.design/mod-policy-workbook.md`:
//!
//! - vocabulary checks (`scope`, `severity`, `autonomy_mode`,
//!   action-kind subset) happen here, before reaching the repo;
//! - threshold ranges (`0.0..=1.0`) are checked here;
//! - the REQ-G3 hard floor (`human_required_always = TRUE` ⇒
//!   `autonomy_mode = autonomous` rejected) is enforced here as
//!   one of the three layers (the dispatcher + action-create are
//!   the other two; out of scope for this issue).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, TimeZone as _, Utc};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::api::admin_policies::dto::{
    CreatePolicyDto, DiffChangeDto, ModPolicyDto, ModPolicyEditDto, ModPolicyHistoryEntryDto,
    ModPolicySummaryDto, PausePolicyDto, PolicyDiffDto,
};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::repo::mod_policies::{
    self, ModPolicy, ModPolicyError, ModPolicyFilters, ModPolicyPatch, NewModPolicy,
};

/// Valid `scope` vocabulary per `.design/mod-policy-workbook.md` REQ-A2.
const VALID_SCOPES: &[&str] = &["account", "post", "both"];
/// Valid `severity` vocabulary per REQ-A2.
const VALID_SEVERITIES: &[&str] = &["inform", "alert", "hide", "remove"];
/// Valid `autonomy_mode` vocabulary per REQ-A3.
const VALID_AUTONOMY_MODES: &[&str] = &["manual", "assisted", "autonomous"];
/// Action kinds eligible for `autonomous_action_kinds` per REQ-G1.
/// Strictly a subset of `actions.kind` — `escalate`/`mute`/`no_action`
/// /`reverse`/`comment` cannot auto-fire.
const ELIGIBLE_AUTONOMOUS_KINDS: &[&str] = &["label", "warn", "takedown"];
/// Action kinds that may appear in `suggested_action_kinds`. Matches
/// the `actions.kind` enum (any moderator-issued verb).
const VALID_SUGGESTED_KINDS: &[&str] = &[
    "label",
    "warn",
    "takedown",
    "mute",
    "escalate",
    "no_action",
    "reverse",
    "comment",
];
/// Minimum length of `decision_criteria` per REQ-A2 (the DB CHECK
/// enforces the same — we duplicate at the boundary so a bad request
/// is a clean 400 rather than a 500 round-trip through the repo).
const DECISION_CRITERIA_MIN_LEN: usize = 64;

/// Verify the caller is `Role::Admin`. Mirrors
/// `crate::api::admin_moderators::require_admin`.
fn require_admin(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Map [`ModPolicyError`] to the wire-facing [`ApiError`].
fn map_policy_err(err: ModPolicyError) -> ApiError {
    match err {
        ModPolicyError::UnknownIdentifier { .. } => ApiError::NotFound,
        ModPolicyError::ConcurrentEdit { .. } => {
            ApiError::Conflict("concurrent amendment; retry the request")
        }
        ModPolicyError::StaleVersion { .. } => ApiError::Conflict("policy version is stale"),
        ModPolicyError::RetiredPolicy { .. } => ApiError::BadRequest("policy is retired"),
        ModPolicyError::Database(e) => ApiError::Internal(anyhow::Error::new(e)),
    }
}

// ── Validation helpers ─────────────────────────────────────────────────

/// Validate a `scope` vocabulary value.
fn check_scope(s: &str) -> Result<(), ApiError> {
    if VALID_SCOPES.contains(&s) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "scope must be one of: account, post, both",
        ))
    }
}

/// Validate a `severity` vocabulary value.
fn check_severity(s: &str) -> Result<(), ApiError> {
    if VALID_SEVERITIES.contains(&s) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "severity must be one of: inform, alert, hide, remove",
        ))
    }
}

/// Validate `autonomy_mode`.
fn check_autonomy_mode(s: &str) -> Result<(), ApiError> {
    if VALID_AUTONOMY_MODES.contains(&s) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "autonomy_mode must be one of: manual, assisted, autonomous",
        ))
    }
}

/// Validate the autonomous-kinds list is a subset of REQ-G1's eligible
/// set.
fn check_autonomous_action_kinds(kinds: &[String]) -> Result<(), ApiError> {
    for k in kinds {
        if !ELIGIBLE_AUTONOMOUS_KINDS.contains(&k.as_str()) {
            return Err(ApiError::BadRequest(
                "autonomous_action_kinds must be a subset of {label, warn, takedown}",
            ));
        }
    }
    Ok(())
}

/// Validate the suggested-kinds list is non-empty and a subset of the
/// `actions.kind` vocabulary.
fn check_suggested_action_kinds(kinds: &[String]) -> Result<(), ApiError> {
    if kinds.is_empty() {
        return Err(ApiError::BadRequest(
            "suggested_action_kinds must be non-empty",
        ));
    }
    for k in kinds {
        if !VALID_SUGGESTED_KINDS.contains(&k.as_str()) {
            return Err(ApiError::BadRequest(
                "suggested_action_kinds must reference valid action kinds",
            ));
        }
    }
    Ok(())
}

/// Validate a `0.0..=1.0` confidence threshold.
fn check_confidence_threshold(value: f32) -> Result<(), ApiError> {
    if value.is_nan() || !(0.0..=1.0).contains(&value) {
        return Err(ApiError::BadRequest(
            "confidence threshold must be in [0.0, 1.0]",
        ));
    }
    Ok(())
}

/// Validate `decision_criteria` length.
fn check_decision_criteria(text: &str) -> Result<(), ApiError> {
    if text.chars().count() < DECISION_CRITERIA_MIN_LEN {
        return Err(ApiError::BadRequest(
            "decision_criteria must be at least 64 characters",
        ));
    }
    Ok(())
}

/// REQ-G3 floor: a `human_required_always = TRUE` policy cannot have
/// `autonomy_mode = 'autonomous'` set. The wire shape is
/// `403 policy_autonomy_forbidden` per the design.
fn check_req_g3(human_required_always: bool, autonomy_mode: &str) -> Result<(), ApiError> {
    if human_required_always && autonomy_mode == "autonomous" {
        return Err(ApiError::PreconditionFailed {
            code: "policy_autonomy_forbidden",
            message: "policy is marked human_required_always; flip that off first if you really mean to autonomously enforce",
        });
    }
    Ok(())
}

// ── Query / handler payloads ───────────────────────────────────────────

/// Query-string filters for `GET /api/admin/policies` (and the
/// moderator-facing `GET /api/policies`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ListPoliciesQuery {
    /// Restrict to a specific `scope` vocabulary value.
    #[serde(default)]
    pub scope: Option<String>,
    /// Restrict to a specific `autonomy_mode` vocabulary value.
    #[serde(default)]
    pub autonomy_mode: Option<String>,
    /// Free-text substring match across name + description +
    /// `decision_criteria`.
    #[serde(default)]
    pub q: Option<String>,
}

/// Query-string for `GET /api/admin/policies/:identifier/diff?from=N&to=M`.
#[derive(Debug, Clone, Deserialize)]
pub struct DiffQuery {
    /// Lower-side version number.
    pub from: i32,
    /// Upper-side version number.
    pub to: i32,
}

// ── Admin handlers ─────────────────────────────────────────────────────

/// `GET /api/admin/policies`.
///
/// Returns the slim summary projection of every current-version
/// policy, filtered per the query string.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] when a vocabulary filter is invalid.
/// - [`ApiError::Internal`] on DB failure.
///
/// # Example
///
/// ```ignore
/// // Admin lists all post-scope policies in autonomous mode:
/// // GET /api/admin/policies?scope=post&autonomy_mode=autonomous
/// ```
pub async fn list_admin_policies(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Query(filters): Query<ListPoliciesQuery>,
) -> Result<Json<Vec<ModPolicySummaryDto>>, ApiError> {
    require_admin(&ctx)?;
    if let Some(scope) = &filters.scope {
        check_scope(scope)?;
    }
    if let Some(mode) = &filters.autonomy_mode {
        check_autonomy_mode(mode)?;
    }
    let rows = mod_policies::list(
        &state.pool,
        ModPolicyFilters {
            scope: filters.scope,
            autonomy_mode: filters.autonomy_mode,
            q: filters.q,
        },
    )
    .await
    .map_err(map_policy_err)?;
    Ok(Json(
        rows.into_iter().map(ModPolicySummaryDto::from).collect(),
    ))
}

/// `GET /api/admin/policies/:identifier`.
///
/// Returns the current version of `identifier` with the full payload
/// (examples included).
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::NotFound`] when no current-version row exists.
/// - [`ApiError::Internal`] on DB failure.
///
/// # Example
///
/// ```ignore
/// // GET /api/admin/policies/polaris.harassment
/// ```
pub async fn get_admin_policy(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(identifier): Path<String>,
) -> Result<Json<ModPolicyDto>, ApiError> {
    require_admin(&ctx)?;
    let policy = mod_policies::current_by_identifier(&state.pool, &identifier)
        .await
        .map_err(map_policy_err)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(policy.into()))
}

/// `GET /api/admin/policies/:identifier/history`.
///
/// Returns the full version chain (oldest first).
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::NotFound`] when no row at all matches the identifier.
/// - [`ApiError::Internal`] on DB failure.
///
/// # Example
///
/// ```ignore
/// // GET /api/admin/policies/polaris.harassment/history
/// ```
pub async fn get_admin_policy_history(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(identifier): Path<String>,
) -> Result<Json<Vec<ModPolicyHistoryEntryDto>>, ApiError> {
    require_admin(&ctx)?;
    let rows = mod_policies::history(&state.pool, &identifier)
        .await
        .map_err(map_policy_err)?;
    if rows.is_empty() {
        return Err(ApiError::NotFound);
    }
    let entries: Vec<ModPolicyHistoryEntryDto> = rows
        .into_iter()
        .map(|row| ModPolicyHistoryEntryDto {
            diff_url: if row.version > 1 {
                Some(format!(
                    "/api/admin/policies/{}/diff?from={}&to={}",
                    row.identifier,
                    row.version - 1,
                    row.version,
                ))
            } else {
                None
            },
            id: row.id,
            version: row.version,
            change_summary: row.change_summary,
            created_by_moderator_id: row.created_by_moderator_id,
            created_at: row.created_at,
            effective_from: row.effective_from,
            effective_until: row.effective_until,
            is_retired: row.is_retired,
        })
        .collect();
    Ok(Json(entries))
}

/// `GET /api/admin/policies/:identifier/:version`.
///
/// Returns a specific historical version. Useful for following a
/// diff URL or auditing what version a stale action cited.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::NotFound`] when no row matches the
///   `(identifier, version)` pair.
/// - [`ApiError::Internal`] on DB failure.
///
/// # Example
///
/// ```ignore
/// // GET /api/admin/policies/polaris.harassment/3
/// ```
pub async fn get_admin_policy_at_version(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path((identifier, version)): Path<(String, i32)>,
) -> Result<Json<ModPolicyDto>, ApiError> {
    require_admin(&ctx)?;
    let policy = mod_policies::at_version(&state.pool, &identifier, version)
        .await
        .map_err(map_policy_err)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(policy.into()))
}

/// `GET /api/admin/policies/:identifier/diff?from=N&to=M`.
///
/// Returns a per-field diff between the two versions. Only fields
/// that differ appear under `changes`.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] when `from == to` or either is `< 1`.
/// - [`ApiError::NotFound`] when either version is missing.
/// - [`ApiError::Internal`] on DB failure.
///
/// # Example
///
/// ```ignore
/// // GET /api/admin/policies/polaris.harassment/diff?from=3&to=5
/// ```
pub async fn get_admin_policy_diff(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(identifier): Path<String>,
    Query(q): Query<DiffQuery>,
) -> Result<Json<PolicyDiffDto>, ApiError> {
    require_admin(&ctx)?;
    if q.from < 1 || q.to < 1 {
        return Err(ApiError::BadRequest("from and to must be >= 1"));
    }
    if q.from == q.to {
        return Err(ApiError::BadRequest("from and to must differ"));
    }
    let from = mod_policies::at_version(&state.pool, &identifier, q.from)
        .await
        .map_err(map_policy_err)?
        .ok_or(ApiError::NotFound)?;
    let to = mod_policies::at_version(&state.pool, &identifier, q.to)
        .await
        .map_err(map_policy_err)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(PolicyDiffDto {
        identifier,
        from_version: q.from,
        to_version: q.to,
        changes: diff_policies(&from, &to),
    }))
}

/// Compute the per-field diff between two policy versions.
///
/// Excludes audit metadata fields (`id`, `created_*`, `effective_*`,
/// `supersedes_id`, `autonomous_paused_until`, `change_summary`) per
/// the issue plan: those trivially differ on every amendment and the
/// admin UI does not surface them in the diff view.
fn diff_policies(a: &ModPolicy, b: &ModPolicy) -> BTreeMap<String, DiffChangeDto> {
    let mut out = BTreeMap::new();
    macro_rules! diff_scalar {
        ($field:ident) => {
            if a.$field != b.$field {
                out.insert(
                    stringify!($field).to_owned(),
                    DiffChangeDto {
                        from: serde_json::to_value(&a.$field).unwrap_or(serde_json::Value::Null),
                        to: serde_json::to_value(&b.$field).unwrap_or(serde_json::Value::Null),
                    },
                );
            }
        };
    }
    diff_scalar!(name);
    diff_scalar!(description);
    diff_scalar!(scope);
    diff_scalar!(severity);
    diff_scalar!(decision_criteria);
    diff_scalar!(examples_positive);
    diff_scalar!(examples_negative);
    diff_scalar!(suggested_action_kinds);
    diff_scalar!(linked_label_value);
    diff_scalar!(exceptions);
    diff_scalar!(human_required_always);
    diff_scalar!(autonomy_mode);
    diff_scalar!(autonomous_action_kinds);
    // Float-NaN check: f32::partial_cmp != Eq, but PartialEq treats NaN
    // as != NaN — surfacing such a row would be misleading. NaN never
    // reaches here because the threshold validators reject NaN at the
    // boundary.
    if (a.autonomous_confidence_threshold - b.autonomous_confidence_threshold).abs() > f32::EPSILON
    {
        out.insert(
            "autonomous_confidence_threshold".to_owned(),
            DiffChangeDto {
                from: serde_json::to_value(a.autonomous_confidence_threshold)
                    .unwrap_or(serde_json::Value::Null),
                to: serde_json::to_value(b.autonomous_confidence_threshold)
                    .unwrap_or(serde_json::Value::Null),
            },
        );
    }
    if (a.assisted_confidence_threshold - b.assisted_confidence_threshold).abs() > f32::EPSILON {
        out.insert(
            "assisted_confidence_threshold".to_owned(),
            DiffChangeDto {
                from: serde_json::to_value(a.assisted_confidence_threshold)
                    .unwrap_or(serde_json::Value::Null),
                to: serde_json::to_value(b.assisted_confidence_threshold)
                    .unwrap_or(serde_json::Value::Null),
            },
        );
    }
    diff_scalar!(is_retired);
    out
}

/// `POST /api/admin/policies`.
///
/// Creates a brand-new policy at version 1. The body is the
/// [`CreatePolicyDto`] shape — required fields enforced by serde,
/// vocabulary + range checks here.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] on validation failure.
/// - [`ApiError::PreconditionFailed`] (`policy_autonomy_forbidden`)
///   when REQ-G3 would be violated.
/// - [`ApiError::Conflict`] when the identifier already exists at
///   v1 (unique violation surfaces from the repo).
/// - [`ApiError::Internal`] on any other DB failure.
///
/// # Example
///
/// ```ignore
/// // POST /api/admin/policies
/// // body: { identifier, name, description, scope: "post", ... }
/// ```
pub async fn create_admin_policy(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(body): Json<CreatePolicyDto>,
) -> Result<(StatusCode, Json<ModPolicyDto>), ApiError> {
    require_admin(&ctx)?;
    validate_create(&body)?;

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let inserted = mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: body.identifier.clone(),
            name: body.name,
            description: body.description,
            scope: body.scope,
            severity: body.severity,
            decision_criteria: body.decision_criteria,
            examples_positive: body.examples_positive,
            examples_negative: body.examples_negative,
            suggested_action_kinds: body.suggested_action_kinds,
            linked_label_value: body.linked_label_value,
            exceptions: body.exceptions,
            human_required_always: body.human_required_always,
            autonomy_mode: body.autonomy_mode,
            autonomous_action_kinds: body.autonomous_action_kinds,
            autonomous_confidence_threshold: body.autonomous_confidence_threshold,
            assisted_confidence_threshold: body.assisted_confidence_threshold,
            change_summary: body.change_summary,
        },
        ctx.moderator_id.0,
    )
    .await
    .map_err(|err| match err {
        ModPolicyError::Database(e) => {
            if let Some(db_err) = e.as_database_error() {
                if db_err.code().as_deref() == Some("23505") {
                    return ApiError::Conflict("policy identifier already exists");
                }
            }
            ApiError::Internal(anyhow::Error::new(e))
        }
        other => map_policy_err(other),
    })?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "policy_created".to_owned(),
            payload: serde_json::json!({
                "identifier": inserted.identifier,
                "version": inserted.version,
                "moderator_id": ctx.moderator_id.to_string(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok((StatusCode::CREATED, Json(inserted.into())))
}

/// `PATCH /api/admin/policies/:identifier`.
///
/// Amends the policy: writes a successor row with `version = prior + 1`
/// and sets the prior row's `effective_until = now()`. Body must carry
/// `change_summary`; every other field is optional.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] on validation failure (vocabulary,
///   threshold range, missing `change_summary`).
/// - [`ApiError::PreconditionFailed`] (`policy_autonomy_forbidden`)
///   when REQ-G3 would be violated by the resulting row.
/// - [`ApiError::NotFound`] when the identifier is unknown.
/// - [`ApiError::Conflict`] on a concurrent-edit race.
/// - [`ApiError::Internal`] on any other DB failure.
///
/// # Example
///
/// ```ignore
/// // PATCH /api/admin/policies/polaris.harassment
/// // body: { autonomy_mode: "assisted", change_summary: "raise the floor" }
/// ```
pub async fn patch_admin_policy(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(identifier): Path<String>,
    Json(body): Json<ModPolicyEditDto>,
) -> Result<Json<ModPolicyDto>, ApiError> {
    require_admin(&ctx)?;
    if body.change_summary.trim().is_empty() {
        return Err(ApiError::BadRequest("change_summary is required"));
    }
    validate_patch(&body)?;

    // REQ-G3 / autonomy-floor pre-check: we need the prior row's
    // `human_required_always` value when the patch doesn't change it.
    // Read the current version first so the autonomy-vs-human-required
    // floor is evaluated against the row that will actually exist
    // post-amend. The repo's `amend` then locks the same row inside
    // its transaction — a concurrent retirement / amendment in
    // between manifests as `ConcurrentEdit` / `UnknownIdentifier` and
    // surfaces as a 409 / 404 respectively.
    let prior = mod_policies::current_by_identifier(&state.pool, &identifier)
        .await
        .map_err(map_policy_err)?
        .ok_or(ApiError::NotFound)?;
    let resulting_hra = body
        .human_required_always
        .unwrap_or(prior.human_required_always);
    let resulting_mode = body
        .autonomy_mode
        .clone()
        .unwrap_or(prior.autonomy_mode.clone());
    check_req_g3(resulting_hra, &resulting_mode)?;

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let new_version = mod_policies::amend(
        &mut tx,
        &identifier,
        ModPolicyPatch {
            name: body.name,
            description: body.description,
            scope: body.scope,
            severity: body.severity,
            decision_criteria: body.decision_criteria,
            examples_positive: body.examples_positive,
            examples_negative: body.examples_negative,
            suggested_action_kinds: body.suggested_action_kinds,
            linked_label_value: body.linked_label_value,
            exceptions: body.exceptions,
            human_required_always: body.human_required_always,
            autonomy_mode: body.autonomy_mode,
            autonomous_action_kinds: body.autonomous_action_kinds,
            autonomous_confidence_threshold: body.autonomous_confidence_threshold,
            assisted_confidence_threshold: body.assisted_confidence_threshold,
            is_retired: body.is_retired,
        },
        ctx.moderator_id.0,
        Some(body.change_summary.clone()),
    )
    .await
    .map_err(map_policy_err)?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "policy_amended".to_owned(),
            payload: serde_json::json!({
                "identifier": new_version.identifier,
                "from_version": prior.version,
                "to_version": new_version.version,
                "change_summary": body.change_summary,
                "moderator_id": ctx.moderator_id.to_string(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(Json(new_version.into()))
}

/// `POST /api/admin/policies/:identifier/pause`.
///
/// Sets `autonomous_paused_until` on the current version. Body is
/// optional — empty body / `{}` / `{ "forever": true }` all map to
/// "pause until `'9999-12-31'`"; an explicit `{ "until": "<RFC3339>" }`
/// pauses until that timestamp.
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::BadRequest`] when `until` is in the past.
/// - [`ApiError::NotFound`] when the identifier is unknown.
/// - [`ApiError::Internal`] on any DB failure.
///
/// # Example
///
/// ```ignore
/// // POST /api/admin/policies/polaris.harassment/pause
/// // body: { "until": "2026-12-31T00:00:00Z" }
/// ```
pub async fn pause_admin_policy(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(identifier): Path<String>,
    raw: axum::body::Bytes,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx)?;
    // Manual body decode: an empty body (no payload at all) is the
    // documented "pause forever" affordance per REQ-C2; pushing that
    // through the `Json<T>` extractor would 400 on the empty body.
    // We parse the bytes ourselves and treat
    // empty / whitespace-only as `PausePolicyDto::default()`.
    let body: PausePolicyDto = if raw.is_empty() || raw.iter().all(u8::is_ascii_whitespace) {
        PausePolicyDto::default()
    } else {
        serde_json::from_slice(&raw)
            .map_err(|_| ApiError::BadRequest("pause body must be valid JSON"))?
    };

    // Resolve to the absolute timestamp the repo writes:
    //   - explicit `until` → use it
    //   - else → '9999-12-31T00:00:00Z' (the "forever" sentinel)
    let until = match body.until {
        Some(t) => {
            if t < Utc::now() {
                return Err(ApiError::BadRequest("until must be in the future"));
            }
            t
        }
        None => forever_sentinel(),
    };

    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    mod_policies::pause(&mut tx, &identifier, Some(until))
        .await
        .map_err(map_policy_err)?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "policy_paused".to_owned(),
            payload: serde_json::json!({
                "identifier": identifier,
                "until": until.to_rfc3339(),
                "moderator_id": ctx.moderator_id.to_string(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /api/admin/policies/:identifier/pause`.
///
/// Clears `autonomous_paused_until` on the current version (resumes
/// auto-firing on the next dispatcher poll — no cache invalidation
/// needed; the LLM dispatcher re-reads on every call).
///
/// # Errors
///
/// - [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// - [`ApiError::NotFound`] when the identifier is unknown.
/// - [`ApiError::Internal`] on any DB failure.
///
/// # Example
///
/// ```ignore
/// // DELETE /api/admin/policies/polaris.harassment/pause
/// ```
pub async fn resume_admin_policy(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(identifier): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx)?;
    let actor = format!("moderator:{}", ctx.moderator_id);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    mod_policies::resume(&mut tx, &identifier)
        .await
        .map_err(map_policy_err)?;

    crate::audit::AuditLog::record(
        &mut tx,
        crate::audit::AuditEvent {
            actor,
            kind: "policy_resumed".to_owned(),
            payload: serde_json::json!({
                "identifier": identifier,
                "moderator_id": ctx.moderator_id.to_string(),
            }),
        },
    )
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    tx.commit()
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Validation entry points ────────────────────────────────────────────

/// Cross-field validation for `CreatePolicyDto`.
fn validate_create(body: &CreatePolicyDto) -> Result<(), ApiError> {
    if body.identifier.trim().is_empty() {
        return Err(ApiError::BadRequest("identifier must not be empty"));
    }
    if body.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty"));
    }
    if body.description.trim().is_empty() {
        return Err(ApiError::BadRequest("description must not be empty"));
    }
    check_scope(&body.scope)?;
    check_severity(&body.severity)?;
    check_decision_criteria(&body.decision_criteria)?;
    check_suggested_action_kinds(&body.suggested_action_kinds)?;
    check_autonomy_mode(&body.autonomy_mode)?;
    check_autonomous_action_kinds(&body.autonomous_action_kinds)?;
    check_confidence_threshold(body.autonomous_confidence_threshold)?;
    check_confidence_threshold(body.assisted_confidence_threshold)?;
    check_req_g3(body.human_required_always, &body.autonomy_mode)?;
    Ok(())
}

/// Cross-field validation for `ModPolicyEditDto`. Only validates fields
/// the patch actually carries — REQ-G3 is rechecked by
/// [`patch_admin_policy`] after the prior row is read so the floor is
/// evaluated against the resulting row.
fn validate_patch(body: &ModPolicyEditDto) -> Result<(), ApiError> {
    if let Some(s) = &body.scope {
        check_scope(s)?;
    }
    if let Some(s) = &body.severity {
        check_severity(s)?;
    }
    if let Some(dc) = &body.decision_criteria {
        check_decision_criteria(dc)?;
    }
    if let Some(ks) = &body.suggested_action_kinds {
        check_suggested_action_kinds(ks)?;
    }
    if let Some(m) = &body.autonomy_mode {
        check_autonomy_mode(m)?;
    }
    if let Some(ks) = &body.autonomous_action_kinds {
        check_autonomous_action_kinds(ks)?;
    }
    if let Some(t) = body.autonomous_confidence_threshold {
        check_confidence_threshold(t)?;
    }
    if let Some(t) = body.assisted_confidence_threshold {
        check_confidence_threshold(t)?;
    }
    Ok(())
}

/// The "forever" sentinel timestamp the design specifies for
/// `POST .../pause` with no body. Matches `'9999-12-31T00:00:00Z'`.
#[allow(
    clippy::expect_used,
    reason = "9999-12-31 is a static, known-valid UTC instant; the parse cannot fail at runtime."
)]
fn forever_sentinel() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(9999, 12, 31, 0, 0, 0)
        .single()
        .expect("9999-12-31T00:00:00Z is a valid UTC instant")
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
    use crate::auth::ModeratorId;
    use std::collections::HashSet;

    fn ctx_with(roles: &[Role]) -> ModeratorAuthCtx {
        ModeratorAuthCtx::new(
            ModeratorId::new_v4(),
            roles.iter().copied().collect::<HashSet<_>>(),
        )
    }

    #[test]
    fn require_admin_accepts_admin_rejects_others() {
        assert!(require_admin(&ctx_with(&[Role::Admin])).is_ok());
        assert!(matches!(
            require_admin(&ctx_with(&[Role::SeniorModerator])),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            require_admin(&ctx_with(&[Role::Moderator])),
            Err(ApiError::Forbidden)
        ));
        assert!(matches!(
            require_admin(&ctx_with(&[Role::Triage])),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn check_scope_accepts_designed_vocabulary() {
        assert!(check_scope("account").is_ok());
        assert!(check_scope("post").is_ok());
        assert!(check_scope("both").is_ok());
        assert!(matches!(
            check_scope("planet"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn check_severity_accepts_designed_vocabulary() {
        for s in ["inform", "alert", "hide", "remove"] {
            assert!(check_severity(s).is_ok());
        }
        assert!(matches!(
            check_severity("nuclear"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn check_autonomy_mode_accepts_designed_vocabulary() {
        for m in ["manual", "assisted", "autonomous"] {
            assert!(check_autonomy_mode(m).is_ok());
        }
        assert!(matches!(
            check_autonomy_mode("turbo"),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn check_autonomous_kinds_subset_only() {
        assert!(check_autonomous_action_kinds(&[]).is_ok());
        assert!(
            check_autonomous_action_kinds(&[
                "label".to_owned(),
                "warn".to_owned(),
                "takedown".to_owned()
            ])
            .is_ok()
        );
        // REQ-G1: escalate / mute / no_action / reverse cannot
        // auto-fire even if an operator tries to set them.
        assert!(matches!(
            check_autonomous_action_kinds(&["escalate".to_owned()]),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            check_autonomous_action_kinds(&["mute".to_owned()]),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            check_autonomous_action_kinds(&["no_action".to_owned()]),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn check_suggested_kinds_non_empty_and_valid() {
        assert!(matches!(
            check_suggested_action_kinds(&[]),
            Err(ApiError::BadRequest(_))
        ));
        assert!(check_suggested_action_kinds(&["label".to_owned()]).is_ok());
        assert!(matches!(
            check_suggested_action_kinds(&["nonsense".to_owned()]),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn confidence_thresholds_bounded_inclusive_unit_interval() {
        assert!(check_confidence_threshold(0.0).is_ok());
        assert!(check_confidence_threshold(1.0).is_ok());
        assert!(check_confidence_threshold(0.5).is_ok());
        assert!(matches!(
            check_confidence_threshold(-0.01),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            check_confidence_threshold(1.01),
            Err(ApiError::BadRequest(_))
        ));
        assert!(matches!(
            check_confidence_threshold(f32::NAN),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn decision_criteria_minimum_length_is_64_chars() {
        let too_short = "x".repeat(63);
        let exactly = "x".repeat(64);
        assert!(matches!(
            check_decision_criteria(&too_short),
            Err(ApiError::BadRequest(_))
        ));
        assert!(check_decision_criteria(&exactly).is_ok());
    }

    #[test]
    fn req_g3_blocks_autonomous_on_human_required_only() {
        // Human-required + autonomous → 403 policy_autonomy_forbidden.
        assert!(matches!(
            check_req_g3(true, "autonomous"),
            Err(ApiError::PreconditionFailed {
                code: "policy_autonomy_forbidden",
                ..
            })
        ));
        // Human-required + manual / assisted → fine.
        assert!(check_req_g3(true, "manual").is_ok());
        assert!(check_req_g3(true, "assisted").is_ok());
        // Not human-required + autonomous → fine.
        assert!(check_req_g3(false, "autonomous").is_ok());
    }

    #[test]
    fn forever_sentinel_is_9999_12_31() {
        let s = forever_sentinel();
        assert_eq!(s.format("%Y-%m-%d").to_string(), "9999-12-31");
    }

    #[test]
    fn diff_emits_only_changed_fields() {
        // Build two minimal policies identical except for `name`.
        let base = sample_policy("polaris.test", 1, "Alpha");
        let mut next = base.clone();
        next.version = 2;
        next.name = "Beta".to_owned();
        let changes = diff_policies(&base, &next);
        assert_eq!(changes.len(), 1, "only `name` changed; got {changes:?}");
        assert!(changes.contains_key("name"));
    }

    fn sample_policy(identifier: &str, version: i32, name: &str) -> ModPolicy {
        use uuid::Uuid;
        ModPolicy {
            id: Uuid::new_v4(),
            identifier: identifier.to_owned(),
            version,
            name: name.to_owned(),
            description: "test".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "x".repeat(64),
            examples_positive: serde_json::json!([]),
            examples_negative: serde_json::json!([]),
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "manual".to_owned(),
            autonomous_action_kinds: vec![],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.7,
            autonomous_paused_until: None,
            is_retired: false,
            created_at: Utc::now(),
            created_by_moderator_id: Uuid::new_v4(),
            effective_from: Utc::now(),
            effective_until: None,
            supersedes_id: None,
            change_summary: None,
        }
    }
}
