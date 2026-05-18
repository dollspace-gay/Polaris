//! `GET /api/admin/llm/audit` — operator's "what is my agent doing?"
//! audit surface (LLM-9 / #238 / `.design/llm-moderation-assist.md`
//! REQ-F4).
//!
//! Returns the most recent autonomous-agent actions, newest-first, with
//! every audit field the dispatcher recorded (model + version + prompt
//! template + confidence + input hash), the snapshotted policy
//! citations, the subject DID + URI, and the reversal action info when
//! a moderator has overturned the autonomous decision.
//!
//! # RBAC
//!
//! Admin-only. Non-admins get `403 Forbidden` via the standard
//! [`require_admin`] gate; the auth middleware has already attached the
//! `ModeratorAuthCtx` extension before this handler runs.
//!
//! # Filters
//!
//! All optional, all AND-composed:
//!
//! * `?model=<string>` — exact `actions.model` match.
//! * `?policy=<identifier>` — autonomous action that cites a policy
//!   with this identifier (any version).
//! * `?reversed=true|false` — restrict to reversed (or non-reversed)
//!   rows.
//! * `?from=<RFC3339>` — earliest `actions.created_at`.
//! * `?to=<RFC3339>` — latest `actions.created_at`.
//! * `?cursor=<opaque>` — keyset cursor from a prior page; base64-of-
//!   JSON encoding the `(created_at, action_id)` tuple of the previous
//!   page's last row.
//! * `?limit=<int>` — defaults to 50, clamped to `[1, 200]`.

use axum::extract::{Query, State};
use axum::{Extension, Json};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::{ModeratorAuthCtx, Role};
use crate::repo::llm_audit::{
    self, AuditCursor, AuditEntry, AuditFilters, DEFAULT_LIMIT, MAX_LIMIT,
};

/// One row of the audit list as it appears on the wire.
///
/// Mirrors [`AuditEntry`] field-for-field with serializable types
/// (UUIDs as strings, timestamps as RFC3339 via serde's `chrono`
/// integration). The frontend mirror lives in
/// [`polaris_frontend::api_client::dto::LlmAuditEntryDto`].
#[derive(Debug, Clone, Serialize)]
pub struct LlmAuditEntryDto {
    /// The autonomous action's id.
    pub action_id: Uuid,
    /// `actions.kind`. One of `label` / `warn` / `takedown` / …
    pub action_kind: String,
    /// `actions.label_value` when the action is a label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label_value: Option<String>,
    /// Subject DID (when present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    /// Subject kind — one of `account` / `post` / `list` / `feed`.
    pub subject_kind: String,
    /// Subject AT-URI (when present).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_uri: Option<String>,
    /// Always `"autonomous_agent"` — every row of this surface is
    /// autonomous-agent-emitted by construction.
    pub actor_kind: &'static str,
    /// LLM model identifier (e.g. `qwen2.5-32b-instruct-q3_k_m`).
    pub model: String,
    /// LLM model version string.
    pub model_version: String,
    /// Adapter-stable prompt template identifier.
    pub prompt_template_id: String,
    /// Top recommendation's confidence (`[0.0, 1.0]`).
    pub recommendation_confidence: f32,
    /// SHA-256-hex of the canonicalised `RecommendRequest`.
    pub input_hash: String,
    /// Snapshotted `(identifier, version)` citations.
    pub cited_policies: Vec<CitedPolicyDto>,
    /// Top recommendation's reasoning string.
    pub reasoning: String,
    /// When the action was created.
    pub created_at: DateTime<Utc>,
    /// When the action's reversal window closes.
    pub reversible_until: DateTime<Utc>,
    /// Reversal info when one exists; `null` otherwise.
    pub reversal: Option<ReversalDto>,
    /// Points at the `LlmRecommendation` observation whose `evidence`
    /// JSONB carries the full LLM response payload (REQ-B2).
    pub llm_observation_id: Uuid,
}

/// Cited-policy snapshot on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct CitedPolicyDto {
    /// Policy identifier (e.g. `polaris.spam`).
    pub identifier: String,
    /// Pinned version at action-create time.
    pub version: i32,
}

/// Reversal-side info on the wire.
#[derive(Debug, Clone, Serialize)]
pub struct ReversalDto {
    /// The reversal action's id.
    pub action_id: Uuid,
    /// When the reversal was created.
    pub reversed_at: DateTime<Utc>,
    /// Moderator who issued the reversal.
    pub reversed_by_moderator_id: Uuid,
}

/// Full page-shape returned by the endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct LlmAuditPageDto {
    /// Rows in the page, newest-first.
    pub items: Vec<LlmAuditEntryDto>,
    /// Opaque cursor for the next page when more rows exist.
    pub next_cursor: Option<String>,
}

/// Query-string for `GET /api/admin/llm/audit`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct LlmAuditQuery {
    /// Filter by `actions.model`.
    #[serde(default)]
    pub model: Option<String>,
    /// Filter by cited policy identifier.
    #[serde(default)]
    pub policy: Option<String>,
    /// Filter to reversed / non-reversed rows.
    #[serde(default)]
    pub reversed: Option<bool>,
    /// Earliest `actions.created_at` (inclusive).
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    /// Latest `actions.created_at` (inclusive).
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
    /// Opaque cursor from a prior page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Page size; defaults to 50, clamped to `[1, 200]`.
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Verify the caller is `Role::Admin`. Mirrors the gate pattern used
/// across the other admin surfaces (admin_moderators, admin_policies).
fn require_admin(ctx: &ModeratorAuthCtx) -> Result<(), ApiError> {
    if ctx.roles.contains(&Role::Admin) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

/// Translate an [`AuditEntry`] into its wire DTO.
fn entry_to_dto(entry: AuditEntry) -> LlmAuditEntryDto {
    LlmAuditEntryDto {
        action_id: entry.action_id,
        action_kind: entry.action_kind,
        label_value: entry.label_value,
        subject_did: entry.subject_did,
        subject_kind: entry.subject_kind,
        subject_uri: entry.subject_uri,
        actor_kind: "autonomous_agent",
        model: entry.model,
        model_version: entry.model_version,
        prompt_template_id: entry.prompt_template_id,
        recommendation_confidence: entry.recommendation_confidence,
        input_hash: entry.input_hash,
        cited_policies: entry
            .cited_policies
            .into_iter()
            .map(|c| CitedPolicyDto {
                identifier: c.identifier,
                version: c.version,
            })
            .collect(),
        reasoning: entry.reasoning,
        created_at: entry.created_at,
        reversible_until: entry.reversible_until,
        reversal: entry.reversal.map(|r| ReversalDto {
            action_id: r.action_id,
            reversed_at: r.reversed_at,
            reversed_by_moderator_id: r.reversed_by_moderator_id,
        }),
        llm_observation_id: entry.llm_observation_id,
    }
}

/// `GET /api/admin/llm/audit`.
///
/// Returns the most recent autonomous-agent actions, filtered per the
/// query string, with keyset pagination.
///
/// # Errors
///
/// * [`ApiError::Forbidden`] when the caller lacks `Role::Admin`.
/// * [`ApiError::BadRequest`] when the cursor is malformed or the
///   date range is inverted (`from > to`).
/// * [`ApiError::Internal`] on DB failure.
pub async fn list_llm_audit(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Query(query): Query<LlmAuditQuery>,
) -> Result<Json<LlmAuditPageDto>, ApiError> {
    require_admin(&ctx)?;

    // Decode the cursor up-front so a malformed cursor surfaces as 400
    // before we burn a DB round-trip on it.
    let cursor = if let Some(raw) = query.cursor.as_deref().filter(|c| !c.is_empty()) {
        Some(AuditCursor::decode(raw).map_err(|_| ApiError::BadRequest("cursor is malformed"))?)
    } else {
        None
    };

    // Reject an inverted date range up-front. The repo would return
    // an empty page either way, but a 400 here clarifies the operator
    // input mistake.
    if let (Some(from), Some(to)) = (query.from, query.to) {
        if from > to {
            return Err(ApiError::BadRequest(
                "from must be <= to in the audit date range",
            ));
        }
    }

    // Clamp the limit. The repo also clamps, but doing it at the wire
    // boundary lets the response shape's cursor reflect what we
    // actually fetched.
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let filters = AuditFilters {
        model: query.model.filter(|s| !s.is_empty()),
        policy: query.policy.filter(|s| !s.is_empty()),
        reversed: query.reversed,
        from: query.from,
        to: query.to,
        cursor,
        limit,
    };

    let page = llm_audit::list_autonomous_audit(&state.pool, &filters)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    let next_cursor = page
        .next_cursor
        .map(|c| {
            c.encode().map_err(|e| {
                ApiError::Internal(anyhow::anyhow!("failed to encode audit cursor: {e}"))
            })
        })
        .transpose()?;

    let items = page.items.into_iter().map(entry_to_dto).collect();
    Ok(Json(LlmAuditPageDto { items, next_cursor }))
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
    fn require_admin_accepts_admin() {
        require_admin(&ctx_with(&[Role::Admin])).unwrap();
    }

    #[test]
    fn require_admin_rejects_non_admin() {
        let err = require_admin(&ctx_with(&[Role::SeniorModerator])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[Role::Moderator])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[Role::Triage])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
        let err = require_admin(&ctx_with(&[])).unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn entry_to_dto_carries_static_actor_kind() {
        let dto = entry_to_dto(AuditEntry {
            action_id: Uuid::new_v4(),
            action_kind: "label".to_owned(),
            label_value: Some("spam".to_owned()),
            subject_did: Some("did:plc:abc".to_owned()),
            subject_kind: "post".to_owned(),
            subject_uri: Some("at://x".to_owned()),
            model: "qwen2.5-32b-instruct-q3_k_m".to_owned(),
            model_version: "v1".to_owned(),
            prompt_template_id: "polaris.case-review.v1".to_owned(),
            recommendation_confidence: 0.94,
            input_hash: "deadbeef".to_owned(),
            cited_policies: vec![],
            reasoning: "...".to_owned(),
            created_at: chrono::Utc::now(),
            reversible_until: chrono::Utc::now() + chrono::Duration::hours(24),
            reversal: None,
            llm_observation_id: Uuid::new_v4(),
        });
        assert_eq!(dto.actor_kind, "autonomous_agent");
        assert_eq!(dto.action_kind, "label");
    }
}
