//! Wire-shape DTOs for the policies admin REST surface (WB-3, #225).
//!
//! Mirrors the policy workbook design in `.design/mod-policy-workbook.md`
//! (REQ-C1..C4 + REQ-D4). The shapes here are what crosses the JSON
//! boundary on `/api/admin/policies/*` and `/api/policies/*`; the
//! `polaris-frontend` `api_client/dto.rs` (WB-4 / #226) re-exports
//! [`ModPolicyDto`] verbatim so the two layers stay byte-compatible.
//!
//! # Why a separate module
//!
//! The repo layer ([`crate::repo::mod_policies`]) is the source of truth
//! for typed Rust shapes the rest of the backend consumes. The wire
//! contract is intentionally narrower: it derives `Serialize` /
//! `Deserialize` for serde, names the fields in `snake_case` to match
//! the established API convention, and elides repo-internal hooks
//! (e.g. the prior-row supersession id surfaces as `supersedes_id` —
//! a UUID the frontend can treat opaquely).
//!
//! Re-exported from [`crate::api::dto::ModPolicyDto`] for the canonical
//! cross-module import path (REQ-C3).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::repo::mod_policies::{ModPolicy, ModPolicySummary};

/// Full wire shape for one `mod_policies` row.
///
/// Mirrors the column layout 1:1; serde-renames are deliberately *not*
/// applied so the snake-case identifier strings already chosen for the
/// SQL schema and the Rust repo carry through to the JSON wire
/// (`identifier` / `autonomy_mode` / `created_by_moderator_id` /…).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModPolicyDto {
    /// Row identity (primary key).
    pub id: Uuid,
    /// Human-stable identifier (`polaris.harassment` etc.).
    pub identifier: String,
    /// Monotonic edit counter; 1 on initial insert.
    pub version: i32,
    /// Short human-readable title.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// `account` | `post` | `both`.
    pub scope: String,
    /// `inform` | `alert` | `hide` | `remove`.
    pub severity: String,
    /// Markdown-formatted decision criteria (≥ 64 chars).
    pub decision_criteria: String,
    /// Positive worked-example array (`[{excerpt, context,
    /// expected_action_kind}]`).
    pub examples_positive: serde_json::Value,
    /// Negative worked-example array (`[{excerpt, context,
    /// why_not_a_violation}]`).
    pub examples_negative: serde_json::Value,
    /// Suggested action kinds for cases that violate this policy.
    pub suggested_action_kinds: Vec<String>,
    /// Optional default label value when the action is `label`.
    pub linked_label_value: Option<String>,
    /// Free-text "when this policy does not apply".
    pub exceptions: Option<String>,
    /// REQ-A2 hard-floor marker; `true` means autonomy cannot be set
    /// to `autonomous` on this row (REQ-G3).
    pub human_required_always: bool,
    /// `manual` | `assisted` | `autonomous`.
    pub autonomy_mode: String,
    /// Subset of `actions.kind` allowed for auto-fire. Must be a
    /// subset of `{label, warn, takedown}` (REQ-G1).
    pub autonomous_action_kinds: Vec<String>,
    /// Confidence floor for autonomous emission. `0.0..=1.0`.
    pub autonomous_confidence_threshold: f32,
    /// Confidence floor for assisted draft creation. `0.0..=1.0`.
    pub assisted_confidence_threshold: f32,
    /// When `Some(t)` and `t > now()`, autonomy is suspended.
    pub autonomous_paused_until: Option<DateTime<Utc>>,
    /// Tombstone marker — `true` means this version retires the
    /// policy (REQ-F1).
    pub is_retired: bool,
    /// When this row was inserted.
    pub created_at: DateTime<Utc>,
    /// Moderator who wrote this version.
    pub created_by_moderator_id: Uuid,
    /// When this version started binding decisions.
    pub effective_from: DateTime<Utc>,
    /// When this version stopped being current. `None` while current.
    pub effective_until: Option<DateTime<Utc>>,
    /// `Some(id)` of the prior version row, `None` for v1.
    pub supersedes_id: Option<Uuid>,
    /// "Why this version was written" — surfaced in history view.
    pub change_summary: Option<String>,
}

impl From<ModPolicy> for ModPolicyDto {
    fn from(p: ModPolicy) -> Self {
        Self {
            id: p.id,
            identifier: p.identifier,
            version: p.version,
            name: p.name,
            description: p.description,
            scope: p.scope,
            severity: p.severity,
            decision_criteria: p.decision_criteria,
            examples_positive: p.examples_positive,
            examples_negative: p.examples_negative,
            suggested_action_kinds: p.suggested_action_kinds,
            linked_label_value: p.linked_label_value,
            exceptions: p.exceptions,
            human_required_always: p.human_required_always,
            autonomy_mode: p.autonomy_mode,
            autonomous_action_kinds: p.autonomous_action_kinds,
            autonomous_confidence_threshold: p.autonomous_confidence_threshold,
            assisted_confidence_threshold: p.assisted_confidence_threshold,
            autonomous_paused_until: p.autonomous_paused_until,
            is_retired: p.is_retired,
            created_at: p.created_at,
            created_by_moderator_id: p.created_by_moderator_id,
            effective_from: p.effective_from,
            effective_until: p.effective_until,
            supersedes_id: p.supersedes_id,
            change_summary: p.change_summary,
        }
    }
}

/// Slim list-projection of a policy, for the index endpoint.
///
/// Drops the example arrays and the `decision_criteria` body so a list
/// of 50 policies stays under a kilobyte. The frontend index view
/// renders only the columns surfaced here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModPolicySummaryDto {
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

impl From<ModPolicySummary> for ModPolicySummaryDto {
    fn from(s: ModPolicySummary) -> Self {
        Self {
            id: s.id,
            identifier: s.identifier,
            version: s.version,
            name: s.name,
            description: s.description,
            scope: s.scope,
            severity: s.severity,
            autonomy_mode: s.autonomy_mode,
            is_retired: s.is_retired,
            effective_from: s.effective_from,
        }
    }
}

/// Request body for `POST /api/admin/policies` — create v1 of a new
/// identifier.
///
/// Every field on [`ModPolicyDto`] that an operator can set on a fresh
/// policy is required here (apart from optional `linked_label_value` /
/// `exceptions` / `change_summary`). The audit metadata
/// (`created_at`, `created_by_moderator_id`, `effective_from`,
/// `effective_until`, `supersedes_id`, …) is populated by the repo.
#[derive(Debug, Clone, Deserialize)]
pub struct CreatePolicyDto {
    /// Human-stable identifier; must be unique at v1.
    pub identifier: String,
    /// Short title.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// `account` | `post` | `both`.
    pub scope: String,
    /// `inform` | `alert` | `hide` | `remove`.
    pub severity: String,
    /// Decision criteria (≥ 64 chars).
    pub decision_criteria: String,
    /// Optional positive worked examples — defaults to `[]` when
    /// omitted.
    #[serde(default)]
    pub examples_positive: Option<serde_json::Value>,
    /// Optional negative worked examples — defaults to `[]`.
    #[serde(default)]
    pub examples_negative: Option<serde_json::Value>,
    /// Non-empty subset of `actions.kind` typically applied.
    pub suggested_action_kinds: Vec<String>,
    /// Optional default label value for `kind = label`.
    #[serde(default)]
    pub linked_label_value: Option<String>,
    /// Optional free-text exceptions block.
    #[serde(default)]
    pub exceptions: Option<String>,
    /// REQ-A2 floor; `true` forbids `autonomy_mode = autonomous`.
    #[serde(default)]
    pub human_required_always: bool,
    /// `manual` / `assisted` / `autonomous`. Defaults to `manual`
    /// when omitted (REQ-A3).
    #[serde(default = "default_autonomy_mode")]
    pub autonomy_mode: String,
    /// Subset of `{label, warn, takedown}` (REQ-G1).
    #[serde(default)]
    pub autonomous_action_kinds: Vec<String>,
    /// Defaults to `0.95` when omitted (REQ-A3 default).
    #[serde(default = "default_autonomous_threshold")]
    pub autonomous_confidence_threshold: f32,
    /// Defaults to `0.70` when omitted (REQ-A3 default).
    #[serde(default = "default_assisted_threshold")]
    pub assisted_confidence_threshold: f32,
    /// Optional "why v1" note. Surfaced in history view.
    #[serde(default)]
    pub change_summary: Option<String>,
}

/// Default autonomy mode for `CreatePolicyDto`. Mirrors REQ-A3.
fn default_autonomy_mode() -> String {
    "manual".to_owned()
}

/// Default autonomous confidence threshold. Mirrors REQ-A3.
fn default_autonomous_threshold() -> f32 {
    0.95
}

/// Default assisted confidence threshold. Mirrors REQ-A3.
fn default_assisted_threshold() -> f32 {
    0.70
}

/// Request body for `PATCH /api/admin/policies/:identifier`.
///
/// Every field is optional — omission means "carry forward from the
/// prior version" (REQ-C2). `change_summary` is the only required
/// field; the audit-log entry attached to the version bump cites it.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModPolicyEditDto {
    /// New short title.
    #[serde(default)]
    pub name: Option<String>,
    /// New description paragraph.
    #[serde(default)]
    pub description: Option<String>,
    /// New scope.
    #[serde(default)]
    pub scope: Option<String>,
    /// New severity.
    #[serde(default)]
    pub severity: Option<String>,
    /// New decision criteria text.
    #[serde(default)]
    pub decision_criteria: Option<String>,
    /// Replace positive-example array.
    #[serde(default)]
    pub examples_positive: Option<serde_json::Value>,
    /// Replace negative-example array.
    #[serde(default)]
    pub examples_negative: Option<serde_json::Value>,
    /// Replace suggested-action-kinds list.
    #[serde(default)]
    pub suggested_action_kinds: Option<Vec<String>>,
    /// Replace linked label value. `null` literally clears it; a
    /// missing key carries the prior value forward.
    #[serde(default, deserialize_with = "deser_option_option")]
    pub linked_label_value: Option<Option<String>>,
    /// Replace exceptions text. Same `null`-vs-missing semantic as
    /// `linked_label_value`.
    #[serde(default, deserialize_with = "deser_option_option")]
    pub exceptions: Option<Option<String>>,
    /// Flip the human-required-always floor.
    #[serde(default)]
    pub human_required_always: Option<bool>,
    /// New autonomy mode.
    #[serde(default)]
    pub autonomy_mode: Option<String>,
    /// Replace autonomous-action-kinds list.
    #[serde(default)]
    pub autonomous_action_kinds: Option<Vec<String>>,
    /// New autonomous confidence threshold.
    #[serde(default)]
    pub autonomous_confidence_threshold: Option<f32>,
    /// New assisted confidence threshold.
    #[serde(default)]
    pub assisted_confidence_threshold: Option<f32>,
    /// Retire the policy (writes a tombstone successor row).
    #[serde(default)]
    pub is_retired: Option<bool>,
    /// REQUIRED — operator's note on why this version was written.
    pub change_summary: String,
}

/// Deserialise an `Option<Option<T>>` field where:
///
/// - the JSON key being absent (`#[serde(default)]`) produces `None`,
/// - the key present with a `null` value produces `Some(None)`,
/// - the key present with a typed value produces `Some(Some(T))`.
///
/// Matches the "clear vs. unchanged" semantic the patch endpoint
/// needs for nullable columns: an admin who wants to clear
/// `linked_label_value` sends `{"linked_label_value": null}`; an
/// admin who wants to keep the current value just omits the key.
#[allow(
    clippy::option_option,
    reason = "Option<Option<T>> is load-bearing here: we distinguish \
              'key absent' (None — carry forward) from 'key present with \
              null value' (Some(None) — clear the column) from \
              'key present with a typed value' (Some(Some(value)) — replace). \
              Collapsing to Option<T> would lose the clear-vs-unchanged \
              distinction the patch endpoint needs."
)]
fn deser_option_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d).map(Some)
}

/// Request body for `POST /api/admin/policies/:identifier/pause`.
///
/// Two shapes accepted (both via the same body — see REQ-C2):
/// - `{ "until": "2026-12-31T00:00:00Z" }` — pause until a specific
///   timestamp (UTC).
/// - `{ "forever": true }` (or any empty body) — pause until
///   `9999-12-31` per the design's "forever" affordance.
///
/// Missing both produces "forever" (the design says "no body →
/// pause-forever").
#[derive(Debug, Clone, Deserialize, Default)]
pub struct PausePolicyDto {
    /// Optional explicit timestamp; `None` triggers the "forever"
    /// path.
    #[serde(default)]
    pub until: Option<DateTime<Utc>>,
    /// Optional explicit "forever" toggle; redundant with omitting
    /// `until`, but accepted so the frontend can express the
    /// affordance literally.
    #[serde(default)]
    pub forever: Option<bool>,
}

/// One entry in the version-history response for a policy
/// (`GET /api/admin/policies/:identifier/history`).
///
/// Slimmer than [`ModPolicyDto`] — only what the history-view UI
/// renders top-to-bottom. The frontend follows
/// [`Self::diff_url`] to fetch a per-version diff.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModPolicyHistoryEntryDto {
    /// Row identity for this version.
    pub id: Uuid,
    /// Version number (monotonic).
    pub version: i32,
    /// "Why this version was written" — surfaced inline.
    pub change_summary: Option<String>,
    /// Moderator who wrote this version.
    pub created_by_moderator_id: Uuid,
    /// When this version was inserted.
    pub created_at: DateTime<Utc>,
    /// When this version started binding decisions.
    pub effective_from: DateTime<Utc>,
    /// When this version stopped being current. `None` while
    /// current.
    pub effective_until: Option<DateTime<Utc>>,
    /// Tombstone marker.
    pub is_retired: bool,
    /// Server-rendered URL pointing at the diff between this version
    /// and its predecessor. `None` for v1 (no predecessor).
    pub diff_url: Option<String>,
}

/// One field in a `diff` response: the prior value and the new value.
///
/// Both rendered as `serde_json::Value` so heterogeneous types
/// (strings, booleans, arrays, floats) share one shape on the wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiffChangeDto {
    /// Value at the `from` version.
    pub from: serde_json::Value,
    /// Value at the `to` version.
    pub to: serde_json::Value,
}

/// Response for `GET /api/admin/policies/:identifier/diff?from=N&to=M`.
///
/// Only fields that actually differ between the two versions are
/// listed in `changes`. Audit metadata (`created_at`, `created_by`,
/// `effective_*`, `supersedes_id`, the row `id` itself) is excluded
/// because every amendment trivially changes those.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDiffDto {
    /// Policy identifier being diffed.
    pub identifier: String,
    /// Version on the `from` side.
    pub from_version: i32,
    /// Version on the `to` side.
    pub to_version: i32,
    /// Per-field diff map — empty when the two versions are
    /// content-identical.
    pub changes: std::collections::BTreeMap<String, DiffChangeDto>,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_policy_dto_defaults_apply_when_optional_fields_omitted() {
        let body = json!({
            "identifier": "polaris.test",
            "name": "Test",
            "description": "A test policy.",
            "scope": "post",
            "severity": "alert",
            "decision_criteria":
                "Apply this policy when the test fixture exercises the default-handling code path here.",
            "suggested_action_kinds": ["label"],
        });
        let dto: CreatePolicyDto = serde_json::from_value(body).unwrap();
        assert_eq!(dto.autonomy_mode, "manual");
        assert!((dto.autonomous_confidence_threshold - 0.95).abs() < f32::EPSILON);
        assert!((dto.assisted_confidence_threshold - 0.70).abs() < f32::EPSILON);
        assert!(dto.autonomous_action_kinds.is_empty());
        assert!(!dto.human_required_always);
    }

    #[test]
    fn edit_dto_distinguishes_missing_from_null_for_nullable_fields() {
        // Missing key → None (carry forward).
        let body = json!({ "change_summary": "x" });
        let dto: ModPolicyEditDto = serde_json::from_value(body).unwrap();
        assert!(dto.linked_label_value.is_none(), "missing key → None");

        // Explicit `null` → Some(None) (clear the column).
        let body = json!({ "change_summary": "x", "linked_label_value": null });
        let dto: ModPolicyEditDto = serde_json::from_value(body).unwrap();
        assert_eq!(dto.linked_label_value, Some(None), "null → Some(None)");

        // Explicit value → Some(Some(value)) (replace).
        let body = json!({
            "change_summary": "x",
            "linked_label_value": "polaris.spam-label",
        });
        let dto: ModPolicyEditDto = serde_json::from_value(body).unwrap();
        assert_eq!(
            dto.linked_label_value,
            Some(Some("polaris.spam-label".to_owned())),
            "string → Some(Some(...))"
        );
    }

    #[test]
    fn pause_dto_accepts_empty_body() {
        // POST .../pause with no body → defaults all-None → caller
        // interprets as "forever".
        let body = json!({});
        let dto: PausePolicyDto = serde_json::from_value(body).unwrap();
        assert!(dto.until.is_none());
        assert!(dto.forever.is_none());
    }
}
