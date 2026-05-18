//! Query layer for the admin "what is the autonomous agent doing?"
//! audit list (LLM-9 / #238 / REQ-F4).
//!
//! The endpoint at `GET /api/admin/llm/audit` (handler in
//! [`crate::api::llm::admin_audit`]) needs a single query that walks the
//! `actions` rows with `actor_kind = 'autonomous_agent'`, joins each row
//! against:
//!
//! * its backing `LlmRecommendation` observation (so the full LLM
//!   response payload is reachable via the observation's `evidence`
//!   JSONB),
//! * its `action_policy_citations` rows (so the cited
//!   `{identifier, version}` pairs travel with the row),
//! * the related subject row (so the table renders DID + URI),
//! * and the reversal action — if any — that points at it via
//!   `reverses_action_id` (REQ-F2: a reversal carries the original
//!   action's full audit envelope so an investigator sees both sides
//!   together).
//!
//! Pagination is keyset on `(created_at DESC, id DESC)` — the same
//! tuple that the partial index `actions_autonomous_created_at_idx`
//! (migration 51) keys on. The cursor is encoded as
//! base64-of-JSON so it survives transport without leaking schema
//! details to the caller.
//!
//! Filters are all-AND: model, policy identifier (matched against any
//! cited policy on the row), reversed-state (`true` ⇒ has a reversal,
//! `false` ⇒ does not), and a created-at window.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

/// Maximum number of rows returned in a single page. The handler clamps
/// the operator-supplied `?limit=` to this ceiling so a runaway query
/// cannot exhaust the connection pool. 200 matches the slack the
/// existing dashboard cluster list exposes; the default is 50 (the
/// handler enforces that, not this constant).
pub const MAX_LIMIT: i64 = 200;

/// Default page size when the operator does not supply `?limit=`.
pub const DEFAULT_LIMIT: i64 = 50;

/// Inputs for [`list_autonomous_audit`].
///
/// Every field is optional; an all-defaults call returns the most
/// recent page across all autonomous actions.
#[derive(Debug, Clone, Default)]
pub struct AuditFilters {
    /// Filter to autonomous actions emitted by the named LLM model
    /// (matches `actions.model` verbatim).
    pub model: Option<String>,
    /// Filter to autonomous actions citing a policy with this
    /// identifier (matches any row in `action_policy_citations`).
    pub policy: Option<String>,
    /// `Some(true)` returns only autonomous actions that have a
    /// reversal pointing at them; `Some(false)` returns only those
    /// that do not; `None` returns both.
    pub reversed: Option<bool>,
    /// Earliest `actions.created_at` to include (inclusive).
    pub from: Option<DateTime<Utc>>,
    /// Latest `actions.created_at` to include (inclusive).
    pub to: Option<DateTime<Utc>>,
    /// Keyset cursor from a prior page — when `Some`, only rows
    /// "older" than this tuple are returned.
    pub cursor: Option<AuditCursor>,
    /// Page size. The handler clamps this to `[1, MAX_LIMIT]` before
    /// calling the repo.
    pub limit: i64,
}

/// Keyset cursor — the `(created_at, id)` tuple of the last row of the
/// previous page.
///
/// Encoded on the wire as a base64-of-JSON blob so the caller cannot
/// reverse-engineer the schema and the server can change the encoded
/// shape (e.g. add a tie-breaker) without breaking the wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditCursor {
    /// `actions.created_at` of the last row of the previous page.
    pub created_at: DateTime<Utc>,
    /// `actions.id` of the last row of the previous page (tie-breaker
    /// when two autonomous actions share a microsecond).
    pub id: Uuid,
}

impl AuditCursor {
    /// Encode the cursor as a URL-safe base64-of-JSON string.
    ///
    /// JSON inside base64 is deliberate: it makes the wire form
    /// inspectable in debug logs after a one-step decode, and keeps the
    /// encoded shape forward-compatible with schema evolution (a
    /// future cursor that adds a field decodes the legacy shape via
    /// serde's `#[serde(default)]`). The URL-safe variant means the
    /// cursor sails through query-strings without percent-encoding.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the cursor cannot be serialised
    /// — only possible with a buggy custom serde derive, never with
    /// the current shape.
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json))
    }

    /// Decode a wire-form cursor string back into [`AuditCursor`].
    ///
    /// # Errors
    ///
    /// Returns [`AuditCursorDecodeError`] when the input is not valid
    /// base64 or the decoded bytes are not the expected JSON shape.
    pub fn decode(value: &str) -> Result<Self, AuditCursorDecodeError> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| AuditCursorDecodeError::Base64)?;
        serde_json::from_slice(&bytes).map_err(|_| AuditCursorDecodeError::Json)
    }
}

/// Failure modes for [`AuditCursor::decode`].
///
/// Both variants surface to the handler as `400 Bad Request` with a
/// stable static message; the operator-readable label sits in the
/// `Display` impl.
#[derive(Debug, thiserror::Error)]
pub enum AuditCursorDecodeError {
    /// The input was not valid URL-safe base64 (no-pad).
    #[error("cursor is not valid base64")]
    Base64,
    /// The base64-decoded bytes were not the expected JSON shape.
    #[error("cursor does not decode to the expected JSON shape")]
    Json,
}

/// One row of the audit list. Mirrors the wire DTO field-for-field.
///
/// The cited-policies + reversal fields are joined in-query and
/// returned as in-memory Vecs / `Option`s so the handler does not need
/// a second round-trip per row to render the table.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    /// The autonomous action's id.
    pub action_id: Uuid,
    /// `actions.kind` — one of `label` / `warn` / `takedown` / …
    pub action_kind: String,
    /// `actions.label_value` when the action is a label; `None`
    /// otherwise.
    pub label_value: Option<String>,
    /// Subject DID — pulled from `subjects.did`. `None` when the
    /// subject has no DID (record-kind subjects with unknown
    /// authoring DID).
    pub subject_did: Option<String>,
    /// Subject kind — one of `account` / `post` / `list` / `feed`.
    pub subject_kind: String,
    /// Subject AT-URI when present (record-kind subjects).
    pub subject_uri: Option<String>,
    /// `actions.model` — verbatim from the dispatcher's audit write
    /// (REQ-F1).
    pub model: String,
    /// `actions.model_version` — same role.
    pub model_version: String,
    /// `actions.prompt_template_id` — same role.
    pub prompt_template_id: String,
    /// `actions.recommendation_confidence` — same role.
    pub recommendation_confidence: f32,
    /// `actions.input_hash` — SHA-256-hex of the canonicalised
    /// `RecommendRequest`. Same role.
    pub input_hash: String,
    /// Snapshotted citations from `action_policy_citations` — one
    /// entry per cited policy version.
    pub cited_policies: Vec<CitedPolicy>,
    /// Top recommended action's `reasoning` string, pulled from the
    /// `LlmRecommendation` observation's `evidence.recommended_actions[0]`.
    /// Empty when the evidence shape does not carry one (legacy
    /// rows).
    pub reasoning: String,
    /// `actions.created_at`.
    pub created_at: DateTime<Utc>,
    /// `actions.reversible_until`.
    pub reversible_until: DateTime<Utc>,
    /// Reversal action info when one exists; `None` otherwise.
    pub reversal: Option<ReversalInfo>,
    /// `actions.llm_observation_id` — points at the
    /// `LlmRecommendation` observation row (its `evidence` JSONB
    /// carries the full LLM response payload per REQ-B2).
    pub llm_observation_id: Uuid,
}

/// One cited-policy snapshot from `action_policy_citations`.
#[derive(Debug, Clone)]
pub struct CitedPolicy {
    /// Policy identifier (e.g. `polaris.spam`).
    pub identifier: String,
    /// Snapshot version at action-create time.
    pub version: i32,
}

/// Reversal-side info attached to an autonomous action when a moderator
/// has reversed it.
#[derive(Debug, Clone)]
pub struct ReversalInfo {
    /// The reversal action's id.
    pub action_id: Uuid,
    /// When the reversal was created (the reversal action's
    /// `created_at`).
    pub reversed_at: DateTime<Utc>,
    /// Moderator who issued the reversal. OK to expose to admins per
    /// REQ-F4.
    pub reversed_by_moderator_id: Uuid,
}

/// One page of [`AuditEntry`] rows plus an optional `next` cursor.
#[derive(Debug, Clone)]
pub struct AuditPage {
    /// Rows in the page, newest-first.
    pub items: Vec<AuditEntry>,
    /// `Some` when more rows exist past the page; encode-and-attach as
    /// `next_cursor` in the wire DTO.
    pub next_cursor: Option<AuditCursor>,
}

/// List the most recent autonomous-action audit entries matching the
/// supplied filters.
///
/// The query is a single LEFT-JOIN sweep:
///
/// 1. `actions a` — the autonomous-agent rows (predicate
///    `a.actor_kind = 'autonomous_agent'` matches the partial index
///    `actions_autonomous_created_at_idx`).
/// 2. `LEFT JOIN actions r ON r.reverses_action_id = a.id` — the
///    reversal action, if any (REQ-F2).
/// 3. `LEFT JOIN action_policy_citations apc ON apc.action_id = a.id`
///    — the cited policy versions; the handler stitches the duplicate
///    rows into the per-action `cited_policies` Vec.
/// 4. `LEFT JOIN subjects s ON s.id = a.subject_id` — for DID + URI +
///    kind.
/// 5. `LEFT JOIN observations o ON o.id = a.llm_observation_id` —
///    pulls `evidence` so the handler can extract the top
///    recommendation's reasoning for the headline cell.
///
/// The keyset cursor predicate is `(a.created_at, a.id) < ($cursor_ts,
/// $cursor_id)` (strictly less, descending), which the partial index
/// satisfies. The query fetches `limit + 1` rows: if `limit + 1` rows
/// come back, the (limit+1)-th row is dropped and its predecessor
/// becomes the `next_cursor`.
///
/// The `policy` filter applies via `EXISTS (SELECT 1 FROM
/// action_policy_citations WHERE action_id = a.id AND policy_identifier
/// = $policy)` rather than as a JOIN predicate so we do not lose rows
/// that legitimately cite multiple policies.
///
/// # Errors
///
/// Surfaces the underlying `sqlx::Error` verbatim — the handler maps
/// it through [`crate::api::error::ApiError::Internal`].
#[allow(clippy::too_many_lines)] // single-query body; splitting hurts readability.
pub async fn list_autonomous_audit(
    pool: &PgPool,
    filters: &AuditFilters,
) -> Result<AuditPage, sqlx::Error> {
    let limit = filters.limit.clamp(1, MAX_LIMIT);
    let fetch = limit + 1; // +1 row sentinel for next-cursor detection.

    // Cursor fields. When None, we use `MAX` sentinels so the predicate
    // is satisfied by every row in the table (DESC order, so the
    // "newest" page starts at the top).
    let cursor_ts = filters.cursor.as_ref().map(|c| c.created_at);
    let cursor_id = filters.cursor.as_ref().map(|c| c.id);

    // The reversed-flag filter is applied via the JOIN-output's
    // `reversal_action_id IS NOT NULL` predicate; converting `Option<bool>`
    // to two `bool`s keeps the SQL match `$8::BOOL OR (...)` clauses
    // explicit. `(only_reversed, only_not_reversed)`:
    //   None        → (false, false) ⇒ no filter
    //   Some(true)  → (true,  false)
    //   Some(false) → (false, true)
    let only_reversed = filters.reversed == Some(true);
    let only_not_reversed = filters.reversed == Some(false);

    let model = filters.model.as_deref();
    let policy = filters.policy.as_deref();
    let from = filters.from;
    let to = filters.to;

    // Single keyset-paginated SELECT. The action and reversal columns
    // come back as wide rows; the cited-policies stitching is a
    // separate small query keyed by the resulting `action_id` set so
    // the JOIN does not duplicate rows.
    let rows = sqlx::query!(
        r#"
        SELECT
            a.id                          AS "action_id!",
            a.kind                        AS "action_kind!",
            a.label_value,
            a.subject_id                  AS "subject_id!",
            s.kind                        AS "subject_kind!",
            s.did                         AS "subject_did?",
            s.uri                         AS "subject_uri?",
            a.model                       AS "model!",
            a.model_version               AS "model_version!",
            a.prompt_template_id          AS "prompt_template_id!",
            a.recommendation_confidence   AS "recommendation_confidence!",
            a.input_hash                  AS "input_hash!",
            a.created_at                  AS "created_at!",
            a.reversible_until            AS "reversible_until!",
            a.llm_observation_id          AS "llm_observation_id!",
            o.evidence                    AS "evidence!",
            r.id                          AS "reversal_id?",
            r.created_at                  AS "reversal_created_at?",
            r.moderator_id                AS "reversal_moderator_id?"
        FROM actions a
        LEFT JOIN actions r          ON r.reverses_action_id = a.id
        LEFT JOIN subjects s         ON s.id = a.subject_id
        LEFT JOIN observations o     ON o.id = a.llm_observation_id
        WHERE a.actor_kind = 'autonomous_agent'
          -- model filter
          AND ($1::TEXT IS NULL OR a.model = $1)
          -- policy filter (any cited policy on the action)
          AND ($2::TEXT IS NULL OR EXISTS (
                SELECT 1 FROM action_policy_citations apc
                WHERE apc.action_id = a.id AND apc.policy_identifier = $2
          ))
          -- reversed-flag filter
          AND ((NOT $3::BOOL) OR r.id IS NOT NULL)
          AND ((NOT $4::BOOL) OR r.id IS NULL)
          -- date-range filter
          AND ($5::TIMESTAMPTZ IS NULL OR a.created_at >= $5)
          AND ($6::TIMESTAMPTZ IS NULL OR a.created_at <= $6)
          -- keyset cursor: strictly less than (ts, id) in DESC order
          AND ($7::TIMESTAMPTZ IS NULL OR (a.created_at, a.id) < ($7, $8::UUID))
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT $9
        "#,
        model,
        policy,
        only_reversed,
        only_not_reversed,
        from,
        to,
        cursor_ts,
        cursor_id,
        fetch,
    )
    .fetch_all(pool)
    .await?;

    // Split sentinel row off if we got `limit + 1`.
    let has_more = rows.len() as i64 > limit;
    let kept = if has_more {
        &rows[..usize::try_from(limit).unwrap_or(rows.len())]
    } else {
        &rows[..]
    };

    // Pull cited-policy snapshots for the kept rows in one batch query.
    let action_ids: Vec<Uuid> = kept.iter().map(|r| r.action_id).collect();
    let citations = if action_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query!(
            r#"
            SELECT action_id, policy_identifier, policy_version
            FROM action_policy_citations
            WHERE action_id = ANY($1)
            ORDER BY action_id, policy_identifier ASC
            "#,
            &action_ids[..],
        )
        .fetch_all(pool)
        .await?
    };

    let items: Vec<AuditEntry> = kept
        .iter()
        .map(|r| {
            let cited_policies = citations
                .iter()
                .filter(|c| c.action_id == r.action_id)
                .map(|c| CitedPolicy {
                    identifier: c.policy_identifier.clone(),
                    version: c.policy_version,
                })
                .collect();
            let reversal =
                match (r.reversal_id, r.reversal_created_at, r.reversal_moderator_id) {
                    (Some(id), Some(ts), Some(mid)) => Some(ReversalInfo {
                        action_id: id,
                        reversed_at: ts,
                        reversed_by_moderator_id: mid,
                    }),
                    _ => None,
                };
            let reasoning = extract_top_reasoning(&r.evidence);
            AuditEntry {
                action_id: r.action_id,
                action_kind: r.action_kind.clone(),
                label_value: r.label_value.clone(),
                subject_did: r.subject_did.clone(),
                subject_kind: r.subject_kind.clone(),
                subject_uri: r.subject_uri.clone(),
                model: r.model.clone(),
                model_version: r.model_version.clone(),
                prompt_template_id: r.prompt_template_id.clone(),
                recommendation_confidence: r.recommendation_confidence,
                input_hash: r.input_hash.clone(),
                cited_policies,
                reasoning,
                created_at: r.created_at,
                reversible_until: r.reversible_until,
                reversal,
                llm_observation_id: r.llm_observation_id,
            }
        })
        .collect();

    let next_cursor = if has_more {
        items.last().map(|last| AuditCursor {
            created_at: last.created_at,
            id: last.action_id,
        })
    } else {
        None
    };

    Ok(AuditPage { items, next_cursor })
}

/// Extract the top recommendation's `reasoning` string from a stored
/// `LlmRecommendation` observation's `evidence` JSONB.
///
/// The dispatcher persists the full `RecommendResponse` verbatim per
/// REQ-B2; the wire shape is `{ "recommended_actions": [{ "reasoning":
/// "...", ... }, ...], ... }`. We surface the first recommendation's
/// reasoning as the headline cell; the full payload is reachable via
/// the row's `llm_observation_id`.
///
/// Returns an empty string when the evidence shape does not match
/// (legacy rows, hand-crafted observations). Never panics — the
/// extractor walks JSON value variants without indexing.
fn extract_top_reasoning(evidence: &serde_json::Value) -> String {
    evidence
        .get("recommended_actions")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|first| first.get("reasoning"))
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_owned()
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
    fn cursor_round_trips_through_base64() {
        let cursor = AuditCursor {
            created_at: chrono::Utc::now(),
            id: Uuid::new_v4(),
        };
        let encoded = cursor.encode().expect("encode");
        let decoded = AuditCursor::decode(&encoded).expect("decode");
        assert_eq!(decoded.created_at, cursor.created_at);
        assert_eq!(decoded.id, cursor.id);
    }

    #[test]
    fn cursor_decode_rejects_garbage_base64() {
        let err = AuditCursor::decode("not base64 !!!").unwrap_err();
        assert!(matches!(err, AuditCursorDecodeError::Base64));
    }

    #[test]
    fn cursor_decode_rejects_wrong_json_shape() {
        // Valid base64, valid JSON, wrong shape.
        let raw = serde_json::to_vec(&serde_json::json!({ "wat": 1 })).unwrap();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&raw);
        let err = AuditCursor::decode(&encoded).unwrap_err();
        assert!(matches!(err, AuditCursorDecodeError::Json));
    }

    #[test]
    fn extract_top_reasoning_pulls_first_recommendation() {
        let evidence = serde_json::json!({
            "recommended_actions": [
                { "reasoning": "head reasoning text" },
                { "reasoning": "second reasoning text" },
            ],
        });
        assert_eq!(extract_top_reasoning(&evidence), "head reasoning text");
    }

    #[test]
    fn extract_top_reasoning_handles_missing_field() {
        assert_eq!(extract_top_reasoning(&serde_json::json!({})), "");
        assert_eq!(extract_top_reasoning(&serde_json::Value::Null), "");
        assert_eq!(
            extract_top_reasoning(&serde_json::json!({ "recommended_actions": [] })),
            "",
        );
        assert_eq!(
            extract_top_reasoning(&serde_json::json!({
                "recommended_actions": [{ "no_reasoning": true }],
            })),
            "",
        );
    }

    #[test]
    fn limits_clamp_to_max() {
        // The function itself is what would clamp; verify the constants
        // are consistent so the handler's `?limit=` clamp can read
        // them directly.
        assert!(DEFAULT_LIMIT < MAX_LIMIT);
        assert_eq!(DEFAULT_LIMIT, 50);
        assert_eq!(MAX_LIMIT, 200);
    }
}
