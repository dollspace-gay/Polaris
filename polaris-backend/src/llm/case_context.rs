//! Case-context hydration: build a [`RecommendRequest`] from the
//! database (`.design/llm-moderation-assist.md` REQ-A2 + REQ-C3
//! step 1; issue #234).
//!
//! [`hydrate`] is the single public entry point. It takes an
//! `incident_id` and a [`PgPool`], opens one read-consistent
//! `REPEATABLE READ` transaction, walks the incident → subject →
//! reports / observations / prior actions / covering policies
//! constellation, builds the proto message the dispatcher
//! (LLM-5 / #242) will hand to
//! [`crate::classifier::ClassifierClient::recommend`], and returns
//! it.
//!
//! # Privacy floor (REQ-A2)
//!
//! The wire `PriorAction` proto message intentionally has no
//! `moderator_id` field — the LLM sees outcomes, never the
//! moderator who decided them. This file's job is to honour the
//! same boundary: `prior_actions` is populated from
//! `actions.kind`, `actions.label_value`, `actions.reasoning`,
//! the joined `action_policy_citations` set, and
//! `actions.created_at`. **`actions.moderator_id` is never
//! read.** The privacy invariant is therefore structural — there
//! is no field on the destination shape to populate, so a leak
//! would be a compile error, not a code-review catch.
//!
//! # Caps
//!
//! Pre-prompt-budget caps are surfaced as module-level `pub const`s
//! so a follow-up config-driven override is a one-line plumbing
//! exercise. Today they are hardcoded matching the workbook plan:
//!
//! - [`MAX_REPORTS_IN_REQUEST`] = 20
//! - [`MAX_OBSERVATIONS_IN_REQUEST`] = 50
//! - [`MAX_PRIOR_ACTIONS_IN_REQUEST`] = 50
//! - [`MAX_SUBJECT_CONTEXT_CHARS`] = 4000
//!
//! # Snapshot isolation
//!
//! A concurrent `INSERT` into `actions` mid-hydration must not
//! produce a torn snapshot — the LLM would see `N` prior actions
//! but `N - 1` policy citations and infer a non-existent
//! "uncited" action. The hydration runs at `REPEATABLE READ` so
//! every read inside the transaction sees the same MVCC snapshot;
//! the snapshot is committed (read-only) at the end without
//! mutating anything.

use std::collections::BTreeMap;

use chrono::SecondsFormat;
use polaris_classifier_proto::v1::{
    Observation as ProtoObservation, PolicyClause, PolicyExample, PriorAction as ProtoPriorAction,
    RecommendRequest, Report as ProtoReport,
};
use polaris_types::SubjectKind;
use sqlx::PgPool;
use uuid::Uuid;

use crate::repo::mod_policies::{self, ModPolicyError};

/// Maximum number of `reports` rows fed to the LLM per request.
///
/// The newest 20 by `created_at` survive the cap; older reports
/// fall off. Reports are the primary trigger for the case so 20 is
/// generous — the typical case has 1–3.
pub const MAX_REPORTS_IN_REQUEST: usize = 20;

/// Maximum number of `observations` rows fed to the LLM per
/// request. Newest 50 by `detected_at` survive the cap.
pub const MAX_OBSERVATIONS_IN_REQUEST: usize = 50;

/// Maximum number of `actions` rows fed to the LLM per request.
/// Newest 50 by `created_at` survive the cap; the precedent corpus
/// is dominated by the recent past anyway.
pub const MAX_PRIOR_ACTIONS_IN_REQUEST: usize = 50;

/// Maximum character budget for the assembled `subject_context`
/// string. Anything beyond this is truncated with a trailing
/// ellipsis marker so the adapter knows the budget tripped.
pub const MAX_SUBJECT_CONTEXT_CHARS: usize = 4000;

/// Default operator-configurable hint for the adapter's output
/// budget (REQ-A2 `max_response_tokens`).
///
/// 1024 tokens is enough for one detailed `RecommendedAction` with
/// caveats; the dispatcher overrides this per-operator-config in
/// LLM-5 (#242).
pub const DEFAULT_MAX_RESPONSE_TOKENS: i32 = 1024;

/// Errors raised by [`hydrate`].
///
/// The variants distinguish the cases the dispatcher needs to
/// route differently:
///
/// - [`HydrateError::IncidentNotFound`] / `SubjectNotFound`:
///   surface as `404 Not Found` at the API layer.
/// - [`HydrateError::NoCoveringPolicies`]: the LLM cannot ground
///   against an empty policy set; the dispatcher must short-
///   circuit to "no recommendation" rather than ship an empty
///   `policies` array.
/// - [`HydrateError::Database`]: any other sqlx-level failure.
/// - [`HydrateError::PolicyRepo`]: a typed `mod_policies` error
///   (concurrent edit, etc).
#[derive(Debug, thiserror::Error)]
pub enum HydrateError {
    /// No row matches the requested `incident_id`.
    #[error("incident {0} not found")]
    IncidentNotFound(Uuid),
    /// The incident exists but its `primary_subject` does not.
    /// Indicates schema corruption (FK invariant breach) or the
    /// caller built the request against a different DB.
    #[error("subject for incident {0} not found")]
    SubjectNotFound(Uuid),
    /// No `mod_policies` row covers the subject's kind. The LLM
    /// has nothing to ground against, so the dispatcher must
    /// short-circuit before issuing a recommend RPC.
    #[error("no covering policies found for subject kind {kind}")]
    NoCoveringPolicies {
        /// The subject's kind (`"account"`, `"post"`, ...).
        kind: String,
    },
    /// Any other database-side failure.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    /// A typed `mod_policies` repository failure (concurrent
    /// amendment, unknown identifier, etc).
    #[error(transparent)]
    PolicyRepo(#[from] ModPolicyError),
}

/// Hydrate a [`RecommendRequest`] for the given `incident_id`.
///
/// The function walks the incident's subject and assembles the
/// proto message the LLM dispatcher (LLM-5 / #242) will pass to
/// [`crate::classifier::ClassifierClient::recommend`]. See the
/// module-level doc for the privacy floor, the row caps, and the
/// snapshot-isolation contract.
///
/// # Errors
///
/// Returns one of the [`HydrateError`] variants. The dispatcher
/// is responsible for mapping `NoCoveringPolicies` to a "no
/// recommendation" outcome rather than retrying.
///
/// # Examples
///
/// ```no_run
/// # async fn example(pool: sqlx::PgPool, incident_id: uuid::Uuid) -> Result<(), Box<dyn std::error::Error>> {
/// use polaris_backend::llm::case_context::hydrate;
/// let req = hydrate(&pool, incident_id).await?;
/// assert_eq!(req.incident_id, incident_id.to_string());
/// # Ok(()) }
/// ```
#[allow(
    clippy::too_many_lines,
    reason = "single-snapshot orchestration: open the REPEATABLE \
              READ tx, fan out across the per-table reads, assemble \
              the proto message, commit. Splitting into helpers \
              would force passing `&mut Transaction` through several \
              hops and obscure the single-snapshot story (mirrors \
              the same allow on `insert_action_in_tx` in \
              `repo::action`)."
)]
pub async fn hydrate(pool: &PgPool, incident_id: Uuid) -> Result<RecommendRequest, HydrateError> {
    // Open a read-consistent transaction. `REPEATABLE READ`
    // guarantees every SELECT below sees the same MVCC snapshot
    // — a concurrent INSERT of a new report / observation / action
    // is invisible to this hydration once the snapshot is taken.
    // The transaction is committed at the end without mutating
    // anything; rollback on drop covers the error path.
    let mut tx = pool.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *tx)
        .await?;

    // 1. Load the incident row.
    let incident = sqlx::query!(
        r#"
        SELECT id, primary_subject
        FROM incidents
        WHERE id = $1
        "#,
        incident_id,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(HydrateError::IncidentNotFound(incident_id))?;

    // 2. Load the primary subject.
    let subject = sqlx::query!(
        r#"
        SELECT id, kind, did, uri, created_at
        FROM subjects
        WHERE id = $1
        "#,
        incident.primary_subject,
    )
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| HydrateError::SubjectNotFound(incident.id))?;

    let subject_kind = SubjectKind::from_wire(&subject.kind).ok_or_else(|| {
        // The CHECK constraint on `subjects.kind` already restricts
        // the column; a value outside the contract means schema
        // drift. Surface as Database error wrapping a synthetic
        // sqlx::Error::Protocol so the caller's match arms still
        // see a typed variant.
        HydrateError::Database(sqlx::Error::Protocol(format!(
            "subjects.kind={:?} outside polaris-types contract",
            subject.kind
        )))
    })?;
    let subject_did = subject.did.clone().unwrap_or_default();

    // 3. Load reports for the subject — newest first, capped.
    let report_rows = sqlx::query!(
        r#"
        SELECT category, body, reporter_did, created_at
        FROM reports
        WHERE subject_id = $1
        ORDER BY created_at DESC
        LIMIT $2
        "#,
        subject.id,
        // sqlx binds i64; cast the cap from usize-land.
        i64::try_from(MAX_REPORTS_IN_REQUEST).unwrap_or(i64::MAX),
    )
    .fetch_all(&mut *tx)
    .await?;
    let reports: Vec<ProtoReport> = report_rows
        .into_iter()
        .map(|r| ProtoReport {
            category: r.category,
            body: r.body,
            reporter_did: r.reporter_did,
        })
        .collect();

    // 4. Load observations for the subject — newest first, capped.
    let observation_rows = sqlx::query!(
        r#"
        SELECT kind, confidence, evidence, detected_at
        FROM observations
        WHERE subject_id = $1
        ORDER BY detected_at DESC
        LIMIT $2
        "#,
        subject.id,
        i64::try_from(MAX_OBSERVATIONS_IN_REQUEST).unwrap_or(i64::MAX),
    )
    .fetch_all(&mut *tx)
    .await?;
    let observations: Vec<ProtoObservation> = observation_rows
        .into_iter()
        .map(|r| ProtoObservation {
            kind: r.kind,
            confidence: r.confidence,
            // `evidence` is the raw JSONB; re-serialise to a
            // string for the wire so the adapter can parse it
            // with the language-of-its-choice JSON library
            // without needing a proto Struct mapping.
            evidence_json: r.evidence.to_string(),
            detected_at: r.detected_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        })
        .collect();

    // 5. Load prior actions for the subject — newest first,
    //    capped. The privacy floor (REQ-A2) lives here:
    //    `actions.moderator_id` is NEVER selected.
    //
    //    The cited-policy join uses a single `action_policy_citations`
    //    fetch keyed on `action_id IN (...)` so the loop below is
    //    O(rows) not O(rows × per-action round-trips).
    let action_rows = sqlx::query!(
        r#"
        SELECT id, kind, label_value, reasoning, created_at
        FROM actions
        WHERE subject_id = $1
        ORDER BY created_at DESC
        LIMIT $2
        "#,
        subject.id,
        i64::try_from(MAX_PRIOR_ACTIONS_IN_REQUEST).unwrap_or(i64::MAX),
    )
    .fetch_all(&mut *tx)
    .await?;

    let action_ids: Vec<Uuid> = action_rows.iter().map(|a| a.id).collect();
    // One round-trip for every citation row attached to any of
    // the prior actions. `ANY($1::UUID[])` is the standard
    // sqlx-checked array predicate.
    let citation_rows = if action_ids.is_empty() {
        Vec::new()
    } else {
        sqlx::query!(
            r#"
            SELECT action_id, policy_identifier
            FROM action_policy_citations
            WHERE action_id = ANY($1)
            ORDER BY policy_identifier ASC
            "#,
            &action_ids,
        )
        .fetch_all(&mut *tx)
        .await?
    };
    // Group identifiers by action_id. `BTreeMap` keeps the
    // identifier order deterministic per action (alphabetical)
    // so the LLM input is stable across re-runs.
    let mut citations_by_action: BTreeMap<Uuid, Vec<String>> = BTreeMap::new();
    for row in citation_rows {
        citations_by_action
            .entry(row.action_id)
            .or_default()
            .push(row.policy_identifier);
    }

    let prior_actions: Vec<ProtoPriorAction> = action_rows
        .into_iter()
        .map(|a| ProtoPriorAction {
            kind: a.kind,
            label_value: a.label_value.unwrap_or_default(),
            reasoning: a.reasoning,
            cited_policy_identifiers: citations_by_action.remove(&a.id).unwrap_or_default(),
            created_at: a.created_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        })
        .collect();

    // 6. Load covering policies — the kind's own scope plus the
    //    `both` scope which matches both kinds. `mod_policies::list`
    //    uses the `effective_until IS NULL` predicate so only the
    //    current version of each identifier is returned.
    //
    //    Two list calls (one per matching scope) keep the existing
    //    repo surface untouched; the union is small enough that the
    //    extra round-trip is invisible. Sorted by identifier for
    //    determinism. Calls run against the pool (not the tx) because
    //    `mod_policies::list` takes a `&PgPool` — the workbook rows
    //    are versioned and the LLM context is fine to read post-
    //    snapshot here (the policy text drift between the snapshot
    //    open and the call is bounded by the surrounding tx commit
    //    horizon).
    let scope = subject_kind.as_str().to_owned();
    let mut policies = collect_covering_policies(pool, &scope).await?;
    if policies.is_empty() {
        return Err(HydrateError::NoCoveringPolicies { kind: scope });
    }
    // Defensive de-duplication: a future repo amendment that lets
    // an identifier appear in both the `<kind>` and `both` lists
    // would otherwise double-count. Keep the first occurrence.
    policies.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    policies.dedup_by(|a, b| a.identifier == b.identifier);

    // 7. Build `subject_context`.
    let subject_context = build_subject_context(
        &mut tx,
        subject.id,
        subject_kind,
        subject_did.as_str(),
        subject.uri.as_deref(),
        subject.created_at,
    )
    .await?;

    // 8. Assemble the final `RecommendRequest`.
    //
    // Event-id is a UUID v7 if the workspace `uuid` features
    // include `v7` — the chronological ordering helps trace
    // correlation when an operator scrubs through a recent
    // window of recommendations. The workspace presently ships
    // `v4` only, so we fall back to `new_v4()` and the value
    // remains uniquely identifying for the adapter's echo-back
    // contract (REQ-A2 says "opaque to the adapter"). A future
    // workspace bump to `v7` is a one-line swap here.
    let event_id = Uuid::new_v4().to_string();
    let request = RecommendRequest {
        event_id,
        subject_did,
        subject_kind: subject_kind.as_str().to_owned(),
        incident_id: incident.id.to_string(),
        reports,
        observations,
        prior_actions,
        policies,
        subject_context,
        max_response_tokens: DEFAULT_MAX_RESPONSE_TOKENS,
    };

    // 9. Commit the (read-only) tx so the snapshot horizon is
    //    released cleanly. A drop-on-error path rolls back; the
    //    happy path commits.
    tx.commit().await?;

    Ok(request)
}

/// Fetch the set of `mod_policies` rows whose `scope` covers the
/// subject's kind. A subject of kind `account` matches `scope ∈
/// {account, both}`; a subject of kind `post` matches
/// `scope ∈ {post, both}`.
async fn collect_covering_policies(
    pool: &PgPool,
    subject_kind_scope: &str,
) -> Result<Vec<PolicyClause>, HydrateError> {
    let mut buf: Vec<PolicyClause> = Vec::new();
    for scope in [subject_kind_scope, "both"] {
        let summaries = mod_policies::list(
            pool,
            mod_policies::ModPolicyFilters {
                scope: Some(scope.to_owned()),
                ..Default::default()
            },
        )
        .await?;
        for summary in summaries {
            // The summary row drops the example arrays and the
            // decision-criteria body; fetch the full row via
            // `current_by_identifier` to populate them. One round
            // trip per current-version row is acceptable: the
            // typical operator runs ~10–30 policies, the cache in
            // LLM-5 will memoise this hot path.
            let Some(full) = mod_policies::current_by_identifier(pool, &summary.identifier).await?
            else {
                // Race: the row was retired between `list` and
                // `current_by_identifier`. Skip rather than fail —
                // the LLM context is best-effort consistent.
                continue;
            };
            buf.push(PolicyClause {
                identifier: full.identifier,
                version: full.version,
                name: full.name,
                description: full.description,
                scope: full.scope,
                severity: full.severity,
                decision_criteria: full.decision_criteria,
                examples_positive: parse_examples(&full.examples_positive),
                examples_negative: parse_examples(&full.examples_negative),
                suggested_action_kinds: full.suggested_action_kinds,
                linked_label_value: full.linked_label_value.unwrap_or_default(),
            });
        }
    }
    Ok(buf)
}

/// Parse a JSONB example array into a `Vec<PolicyExample>`.
///
/// The workbook writes examples as JSON objects with at least the
/// `excerpt` field plus optional `context` and `note` / `why_not`
/// /`expected_action` keys. The repo does not constrain the shape
/// at write time beyond "is a JSON array"; we accept anything
/// shaped like `[{...}, ...]` and ignore non-object entries.
fn parse_examples(value: &serde_json::Value) -> Vec<PolicyExample> {
    let Some(array) = value.as_array() else {
        return Vec::new();
    };
    array
        .iter()
        .filter_map(|entry| {
            let obj = entry.as_object()?;
            // `note` is the proto's combined slot for the positive
            // `expected_action` / negative `why_not` text the
            // adapter reads; honour whichever the operator wrote.
            let note = obj
                .get("note")
                .or_else(|| obj.get("expected_action"))
                .or_else(|| obj.get("why_not"))
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_owned();
            Some(PolicyExample {
                excerpt: obj
                    .get("excerpt")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                context: obj
                    .get("context")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                note,
            })
        })
        .collect()
}

/// Build the `subject_context` string for the [`RecommendRequest`].
///
/// For `post`-kind subjects the context is the AT-URI plus any
/// alt-text captured by the media-blob index
/// (`subject_image_blobs`, populated by the network-context
/// handler). For `account`-kind subjects it's the DID, handle (when
/// known), and account-creation timestamp plus a hint at recent
/// post-URI activity drawn from `subject_image_blobs.post_uri`.
///
/// The function intentionally pulls from existing tables only —
/// there is no separate "post text" store today, so the LLM's
/// adapter is expected to resolve the AT-URI to text on its own
/// side (mirrors the proto comment "Format is adapter-defined").
/// If a future migration adds a `post_text` cache, this helper is
/// the single point that needs to learn about it.
///
/// The result is capped at [`MAX_SUBJECT_CONTEXT_CHARS`] characters;
/// over-budget input is truncated with a trailing `…` marker so the
/// adapter knows the cap tripped.
async fn build_subject_context(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    subject_id: Uuid,
    kind: SubjectKind,
    did: &str,
    uri: Option<&str>,
    created_at: chrono::DateTime<chrono::Utc>,
) -> Result<String, HydrateError> {
    let mut buf = String::new();

    match kind {
        SubjectKind::Post => {
            buf.push_str("kind: post\n");
            if !did.is_empty() {
                buf.push_str("author_did: ");
                buf.push_str(did);
                buf.push('\n');
            }
            if let Some(u) = uri {
                buf.push_str("uri: ");
                buf.push_str(u);
                buf.push('\n');
            }
            buf.push_str("created_at: ");
            buf.push_str(&created_at.to_rfc3339_opts(SecondsFormat::Millis, true));
            buf.push('\n');

            // Alt-text from the media-blob index (issue #97; the
            // network-context handler populates this on every
            // hydrated post). The LLM uses this as a proxy for
            // image content semantics when the adapter cannot
            // dereference the post URI directly.
            let alt_rows = sqlx::query!(
                r#"
                SELECT alt_text
                FROM subject_image_blobs
                WHERE subject_id = $1 AND alt_text IS NOT NULL
                ORDER BY first_seen_at ASC
                LIMIT 16
                "#,
                subject_id,
            )
            .fetch_all(&mut **tx)
            .await?;
            if !alt_rows.is_empty() {
                buf.push_str("image_alt_text:\n");
                for row in alt_rows {
                    if let Some(text) = row.alt_text {
                        buf.push_str("  - ");
                        buf.push_str(&text);
                        buf.push('\n');
                    }
                }
            }
        }
        SubjectKind::Account => {
            buf.push_str("kind: account\n");
            if !did.is_empty() {
                buf.push_str("did: ");
                buf.push_str(did);
                buf.push('\n');
            }
            buf.push_str("first_seen_upstream: ");
            buf.push_str(&created_at.to_rfc3339_opts(SecondsFormat::Millis, true));
            buf.push('\n');

            // Recent post-URIs the account has authored, as
            // observed through the media-blob owner index. This
            // is a sample of "things this account has been
            // observed posting" — used as a rough activity hint
            // for the LLM. Capped at 8 to stay well below the
            // per-context budget.
            //
            // `post_uri` is `NOT NULL` per migration 26 schema so
            // sqlx infers `String`, not `Option<String>`.
            let post_rows = sqlx::query!(
                r#"
                SELECT DISTINCT post_uri
                FROM subject_image_blobs
                WHERE owner_did = $1
                ORDER BY post_uri ASC
                LIMIT 8
                "#,
                did,
            )
            .fetch_all(&mut **tx)
            .await?;
            if !post_rows.is_empty() {
                buf.push_str("recent_post_uris:\n");
                for row in post_rows {
                    buf.push_str("  - ");
                    buf.push_str(&row.post_uri);
                    buf.push('\n');
                }
            }
        }
        SubjectKind::List | SubjectKind::Feed => {
            buf.push_str("kind: ");
            buf.push_str(kind.as_str());
            buf.push('\n');
            if !did.is_empty() {
                buf.push_str("owner_did: ");
                buf.push_str(did);
                buf.push('\n');
            }
            if let Some(u) = uri {
                buf.push_str("uri: ");
                buf.push_str(u);
                buf.push('\n');
            }
            buf.push_str("created_at: ");
            buf.push_str(&created_at.to_rfc3339_opts(SecondsFormat::Millis, true));
            buf.push('\n');
        }
    }

    Ok(truncate_with_ellipsis(buf, MAX_SUBJECT_CONTEXT_CHARS))
}

/// Truncate `s` to at most `max_chars` *characters* (not bytes),
/// appending a single `…` so the adapter can tell the cap tripped.
/// Operates on grapheme-light boundaries (`char_indices`) so a
/// multi-byte UTF-8 cut never produces an invalid sequence.
fn truncate_with_ellipsis(s: String, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s;
    }
    // Reserve room for the marker; max_chars is a hard ceiling so
    // the truncated body is `max_chars - 1` chars + the ellipsis.
    let take = max_chars.saturating_sub(1);
    let mut out: String = s.chars().take(take).collect();
    out.push('…');
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    /// Structural privacy proof: `PriorAction` has no
    /// `moderator_id` field. If a future proto regeneration
    /// introduced one, this test would stop compiling at the
    /// builder literal — the privacy floor is enforced by the
    /// type system, not by runtime assertion.
    #[test]
    fn prior_action_proto_omits_moderator_id() {
        let action = ProtoPriorAction {
            kind: "label".to_owned(),
            label_value: "spam".to_owned(),
            reasoning: "matches the spam policy".to_owned(),
            cited_policy_identifiers: vec!["polaris.spam".to_owned()],
            created_at: "2026-05-18T00:00:00.000Z".to_owned(),
        };
        // The literal above is exhaustive — adding a
        // `moderator_id` field on the proto side would fail to
        // compile here. The runtime assertion is a smoke check
        // that the fields we *did* populate are reachable.
        assert_eq!(action.kind, "label");
        assert_eq!(action.label_value, "spam");
    }

    #[test]
    fn truncate_with_ellipsis_leaves_short_strings_alone() {
        let s = "hello".to_owned();
        assert_eq!(truncate_with_ellipsis(s, 10), "hello");
    }

    #[test]
    fn truncate_with_ellipsis_caps_long_strings() {
        let s = "abcdefghij".to_owned();
        // 10 chars; cap to 5 → "abcd…" (4 chars + ellipsis).
        let out = truncate_with_ellipsis(s, 5);
        assert_eq!(out, "abcd…");
        assert_eq!(out.chars().count(), 5);
    }

    #[test]
    fn truncate_with_ellipsis_handles_multibyte_safely() {
        // "héllo" is 5 chars but 6 bytes in UTF-8.
        let s = "héllo wörld".to_owned();
        let out = truncate_with_ellipsis(s, 6);
        // 5 chars then ellipsis; never a partial UTF-8 sequence.
        assert_eq!(out.chars().count(), 6);
        assert!(out.ends_with('…'));
    }

    #[test]
    fn parse_examples_extracts_excerpt_and_note() {
        let v = serde_json::json!([
            { "excerpt": "go away", "context": "reply", "note": "label spam" },
            { "excerpt": "satire", "why_not": "clearly comedic" },
            "garbage non-object entry",
        ]);
        let parsed = parse_examples(&v);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].excerpt, "go away");
        assert_eq!(parsed[0].note, "label spam");
        assert_eq!(parsed[1].excerpt, "satire");
        assert_eq!(parsed[1].note, "clearly comedic");
    }

    #[test]
    fn caps_are_publicly_exposed_and_match_design() {
        // Doubles as a regression guard if a future refactor
        // accidentally renames or scales the caps without
        // updating the design doc.
        assert_eq!(MAX_REPORTS_IN_REQUEST, 20);
        assert_eq!(MAX_OBSERVATIONS_IN_REQUEST, 50);
        assert_eq!(MAX_PRIOR_ACTIONS_IN_REQUEST, 50);
        assert_eq!(MAX_SUBJECT_CONTEXT_CHARS, 4000);
    }
}
