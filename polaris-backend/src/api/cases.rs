//! Subject-centric case API (issue #14).
//!
//! Four endpoints, all sitting behind the cookie-driven auth middleware from
//! issue #9:
//!
//! 1. `GET    /api/cases/:subject_id`             — full case view (§5.2).
//! 2. `GET    /api/cases?status=open`             — slim incident list.
//! 3. `POST   /api/cases/:subject_id/actions`     — submit an action (§5.5).
//! 4. `POST   /api/cases/:incident_id/escalate`   — escalate the incident.
//!
//! # Handler-as-orchestrator
//!
//! Each handler is ≤ 25 lines and does exactly four things:
//!
//! 1. Extract the auth context from `Extension<ModeratorAuthCtx>`.
//! 2. Extract path / query / body parameters via `axum` extractors.
//! 3. Delegate validation + repo composition to a `validate_*` /
//!    `build_*` helper in this module.
//! 4. Map the helper's `Result<T, ApiError>` to an HTTP response.
//!
//! Business logic (validation rules, repo composition order, status
//! transitions) lives in the helpers. The forbidden-pattern checklist in
//! the architect's pre-flight forbids handlers from owning that logic.
//!
//! # Append-only contract is preserved
//!
//! Submit-action inserts via [`ActionRepo::insert`]; the trigger on the
//! `actions` table rejects any UPDATE. Escalate calls
//! [`IncidentRepo::update_status`], which is the *only* mutator added to
//! the incident repo for this issue — see the doc comment on
//! [`crate::repo::IncidentRepo`] for the rationale.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use polaris_types::{
    Action, ActionId, ActionKind, Incident, IncidentId, IncidentStatus,
    NewAction as TypesNewAction, ReportId, SubjectId,
};

use crate::api::dto::{
    CaseView, Escalate, IncidentList, IncidentListQuery, IncidentSummary, ReporterContext,
    SubjectMediaBlob, SubmitAction,
};
use crate::api::error::ApiError;
use crate::api::policy_cache;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;
use crate::labeler::emitter::{SubjectRef, emit_best_effort};
use crate::repo::action::LlmAuditFields;
use crate::repo::mod_policies::ModPolicyError;
use crate::repo::{
    ActionRepo, IncidentRepo, NewAction as RepoNewAction, ObservationRepo, ReportRepo, SubjectRepo,
    action_policy_citations,
};

/// Hard upper bound on the per-call row count returned by list-style repo
/// methods. The case view fetches "everything for this subject"; a bounded
/// `LIMIT` keeps a pathological case (10k actions on one subject) from
/// blowing past the response budget. The paginated cases-list handler
/// clamps caller-supplied `?limit=` values to this ceiling.
pub(crate) const MAX_ROWS_PER_LIST: i64 = 256;

/// Default page size for `GET /api/cases` when the caller omits `?limit=`.
/// Sized to fit comfortably in a single dashboard render without forcing
/// the frontend into an immediate second fetch.
const DEFAULT_PAGE_LIMIT: i64 = 50;

// ── 1. GET /api/cases/:subject_id ───────────────────────────────────────

/// Handler: full subject-centric case view.
pub async fn get_case(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
) -> Result<Json<CaseView>, ApiError> {
    let view = build_case_view(&state, subject_id).await?;
    Ok(Json(view))
}

/// Helper: compose the [`CaseView`] from four repo calls. Returns
/// [`ApiError::NotFound`] when the subject does not exist.
async fn build_case_view(state: &ApiState, subject_id: SubjectId) -> Result<CaseView, ApiError> {
    let subject = state
        .subjects
        .get(subject_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let history = list_history_for_subject(state, subject_id).await?;
    let reports = state
        .reports
        .list_by_subject(subject_id, MAX_ROWS_PER_LIST)
        .await?;
    let observations = state.observations.list_by_subject(subject_id).await?;
    let reporter_contexts = build_reporter_contexts(state, &reports).await?;
    let media_blobs = build_media_blobs(state, subject_id).await?;
    let related_actions = build_related_actions(state, &subject).await?;
    Ok(CaseView {
        subject,
        history,
        reports,
        reporter_contexts,
        observations,
        media_blobs,
        related_actions,
        network_context: serde_json::Value::Null,
    })
}

/// Gather every Polaris moderation action targeting a subject that
/// shares this case's DID — accounts under the same DID, plus posts
/// authored by this DID — and excluding the current case's own
/// `subject_id` (those rows are already in the primary `history`).
///
/// Returns an empty Vec when this subject has no `did` populated
/// (list-/feed-kind subjects). Otherwise issues ONE SQL pass with
/// a JOIN from `actions` to `subjects` so the timeline can render
/// the target subject's kind/uri alongside each action without an
/// N+1 hydrate.
async fn build_related_actions(
    state: &ApiState,
    subject: &polaris_types::Subject,
) -> Result<Vec<crate::api::dto::RelatedAction>, ApiError> {
    let Some(did) = subject.did.as_ref().map(ToString::to_string) else {
        return Ok(Vec::new());
    };
    let primary_id = subject.id.as_uuid();

    // Single SQL pass: actions joined to their target subject row,
    // filtered to subjects with the same `did` but EXCLUDING the
    // current case's subject id. Ordered newest-first; capped at the
    // standard row budget.
    let rows = sqlx::query!(
        r#"
        SELECT
            a.id                AS action_id,
            a.incident_id       AS incident_id,
            a.subject_id        AS action_subject_id,
            a.moderator_id      AS moderator_id,
            a.kind              AS "kind!: String",
            a.label_value       AS label_value,
            a.reasoning         AS reasoning,
            a.policy_refs       AS policy_refs,
            a.reversible_until  AS reversible_until,
            a.reverses_action_id AS reverses_action_id,
            a.emitted_to_atproto AS emitted_to_atproto,
            a.evidence_car_cid  AS evidence_car_cid,
            a.created_at        AS created_at,
            s.kind              AS "target_kind!: String",
            s.uri               AS target_uri
        FROM actions a
        JOIN subjects s ON s.id = a.subject_id
        WHERE s.did = $1
          AND s.id <> $2
        ORDER BY a.created_at DESC
        LIMIT $3
        "#,
        did,
        primary_id,
        MAX_ROWS_PER_LIST,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let action = crate::repo::action::row_to_action(
            row.action_id,
            row.incident_id,
            row.action_subject_id,
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
        .map_err(ApiError::from)?;
        out.push(crate::api::dto::RelatedAction {
            action,
            target_subject_id: SubjectId::from(row.action_subject_id),
            target_subject_kind: row.target_kind,
            target_subject_uri: row.target_uri,
        });
    }
    Ok(out)
}

/// Build the per-subject [`SubjectMediaBlob`] list from the
/// `subject_image_blobs` index (issue #97 work landed migration 0026).
///
/// The case-view DTO surfaces every distinct (`blob_cid`, `post_uri`)
/// pair the network-context handler has observed for this subject so
/// the case-view can render media blur-by-default previews (#95).
/// Duplicates from the same blob being re-embedded across multiple
/// posts are deduplicated on the wire by the `DISTINCT ON (blob_cid)`
/// clause — the moderator sees one row per unique image, with the
/// most-recent `post_uri` where it appeared.
async fn build_media_blobs(
    state: &ApiState,
    subject_id: SubjectId,
) -> Result<Vec<SubjectMediaBlob>, ApiError> {
    // `DISTINCT ON (blob_cid)` collapses the multi-post-per-blob
    // case to one row per unique image; `ORDER BY blob_cid,
    // first_seen_at DESC` then makes the row's `post_uri` +
    // `alt_text` carry the most-recent post's data. The outer
    // `ORDER BY first_seen_at DESC` re-sorts the deduped set so
    // the moderator sees the newest images first in the carousel
    // (the `SELECT` is wrapped in a subquery because Postgres
    // does not allow `DISTINCT ON` and a non-leading `ORDER BY`
    // in the same query level).
    // Reverse-chronological order — see the matching SELECT in
    // `polaris_backend::api::media::read_media_blobs` for the
    // detailed dedup-vs-ordering rationale.
    let rows = sqlx::query!(
        r#"
        SELECT blob_cid, post_uri, alt_text, owner_did, post_indexed_at, first_seen_at
        FROM (
            SELECT DISTINCT ON (blob_cid)
                blob_cid,
                post_uri,
                alt_text,
                owner_did,
                post_indexed_at,
                first_seen_at
            FROM subject_image_blobs
            WHERE subject_id = $1
            ORDER BY blob_cid, post_indexed_at DESC NULLS LAST, first_seen_at DESC
        ) AS distinct_blobs
        ORDER BY post_indexed_at DESC NULLS LAST, first_seen_at DESC
        "#,
        subject_id.as_uuid(),
    )
    .fetch_all(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    Ok(rows
        .into_iter()
        .map(|r| SubjectMediaBlob {
            blob_cid: r.blob_cid,
            post_uri: r.post_uri,
            alt_text: r.alt_text,
            owner_did: r.owner_did,
            post_indexed_at: r.post_indexed_at,
            first_seen_at: r.first_seen_at,
        })
        .collect())
}

/// Build the [`ReporterContext`] list for every distinct reporter that
/// appears in `reports` (design.md §5.2; issue #37).
///
/// One SELECT against `reporter_stats` for the distinct DID set. Reporters
/// without a stats row (never seen before; the case-view is the first time
/// they show up) are emitted with `reports_filed = 0`, the neutral score,
/// and `account_age_days = 0` — the moderator's "new account" signal.
async fn build_reporter_contexts(
    state: &ApiState,
    reports: &[polaris_types::Report],
) -> Result<Vec<ReporterContext>, ApiError> {
    use std::collections::BTreeSet;

    let dids: BTreeSet<&str> = reports.iter().map(|r| r.reporter_did.as_str()).collect();
    if dids.is_empty() {
        return Ok(Vec::new());
    }
    let did_vec: Vec<String> = dids.iter().map(|d| (*d).to_owned()).collect();
    let rows = sqlx::query!(
        r#"
        SELECT did, reports_filed, reports_actioned, cached_score, first_seen
        FROM reporter_stats
        WHERE did = ANY($1)
        "#,
        &did_vec,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(crate::repo::RepoError::from)?;

    let now = chrono::Utc::now();
    let mut contexts: std::collections::HashMap<String, ReporterContext> =
        std::collections::HashMap::with_capacity(rows.len());
    for row in rows {
        let age_days = (now - row.first_seen).num_days();
        contexts.insert(
            row.did.clone(),
            ReporterContext {
                did: row.did,
                reports_filed: row.reports_filed,
                reports_actioned: row.reports_actioned,
                reputation_score: row.cached_score,
                account_age_days: age_days,
            },
        );
    }
    // Emit a row for every distinct DID — fall back to "no history yet"
    // for DIDs not in `reporter_stats`. The case-view DTO is stable: one
    // entry per reporter who filed any of the displayed reports.
    let mut out: Vec<ReporterContext> = did_vec
        .into_iter()
        .map(|did| {
            contexts.remove(&did).unwrap_or_else(|| ReporterContext {
                did,
                reports_filed: 0,
                reports_actioned: 0,
                reputation_score: crate::reputation::ReputationScore::neutral().into_inner(),
                account_age_days: 0,
            })
        })
        .collect();
    // Stable order (alphabetical DID) for deterministic snapshots.
    out.sort_by(|a, b| a.did.cmp(&b.did));
    Ok(out)
}

/// Helper: gather every [`Action`] ever taken against `subject_id`.
///
/// One SQL pass via [`crate::repo::ActionRepo::list_by_subject`] —
/// previously this walked every incident in the table, filtered by
/// `primary_subject == subject_id` in Rust, and then re-queried
/// actions per matched incident. The dedicated query is correct
/// against the same column the action insert path writes
/// (`actions.subject_id`) and is O(1) round-trips instead of O(N).
async fn list_history_for_subject(
    state: &ApiState,
    subject_id: SubjectId,
) -> Result<Vec<Action>, ApiError> {
    Ok(state
        .actions
        .list_by_subject(subject_id, MAX_ROWS_PER_LIST)
        .await?)
}

// ── 2. GET /api/cases?status=open ───────────────────────────────────────

/// Handler: slim incident list (queue-fallback projection).
///
/// Pagination contract:
///   * `?status=open` filters by [`polaris_types::IncidentStatus`] wire
///     form.
///   * `?limit=<n>` page size — defaults to [`DEFAULT_PAGE_LIMIT`],
///     clamped to [`MAX_ROWS_PER_LIST`].
///   * `?offset=<n>` skip count — defaults to 0; negative values
///     clamp to 0.
///
/// The response's `total` field carries the count of rows matching
/// the filter BEFORE pagination so the frontend can render the
/// "showing N of M" affordance without a second probe.
pub async fn list_cases(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Query(query): Query<IncidentListQuery>,
) -> Result<Json<IncidentList>, ApiError> {
    // Clamp the caller-supplied paging controls. A non-positive limit
    // (zero or negative) falls back to the default; offsets clamp at
    // zero so we never bind a negative `OFFSET` to Postgres.
    let limit = query
        .limit
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .min(MAX_ROWS_PER_LIST);
    let offset = query.offset.unwrap_or(0).max(0);

    let (incidents, total) = state
        .incidents
        .list_paginated_by_status(query.status, limit, offset)
        .await?;
    let summaries: Vec<IncidentSummary> = incidents
        .iter()
        .map(IncidentSummary::from_incident)
        .collect();
    // `total` is the unfiltered-by-page count from `COUNT(*) OVER ()`;
    // cast to `u64` is lossless since the SQL value is non-negative.
    let total = u64::try_from(total).unwrap_or(0);
    Ok(Json(IncidentList {
        incidents: summaries,
        total,
    }))
}

// ── 3. POST /api/cases/:subject_id/actions ──────────────────────────────

/// Handler: submit a new action against the subject.
///
/// REQ-D3 wraps the body in a `submit_action` tracing span carrying
/// `action_id = %inserted.id` so the action → sign → persist →
/// broadcast timeline is greppable by a single UUID.
///
/// # Per-report idempotency (issue #202)
///
/// When `body.report_id` is `Some(_)`, the handler routes through
/// [`submit_action_with_report`]: a `SELECT … FOR UPDATE` lock on the
/// `reports` row gates the action insert. A second click with the same
/// `report_id` returns the existing action verbatim (HTTP 200) rather
/// than inserting a duplicate. Validation runs on the cold path only —
/// the idempotent return path echoes the already-stored action without
/// re-validating the wire body.
///
/// When `body.report_id` is `None` (action-composer submissions, the
/// Mute-Reporter button, bulk-action subroutes), the handler preserves
/// the pre-#202 behavior: validation + insert + emit, returning HTTP 201.
#[allow(
    clippy::missing_panics_doc,
    reason = "the inserted action ID is always present on the successful path; the panics doc is N/A"
)]
pub async fn submit_action(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
    Json(body): Json<SubmitAction>,
) -> Result<(StatusCode, Json<Action>), ApiError> {
    if let Some(report_id) = body.report_id {
        return submit_action_with_report(&state, &ctx, subject_id, report_id, &body).await;
    }
    submit_action_cold(&state, &ctx, subject_id, &body).await
}

/// Cold-path action insert — the pre-#202 behavior, used when the wire
/// body omits `report_id`.
///
/// Validates the body, gates emit-shaped kinds on the labeler's signing
/// key, resolves every cited policy identifier against `mod_policies`
/// (WB-2 / REQ-B3) to snapshot the current `(identifier, version)`
/// pair, and finally opens a single `sqlx::Transaction` that inserts
/// the action row plus its citation rows so a partial citation is
/// never visible. The legacy `actions.policy_refs TEXT[]` column is
/// also populated with the flat identifier list per REQ-B2.
///
/// Public-HTTP wire calls always land here with `actor_kind = 'human'`
/// (`autonomous_audit = None`) — the wire `SubmitAction` shape carries
/// no `actor_kind` field, and this handler never invents one. The
/// autonomous-agent code path goes through the deliberately narrow
/// [`submit_action_autonomous_for_test`] entry point (today exercised
/// only by [`tests/policy_human_required_never_autonomous.rs`]; will
/// be replaced by the LLM dispatcher LLM-5 / #242 once it lands), so
/// REQ-G3 / REQ-G2 cannot be tripped from an external caller.
async fn submit_action_cold(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    subject_id: SubjectId,
    body: &SubmitAction,
) -> Result<(StatusCode, Json<Action>), ApiError> {
    submit_action_inner(state, ctx, subject_id, body, None).await
}

/// Shared core of the cold-path action insert. Threaded by both
/// [`submit_action_cold`] (HTTP entry, always `autonomous_audit = None`)
/// and [`submit_action_autonomous_for_test`] (test-only entry, always
/// `Some(_)`).
///
/// When `autonomous_audit` is `Some`, the inserted row carries
/// `actor_kind = 'autonomous_agent'` and the migration-51 audit-column
/// CHECK at the DB boundary will reject a partial envelope. The two
/// REQ-G2 / REQ-G3 floors are evaluated server-side BEFORE the insert
/// so an autonomous emission against a `human_required_always` policy
/// (or an autonomous account-takedown) is rejected with the typed
/// `403` shape rather than reaching the DB and surfacing as a `500`.
async fn submit_action_inner(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    subject_id: SubjectId,
    body: &SubmitAction,
    autonomous_audit: Option<LlmAuditFields>,
) -> Result<(StatusCode, Json<Action>), ApiError> {
    validate_submit_action_shape(body)?;

    // REQ-A3: emit-shaped actions (Label, Takedown) require the
    // labeler's signing key to be provisioned — without it the emit
    // path would either crash on a stub-signer error or silently
    // skip. We surface that condition as `412 Precondition Failed`
    // BEFORE the insert so the action is not recorded in a state
    // the moderator cannot reverse cleanly. Non-emit actions (Mute,
    // Warn, Escalate, NoAction) bypass the check — those never reach
    // the emitter and so do not depend on a signing key.
    if matches!(body.kind, ActionKind::Label | ActionKind::Takedown) {
        ensure_labeler_provisioned(state).await?;
    }

    // REQ-B3: snapshot every cited identifier at `(identifier, version)`
    // BEFORE opening the transaction so an unknown / retired policy
    // surfaces a `400` without ever touching the actions table.
    let citations = resolve_policy_citations(&state.pool, body).await?;

    // REQ-G2 / REQ-G3 layer-2 autonomy floors. Only evaluated when the
    // caller asserted `actor_kind = 'autonomous_agent'` via
    // `autonomous_audit = Some(_)`. The default HTTP path
    // (`autonomous_audit = None` → `actor_kind = 'human'`) is unaffected.
    if autonomous_audit.is_some() {
        enforce_autonomy_floors(state, subject_id, body, &citations).await?;
    }

    let new_action = build_new_action(body, subject_id, ctx, autonomous_audit);

    // Single tx: action insert + per-citation inserts. Either both
    // commit or neither — REQ-B3 atomicity invariant.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(crate::repo::RepoError::from)?;
    let inserted = state.actions.insert_in_tx(&mut tx, new_action).await?;
    action_policy_citations::insert_for_action(&mut tx, inserted.id.0, &citations).await?;
    tx.commit().await.map_err(crate::repo::RepoError::from)?;

    instrument_and_emit(state, subject_id, &inserted, &body.reasoning).await?;
    Ok((StatusCode::CREATED, Json(inserted)))
}

/// Test-only handle on the autonomous-agent action-create path.
///
/// Drives the same cold-path validation + autonomy-floor + insert flow
/// as a wire HTTP submission but with an explicitly-provided LLM audit
/// envelope so the inserted row's `actor_kind = 'autonomous_agent'`
/// satisfies the migration-51 CHECK constraint. Used exclusively by
/// `tests/policy_human_required_never_autonomous.rs` to prove the
/// action-create layer of the REQ-G2 / REQ-G3 enforcement triple
/// rejects an autonomously-cited human-required policy (or an
/// autonomous account takedown) with the documented `403` shape.
///
/// **Do not call from production code.** The LLM dispatcher (LLM-5 /
/// #242) will land its own typed entry point once that work ships;
/// widening this surface in the meantime would re-introduce the
/// "external caller forges actor_kind" attack the
/// `submit_action`-via-HTTP path is structurally immune to.
///
/// # Errors
///
/// Returns the same [`ApiError`] variants as the HTTP cold path, plus
/// [`ApiError::PolicyAutonomyForbidden`] (REQ-G3) and
/// [`ApiError::AccountTakedownAutonomousForbidden`] (REQ-G2) for the
/// autonomy-specific rejections.
#[doc(hidden)]
pub async fn submit_action_autonomous_for_test(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    subject_id: SubjectId,
    body: &SubmitAction,
    audit: LlmAuditFields,
) -> Result<(StatusCode, Json<Action>), ApiError> {
    submit_action_inner(state, ctx, subject_id, body, Some(audit)).await
}

/// REQ-G2 / REQ-G3 layer-2 enforcement.
///
/// Runs only when the caller asserts `actor_kind = 'autonomous_agent'`
/// (i.e. an internal dispatcher path, never a wire HTTP submission;
/// see the doc-comment on [`submit_action_autonomous_for_test`]).
///
/// 1. REQ-G3: read every cited policy's *current* row via the
///    `policy_cache` (the same cache the citation snapshot itself
///    came from, so the read is in-process and warm). If any cited
///    policy carries `human_required_always = TRUE`, reject with
///    `403 policy_autonomy_forbidden` naming the offending identifier.
/// 2. REQ-G2: if the action's `kind = takedown` AND the subject's
///    `kind = 'account'`, reject with `403
///    account_takedown_autonomous_forbidden`. Account-level
///    takedowns are never autonomous.
///
/// The two checks are independent — both fire when both apply, with
/// REQ-G3 evaluated first because a policy-level rejection is the
/// stronger signal (the policy contract itself forbids autonomy)
/// while REQ-G2 is a subject-shape constraint applied on top.
async fn enforce_autonomy_floors(
    state: &ApiState,
    subject_id: SubjectId,
    body: &SubmitAction,
    citations: &[(String, i32)],
) -> Result<(), ApiError> {
    // REQ-G3: any cited human-required policy aborts the autonomous
    // emission. The cache hit shares the snapshot the citation
    // resolver just populated, so this is a microsecond-level
    // in-process lookup rather than a re-roundtrip to Postgres.
    for (identifier, _) in citations {
        let policy = policy_cache::get_current(&state.pool, identifier)
            .await
            .map_err(map_policy_lookup_err)?;
        // `Ok(None)` cannot occur here in practice: the citation set
        // was just resolved against the same pool moments ago. The
        // defensive branch returns the same `unknown_policy_ref` shape
        // the citation resolver would, so a hypothetical
        // delete-between-reads race surfaces the same wire code rather
        // than a 500.
        let Some(policy) = policy else {
            return Err(ApiError::UnknownPolicyRef {
                identifier: identifier.clone(),
            });
        };
        if policy.human_required_always {
            return Err(ApiError::PolicyAutonomyForbidden {
                identifier: identifier.clone(),
            });
        }
    }

    // REQ-G2: autonomous + takedown + account-kind subject → refuse.
    // The subject's kind is read fresh rather than carried in the
    // wire body so a caller cannot forge a non-account kind to slip
    // an account-level takedown past the floor.
    if matches!(body.kind, ActionKind::Takedown) {
        let subject = state
            .subjects
            .get(subject_id)
            .await?
            .ok_or(ApiError::NotFound)?;
        if matches!(subject.kind, polaris_types::SubjectKind::Account) {
            return Err(ApiError::AccountTakedownAutonomousForbidden);
        }
    }
    Ok(())
}

/// Per-report idempotent action insert (issue #202).
///
/// The transaction shape:
///   1. `SELECT … FOR UPDATE` on the `reports` row — row-locks
///      against concurrent clicks of the same Ack / Dismiss /
///      Escalate button.
///   2. If `actioned_at IS NOT NULL`, fetch the existing `actions`
///      row and return it. **No validation, no new insert, no emit.**
///      Idempotent.
///   3. Otherwise, validate the body (cold-path rules), insert the
///      new action via [`crate::repo::PgActionRepo::insert_in_tx`]
///      (so the evidence-job + reputation + audit-log side-effects
///      commit in the same tx), then UPDATE the report's
///      `actioned_at` / `actioned_by_action_id` columns.
///   4. Commit.
///
/// REQ-D2 / REQ-D3 instrumentation and the best-effort label-emit run
/// AFTER the commit, just as on the cold path.
async fn submit_action_with_report(
    state: &ApiState,
    ctx: &ModeratorAuthCtx,
    subject_id: SubjectId,
    report_id: ReportId,
    body: &SubmitAction,
) -> Result<(StatusCode, Json<Action>), ApiError> {
    // The signing-key gate runs BEFORE we open the row lock so a
    // mis-provisioned labeler does not hold the report row for the
    // duration of a precondition-failed response. The cold-path
    // ordering is preserved.
    if matches!(body.kind, ActionKind::Label | ActionKind::Takedown) {
        ensure_labeler_provisioned(state).await?;
    }

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(crate::repo::RepoError::from)?;

    // Row-lock against concurrent clicks. The partial index on
    // `(actioned_at) WHERE actioned_at IS NULL` (migration 45) does
    // not help here — the predicate inside the `SELECT` filters on
    // `id`, which uses the partitioned PK — but the lock is the
    // correctness property either way.
    let report = sqlx::query!(
        r#"
        SELECT id, actioned_at, actioned_by_action_id
        FROM reports
        WHERE id = $1
        FOR UPDATE
        "#,
        report_id.as_uuid(),
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(crate::repo::RepoError::from)?
    .ok_or(ApiError::NotFound)?;

    // Idempotent path: the report has already been actioned. Return
    // the stored action verbatim, no new insert, no validation.
    if report.actioned_at.is_some()
        && let Some(existing_action_id) = report.actioned_by_action_id
    {
        let existing = state
            .actions
            .get(ActionId(existing_action_id))
            .await?
            .ok_or_else(|| {
                // The FK has `ON DELETE SET NULL`, so this branch
                // only fires when the row was hard-deleted out from
                // under us — operator-side data repair. Surface as
                // 404 rather than papering over the inconsistency.
                ApiError::NotFound
            })?;
        tx.commit().await.map_err(crate::repo::RepoError::from)?;
        return Ok((StatusCode::OK, Json(existing)));
    }

    // Cold path inside the lock: validate, resolve citations, insert,
    // bind the action to the report, write citations, then commit.
    validate_submit_action_shape(body)?;

    // REQ-B3 policy lookup. Done inside the report lock so the cited
    // policies are resolved against the snapshot the moderator's UI
    // saw; the action insert + citation inserts ride the same
    // transaction so a partial citation is never visible.
    let citations = resolve_policy_citations(&state.pool, body).await?;

    // Per-report path is the cookie-driven moderator click path — the
    // wire body carries no `actor_kind`, so the row is always
    // `actor_kind = 'human'`. The autonomous-agent floors do not need
    // to run here; see [`submit_action_autonomous_for_test`] for the
    // narrow internal path that does carry an audit envelope.
    let new_action = build_new_action(body, subject_id, ctx, None);
    let inserted = state.actions.insert_in_tx(&mut tx, new_action).await?;

    sqlx::query!(
        r#"
        UPDATE reports
        SET actioned_at = now(),
            actioned_by_action_id = $1
        WHERE id = $2
        "#,
        inserted.id.0,
        report_id.as_uuid(),
    )
    .execute(&mut *tx)
    .await
    .map_err(crate::repo::RepoError::from)?;

    action_policy_citations::insert_for_action(&mut tx, inserted.id.0, &citations).await?;

    tx.commit().await.map_err(crate::repo::RepoError::from)?;

    instrument_and_emit(state, subject_id, &inserted, &body.reasoning).await?;
    Ok((StatusCode::CREATED, Json(inserted)))
}

/// Post-insert tracing + metrics + best-effort label emit. Shared by
/// the cold and idempotent paths so the observable side-effects of a
/// newly-recorded action are identical regardless of caller wire shape.
async fn instrument_and_emit(
    state: &ApiState,
    subject_id: SubjectId,
    inserted: &Action,
    reversal_reasoning: &str,
) -> Result<(), ApiError> {
    // REQ-D3: scope under a `submit_action` span carrying the
    // persisted action's UUID. The same UUID appears on the emitter's
    // `emit_label` span (via `#[instrument(...)]` on
    // `LabelEmitter::emit`) and on the broadcaster's
    // `broadcaster_publish` span.
    let span = tracing::info_span!(
        "submit_action",
        action_id = %inserted.id,
        kind = inserted.kind.as_str(),
        subject_id = %subject_id.0,
    );
    let _enter = span.enter();
    tracing::info!(
        action_id = %inserted.id,
        kind = inserted.kind.as_str(),
        "moderator action recorded",
    );

    // REQ-D2: bump `polaris_actions_total{kind}` once per accepted action.
    metrics::counter!(
        "polaris_actions_total",
        "kind" => inserted.kind.as_str().to_owned(),
    )
    .increment(1);

    // Best-effort label emission for kind=Label|Takedown. The action
    // is already committed; emit failures stay local.
    if matches!(inserted.kind, ActionKind::Label | ActionKind::Takedown)
        && let Some(emitter) = state.label_emitter.as_ref()
    {
        let subject_ref = build_subject_ref(state, subject_id).await?;
        let _ = emit_best_effort(emitter, inserted, &subject_ref, None).await;
    }

    // LLM-10 / #239 / REQ-G1: when a moderator reverses an autonomous
    // action, fan out a fire-and-forget `Feedback` RPC to the LLM
    // adapter so the operator's substrate can learn from the negative
    // signal. The check is gated on:
    //
    //   * `inserted.kind == Reverse` AND a target action id is set.
    //   * The dispatcher is configured (production wiring; tests that
    //     do not exercise the LLM pipeline pass `None` and skip).
    //   * The target action's `actor_kind = 'autonomous_agent'`.
    //
    // The dispatcher exposes a clone of its `ClassifierClient` so the
    // feedback delivery shares the same transport (and circuit
    // breaker) the recommend path uses — operator-configurable in
    // one place. See [`crate::llm::feedback::fire_reversal_feedback`].
    if matches!(inserted.kind, ActionKind::Reverse)
        && let Some(reversed_id) = inserted.reverses_action_id
        && let Some(dispatcher) = state.llm_dispatcher.as_ref()
    {
        let reversed_autonomous =
            is_action_autonomous(&state.pool, reversed_id.0)
                .await
                .unwrap_or(false);
        if reversed_autonomous {
            match crate::llm::feedback::load_feedback_context(
                &state.pool,
                reversed_id.0,
                ActionKind::Reverse,
            )
            .await
            {
                Ok(ctx) => {
                    crate::llm::feedback::fire_reversal_feedback(
                        dispatcher.classifier_client(),
                        "llm-autonomous".to_owned(),
                        ctx,
                        reversal_reasoning,
                    );
                }
                Err(err) => {
                    tracing::warn!(
                        action_id = %inserted.id,
                        reversed_id = %reversed_id.0,
                        error = %err,
                        "LLM reversal-feedback context load failed; reversal proceeded",
                    );
                }
            }
        }
    }

    Ok(())
}

/// SELECT `actor_kind = 'autonomous_agent'` for one action row.
///
/// Returns `Ok(true)` if the target was authored by the LLM
/// dispatcher, `Ok(false)` otherwise. Errors (row missing, SQL
/// failure) collapse to `Err` — the caller falls back to "not
/// autonomous" because skipping the feedback fan-out is preferable
/// to a 500 on the moderator's reversal path.
async fn is_action_autonomous(
    pool: &sqlx::PgPool,
    action_id: uuid::Uuid,
) -> Result<bool, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT actor_kind AS "actor_kind!"
        FROM actions
        WHERE id = $1
        "#,
        action_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.actor_kind == "autonomous_agent")
}

// ── 4. POST /api/bulk-actions ───────────────────────────────────────────
//
// Issue #193: multi-subject bulk apply. The moderator selects N subjects
// from the dashboard / search surface, fills in a single action body
// (kind / label / reasoning / policy refs), and the server records one
// `actions` row per subject — exactly the same shape as a single-subject
// submission, just N of them in one round-trip.

/// Hard cap on the number of subjects a single bulk-actions call accepts.
///
/// Above this threshold the operator must use the typed pattern-actions
/// surface (`POST /api/pattern-actions`) which carries the senior-cosign
/// invariant for batches of this scale (design.md §5.3). 50 is a
/// pragmatic limit: large enough to cover real moderator workflows
/// (clearing a queue of similar spam reports), small enough that one
/// person can still review the list before confirming.
const BULK_ACTIONS_MAX_SUBJECTS: usize = 50;

/// Wire body for `POST /api/bulk-actions`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BulkSubmitAction {
    /// Subject IDs to apply the action to. Length must be in
    /// `1..=BULK_ACTIONS_MAX_SUBJECTS`.
    pub subject_ids: Vec<SubjectId>,
    /// Body applied per-subject. The `incident_id` here is shared
    /// across all subjects in the batch — for a heterogeneous
    /// selection where subjects have different incidents, the caller
    /// must split into per-incident batches.
    pub body: crate::api::dto::SubmitAction,
}

/// Per-subject outcome of a bulk action. Mirrors Ozone's
/// `Promise.allSettled`-style "succeeded / failed" split so a UI
/// client can render a partial-success summary.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BulkActionOutcome {
    /// Subject IDs whose action was recorded.
    pub succeeded: Vec<SubjectId>,
    /// Subject IDs whose action failed, with a short reason per row.
    pub failed: Vec<BulkActionFailure>,
}

/// One entry of [`BulkActionOutcome::failed`]. Carries the subject
/// id whose insert failed plus a short operator-readable reason so
/// the UI can render a "5 succeeded, 2 failed: …" summary without
/// re-correlating against the request body.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct BulkActionFailure {
    /// Subject ID that failed.
    pub subject_id: SubjectId,
    /// Operator-readable failure cause (typed-error display string).
    pub reason: String,
}

/// `POST /api/bulk-actions` — apply a single `SubmitAction` body to
/// each subject in `subject_ids`. Per-subject failures are collected
/// rather than aborting the batch.
///
/// Per design.md §5.3, every affected subject still gets its own
/// `actions` row — there's no shared "bulk action" entity. Reversal
/// + audit therefore work the same as for single-subject actions.
///
/// # Errors
///
/// * `400 Bad Request` — empty `subject_ids`, batch above
///   [`BULK_ACTIONS_MAX_SUBJECTS`], or the embedded `body` fails the
///   same validation as `submit_action`.
/// * `412 Precondition Failed` — emit-shaped kind (Label / Takedown)
///   without a provisioned signing key.
pub async fn submit_bulk_action(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(body): Json<BulkSubmitAction>,
) -> Result<(StatusCode, Json<BulkActionOutcome>), ApiError> {
    if body.subject_ids.is_empty() {
        return Err(ApiError::BadRequest("subject_ids must be non-empty"));
    }
    if body.subject_ids.len() > BULK_ACTIONS_MAX_SUBJECTS {
        return Err(ApiError::BadRequest(
            "subject_ids exceeds bulk-actions limit; use pattern-actions for larger batches",
        ));
    }
    validate_submit_action_shape(&body.body)?;

    if matches!(body.body.kind, ActionKind::Label | ActionKind::Takedown) {
        ensure_labeler_provisioned(&state).await?;
    }

    // REQ-B3 citation snapshot — resolved once for the whole batch
    // because the body is identical per subject. If any cited
    // identifier is unknown / retired, the whole batch is rejected at
    // the edge with the typed error code; no actions are inserted.
    let citations = resolve_policy_citations(&state.pool, &body.body).await?;

    let mut succeeded: Vec<SubjectId> = Vec::with_capacity(body.subject_ids.len());
    let mut failed: Vec<BulkActionFailure> = Vec::new();
    let emit_eligible = matches!(body.body.kind, ActionKind::Label | ActionKind::Takedown);

    for subject_id in &body.subject_ids {
        // Bulk-action submissions ride the same cookie-authenticated
        // wire path as single-subject ones: human moderator, no LLM
        // audit envelope. The autonomous-agent floors do not apply
        // here for the same reason — bulk-actions cannot route
        // through the dispatcher.
        let new_action = build_new_action(&body.body, *subject_id, &ctx, None);
        match insert_action_with_citations(&state, new_action, &citations).await {
            Ok(inserted) => {
                metrics::counter!(
                    "polaris_actions_total",
                    "kind" => inserted.kind.as_str().to_owned(),
                )
                .increment(1);
                if emit_eligible && let Some(emitter) = state.label_emitter.as_ref() {
                    if let Ok(subject_ref) = build_subject_ref(&state, *subject_id).await {
                        let _ = emit_best_effort(emitter, &inserted, &subject_ref, None).await;
                    }
                }
                succeeded.push(*subject_id);
            }
            Err(err) => {
                tracing::warn!(
                    subject_id = %subject_id.0,
                    error = ?err,
                    "bulk-action: per-subject insert failed; recording in failed[]",
                );
                failed.push(BulkActionFailure {
                    subject_id: *subject_id,
                    reason: err.to_string(),
                });
            }
        }
    }

    tracing::info!(
        succeeded = succeeded.len(),
        failed = failed.len(),
        kind = body.body.kind.as_str(),
        "bulk-action complete",
    );

    Ok((
        StatusCode::OK,
        Json(BulkActionOutcome { succeeded, failed }),
    ))
}

/// Verify `polaris_setup_state.signing_pubkey_did IS NOT NULL`.
///
/// REQ-A3 gate: an emit-shaped action submitted before the setup
/// wizard has minted the labeler's signing key would either crash the
/// emitter (`StubSigner` refuses to sign) or quietly skip the broadcast.
/// Surfacing the missing-key state as `412` lets the wizard / UI
/// guide the operator to `/setup` before any moderation work is
/// recorded.
///
/// # Errors
///
/// - [`ApiError::PreconditionFailed`] with code
///   `labeler_not_provisioned` when the column is `NULL`.
/// - [`ApiError::Repo`] when the underlying SELECT fails (db loss,
///   schema drift). The repo error is upgraded by the existing
///   `From<RepoError>` chain.
async fn ensure_labeler_provisioned(state: &ApiState) -> Result<(), ApiError> {
    let row = sqlx::query!(r"SELECT signing_pubkey_did FROM polaris_setup_state WHERE id = TRUE",)
        .fetch_optional(&state.pool)
        .await
        .map_err(crate::repo::RepoError::from)?;
    let provisioned = row
        .and_then(|r| r.signing_pubkey_did)
        .is_some_and(|did| !did.is_empty());
    if provisioned {
        Ok(())
    } else {
        Err(ApiError::PreconditionFailed {
            code: "labeler_not_provisioned",
            message: "complete /setup before recording labelling actions",
        })
    }
}

/// Resolve the subject row into the emitter-facing [`SubjectRef`].
///
/// The subject is read after the action insert succeeds because (a) the
/// insert already verified the subject FK and (b) we want to read the
/// freshest row in case the action's effect on `risk_signals` matters
/// downstream (it currently doesn't, but the shape stays consistent with
/// other read-after-write paths in this handler).
async fn build_subject_ref(
    state: &ApiState,
    subject_id: SubjectId,
) -> Result<SubjectRef, ApiError> {
    let subject = state
        .subjects
        .get(subject_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(SubjectRef {
        did: subject.did.map(|d| d.as_str().to_owned()),
        uri: subject.uri.map(|u| u.as_str().to_owned()),
        // The Polaris Subject row does not carry a content-CID column
        // today; record-CID pinning is a future revision (filed as a
        // follow-up per the architect's note on the original issue).
        cid: None,
    })
}

/// Helper: shape-only payload validation for [`SubmitAction`]. The
/// policy-existence / retirement check moved to
/// [`resolve_policy_citations`] (WB-2 / #224) so the bare-shape rules
/// here stay synchronous and reusable from tests that do not exercise
/// the DB.
fn validate_submit_action_shape(body: &SubmitAction) -> Result<(), ApiError> {
    if body.reasoning.len() < 10 {
        return Err(ApiError::BadRequest(
            "reasoning must be at least 10 characters",
        ));
    }
    if body.policy_refs.is_empty() {
        return Err(ApiError::BadRequest("policy_refs must be non-empty"));
    }
    Ok(())
}

/// Resolve every cited policy identifier in `body.policy_refs` against
/// the workbook (`mod_policies` via [`policy_cache::get_current`]) and
/// snapshot the `(identifier, version)` pair for the citation insert
/// (REQ-B3).
///
/// Returns the snapshot vec in the same order as `body.policy_refs`.
/// On any unknown or retired identifier returns the typed `ApiError`
/// variant the action-create handler maps to a `400 Bad Request` body
/// with the documented `code` shape.
async fn resolve_policy_citations(
    pool: &sqlx::PgPool,
    body: &SubmitAction,
) -> Result<Vec<(String, i32)>, ApiError> {
    let mut snapshots: Vec<(String, i32)> = Vec::with_capacity(body.policy_refs.len());
    for r in &body.policy_refs {
        let identifier = r.as_str();
        let resolved = policy_cache::get_current(pool, identifier)
            .await
            .map_err(map_policy_lookup_err)?;
        let Some(policy) = resolved else {
            return Err(ApiError::UnknownPolicyRef {
                identifier: identifier.to_owned(),
            });
        };
        if policy.is_retired {
            // REQ-F1: a retired policy carries `is_retired = TRUE` on
            // its current row; surface as `policy_retired` with the
            // tombstone's `effective_from` (the moment the retirement
            // version was written).
            return Err(ApiError::PolicyRetired {
                identifier: identifier.to_owned(),
                retired_at: policy.effective_from,
            });
        }
        snapshots.push((policy.identifier, policy.version));
    }
    Ok(snapshots)
}

/// Helper: open a tx, insert the action and its citations, commit.
/// Shared by the bulk-action path so the per-subject single-tx
/// atomicity invariant matches the cold + report paths.
async fn insert_action_with_citations(
    state: &ApiState,
    new_action: RepoNewAction,
    citations: &[(String, i32)],
) -> Result<Action, ApiError> {
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(crate::repo::RepoError::from)?;
    let inserted = state.actions.insert_in_tx(&mut tx, new_action).await?;
    action_policy_citations::insert_for_action(&mut tx, inserted.id.0, citations).await?;
    tx.commit().await.map_err(crate::repo::RepoError::from)?;
    Ok(inserted)
}

/// Translate a [`ModPolicyError`] from `policy_cache::get_current` into
/// an [`ApiError`]. The lookup path can only realistically yield the
/// `Database` variant (the typed `Unknown` / `Retired` variants are
/// the repo's *write*-time surface; reads return `Ok(None)` or `Ok(Some(_))`).
/// Map the remainder defensively so a future variant change does not
/// silently produce a 500.
fn map_policy_lookup_err(err: ModPolicyError) -> ApiError {
    match err {
        ModPolicyError::UnknownIdentifier { identifier } => {
            ApiError::UnknownPolicyRef { identifier }
        }
        ModPolicyError::RetiredPolicy {
            identifier,
            retired_at,
        } => ApiError::PolicyRetired {
            identifier,
            retired_at,
        },
        ModPolicyError::Database(e) => ApiError::Repo(crate::repo::RepoError::from(e)),
        ModPolicyError::StaleVersion { .. } | ModPolicyError::ConcurrentEdit { .. } => {
            // These variants are write-path failure modes from `amend`;
            // reaching them on a `current_by_identifier` read would
            // indicate a contract change. Surface as a 500 with a
            // descriptive log line so the regression is easy to spot.
            tracing::error!(error = ?err, "policy lookup yielded a write-path error");
            ApiError::Internal(anyhow::anyhow!("policy lookup returned write-path error"))
        }
    }
}

/// Helper: translate the wire DTO into a repo-level `NewAction`. The
/// moderator id comes from `ctx`, NOT from the request body — that is the
/// AC-7 attribution contract.
///
/// `llm_audit` is `Some(_)` only for the autonomous-agent test-only
/// path ([`submit_action_autonomous_for_test`]); every wire HTTP call
/// passes `None`, producing a row with `actor_kind = 'human'` and the
/// LLM audit columns NULL (the migration-51 backward-compat shape).
fn build_new_action(
    body: &SubmitAction,
    subject_id: SubjectId,
    ctx: &ModeratorAuthCtx,
    llm_audit: Option<LlmAuditFields>,
) -> RepoNewAction {
    // `polaris_types::NewAction` and `repo::NewAction` are structurally
    // identical; we go through the typed conversion to keep the two crates'
    // shapes free to diverge without touching this handler.
    let typed = TypesNewAction {
        incident_id: body.incident_id,
        subject_id,
        moderator_id: polaris_types::ModeratorId(ctx.moderator_id.0),
        kind: body.kind,
        label: body.label.clone(),
        reasoning: body.reasoning.clone(),
        policy_refs: body.policy_refs.clone(),
        reversible_until: body.reversible_until,
        reverses_action_id: body.reverses_action_id,
    };
    RepoNewAction {
        incident_id: typed.incident_id,
        subject_id: typed.subject_id,
        moderator_id: typed.moderator_id,
        kind: typed.kind,
        label: typed.label,
        reasoning: typed.reasoning,
        policy_refs: typed.policy_refs,
        reversible_until: typed.reversible_until,
        reverses_action_id: typed.reverses_action_id,
        llm_audit,
    }
}

// ── 4. POST /api/cases/:incident_id/escalate ────────────────────────────

/// Handler: flip the incident's status to [`IncidentStatus::Escalated`].
pub async fn escalate_incident(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(incident_id): Path<IncidentId>,
    Json(body): Json<Escalate>,
) -> Result<Json<Incident>, ApiError> {
    validate_escalate(&body)?;
    let updated = state
        .incidents
        .update_status(incident_id, IncidentStatus::Escalated)
        .await?;
    Ok(Json(updated))
}

/// Helper: payload validation for [`Escalate`].
fn validate_escalate(body: &Escalate) -> Result<(), ApiError> {
    if body.reasoning.len() < 10 {
        return Err(ApiError::BadRequest(
            "reasoning must be at least 10 characters",
        ));
    }
    Ok(())
}

// Keep `Arc` reachable in this module so the `ApiState` re-export stays
// satisfied even after a future refactor strips an unused import; the type
// appears in `ApiState`'s field types but the `use` is brought in through
// `crate::api::state`. The empty function below is a compile-time anchor.
#[allow(dead_code)]
fn _arc_anchor<T>(_: Arc<T>) {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use chrono::Utc;
    use polaris_types::{ActionKind, IncidentId, LabelValue, PolicyId};

    fn ctx() -> ModeratorAuthCtx {
        ModeratorAuthCtx::new(
            crate::auth::ModeratorId::new_v4(),
            std::collections::HashSet::new(),
        )
    }

    fn good_body() -> SubmitAction {
        SubmitAction {
            incident_id: IncidentId::new(),
            kind: ActionKind::Label,
            label: Some(LabelValue::new("spam")),
            reasoning: "This is sufficiently long reasoning text.".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            // Issue #202: cold-path body. The idempotent path is
            // exercised by the integration test in
            // `tests/report_action_idempotency.rs`.
            report_id: None,
        }
    }

    #[test]
    fn validate_submit_action_shape_accepts_valid_body() {
        validate_submit_action_shape(&good_body()).expect("valid body should pass");
    }

    #[test]
    fn validate_submit_action_shape_rejects_short_reasoning() {
        let mut b = good_body();
        b.reasoning = "tooshort".to_owned();
        let err = validate_submit_action_shape(&b).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("reasoning")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn validate_submit_action_shape_rejects_empty_policy_refs() {
        let mut b = good_body();
        b.policy_refs = vec![];
        let err = validate_submit_action_shape(&b).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("policy_refs")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }
    // Note: The previous `validate_submit_action_rejects_unknown_policy_ref`
    // unit test was retired with the WB-2 rewrite. Unknown-identifier
    // rejection now requires a `mod_policies` lookup against a live DB,
    // so the equivalent coverage moved into the integration suite at
    // `tests/policy_version_pinning.rs::action_with_unknown_identifier_returns_400`
    // and the existing `tests/case_api.rs` regression test (REQ-B3 /
    // AC-3).

    #[test]
    fn build_new_action_uses_session_moderator_id_not_request() {
        // Compile-time + run-time check: there is no path for the request to
        // forge a moderator_id, because the field is not in `SubmitAction`.
        let body = good_body();
        let session_ctx = ctx();
        let new = build_new_action(&body, SubjectId::new(), &session_ctx, None);
        assert_eq!(new.moderator_id.0, session_ctx.moderator_id.0);
        // Round-trip the human default: no audit envelope means
        // `actor_kind` will land as `'human'` at the DB boundary
        // (the repo selects the column literal from
        // `new.llm_audit.is_some()`).
        assert!(new.llm_audit.is_none());
    }

    #[test]
    fn validate_escalate_rejects_short_reasoning() {
        let err = validate_escalate(&Escalate {
            reasoning: "short".to_owned(),
        })
        .unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("reasoning")),
            _ => panic!("expected BadRequest"),
        }
    }
}
