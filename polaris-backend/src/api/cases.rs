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
    Action, ActionKind, Incident, IncidentId, IncidentStatus, NewAction as TypesNewAction,
    SubjectId,
};

use crate::api::dto::{
    CaseView, Escalate, IncidentList, IncidentListQuery, IncidentSummary, ReporterContext,
    SubmitAction,
};
use crate::api::error::ApiError;
use crate::api::policy;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;
use crate::labeler::emitter::{SubjectRef, emit_best_effort};
use crate::repo::{
    ActionRepo, IncidentRepo, NewAction as RepoNewAction, ObservationRepo, ReportRepo, SubjectRepo,
};

/// Hard upper bound on the per-call row count returned by list-style repo
/// methods. The case view fetches "everything for this subject"; a bounded
/// `LIMIT` keeps a pathological case (10k actions on one subject) from
/// blowing past the response budget. M2 will introduce pagination.
const MAX_ROWS_PER_LIST: i64 = 256;

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
    Ok(CaseView {
        subject,
        history,
        reports,
        reporter_contexts,
        observations,
        network_context: serde_json::Value::Null,
    })
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

/// Helper: gather every [`Action`] across every incident attached to the
/// subject. M2 will introduce a dedicated `ActionRepo::list_by_subject`
/// query; for #14 we walk incidents-by-subject → actions-by-incident.
async fn list_history_for_subject(
    state: &ApiState,
    subject_id: SubjectId,
) -> Result<Vec<Action>, ApiError> {
    let all_incidents = state
        .incidents
        .list_by_status(None, MAX_ROWS_PER_LIST)
        .await?;
    let mut history = Vec::new();
    for incident in all_incidents
        .into_iter()
        .filter(|i| i.primary_subject == subject_id)
    {
        let mut actions = state
            .actions
            .list_by_incident(incident.id, MAX_ROWS_PER_LIST)
            .await?;
        history.append(&mut actions);
    }
    Ok(history)
}

// ── 2. GET /api/cases?status=open ───────────────────────────────────────

/// Handler: slim incident list (queue-fallback projection).
pub async fn list_cases(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Query(query): Query<IncidentListQuery>,
) -> Result<Json<IncidentList>, ApiError> {
    let incidents = state
        .incidents
        .list_by_status(query.status, MAX_ROWS_PER_LIST)
        .await?;
    let summaries: Vec<IncidentSummary> = incidents
        .iter()
        .map(IncidentSummary::from_incident)
        .collect();
    let total = summaries.len() as u64;
    Ok(Json(IncidentList {
        incidents: summaries,
        total,
    }))
}

// ── 3. POST /api/cases/:subject_id/actions ──────────────────────────────

/// Handler: submit a new action against the subject.
pub async fn submit_action(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Path(subject_id): Path<SubjectId>,
    Json(body): Json<SubmitAction>,
) -> Result<(StatusCode, Json<Action>), ApiError> {
    validate_submit_action(&body)?;
    let new_action = build_new_action(&body, subject_id, &ctx);
    let inserted = state.actions.insert(new_action).await?;

    // Best-effort label emission for kind=Label|Takedown. The action is
    // already committed; emit failures stay local (logged + recoverable
    // via re-emit job per #63) so the moderator's submission always
    // returns 201 on a successful insert. The emit happens BEFORE the
    // response goes out so the `subscribeLabels` fan-out is observable
    // by the time the HTTP client knows the request succeeded, but the
    // response shape does not depend on emit success.
    if matches!(inserted.kind, ActionKind::Label | ActionKind::Takedown)
        && let Some(emitter) = state.label_emitter.as_ref()
    {
        let subject_ref = build_subject_ref(&state, subject_id).await?;
        let _ = emit_best_effort(emitter, &inserted, &subject_ref, None).await;
    }

    Ok((StatusCode::CREATED, Json(inserted)))
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

/// Helper: payload validation for [`SubmitAction`]. Returns the first
/// rule failure as an [`ApiError::BadRequest`] with a static message.
fn validate_submit_action(body: &SubmitAction) -> Result<(), ApiError> {
    if body.reasoning.len() < 10 {
        return Err(ApiError::BadRequest(
            "reasoning must be at least 10 characters",
        ));
    }
    if body.policy_refs.is_empty() {
        return Err(ApiError::BadRequest("policy_refs must be non-empty"));
    }
    for r in &body.policy_refs {
        if !policy::is_known_policy_ref(r.as_str()) {
            return Err(ApiError::BadRequest(
                "policy_refs contains an unknown policy id",
            ));
        }
    }
    Ok(())
}

/// Helper: translate the wire DTO into a repo-level `NewAction`. The
/// moderator id comes from `ctx`, NOT from the request body — that is the
/// AC-7 attribution contract.
fn build_new_action(
    body: &SubmitAction,
    subject_id: SubjectId,
    ctx: &ModeratorAuthCtx,
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
        }
    }

    #[test]
    fn validate_submit_action_accepts_valid_body() {
        validate_submit_action(&good_body()).expect("valid body should pass");
    }

    #[test]
    fn validate_submit_action_rejects_short_reasoning() {
        let mut b = good_body();
        b.reasoning = "tooshort".to_owned();
        let err = validate_submit_action(&b).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("reasoning")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn validate_submit_action_rejects_empty_policy_refs() {
        let mut b = good_body();
        b.policy_refs = vec![];
        let err = validate_submit_action(&b).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("policy_refs")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn validate_submit_action_rejects_unknown_policy_ref() {
        let mut b = good_body();
        b.policy_refs = vec![PolicyId::new("unknown.policy")];
        let err = validate_submit_action(&b).unwrap_err();
        match err {
            ApiError::BadRequest(msg) => assert!(msg.contains("unknown")),
            _ => panic!("expected BadRequest, got {err:?}"),
        }
    }

    #[test]
    fn build_new_action_uses_session_moderator_id_not_request() {
        // Compile-time + run-time check: there is no path for the request to
        // forge a moderator_id, because the field is not in `SubmitAction`.
        let body = good_body();
        let session_ctx = ctx();
        let new = build_new_action(&body, SubjectId::new(), &session_ctx);
        assert_eq!(new.moderator_id.0, session_ctx.moderator_id.0);
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
