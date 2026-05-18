//! `POST /api/cases/:incident_id/llm-recommendation`
//! (`.design/llm-moderation-assist.md` REQ-C2 "Pull" trigger; issue
//! #242 / LLM-5).
//!
//! Moderator-initiated request for a fresh LLM recommendation against
//! a specific case. The handler is a thin wrapper around
//! [`crate::llm::recommend_dispatcher::RecommendDispatcher::dispatch_case`]
//! with the [`DispatchTrigger::Pull`] variant — debounce + queue-depth
//! gates are bypassed (a moderator clicked the button; they own the
//! rate).
//!
//! # RBAC
//!
//! Any authenticated moderator may request a recommendation; the
//! dispatcher enforces autonomy at evaluation time. The middleware
//! has already validated the session cookie before this handler runs.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use polaris_types::IncidentId;
use serde::Serialize;
use uuid::Uuid;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;
use crate::llm::recommend_dispatcher::{
    DispatchError, DispatchOutcome, DispatchTrigger, SkipReason,
};

/// Wire DTO for `POST /api/cases/:incident_id/llm-recommendation`.
///
/// The serialised shape distinguishes the four outcomes the
/// dispatcher can produce so the case-view client can render
/// appropriate UI without re-deriving state from the action / draft
/// tables.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum DispatchOutcomeDto {
    /// LLM recommendation persisted; no draft or action.
    Advisory {
        /// Observation row id.
        observation_id: Uuid,
    },
    /// Assisted-mode draft inserted into `pending_auto_actions`.
    AssistedDraft {
        /// First inserted draft id (multi-action responses produce
        /// additional drafts reachable via the observation).
        draft_id: Uuid,
        /// Backing observation row id.
        observation_id: Uuid,
    },
    /// Autonomous-mode action emitted to atproto.
    AutonomousAction {
        /// The action row inserted by the dispatcher.
        action_id: Uuid,
        /// Backing observation row id.
        observation_id: Uuid,
    },
    /// No work happened. `reason` describes which gate tripped.
    Skipped {
        /// Operator-readable rationale (debounce, queue ceiling, no
        /// autonomy enabled, …).
        reason: String,
    },
}

impl From<DispatchOutcome> for DispatchOutcomeDto {
    fn from(outcome: DispatchOutcome) -> Self {
        match outcome {
            DispatchOutcome::Advisory { observation_id } => Self::Advisory {
                observation_id: observation_id.0,
            },
            DispatchOutcome::AssistedDraft {
                draft_id,
                observation_id,
            } => Self::AssistedDraft {
                draft_id,
                observation_id: observation_id.0,
            },
            DispatchOutcome::AutonomousAction {
                action_id,
                observation_id,
            } => Self::AutonomousAction {
                action_id: action_id.0,
                observation_id: observation_id.0,
            },
            DispatchOutcome::Skipped { reason } => Self::Skipped {
                reason: skip_reason_label(&reason).to_owned(),
            },
        }
    }
}

/// Stable wire string for a [`SkipReason`]. Frontends match on this.
fn skip_reason_label(reason: &SkipReason) -> &'static str {
    match reason {
        SkipReason::DebounceHit { .. } => "debounce_hit",
        SkipReason::QueueDepthExceeded { .. } => "queue_depth_exceeded",
        SkipReason::NoAutonomyEnabled => "no_autonomy_enabled",
    }
}

/// Translate a [`DispatchError`] into the typed [`ApiError`] the
/// rest of `/api` surfaces.
fn map_dispatch_err(err: DispatchError) -> ApiError {
    use crate::llm::case_context::HydrateError;
    match err {
        DispatchError::Hydrate(
            HydrateError::IncidentNotFound(_) | HydrateError::SubjectNotFound(_),
        ) => ApiError::NotFound,
        DispatchError::Hydrate(HydrateError::NoCoveringPolicies { kind: _ }) => {
            // The LLM cannot ground without policies — surface a
            // 412 precondition so the operator knows to populate
            // the workbook first.
            ApiError::PreconditionFailed {
                code: "no_covering_policies",
                message: "no mod_policies row covers the subject's kind; \
                          populate the workbook before requesting a recommendation",
            }
        }
        DispatchError::Hydrate(
            HydrateError::Database(e)
            | HydrateError::PolicyRepo(crate::repo::mod_policies::ModPolicyError::Database(e)),
        ) => ApiError::Repo(crate::repo::RepoError::from(e)),
        DispatchError::Hydrate(HydrateError::PolicyRepo(other)) => {
            tracing::error!(error = ?other, "llm dispatcher: unexpected policy-repo error during hydrate");
            ApiError::Internal(anyhow::Error::new(other))
        }
        DispatchError::Classifier(e) => {
            tracing::warn!(error = ?e, "llm dispatcher: classifier RPC failed");
            ApiError::BadGateway("classifier recommend RPC failed")
        }
        DispatchError::Repo(e) => ApiError::Repo(e),
        DispatchError::Emitter(e) => {
            // Emitter failures during the autonomous emit path are
            // logged best-effort inside the dispatcher; reaching
            // this arm means the caller asked for an emit that the
            // dispatcher could not satisfy. Surface as 500 —
            // the action was already recorded.
            tracing::error!(error = ?e, "llm dispatcher: label emitter refused autonomous action");
            ApiError::Internal(anyhow::Error::new(e))
        }
        DispatchError::UnknownCitedPolicy { identifier } => ApiError::BadRequest(
            // The identifier is a classifier contract violation, not
            // moderator input — log the identifier but surface the
            // canonical static message the typed variant uses.
            {
                tracing::warn!(identifier = %identifier, "llm dispatcher: adapter hallucinated policy identifier");
                "classifier returned a hallucinated policy identifier"
            },
        ),
        DispatchError::UnknownActionKind { kind } => {
            tracing::warn!(kind = %kind, "llm dispatcher: adapter returned unknown action_kind");
            ApiError::BadRequest("classifier returned an unknown action_kind")
        }
    }
}

/// Handler for `POST /api/cases/:incident_id/llm-recommendation`.
///
/// # Errors
///
/// * `404 Not Found` — incident or its subject is missing.
/// * `412 Precondition Failed` — no covering policies for the
///   subject's kind.
/// * `502 Bad Gateway` — classifier RPC failed (timeout, transport,
///   circuit-open).
/// * `503 Service Unavailable` — dispatcher not configured on the
///   server (production wiring installs it; tests that don't exercise
///   the LLM pipeline leave the slot `None`).
/// * `500 Internal Server Error` — repo / emitter / classifier
///   contract failures the dispatcher could not classify.
pub async fn request_recommendation(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    Path(incident_id): Path<IncidentId>,
) -> Result<(StatusCode, Json<DispatchOutcomeDto>), ApiError> {
    let dispatcher = state
        .llm_dispatcher
        .as_ref()
        .ok_or(ApiError::PreconditionFailed {
            code: "llm_dispatcher_not_configured",
            message: "LLM moderation-assist subsystem is not configured on this deployment",
        })?;
    let outcome = dispatcher
        .dispatch_case(incident_id.0, DispatchTrigger::Pull)
        .await
        .map_err(map_dispatch_err)?;
    Ok((StatusCode::OK, Json(DispatchOutcomeDto::from(outcome))))
}
