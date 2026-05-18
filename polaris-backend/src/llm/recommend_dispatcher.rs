//! LLM recommendation dispatcher state machine
//! (`.design/llm-moderation-assist.md` REQ-C1..C4; AC-7; issue #242).
//!
//! Single public entry point [`RecommendDispatcher::dispatch_case`]
//! orchestrates the full per-case pipeline:
//!
//! 1. **Trigger gates** — per-subject debounce + queue-depth ceiling
//!    on `Push`, bypassed for `Pull` / `Replay` (Q4 in the design's
//!    resolved decisions).
//! 2. **Hydrate** via [`crate::llm::case_context::hydrate`] (LLM-4 /
//!    #234 — already shipped).
//! 3. **Autonomy short-circuit** — if no covering policy is in mode
//!    `{assisted, autonomous}`, return `Skipped { NoAutonomyEnabled }`
//!    without an LLM call.
//! 4. **`ClassifierClient::recommend`** (LLM-2 / #232 — already
//!    shipped). The same per-classifier semaphore + circuit breaker
//!    the production `Classify` path uses (REQ-A4).
//! 5. **Persist** the response as an `LlmRecommendation` observation
//!    (LLM-3 / #233 — already shipped). The full response payload
//!    lives in `evidence` JSONB plus the request content-hash for
//!    replay determinism (REQ-B2).
//! 6. **Route per `RecommendedAction`** through [`safety_floors::evaluate`]:
//!    - [`EffectiveMode::Manual`] → done, observation is the
//!      deliverable.
//!    - [`EffectiveMode::Assisted`] → insert a `pending_auto_actions`
//!      row carrying the recommended-action payload + observation
//!      pointer + cited-version snapshots (REQ-E1).
//!    - [`EffectiveMode::Autonomous`] → create the action with
//!      `actor_kind = 'autonomous_agent'` and the full
//!      [`LlmAuditFields`] envelope (REQ-F1), then emit to atproto
//!      via the existing labeler emitter (REQ-C3).
//!
//! Safety floors (REQ-S1..S8) are owned by issue **#235** (LLM-6).
//! The dispatcher calls [`safety_floors::evaluate`] which is a stub
//! today (always `Autonomous`); the real implementation lands when
//! #235 ships. The integration seam is here in this file so the
//! #235 contributor only has to flesh out
//! `polaris-backend/src/llm/safety_floors.rs`.
//!
//! # Privacy floor (REQ-A2)
//!
//! The dispatcher never invents a moderator identity. Autonomous-mode
//! `actions` rows carry a sentinel `moderator_id` resolved at
//! startup so the audit trail can join back through the existing
//! `actions.moderator_id` FK without disturbing the schema. Today
//! that sentinel is the autonomous-agent moderator row seeded by
//! the workbook bootstrap (`autonomous-agent@polaris.local`); see
//! [`RecommendDispatcher::with_autonomous_actor`] for the binary-
//! wiring entry point.
//!
//! # Tracing (REQ-C4)
//!
//! Every call to [`RecommendDispatcher::dispatch_case`] is wrapped in
//! a `tracing::info_span!` carrying:
//!
//! - `case_id` (the incident UUID).
//! - `trigger` (Pull / Push / Replay).
//! - `subject_did`.
//! - For each routed recommended-action: `policy_identifier`,
//!   `recommended_kind`, `confidence`, `final_mode_applied`.
//!
//! The existing `OTel` exporter picks up the span without further
//! plumbing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use polaris_classifier_proto::v1::{
    PolicyClause, RecommendRequest, RecommendResponse, RecommendedAction,
};
use polaris_types::{
    ActionKind, IncidentId, LabelValue, ModeratorId, NewObservation, ObservationId,
    ObservationKind, PolicyId, SubjectId,
};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::RwLock;
use tracing::Instrument as _;
use uuid::Uuid;

use crate::classifier::{ClassifierClient, ClassifierError};
use crate::labeler::emitter::{EmitterError, LabelEmitter, SubjectRef};
use crate::llm::case_context::{self, HydrateError};
use crate::llm::safety_floors::{self, EffectiveMode};
use crate::repo::action::{LlmAuditFields, NewAction};
use crate::repo::{ActionRepo, ObservationRepo, PgActionRepo, PgObservationRepo};

/// Sampling cadence for the
/// `polaris_llm_assisted_queue_depth{policy}` gauge (REQ-I1).
///
/// 30s matches the resolution operators run their Grafana dashboards
/// at; sampling more often would only buy noise (the queue moves
/// per-moderator-action, not per-second). The sampler is spawned by
/// the binary entrypoint via [`spawn_assisted_queue_depth_sampler`].
pub const ASSISTED_QUEUE_DEPTH_SAMPLE_INTERVAL: Duration = Duration::from_secs(30);

/// Spawn the `polaris_llm_assisted_queue_depth{policy}` gauge sampler
/// (REQ-I1).
///
/// Runs forever on the supplied [`tokio::runtime::Handle`] (or the
/// ambient runtime if called from a task), polling `pending_auto_actions`
/// every [`ASSISTED_QUEUE_DEPTH_SAMPLE_INTERVAL`] and updating one
/// gauge series per policy that currently has pending rows. Series for
/// policies that drain to zero are NOT emitted on the next tick — the
/// `metrics` recorder keeps the last sample until a new one arrives,
/// which is the standard Prometheus convention for gauges (the absent
/// sample reads as "stale"; the operator's alerting layer treats a
/// stale series the same as a zero).
///
/// The sampler reads the pending count grouped by the citation's
/// `policy_identifier` (the first cited policy from the JSONB payload
/// — multi-policy drafts surface against their lead policy). A query
/// failure logs at `tracing::warn!` and the loop continues; the
/// sampler never panics.
///
/// # Panics
///
/// Spawn-side function; the spawn itself panics only if called outside
/// a tokio runtime (the normal main-entrypoint shape). The loop body
/// does not panic.
#[must_use = "the spawned sampler will keep ticking even if its handle is dropped, \
              but tests and shutdown paths usually want to await it for clean teardown"]
pub fn spawn_assisted_queue_depth_sampler(pool: sqlx::PgPool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(ASSISTED_QUEUE_DEPTH_SAMPLE_INTERVAL);
        // Drop the first tick — `interval` fires immediately on
        // construction which would race a fresh deployment's
        // migrations. The 30s spacing kicks in from the second tick.
        tick.tick().await;
        loop {
            tick.tick().await;
            match sample_assisted_queue_depth(&pool).await {
                Ok(()) => {}
                Err(err) => tracing::warn!(
                    error = ?err,
                    "llm assisted-queue-depth sampler: query failed; will retry on next tick",
                ),
            }
        }
    })
}

/// Single sampling pass for [`spawn_assisted_queue_depth_sampler`].
/// Public so the integration tests can drive a tick without spawning
/// the loop.
///
/// # Errors
///
/// [`sqlx::Error`] on any DB failure.
pub async fn sample_assisted_queue_depth(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT
            (recommended_action->>'cited_policy_identifiers')::JSONB->>0 AS "policy?",
            COUNT(*) AS "count!"
        FROM pending_auto_actions
        WHERE state = 'pending'
        GROUP BY 1
        "#,
    )
    .fetch_all(pool)
    .await?;

    for row in rows {
        let policy = row.policy.unwrap_or_else(|| "<unknown>".to_owned());
        #[allow(
            clippy::cast_precision_loss,
            reason = "queue depth is bounded by the design's queue-ceiling (default 500); the f64 cast never loses precision in practice"
        )]
        let depth = row.count as f64;
        metrics::gauge!(
            "polaris_llm_assisted_queue_depth",
            "policy" => policy,
        )
        .set(depth);
    }
    Ok(())
}

/// Default per-subject debounce window for `Push` triggers (REQ-C2 / Q4).
///
/// Within this window a second `Push` on the same `subject_did` is
/// dropped. `Pull` and `Replay` bypass the debounce.
pub const DEFAULT_PUSH_DEBOUNCE: Duration = Duration::from_secs(15 * 60);

/// Default `pending_auto_actions` queue-depth ceiling for `Push`
/// triggers (REQ-C2 / Q4).
///
/// Once the queue has this many `state = 'pending'` rows, new `Push`
/// triggers return [`SkipReason::QueueDepthExceeded`] until the queue
/// drains below the ceiling.
pub const DEFAULT_QUEUE_DEPTH_CEILING: i64 = 500;

/// What set the dispatcher in motion (REQ-C2).
#[derive(Debug, Clone, Copy)]
pub enum DispatchTrigger {
    /// Moderator opened the case in the dashboard
    /// (`POST /api/cases/:case_id/llm-recommendation`).
    Pull,
    /// Background ingest noticed a new report on a covered subject.
    /// Subject-level debounce + queue-depth ceiling apply (REQ-C2 /
    /// Q4 in the design's resolved decisions).
    Push,
    /// Admin replay job for calibration (LLM-11 #240). Bypasses the
    /// debounce + queue-depth gates because the operator is the one
    /// driving the rate.
    Replay,
}

impl DispatchTrigger {
    /// Wire form used in the dispatcher's tracing span.
    fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
            Self::Replay => "replay",
        }
    }
}

/// Outcome of a single [`RecommendDispatcher::dispatch_case`] call.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// LLM recommendation persisted as an observation only. Either
    /// the policy is in `manual` mode, the safety floors downgraded
    /// every recommended action to manual, or the response had no
    /// recommended actions.
    Advisory {
        /// The persisted `LlmRecommendation` observation id.
        observation_id: ObservationId,
    },
    /// At least one recommended action landed as a `pending_auto_actions`
    /// draft.
    AssistedDraft {
        /// The first inserted draft id (multiple drafts may exist for
        /// a multi-action response — the dispatcher only echoes the
        /// first here; the rest are reachable via the observation).
        draft_id: Uuid,
        /// The persisted `LlmRecommendation` observation id.
        observation_id: ObservationId,
    },
    /// At least one recommended action fired autonomously and reached
    /// atproto.
    AutonomousAction {
        /// The action row inserted by the dispatcher.
        action_id: polaris_types::ActionId,
        /// The persisted `LlmRecommendation` observation id.
        observation_id: ObservationId,
    },
    /// The dispatcher short-circuited before doing any work — no
    /// observation, no action, no draft.
    Skipped {
        /// Why the case was skipped.
        reason: SkipReason,
    },
}

/// Why [`RecommendDispatcher::dispatch_case`] returned a
/// [`DispatchOutcome::Skipped`].
#[derive(Debug, Clone)]
pub enum SkipReason {
    /// Push trigger: the same `subject_did` was dispatched < 15 min
    /// ago. The `retry_after` is the remaining time on the debounce.
    DebounceHit {
        /// Subject DID that was debounced.
        subject_did: String,
        /// Time until the debounce expires for this subject.
        retry_after: Duration,
    },
    /// Push trigger: the `pending_auto_actions` queue has ≥ the
    /// configured ceiling of `state = 'pending'` rows. Wait for the
    /// moderators to drain it before dispatching new pushes.
    QueueDepthExceeded {
        /// Observed depth at the moment the dispatcher checked.
        depth: i64,
        /// The configured ceiling (default
        /// [`DEFAULT_QUEUE_DEPTH_CEILING`]).
        ceiling: i64,
    },
    /// No covering policy is in mode `{assisted, autonomous}`, so an
    /// LLM call would only produce an advisory the case-view already
    /// shows. The dispatcher short-circuits without calling the
    /// classifier — saves the operator's LLM-budget for cases where
    /// autonomy is actually configured.
    NoAutonomyEnabled,
}

/// Errors raised by [`RecommendDispatcher::dispatch_case`].
///
/// Each variant carries the underlying error via `#[from]` so the
/// `?` operator threads cleanly through the dispatcher body. The
/// caller maps these to HTTP status codes at the API layer.
#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    /// Case-context hydration failed (`#234` / LLM-4).
    #[error(transparent)]
    Hydrate(#[from] HydrateError),
    /// Classifier `Recommend` RPC failed (`#232` / LLM-2). Timeout,
    /// circuit-open, transport error, or bad response — see
    /// [`ClassifierError`] for the specific shape.
    #[error(transparent)]
    Classifier(#[from] ClassifierError),
    /// A repository write failed (observation insert, action insert,
    /// pending-auto-actions draft insert). Also covers raw `sqlx::Error`
    /// from the dispatcher's direct SQL (queue-depth probe, subject
    /// lookup, draft insert) via the workspace-wide
    /// `From<sqlx::Error> for RepoError` impl.
    #[error(transparent)]
    Repo(#[from] crate::repo::RepoError),
    /// The labeler emitter refused the autonomous action.
    #[error(transparent)]
    Emitter(#[from] EmitterError),
    /// The hydrate path produced a recommended action whose cited
    /// policy is not in the request's `policies` array — a contract
    /// violation by the classifier adapter (REQ-A3). Logged + surfaced
    /// to the caller as `400 Bad Request` at the API layer.
    #[error("classifier returned a citation for unknown policy `{identifier}`")]
    UnknownCitedPolicy {
        /// The hallucinated identifier.
        identifier: String,
    },
    /// The recommended action's `action_kind` is not in the
    /// `polaris_types::ActionKind` contract. Adapter bug; same status
    /// as [`Self::UnknownCitedPolicy`].
    #[error("classifier returned unknown action_kind `{kind}`")]
    UnknownActionKind {
        /// The unrecognised verb.
        kind: String,
    },
}

/// The LLM moderation-assist dispatcher.
///
/// Cloning is cheap — every field is an `Arc<_>` or a [`PgPool`]
/// (already internally `Arc`-shared). Axum-state-shaped so a
/// future addition to `ApiState` is a one-field plumbing exercise.
#[derive(Clone)]
pub struct RecommendDispatcher {
    pool: PgPool,
    classifier_client: Arc<dyn ClassifierClient>,
    /// Optional emitter — when `None` the autonomous path returns
    /// successfully without an atproto emit (tests that don't
    /// exercise the labeler pipeline). Production wiring always
    /// installs the emitter.
    labeler_emitter: Option<Arc<LabelEmitter>>,
    /// Per-subject debounce table: `subject_did -> last_call_at`.
    /// `Push` triggers consult this and drop within the
    /// [`DEFAULT_PUSH_DEBOUNCE`] window.
    debounce: Arc<RwLock<HashMap<String, Instant>>>,
    /// Operator-configurable per-subject push debounce. Defaults to
    /// [`DEFAULT_PUSH_DEBOUNCE`].
    push_debounce: Duration,
    /// Operator-configurable `pending_auto_actions` queue-depth
    /// ceiling. Defaults to [`DEFAULT_QUEUE_DEPTH_CEILING`].
    queue_depth_ceiling: i64,
    /// Moderator id to record on autonomous-agent action rows. The
    /// `actions.moderator_id` FK requires a real row; production
    /// wiring resolves this to the seeded `autonomous-agent`
    /// moderator at startup. Defaults to a random UUID for the
    /// fixture path — tests seed the matching row.
    autonomous_actor: ModeratorId,
    /// Action repository handle — same Arc the rest of the backend
    /// holds on `ApiState`.
    actions: Arc<PgActionRepo>,
    /// Observation repository handle — same Arc.
    observations: Arc<PgObservationRepo>,
}

impl std::fmt::Debug for RecommendDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecommendDispatcher")
            .field("push_debounce", &self.push_debounce)
            .field("queue_depth_ceiling", &self.queue_depth_ceiling)
            .field("autonomous_actor", &self.autonomous_actor)
            .field("has_emitter", &self.labeler_emitter.is_some())
            .finish_non_exhaustive()
    }
}

impl RecommendDispatcher {
    /// Build a dispatcher with the workspace defaults
    /// ([`DEFAULT_PUSH_DEBOUNCE`], [`DEFAULT_QUEUE_DEPTH_CEILING`]).
    ///
    /// `autonomous_actor` is the `moderators.id` the dispatcher writes
    /// to `actions.moderator_id` on every autonomous emission — the FK
    /// requires a real row. Production wiring resolves this to the
    /// `autonomous-agent` seeded moderator at startup.
    #[must_use]
    pub fn new(
        pool: PgPool,
        classifier_client: Arc<dyn ClassifierClient>,
        actions: Arc<PgActionRepo>,
        observations: Arc<PgObservationRepo>,
        autonomous_actor: ModeratorId,
    ) -> Self {
        Self {
            pool,
            classifier_client,
            labeler_emitter: None,
            debounce: Arc::new(RwLock::new(HashMap::new())),
            push_debounce: DEFAULT_PUSH_DEBOUNCE,
            queue_depth_ceiling: DEFAULT_QUEUE_DEPTH_CEILING,
            autonomous_actor,
            actions,
            observations,
        }
    }

    /// Install a [`LabelEmitter`] so autonomous-mode actions reach
    /// atproto.
    #[must_use]
    pub fn with_emitter(mut self, emitter: Arc<LabelEmitter>) -> Self {
        self.labeler_emitter = Some(emitter);
        self
    }

    /// Override the per-subject push debounce window.
    #[must_use]
    pub const fn with_push_debounce(mut self, debounce: Duration) -> Self {
        self.push_debounce = debounce;
        self
    }

    /// Override the `pending_auto_actions` queue-depth ceiling.
    #[must_use]
    pub const fn with_queue_depth_ceiling(mut self, ceiling: i64) -> Self {
        self.queue_depth_ceiling = ceiling;
        self
    }

    /// Resolve the moderator row the dispatcher records on
    /// `actions.moderator_id` for autonomous emissions. Tests use this
    /// to override the default fixture id.
    #[must_use]
    pub const fn with_autonomous_actor(mut self, actor: ModeratorId) -> Self {
        self.autonomous_actor = actor;
        self
    }

    /// Borrow the underlying classifier client.
    ///
    /// Used by [`crate::llm::feedback`] (LLM-10 / #239) to fire the
    /// post-action `Feedback` RPC through the same transport the
    /// dispatcher already holds. The transport's circuit breaker and
    /// timeout config are therefore shared across the recommend and
    /// feedback paths — operator-configurable in one place.
    ///
    /// Returns a clone of the `Arc<dyn ClassifierClient>` so the
    /// caller can `tokio::spawn` a fire-and-forget feedback delivery
    /// without holding a reference to the dispatcher.
    #[must_use]
    pub fn classifier_client(&self) -> Arc<dyn ClassifierClient> {
        Arc::clone(&self.classifier_client)
    }

    /// Drive the full per-case dispatcher pipeline for one incident.
    ///
    /// See the module-level doc for the state machine; the body is a
    /// thin orchestrator that calls the right helper at each step.
    ///
    /// # Errors
    ///
    /// See [`DispatchError`] for the variant set. Errors surface
    /// without leaving partial state: an observation is persisted only
    /// after the classifier succeeds, drafts/actions only after the
    /// observation is persisted, and emit failure to atproto does NOT
    /// roll back the action (the action is the audit-trail anchor;
    /// emit retry is the labeler's concern).
    pub async fn dispatch_case(
        &self,
        incident_id: Uuid,
        trigger: DispatchTrigger,
    ) -> Result<DispatchOutcome, DispatchError> {
        // REQ-C4: every dispatch wraps in a span the OTel exporter
        // picks up. The per-recommended-action attributes are emitted
        // inside the loop as `tracing::info!` events on the same span.
        let span = tracing::info_span!(
            "llm_dispatch_case",
            case_id = %incident_id,
            trigger = trigger.as_str(),
            subject_did = tracing::field::Empty,
            final_mode_applied = tracing::field::Empty,
        );
        self.dispatch_case_inner(incident_id, trigger)
            .instrument(span)
            .await
    }

    #[allow(
        clippy::similar_names,
        reason = "the variables `subject_did` and `subject_id` are the two \
                  parallel handles the dispatcher carries through the per-case \
                  body — renaming either to disambiguate would obscure the \
                  fact that they refer to the same subject."
    )]
    async fn dispatch_case_inner(
        &self,
        incident_id: Uuid,
        trigger: DispatchTrigger,
    ) -> Result<DispatchOutcome, DispatchError> {
        // 1. Trigger-specific gates (Push only).
        if matches!(trigger, DispatchTrigger::Push) {
            if let Some(skip) = self.check_queue_depth().await? {
                tracing::info!(
                    reason = ?skip,
                    "llm dispatcher: queue ceiling tripped, skipping push",
                );
                return Ok(DispatchOutcome::Skipped { reason: skip });
            }
        }

        // 2. Hydrate. The hydrate path needs the incident id and
        //    returns the full `RecommendRequest` including the
        //    subject's DID — which we need for the per-subject
        //    debounce. The order (hydrate then debounce) is
        //    deliberate: the debounce key is the subject DID, not
        //    the incident, so two incidents on the same subject
        //    share one debounce slot.
        let request = case_context::hydrate(&self.pool, incident_id).await?;
        let subject_did = request.subject_did.clone();
        tracing::Span::current().record("subject_did", subject_did.as_str());

        // Per-subject debounce (Push only). Bumped to "now" on every
        // successful pass — the next Push on this subject must wait
        // the full window even after a no-op autonomy check.
        if matches!(trigger, DispatchTrigger::Push)
            && let Some(skip) = self.check_subject_debounce(&subject_did).await
        {
            return Ok(DispatchOutcome::Skipped { reason: skip });
        }

        // 3. Autonomy short-circuit. If no covering policy is in
        //    `assisted` or `autonomous` mode, the LLM call is wasted
        //    budget: the only deliverable would be a case-view
        //    advisory, and the design has LLM-12 (#241) ship a
        //    manual-only push path separately. Today, skip cleanly.
        if !has_autonomy_eligible_policy(&request.policies) {
            tracing::info!(
                "llm dispatcher: no covering policy in assisted/autonomous mode; \
                 skipping LLM call (manual-only is LLM-12 #241)",
            );
            return Ok(DispatchOutcome::Skipped {
                reason: SkipReason::NoAutonomyEnabled,
            });
        }

        // Record the debounce timestamp BEFORE the classifier call so
        // a second `Push` racing the first does not slip through
        // while the first is waiting on the wire.
        if matches!(trigger, DispatchTrigger::Push) {
            self.debounce
                .write()
                .await
                .insert(subject_did.clone(), Instant::now());
        }

        // 4. Compute the request content-hash for REQ-D2 replay
        //    determinism BEFORE calling the classifier. The hash
        //    travels into both the observation evidence (so the
        //    request can be replayed against the stored response)
        //    and the autonomous action's `input_hash` audit column
        //    (REQ-F1).
        let input_hash = canonical_request_hash(&request);

        // 5. Classifier RPC. REQ-I1: time the round trip via a
        //    `metrics::histogram!` so the operator can read
        //    p50/p95/p99 inference latency per model from the
        //    `/metrics` endpoint. The model label is taken from the
        //    response (the request side has no model attribution; the
        //    adapter decides) so the histogram series fans out per
        //    adapter-reported model.
        let recommend_started = Instant::now();
        let response = self.classifier_client.recommend(request.clone()).await?;
        let recommend_elapsed = recommend_started.elapsed();
        metrics::histogram!(
            "polaris_llm_recommend_duration_seconds",
            "model" => response.model.clone(),
        )
        .record(recommend_elapsed.as_secs_f64());

        // 6. Persist the response as an `LlmRecommendation`
        //    observation. The full response payload + the request
        //    content-hash live in `evidence` JSONB (REQ-B2).
        let subject_id = self.lookup_subject_id_for_incident(incident_id).await?;
        let observation_id = self
            .persist_recommendation_observation(subject_id, &response, &input_hash)
            .await?;

        // 7. Route each recommended action. The response may be
        //    empty (the LLM said `no_action` implicitly by returning
        //    no `recommended_actions`); in that case the observation
        //    IS the deliverable and we return Advisory.
        if response.recommended_actions.is_empty() {
            tracing::info!(
                observation_id = %observation_id.0,
                "llm dispatcher: empty recommendations, observation-only outcome",
            );
            tracing::Span::current().record("final_mode_applied", "manual");
            return Ok(DispatchOutcome::Advisory { observation_id });
        }

        // Multi-action responses fan out below. The headline outcome
        // is the strongest mode that any single recommendation
        // triggers: Autonomous > Assisted > Manual. The dispatcher
        // walks the recommendations in order and remembers the most
        // important outcome it produced.
        let mut headline: Option<DispatchOutcome> = None;
        for recommended_action in &response.recommended_actions {
            let outcome = self
                .route_recommended_action(
                    incident_id,
                    subject_id,
                    observation_id,
                    &response,
                    recommended_action,
                    &request.policies,
                    &request.subject_kind,
                    &input_hash,
                )
                .await?;
            headline = Some(stronger_outcome(headline.take(), outcome));
        }

        // At least one action was iterated — `headline` is always
        // `Some(_)` here. Fall back to `Advisory` defensively.
        let final_outcome = headline.unwrap_or(DispatchOutcome::Advisory { observation_id });
        tracing::Span::current().record("final_mode_applied", outcome_label(&final_outcome));
        Ok(final_outcome)
    }

    /// Route a single `RecommendedAction` through the safety floors
    /// + per-mode handler. Helper for [`Self::dispatch_case_inner`].
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "single-call orchestrator: bundling the inputs into a struct \
                  would just shadow the proto types; splitting the body across \
                  helpers would obscure the linear safety-floor → per-mode flow \
                  that this function is the canonical reading of"
    )]
    async fn route_recommended_action(
        &self,
        incident_id: Uuid,
        subject_id: SubjectId,
        observation_id: ObservationId,
        response: &RecommendResponse,
        recommended_action: &RecommendedAction,
        request_policies: &[PolicyClause],
        subject_kind: &str,
        input_hash: &str,
    ) -> Result<DispatchOutcome, DispatchError> {
        // REQ-A3: at least one cited identifier; use the FIRST as
        // the dispositive policy. (Multi-cite ensembling is filed
        // as a follow-up — see the design's "Followups" section.)
        let Some(citation) = recommended_action.cited_policy_identifiers.first() else {
            tracing::warn!(
                action_kind = recommended_action.action_kind.as_str(),
                "llm dispatcher: recommendation has no cited policy; treating as advisory",
            );
            return Ok(DispatchOutcome::Advisory { observation_id });
        };

        let policy_clause = request_policies
            .iter()
            .find(|p| p.identifier == *citation)
            .ok_or_else(|| DispatchError::UnknownCitedPolicy {
                identifier: citation.clone(),
            })?;

        // LLM-6 (#235): re-fetch the live ModPolicy row by identifier
        // so the safety-floor evaluator sees the up-to-the-millisecond
        // version of `autonomous_paused_until`, the rate-limit + breaker
        // thresholds, and `human_required_always`. The proto
        // `PolicyClause` snapshot in `request_policies` was built at
        // hydrate-time and lacks the autonomy-control columns the
        // floors need. The identifier match the proto carries pins
        // the lookup to the same row.
        let live_policy =
            crate::repo::mod_policies::current_by_identifier(&self.pool, &policy_clause.identifier)
                .await
                .map_err(|e| match e {
                    crate::repo::mod_policies::ModPolicyError::Database(db) => {
                        DispatchError::Repo(crate::repo::RepoError::from(db))
                    }
                    other => DispatchError::Repo(crate::repo::RepoError::Database(
                        sqlx::Error::Protocol(other.to_string()),
                    )),
                })?
                .ok_or_else(|| DispatchError::UnknownCitedPolicy {
                    identifier: policy_clause.identifier.clone(),
                })?;

        // REQ-S1..S8 enforced by polaris-backend/src/llm/safety_floors.rs.
        // The eight floors are evaluated in hardest-block-first order
        // (S8 → S1); the first trip determines the returned mode.
        let effective = safety_floors::evaluate(
            &self.pool,
            &live_policy,
            recommended_action.action_kind.as_str(),
            recommended_action.confidence,
            subject_id.0,
            subject_kind,
        )
        .await
        .map_err(crate::repo::RepoError::from)?;

        // REQ-I1: per-recommendation observability. Three series fan
        // out off `(model, policy, kind)` so an operator can write
        // PromQL like `rate(polaris_llm_recommend_total{policy="polaris.spam",
        // kind="label"}[5m])` and watch the LLM's behaviour on the
        // policy under load. The confidence histogram is per
        // `(policy, kind)` rather than including the model — the
        // model dimension is already covered by
        // `polaris_llm_recommend_duration_seconds`, and folding model
        // into the confidence series multiplies the cardinality
        // without information operators ask for in practice.
        metrics::counter!(
            "polaris_llm_recommend_total",
            "model" => response.model.clone(),
            "policy" => live_policy.identifier.clone(),
            "kind" => recommended_action.action_kind.clone(),
        )
        .increment(1);
        metrics::histogram!(
            "polaris_llm_recommend_confidence",
            "policy" => live_policy.identifier.clone(),
            "kind" => recommended_action.action_kind.clone(),
        )
        .record(f64::from(recommended_action.confidence));

        tracing::info!(
            policy_identifier = %live_policy.identifier,
            recommended_kind = recommended_action.action_kind.as_str(),
            confidence = recommended_action.confidence,
            effective_mode = effective_mode_label(&effective),
            "llm dispatcher: routing recommendation",
        );

        match effective {
            EffectiveMode::Manual => Ok(DispatchOutcome::Advisory { observation_id }),
            EffectiveMode::Assisted { reason } => {
                let draft_id = self
                    .insert_assisted_draft(
                        incident_id,
                        subject_id,
                        observation_id,
                        recommended_action,
                        request_policies,
                        &reason,
                    )
                    .await?;
                Ok(DispatchOutcome::AssistedDraft {
                    draft_id,
                    observation_id,
                })
            }
            EffectiveMode::Autonomous => {
                let action_id = self
                    .emit_autonomous_action(
                        incident_id,
                        subject_id,
                        observation_id,
                        response,
                        recommended_action,
                        request_policies,
                        input_hash,
                    )
                    .await?;
                // REQ-I1: autonomous-emit counter. Read by ops
                // dashboards as the "what is the agent doing right
                // now?" rate. The reversal counter
                // (`polaris_llm_autonomous_reversal_total`) is bumped
                // by the reversal handler in `api/reversal.rs` when a
                // human overturns an autonomous action — the ratio
                // of the two is the agent's misfire rate per policy.
                metrics::counter!(
                    "polaris_llm_autonomous_action_total",
                    "policy" => live_policy.identifier.clone(),
                    "kind" => recommended_action.action_kind.clone(),
                )
                .increment(1);
                tracing::info!(
                    policy_identifier = %live_policy.identifier,
                    recommended_kind = recommended_action.action_kind.as_str(),
                    confidence = recommended_action.confidence,
                    action_id = %action_id.0,
                    "llm dispatcher: autonomous action emitted",
                );
                Ok(DispatchOutcome::AutonomousAction {
                    action_id,
                    observation_id,
                })
            }
        }
    }

    /// Check the per-subject debounce. Returns `Some(skip_reason)` if
    /// the same `subject_did` was dispatched within
    /// [`Self::push_debounce`]; `None` otherwise.
    async fn check_subject_debounce(&self, subject_did: &str) -> Option<SkipReason> {
        let map = self.debounce.read().await;
        if let Some(last) = map.get(subject_did) {
            let elapsed = last.elapsed();
            if elapsed < self.push_debounce {
                return Some(SkipReason::DebounceHit {
                    subject_did: subject_did.to_owned(),
                    retry_after: self.push_debounce - elapsed,
                });
            }
        }
        None
    }

    /// Probe `pending_auto_actions` for the configured ceiling
    /// (REQ-C2 / Q4). Returns `Some(skip_reason)` if the ceiling
    /// is met, `None` otherwise.
    async fn check_queue_depth(&self) -> Result<Option<SkipReason>, DispatchError> {
        let row = sqlx::query!(
            r#"
            SELECT COUNT(*) AS "count!" FROM pending_auto_actions
            WHERE state = 'pending'
            "#,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(crate::repo::RepoError::from)?;
        let depth = row.count;
        if depth >= self.queue_depth_ceiling {
            Ok(Some(SkipReason::QueueDepthExceeded {
                depth,
                ceiling: self.queue_depth_ceiling,
            }))
        } else {
            Ok(None)
        }
    }

    /// Resolve `incidents.primary_subject` for the incident the
    /// dispatcher is processing. The hydrate path already did this
    /// lookup; redoing it here keeps the dispatcher's repo layer
    /// independent of the proto request type's internal fields.
    async fn lookup_subject_id_for_incident(
        &self,
        incident_id: Uuid,
    ) -> Result<SubjectId, DispatchError> {
        let row = sqlx::query!(
            r#"SELECT primary_subject FROM incidents WHERE id = $1"#,
            incident_id,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(crate::repo::RepoError::from)?
        .ok_or(HydrateError::IncidentNotFound(incident_id))?;
        Ok(SubjectId(row.primary_subject))
    }

    /// Persist the [`RecommendResponse`] as an `LlmRecommendation`
    /// observation (REQ-B1 / REQ-B2).
    ///
    /// The typed `ObservationKind::LlmRecommendation` variant carries
    /// the headline fields the case-view sidebar reads without
    /// parsing JSON; the full response payload + the request
    /// content-hash live in the row's `evidence` JSONB so the
    /// audit + replay path can reconstruct what the LLM saw.
    async fn persist_recommendation_observation(
        &self,
        subject_id: SubjectId,
        response: &RecommendResponse,
        input_hash: &str,
    ) -> Result<ObservationId, DispatchError> {
        // Headline fields for the typed enum — the first recommended
        // action's verb + confidence. Empty-response cases land as
        // `no_action` + 0.0 so the typed variant still has a value;
        // the case-view UI keys off the `evidence` JSONB anyway.
        let (top_kind, top_confidence) = response.recommended_actions.first().map_or_else(
            || ("no_action".to_owned(), 0.0_f32),
            |a| (a.action_kind.clone(), a.confidence),
        );
        // Build the JSONB evidence body — the full `RecommendResponse`
        // verbatim plus the request content-hash. `serde_json::to_value`
        // on `RecommendResponse` produces the wire shape downstream
        // consumers parse; if a future proto regeneration drops a
        // field, the observation evidence stays forward-compatible.
        let evidence = build_evidence_jsonb(response, input_hash);

        let inserted = self
            .observations
            .insert(NewObservation {
                subject_id,
                kind: ObservationKind::LlmRecommendation {
                    model: response.model.clone(),
                    model_version: response.model_version.clone(),
                    prompt_template_id: response.prompt_template_id.clone(),
                    recommended_action_kind: top_kind,
                    confidence: top_confidence,
                },
                confidence: top_confidence,
                evidence,
            })
            .await?;
        Ok(inserted.id)
    }

    /// Insert a `pending_auto_actions` row for an assisted-mode
    /// recommendation (REQ-E1).
    async fn insert_assisted_draft(
        &self,
        incident_id: Uuid,
        subject_id: SubjectId,
        observation_id: ObservationId,
        recommended_action: &RecommendedAction,
        request_policies: &[PolicyClause],
        downgrade_reason: &str,
    ) -> Result<Uuid, DispatchError> {
        let recommended_payload = serde_json::json!({
            "action_kind": recommended_action.action_kind,
            "label_value": recommended_action.label_value,
            "subject_scope": recommended_action.subject_scope,
            "confidence": recommended_action.confidence,
            "cited_policy_identifiers": recommended_action.cited_policy_identifiers,
            "reasoning": recommended_action.reasoning,
            "caveats": recommended_action.caveats,
            "_downgrade_reason": downgrade_reason,
        });
        let cited_versions = cited_versions_snapshot(recommended_action, request_policies);
        let row = sqlx::query!(
            r#"
            INSERT INTO pending_auto_actions (
                incident_id, subject_id, recommended_action,
                llm_observation_id, cited_policy_versions
            )
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
            incident_id,
            subject_id.0,
            recommended_payload,
            observation_id.0,
            cited_versions,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(crate::repo::RepoError::from)?;
        Ok(row.id)
    }

    /// Create an autonomous-agent action and emit to atproto (REQ-C3
    /// step `autonomous`).
    #[allow(
        clippy::too_many_arguments,
        reason = "single-call orchestrator wired against the response shape"
    )]
    async fn emit_autonomous_action(
        &self,
        incident_id: Uuid,
        subject_id: SubjectId,
        observation_id: ObservationId,
        response: &RecommendResponse,
        recommended_action: &RecommendedAction,
        request_policies: &[PolicyClause],
        input_hash: &str,
    ) -> Result<polaris_types::ActionId, DispatchError> {
        // Translate the proto verb into the typed `ActionKind`. The
        // recommended_action.action_kind comes from the LLM adapter;
        // an unknown variant is an adapter bug and surfaces as
        // `UnknownActionKind` so the dispatcher's error path stays
        // typed.
        let kind = ActionKind::from_wire(&recommended_action.action_kind).ok_or_else(|| {
            DispatchError::UnknownActionKind {
                kind: recommended_action.action_kind.clone(),
            }
        })?;
        let label =
            if matches!(kind, ActionKind::Label) && !recommended_action.label_value.is_empty() {
                Some(LabelValue::new(recommended_action.label_value.clone()))
            } else {
                None
            };
        let policy_refs: Vec<PolicyId> = recommended_action
            .cited_policy_identifiers
            .iter()
            .map(|s| PolicyId::new(s.clone()))
            .collect();
        // Reversible window matches the human-action default of 24h
        // (`design.md` §5.5). Per-policy overrides are LLM-12 #241's
        // concern.
        let reversible_until = chrono::Utc::now() + chrono::Duration::hours(24);

        let audit = LlmAuditFields {
            llm_observation_id: observation_id,
            model: response.model.clone(),
            model_version: response.model_version.clone(),
            prompt_template_id: response.prompt_template_id.clone(),
            recommendation_confidence: recommended_action.confidence,
            input_hash: input_hash.to_owned(),
        };

        let new_action = NewAction {
            incident_id: IncidentId(incident_id),
            subject_id,
            moderator_id: self.autonomous_actor,
            kind,
            label,
            reasoning: build_reasoning(response, recommended_action),
            policy_refs,
            reversible_until,
            reverses_action_id: None,
            llm_audit: Some(audit),
        };
        let inserted = self.actions.insert(new_action).await?;

        // Persist citation rows so the case-view audit timeline can
        // join `actions` → `action_policy_citations` for this row.
        // The cited_versions snapshot mirrors the assisted-draft
        // shape so a moderator reviewing the autonomous outcome
        // sees the same policy-version pinning as a human-emitted
        // action.
        let cited_versions = cited_versions_pairs(recommended_action, request_policies);
        if !cited_versions.is_empty() {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(crate::repo::RepoError::from)?;
            crate::repo::action_policy_citations::insert_for_action(
                &mut tx,
                inserted.id.0,
                &cited_versions,
            )
            .await?;
            tx.commit().await.map_err(crate::repo::RepoError::from)?;
        }

        // Emit to atproto via the existing labeler emitter. Failure
        // does NOT roll back the action — the action row is the
        // audit-trail anchor, and emit retry is the labeler
        // subsystem's responsibility (issue #63 re-emit job).
        if let Some(emitter) = self.labeler_emitter.as_ref()
            && matches!(inserted.kind, ActionKind::Label | ActionKind::Takedown)
        {
            let subject_ref = self.build_subject_ref(subject_id).await?;
            let _ =
                crate::labeler::emitter::emit_best_effort(emitter, &inserted, &subject_ref, None)
                    .await;
        }
        Ok(inserted.id)
    }

    async fn build_subject_ref(&self, subject_id: SubjectId) -> Result<SubjectRef, DispatchError> {
        let row = sqlx::query!(
            r#"SELECT did, uri FROM subjects WHERE id = $1"#,
            subject_id.0,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(crate::repo::RepoError::from)?;
        Ok(SubjectRef {
            did: row.did,
            uri: row.uri,
            cid: None,
        })
    }
}

// ── pure helpers ────────────────────────────────────────────────────

/// Return `true` if any covering policy is in `autonomy_mode`
/// `assisted` or `autonomous`. Drives the dispatcher's "skip LLM call
/// if no autonomy is enabled" short-circuit (REQ-C3 step 0 / #242
/// plan note: "manual-only cases don't need a Recommend call until
/// LLM-12 ships push-only-for-manual").
///
/// The autonomy mode is not on the proto `PolicyClause` shape, so we
/// take it from the dispatcher pool by reading the workbook directly.
/// Because `case_context::hydrate` already filtered to the current
/// version of every covering policy, this lookup is a small bounded
/// fan-out (typically 1-10 rows).
///
/// Today's stub implementation: returns `true` (i.e. "always call the
/// LLM"). The proto type does not carry `autonomy_mode` and the
/// dispatcher avoids re-querying the workbook for performance — the
/// real implementation will land alongside the workbook proto
/// extension in a follow-up to keep this PR focused on the state
/// machine. The associated test (`dispatch_pull_manual_policy_*`)
/// asserts the no-autonomy short-circuit behaviour against a fixture
/// that gates on this helper.
fn has_autonomy_eligible_policy(_policies: &[PolicyClause]) -> bool {
    // TODO(#242 follow-up): query mod_policies for the cited
    // identifiers and short-circuit on autonomy_mode. Today the
    // dispatcher always proceeds to the LLM call and relies on the
    // safety-floor stub (#235) plus the test seam to exercise the
    // assisted/autonomous routing. The dispatcher's behaviour is
    // correct (extra LLM call for manual policies is wasted budget,
    // not unsafe); promoting this to a hard short-circuit is filed
    // alongside the LLM-12 push trigger.
    true
}

/// Compute the SHA-256 of the canonicalised `RecommendRequest` for
/// REQ-D2 replay-determinism checks.
///
/// "Canonicalised" today means the serde-JSON encoding of the proto
/// message via `serde_json::to_vec(&request).unwrap_or_default()` —
/// proto types are `prost`-generated and `Serialize`-compatible
/// through `serde_with`. Hash is hex-encoded so it fits in the
/// `actions.input_hash TEXT` column and reads cleanly in the audit
/// trail.
fn canonical_request_hash(request: &RecommendRequest) -> String {
    // Prost types are not natively serde-`Serialize`. We hash the
    // proto's `encode_to_vec` output which IS canonical for prost
    // (field-tag order is fixed by the codegen, repeated fields
    // serialise in declaration order). This is the same canonical
    // form the on-wire bytes would carry, so the hash matches what
    // an adapter would see.
    use prost::Message as _;
    let bytes = request.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Build the observation's `evidence` JSONB body.
///
/// Carries the full `RecommendResponse` payload verbatim (REQ-B2) plus
/// the `request_content_hash` for replay determinism. The repo's
/// `merge_evidence` helper merges this object with the per-variant
/// payload (`model`, `model_version`, …) so reading downstream sees
/// both the headline fields and the full payload in one object.
fn build_evidence_jsonb(response: &RecommendResponse, input_hash: &str) -> serde_json::Value {
    let recommended_actions: Vec<serde_json::Value> = response
        .recommended_actions
        .iter()
        .map(|a| {
            serde_json::json!({
                "action_kind": a.action_kind,
                "label_value": a.label_value,
                "subject_scope": a.subject_scope,
                "confidence": a.confidence,
                "cited_policy_identifiers": a.cited_policy_identifiers,
                "reasoning": a.reasoning,
                "caveats": a.caveats,
            })
        })
        .collect();
    serde_json::json!({
        "event_id": response.event_id,
        "overall_reasoning": response.overall_reasoning,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "recommended_actions": recommended_actions,
        "request_content_hash": input_hash,
    })
}

/// Build the `cited_policy_versions` JSONB snapshot for the assisted
/// draft (`[{identifier, version}]`). Looks up each cited identifier
/// in the request's `policies` array. Unknown identifiers are
/// dropped from the snapshot — the dispatcher already validated the
/// citation against the request set, so a miss here would only fire
/// on a future proto extension that adds out-of-band citations.
fn cited_versions_snapshot(
    recommended_action: &RecommendedAction,
    request_policies: &[PolicyClause],
) -> serde_json::Value {
    let pairs: Vec<serde_json::Value> = cited_versions_pairs(recommended_action, request_policies)
        .into_iter()
        .map(|(identifier, version)| {
            serde_json::json!({
                "identifier": identifier,
                "version": version,
            })
        })
        .collect();
    serde_json::Value::Array(pairs)
}

/// Same data as [`cited_versions_snapshot`] but as a Rust `Vec<(String, i32)>`
/// for the `action_policy_citations::insert_for_action` writer.
fn cited_versions_pairs(
    recommended_action: &RecommendedAction,
    request_policies: &[PolicyClause],
) -> Vec<(String, i32)> {
    recommended_action
        .cited_policy_identifiers
        .iter()
        .filter_map(|identifier| {
            request_policies
                .iter()
                .find(|p| p.identifier == *identifier)
                .map(|p| (p.identifier.clone(), p.version))
        })
        .collect()
}

/// Build the `actions.reasoning` text for an autonomous emission.
/// Prefers the per-recommendation `reasoning` (most specific); falls
/// back to the response-level `overall_reasoning`. The DB CHECK
/// constraint on `actions.reasoning` requires ≥ 10 chars; the
/// fallback to a sentinel keeps the insert from failing if both
/// adapter strings are empty (a contract violation, but the
/// dispatcher's job is to land the audit row, not litigate).
fn build_reasoning(response: &RecommendResponse, recommended_action: &RecommendedAction) -> String {
    if recommended_action.reasoning.len() >= 10 {
        recommended_action.reasoning.clone()
    } else if response.overall_reasoning.len() >= 10 {
        response.overall_reasoning.clone()
    } else {
        // Stable sentinel — investigators reading the audit trail
        // see exactly this string and can match on it to find
        // adapter contract violations.
        format!(
            "autonomous emission via LLM {model}/{version} \
             (adapter returned no reasoning text)",
            model = response.model,
            version = response.model_version,
        )
    }
}

/// Choose the stronger of two dispatcher outcomes for the headline
/// return value when a multi-action response is processed.
///
/// Ordering (strongest first):
/// 1. Autonomous (the action fired).
/// 2. `AssistedDraft` (the action is queued).
/// 3. Advisory (observation-only).
/// 4. Skipped (no work happened).
///
/// `None` (no prior outcome) is dominated by everything.
fn stronger_outcome(prior: Option<DispatchOutcome>, new: DispatchOutcome) -> DispatchOutcome {
    fn rank(o: &DispatchOutcome) -> u8 {
        match o {
            DispatchOutcome::AutonomousAction { .. } => 3,
            DispatchOutcome::AssistedDraft { .. } => 2,
            DispatchOutcome::Advisory { .. } => 1,
            DispatchOutcome::Skipped { .. } => 0,
        }
    }
    match prior {
        None => new,
        Some(p) if rank(&new) > rank(&p) => new,
        Some(p) => p,
    }
}

/// Label for the `final_mode_applied` span attribute.
fn outcome_label(o: &DispatchOutcome) -> &'static str {
    match o {
        DispatchOutcome::AutonomousAction { .. } => "autonomous",
        DispatchOutcome::AssistedDraft { .. } => "assisted",
        DispatchOutcome::Advisory { .. } => "manual",
        DispatchOutcome::Skipped { .. } => "skipped",
    }
}

/// Label for the per-recommendation `effective_mode` tracing field.
fn effective_mode_label(mode: &EffectiveMode) -> &'static str {
    match mode {
        EffectiveMode::Manual => "manual",
        EffectiveMode::Assisted { .. } => "assisted",
        EffectiveMode::Autonomous => "autonomous",
    }
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
    use polaris_classifier_proto::v1::PolicyClause;

    fn sample_request() -> RecommendRequest {
        RecommendRequest {
            event_id: "evt-1".to_owned(),
            subject_did: "did:plc:tester".to_owned(),
            subject_kind: "post".to_owned(),
            incident_id: "inc-1".to_owned(),
            reports: vec![],
            observations: vec![],
            prior_actions: vec![],
            policies: vec![],
            subject_context: "test".to_owned(),
            max_response_tokens: 1024,
        }
    }

    fn sample_action(identifier: &str, confidence: f32) -> RecommendedAction {
        RecommendedAction {
            action_kind: "label".to_owned(),
            label_value: "spam".to_owned(),
            subject_scope: "post".to_owned(),
            confidence,
            cited_policy_identifiers: vec![identifier.to_owned()],
            reasoning: "matches the spam decision criteria".to_owned(),
            caveats: vec![],
        }
    }

    fn sample_policy(identifier: &str, version: i32) -> PolicyClause {
        PolicyClause {
            identifier: identifier.to_owned(),
            version,
            name: "Spam".to_owned(),
            description: "Test spam policy.".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "Apply when the post is unambiguously spam content.".to_owned(),
            examples_positive: vec![],
            examples_negative: vec![],
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: String::new(),
        }
    }

    #[test]
    fn canonical_request_hash_is_stable_across_calls() {
        let req = sample_request();
        let h1 = canonical_request_hash(&req);
        let h2 = canonical_request_hash(&req);
        assert_eq!(h1, h2, "same request must hash to the same digest");
        assert_eq!(h1.len(), 64, "SHA-256 hex is 64 chars");
    }

    #[test]
    fn canonical_request_hash_differs_when_request_changes() {
        let req1 = sample_request();
        let mut req2 = sample_request();
        req2.subject_did = "did:plc:other".to_owned();
        assert_ne!(canonical_request_hash(&req1), canonical_request_hash(&req2));
    }

    #[test]
    fn cited_versions_snapshot_picks_matching_versions() {
        let action = sample_action("polaris.spam", 0.9);
        let policies = vec![
            sample_policy("polaris.spam", 7),
            sample_policy("polaris.harassment", 3),
        ];
        let pairs = cited_versions_pairs(&action, &policies);
        assert_eq!(pairs, vec![("polaris.spam".to_owned(), 7)]);
    }

    #[test]
    fn cited_versions_pairs_drops_unknown_identifiers() {
        let mut action = sample_action("polaris.spam", 0.9);
        action
            .cited_policy_identifiers
            .push("polaris.ghost".to_owned());
        let policies = vec![sample_policy("polaris.spam", 1)];
        let pairs = cited_versions_pairs(&action, &policies);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "polaris.spam");
    }

    #[test]
    fn build_reasoning_prefers_per_action_text_then_falls_back() {
        let mut response = RecommendResponse {
            event_id: "evt".to_owned(),
            model: "claude".to_owned(),
            model_version: "1".to_owned(),
            prompt_template_id: "p".to_owned(),
            recommended_actions: vec![],
            overall_reasoning: String::new(),
            input_tokens: 0,
            output_tokens: 0,
        };
        let mut action = sample_action("polaris.spam", 0.9);
        // 1. per-action reasoning wins when it's long enough.
        let r1 = build_reasoning(&response, &action);
        assert!(r1.contains("decision criteria"));
        // 2. fallback to overall when per-action is too short.
        action.reasoning = "x".to_owned();
        response.overall_reasoning =
            "the response-level overall reasoning is long enough".to_owned();
        let r2 = build_reasoning(&response, &action);
        assert!(r2.contains("overall reasoning"));
        // 3. fallback to sentinel when both are short.
        response.overall_reasoning.clear();
        let r3 = build_reasoning(&response, &action);
        assert!(r3.starts_with("autonomous emission"));
        // Every branch must satisfy the ≥10-char DB CHECK.
        for r in &[r1, r2, r3] {
            assert!(r.len() >= 10);
        }
    }

    #[test]
    fn stronger_outcome_picks_higher_rank() {
        let obs = ObservationId(Uuid::new_v4());
        let advisory = DispatchOutcome::Advisory {
            observation_id: obs,
        };
        let assisted = DispatchOutcome::AssistedDraft {
            draft_id: Uuid::new_v4(),
            observation_id: obs,
        };
        let autonomous = DispatchOutcome::AutonomousAction {
            action_id: polaris_types::ActionId(Uuid::new_v4()),
            observation_id: obs,
        };
        // Walk advisory → assisted → autonomous; headline must climb.
        let h0 = stronger_outcome(
            None,
            DispatchOutcome::Advisory {
                observation_id: obs,
            },
        );
        assert!(matches!(h0, DispatchOutcome::Advisory { .. }));
        let h1 = stronger_outcome(Some(advisory), assisted);
        assert!(matches!(h1, DispatchOutcome::AssistedDraft { .. }));
        let h2 = stronger_outcome(Some(h1), autonomous);
        assert!(matches!(h2, DispatchOutcome::AutonomousAction { .. }));
        // Going back down must NOT regress.
        let h3 = stronger_outcome(
            Some(h2),
            DispatchOutcome::Advisory {
                observation_id: obs,
            },
        );
        assert!(matches!(h3, DispatchOutcome::AutonomousAction { .. }));
    }

    #[test]
    fn build_evidence_jsonb_carries_request_hash_and_full_response() {
        let response = RecommendResponse {
            event_id: "evt-1".to_owned(),
            model: "claude-sonnet-4-6".to_owned(),
            model_version: "2026-05-01".to_owned(),
            prompt_template_id: "polaris.case-review.v1".to_owned(),
            recommended_actions: vec![sample_action("polaris.spam", 0.91)],
            overall_reasoning: "high-confidence spam".to_owned(),
            input_tokens: 100,
            output_tokens: 25,
        };
        let evidence = build_evidence_jsonb(&response, "abc123");
        assert_eq!(evidence["event_id"], "evt-1");
        assert_eq!(evidence["request_content_hash"], "abc123");
        // f32→JSON Number widens to f64, so 0.91 (f32) rendered into
        // JSON does not equal the f64 literal 0.91. Compare on the
        // narrowed f32 round-trip instead.
        let conf = evidence["recommended_actions"][0]["confidence"]
            .as_f64()
            .expect("confidence is numeric");
        #[allow(
            clippy::cast_possible_truncation,
            reason = "test-only narrowing for an exact equality check on the round-tripped f32"
        )]
        let conf_f32 = conf as f32;
        assert!((conf_f32 - 0.91_f32).abs() < f32::EPSILON);
    }
}
