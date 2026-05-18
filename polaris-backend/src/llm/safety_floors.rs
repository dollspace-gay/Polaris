//! Safety-floor evaluation for the LLM recommendation dispatcher
//! (`.design/llm-moderation-assist.md` REQ-S1..S8).
//!
//! # Eight server-side invariants
//!
//! Every `RecommendedAction` the dispatcher routes goes through the
//! [`evaluate`] gauntlet below. Each floor is an independent
//! sufficient stop: any single trip downgrades the recommendation
//! from `autonomous` to either `assisted` (soft downgrade, the
//! moderator can still approve) or `manual` (hard block, the case
//! becomes advisory-only).
//!
//! | Floor   | Rule                                                                          |
//! | ------- | ----------------------------------------------------------------------------- |
//! | REQ-S1  | `confidence >= policy.autonomous_confidence_threshold`.                       |
//! | REQ-S2  | `action_kind ∈ policy.autonomous_action_kinds ∩ {label, warn, takedown}`.     |
//! | REQ-S3  | `kind = 'takedown' ⇒ subject.kind = 'post'` (REQ-G2, account-TD post-only).   |
//! | REQ-S4  | No human `no_action` / `reverse` on the subject in the last 30 days.          |
//! | REQ-S5  | Autonomous actions on the policy in the last hour `< rate_limit_per_hour`.   |
//! | REQ-S6  | 7-day reversal rate `<= reversal_breaker_threshold` — trip writes 24-h pause. |
//! | REQ-S7  | `polaris_setup_state.global_autonomous_pause_until <= now()`.                |
//! | REQ-S8  | `policy.human_required_always = FALSE`.                                       |
//!
//! # Evaluation order
//!
//! Floors are walked **hardest-block first** so an operator reading
//! the structured-log trip records sees the highest-priority cause:
//!
//! 1. S8 — `human_required_always` (regulatory / CSAM hard block).
//! 2. S7 — global kill-switch.
//! 3. S6 — reversal-rate circuit breaker (also writes a 24-h pause).
//! 4. S5 — per-policy rate limit.
//! 5. S4 — subject cooldown (human moderator's recent verdict stands).
//! 6. S3 — account-takedown gate.
//! 7. S2 — action-kind gate.
//! 8. S1 — confidence floor (the only one that can downgrade to assisted
//!    *or* manual depending on which threshold the confidence missed).
//!
//! Every floor is evaluated (not just the first to trip) so the
//! `polaris_llm_safety_floor_tripped_total{policy, floor}` counter
//! has the full distribution — operators see "S4 fires often" rather
//! than just "something blocked autonomous mode on this policy".
//! The first trip in priority order is the one the function returns.
//!
//! # Override knobs
//!
//! * `POLARIS_AUTONOMOUS_SUBJECT_COOLDOWN_DAYS` — overrides the S4
//!   window. Default 30. Per Q2 in the design.
//!
//! # Database surface
//!
//! Every query goes through `sqlx::query!` for compile-time
//! verification against the offline schema cache. The floors that
//! touch the DB:
//!
//! * S4 — `actions` filtered by `subject_id, actor_kind='human',
//!   kind IN ('no_action','reverse')`.
//! * S5 — `actions` joined to `action_policy_citations` (cardinality
//!   per policy) filtered by `actor_kind='autonomous_agent'`.
//! * S6 — same join, ratio of reverses to total autonomous actions.
//!   Trip path writes a successor `mod_policies` row via
//!   [`crate::repo::mod_policies::pause_for_circuit_breaker`].
//! * S7 — `polaris_setup_state.global_autonomous_pause_until`.
//!
//! S1, S2, S3, S8 are pure (no I/O); they read from the
//! caller-supplied [`crate::repo::mod_policies::ModPolicy`] +
//! subject metadata.

use std::env;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::repo::mod_policies::{self, ModPolicy};

/// Minimum number of autonomous actions in the 7-day window before
/// the REQ-S6 reversal-rate breaker is allowed to trip. The
/// design's 15%-of-N rule degenerates at small N (one reversal at
/// N=1 reads as 100%); the floor keeps a freshly-enabled policy
/// from getting paused by a single early reversal.
const REVERSAL_BREAKER_MIN_SAMPLES: i64 = 4;

/// The mode the dispatcher actually applies to a recommendation,
/// AFTER the safety-floor evaluation downgrades (or leaves intact)
/// the policy's declared `autonomy_mode`.
///
/// The dispatcher routes per this value, not per the policy column:
/// a policy declared `autonomous` may be downgraded to `Assisted` if
/// a soft floor (e.g. S5 rate limit) trips, and `Assisted` may
/// degrade further to `Manual` if confidence is below
/// `assisted_confidence_threshold` (REQ-S1).
#[derive(Debug, Clone, PartialEq)]
pub enum EffectiveMode {
    /// No action surfaces beyond the persisted `LlmRecommendation`
    /// observation. The case-view advisory panel is the deliverable.
    Manual,
    /// Insert a row into `pending_auto_actions` for moderator review.
    /// The `reason` carries the floor that downgraded an
    /// otherwise-autonomous policy so the operator can read "this
    /// would have auto-fired but the rate-limit tripped".
    Assisted {
        /// Human-readable rationale for the downgrade. Surfaces in
        /// the assisted-queue UI so the moderator understands why the
        /// LLM's autonomous-eligible recommendation landed as a draft.
        reason: String,
    },
    /// Create the action with `actor_kind = 'autonomous_agent'` and
    /// emit to atproto. No human in the loop.
    Autonomous,
}

/// Which floor tripped. Used as the `floor` label on the
/// `polaris_llm_safety_floor_tripped_total` counter and as the
/// machine-readable summary in structured log fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyFloor {
    /// REQ-S1 — confidence below `autonomous_confidence_threshold`.
    Confidence,
    /// REQ-S2 — recommended kind not in
    /// `policy.autonomous_action_kinds ∩ {label, warn, takedown}`.
    KindGate,
    /// REQ-S3 — `kind = takedown` against an account-shaped subject.
    AccountTakedown,
    /// REQ-S4 — human moderator ruled on the subject in the recent
    /// past with `no_action` or `reverse`; that verdict stands.
    SubjectCooldown,
    /// REQ-S5 — autonomous actions on this policy in the last hour
    /// already meet `autonomous_rate_limit_per_hour`.
    RateLimit,
    /// REQ-S6 — 7-day human-reversal rate exceeds the configured
    /// breaker threshold; also writes a 24-h pause.
    ReversalBreaker,
    /// REQ-S7 — `polaris_setup_state.global_autonomous_pause_until`
    /// is in the future.
    GlobalPause,
    /// REQ-S8 — `policy.human_required_always = TRUE`; this policy
    /// can never auto-fire (CSAM / regulatory class).
    HumanRequired,
}

impl SafetyFloor {
    /// Label string for the Prometheus `floor` label
    /// (`polaris_llm_safety_floor_tripped_total`). Stable across
    /// releases — operators write Grafana alerts off these names so
    /// renaming breaks dashboards. Match the names listed in
    /// `.design/llm-moderation-assist.md` REQ-I1 verbatim.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Confidence => "confidence",
            Self::KindGate => "kind_gate",
            Self::AccountTakedown => "account_takedown_block",
            Self::SubjectCooldown => "cooldown",
            Self::RateLimit => "rate_limit",
            Self::ReversalBreaker => "circuit_breaker",
            Self::GlobalPause => "global_pause",
            Self::HumanRequired => "csam_block",
        }
    }
}

/// A single floor's verdict.
///
/// Returned by each per-floor helper inside an `Option`:
/// `None` = the floor passed cleanly, `Some(_)` = it tripped and the
/// dispatcher must downgrade.
///
/// `downgrade_to_manual = true` is the **hard-block** flavour — the
/// recommendation becomes advisory-only no matter what the policy
/// says. `false` is the soft downgrade — a rate-limit trip on an
/// otherwise-autonomous policy lands the recommendation in the
/// `pending_auto_actions` queue for human approval.
#[derive(Debug, Clone)]
pub struct FloorTripped {
    /// Which floor.
    pub which: SafetyFloor,
    /// Human-readable rationale (the assisted-mode UI shows this).
    pub detail: String,
    /// `true` = downgrade to manual (advisory-only); `false` =
    /// downgrade to assisted (queue for moderator approval).
    pub downgrade_to_manual: bool,
}

/// Evaluate every REQ-S1..S8 invariant against the supplied
/// recommendation and return the resulting [`EffectiveMode`].
///
/// # Behaviour
///
/// * Every floor is evaluated (not just the first trip) so the
///   `polaris_llm_safety_floor_tripped_total{policy, floor}`
///   counter records the full distribution. Each pass *and* each
///   trip increments a series tagged with the policy identifier and
///   the floor name.
/// * The first trip in **priority order** (S8 → S7 → S6 → S5 → S4
///   → S3 → S2 → S1) determines the returned mode. The priority
///   ordering matches "hardest block first" so when multiple floors
///   would all trip the operator sees the most consequential cause
///   in the structured log + the assisted-queue UI.
/// * S6 (reversal-rate breaker) has a side effect: tripping writes
///   a successor `mod_policies` row with `autonomous_paused_until =
///   now() + 24h` so the policy is paused without operator
///   intervention. The side effect runs **before** this function
///   returns; the caller does not need to do anything extra.
///
/// # Confidence downgrade (REQ-S1)
///
/// The confidence floor is the only one that can produce *either*
/// [`EffectiveMode::Assisted`] or [`EffectiveMode::Manual`] depending
/// on where the confidence lands:
///
/// * `>= autonomous_confidence_threshold` — S1 passes; check other floors.
/// * `>= assisted_confidence_threshold` and `< autonomous` — downgrade to
///   `Assisted { reason: "confidence below autonomous threshold" }`.
/// * `< assisted_confidence_threshold` — downgrade to `Manual`
///   (the case-view advisory panel; no draft created).
///
/// # Errors
///
/// Returns `sqlx::Error` if any DB-touching floor (S4, S5, S6, S7)
/// fails to query. Pure floors (S1, S2, S3, S8) never fail.
///
/// # Example
///
/// ```ignore
/// use polaris_backend::llm::safety_floors::{evaluate, EffectiveMode};
/// use polaris_backend::repo::mod_policies;
///
/// let policy = mod_policies::current_by_identifier(&pool, "polaris.spam")
///     .await?
///     .expect("policy seeded");
/// let mode = evaluate(&pool, &policy, "label", 0.97, subject_id, "post").await?;
/// assert!(matches!(mode, EffectiveMode::Autonomous));
/// ```
#[allow(
    clippy::too_many_lines,
    reason = "single orchestrator: walks every floor in priority order, \
              increments per-floor metrics, returns the first trip. \
              Splitting would force passing the policy + pool through \
              eight helper hops and obscure the priority-order story."
)]
pub async fn evaluate(
    pool: &PgPool,
    policy: &ModPolicy,
    recommended_action_kind: &str,
    confidence: f32,
    subject_id: Uuid,
    subject_kind: &str,
) -> Result<EffectiveMode, sqlx::Error> {
    // Pre-allocate a vec of trips in priority order. We walk every
    // floor (not short-circuit) so the metric records the full
    // distribution; the *return* picks the first hard-priority trip.
    let mut trips: Vec<FloorTripped> = Vec::with_capacity(8);

    // S8 — hardest block.
    record_floor(policy, SafetyFloor::HumanRequired);
    if let Some(t) = check_s8_human_required(policy) {
        trips.push(t);
    }

    // S7 — global kill switch.
    record_floor(policy, SafetyFloor::GlobalPause);
    if let Some(t) = check_s7_global_pause(pool).await? {
        trips.push(t);
    }

    // S6 — reversal-rate circuit breaker. Side-effecting: trip
    // writes a 24-hour autonomous_paused_until on the policy.
    record_floor(policy, SafetyFloor::ReversalBreaker);
    if let Some(t) = check_s6_reversal_breaker(pool, policy).await? {
        trips.push(t);
    }

    // S5 — per-policy rate limit.
    record_floor(policy, SafetyFloor::RateLimit);
    if let Some(t) = check_s5_rate_limit(pool, policy).await? {
        trips.push(t);
    }

    // S4 — subject cooldown.
    record_floor(policy, SafetyFloor::SubjectCooldown);
    if let Some(t) = check_s4_subject_cooldown(pool, subject_id).await? {
        trips.push(t);
    }

    // S3 — account-takedown gate.
    record_floor(policy, SafetyFloor::AccountTakedown);
    if let Some(t) = check_s3_account_takedown(recommended_action_kind, subject_kind) {
        trips.push(t);
    }

    // S2 — action-kind gate.
    record_floor(policy, SafetyFloor::KindGate);
    if let Some(t) = check_s2_kind_gate(policy, recommended_action_kind) {
        trips.push(t);
    }

    // S1 — confidence floor. Different shape: it can land EITHER on
    // assisted (between thresholds) or on manual (below both), so it
    // is the only floor whose downgrade depends on a magnitude
    // comparison rather than a binary pass/fail. Evaluated last in
    // priority but reported last in the trip vec.
    record_floor(policy, SafetyFloor::Confidence);
    let s1 = check_s1_confidence(policy, confidence);
    if let Some(ref t) = s1 {
        trips.push(t.clone());
    }

    // Priority-order return: walk the trips vec from front (highest
    // priority) to back; the first one decides the mode.
    if let Some(first) = trips.first() {
        tracing::warn!(
            policy_identifier = %policy.identifier,
            floor = %first.which.metric_label(),
            downgrade_to_manual = first.downgrade_to_manual,
            detail = %first.detail,
            trips_count = trips.len(),
            "llm safety floor tripped",
        );
        if first.downgrade_to_manual {
            return Ok(EffectiveMode::Manual);
        }
        return Ok(EffectiveMode::Assisted {
            reason: first.detail.clone(),
        });
    }

    Ok(EffectiveMode::Autonomous)
}

/// Increment the `polaris_llm_safety_floor_tripped_total` counter
/// once per floor evaluation. The counter records *evaluations* not
/// *trips* — both pass and fail bump the same series so the operator
/// can see "S4 was evaluated 1000 times, tripped 12 of them" as
/// rate-of-trip queries on the timeseries.
///
/// Stable label vocabulary (REQ-I1):
/// `confidence | kind_gate | account_takedown_block | cooldown |
///  rate_limit | circuit_breaker | global_pause | csam_block`.
fn record_floor(policy: &ModPolicy, floor: SafetyFloor) {
    metrics::counter!(
        "polaris_llm_safety_floor_tripped_total",
        "policy" => policy.identifier.clone(),
        "floor" => floor.metric_label().to_owned(),
    )
    .increment(1);
}

// ── Pure floors (no I/O) ────────────────────────────────────────────

/// REQ-S1: confidence floors.
///
/// Returns `None` when `confidence >= autonomous_confidence_threshold`.
/// Otherwise returns a [`FloorTripped`] with `downgrade_to_manual`
/// set per the rule:
/// * confidence between the two thresholds → assisted (soft).
/// * confidence below both → manual (hard).
#[must_use]
pub fn check_s1_confidence(policy: &ModPolicy, confidence: f32) -> Option<FloorTripped> {
    if confidence >= policy.autonomous_confidence_threshold {
        return None;
    }
    let downgrade_to_manual = confidence < policy.assisted_confidence_threshold;
    Some(FloorTripped {
        which: SafetyFloor::Confidence,
        detail: format!(
            "confidence {confidence:.3} below autonomous threshold \
             {threshold:.3}",
            threshold = policy.autonomous_confidence_threshold,
        ),
        downgrade_to_manual,
    })
}

/// REQ-S2: action-kind gate.
///
/// The recommended kind must be in `policy.autonomous_action_kinds`
/// AND in the workspace-global eligible set `{label, warn, takedown}`
/// (the latter set is the workbook's REQ-G1 hard floor — `escalate`,
/// `mute`, `no_action`, `reverse` can never auto-fire).
///
/// Returns `Some` with `downgrade_to_manual = true` because a kind
/// outside the policy's allow-list signals "this verb is never
/// permitted autonomously on this policy" — no degree of human
/// re-review changes the verb category, so the queue path is the
/// wrong shape.
#[must_use]
pub fn check_s2_kind_gate(policy: &ModPolicy, recommended_kind: &str) -> Option<FloorTripped> {
    const GLOBAL_AUTONOMOUS_KINDS: &[&str] = &["label", "warn", "takedown"];

    let globally_eligible = GLOBAL_AUTONOMOUS_KINDS.contains(&recommended_kind);
    let policy_allows = policy
        .autonomous_action_kinds
        .iter()
        .any(|k| k == recommended_kind);

    if globally_eligible && policy_allows {
        return None;
    }

    let reason = if globally_eligible {
        format!(
            "action kind {recommended_kind:?} is not in policy's \
             autonomous_action_kinds"
        )
    } else {
        format!(
            "action kind {recommended_kind:?} is never eligible for \
             autonomous emission (allowed: label, warn, takedown)"
        )
    };
    Some(FloorTripped {
        which: SafetyFloor::KindGate,
        detail: reason,
        downgrade_to_manual: true,
    })
}

/// REQ-S3 (REQ-G2): account-takedown gate.
///
/// `kind = 'takedown'` is autonomously eligible only for `subject_kind
/// = 'post'`. Account-level takedowns are always human-required (the
/// blast radius is too large for an LLM to own). Any non-takedown
/// kind passes this check automatically.
///
/// Returns `Some` with `downgrade_to_manual = true` — like S2, this
/// is a categorical "no" not a "wait for a human to approve". The
/// dispatcher should not put an account-takedown draft in the
/// queue; the moderator must take this from scratch.
#[must_use]
pub fn check_s3_account_takedown(
    recommended_kind: &str,
    subject_kind: &str,
) -> Option<FloorTripped> {
    if recommended_kind != "takedown" {
        return None;
    }
    if subject_kind == "post" {
        return None;
    }
    Some(FloorTripped {
        which: SafetyFloor::AccountTakedown,
        detail: format!(
            "takedown of {subject_kind} subject is never autonomously \
             eligible (post-only)"
        ),
        downgrade_to_manual: true,
    })
}

/// REQ-S8: `human_required_always` hard block.
///
/// A policy marked `human_required_always = TRUE` (the CSAM / abuse-
/// of-power / regulatory-class case in the workbook) can never auto-
/// fire regardless of every other config. The action-create API
/// enforces the same floor; the dispatcher refusing here is the
/// defence-in-depth posture.
#[must_use]
pub fn check_s8_human_required(policy: &ModPolicy) -> Option<FloorTripped> {
    if !policy.human_required_always {
        return None;
    }
    Some(FloorTripped {
        which: SafetyFloor::HumanRequired,
        detail: format!(
            "policy {} is human_required_always; never autonomously \
             eligible",
            policy.identifier,
        ),
        downgrade_to_manual: true,
    })
}

// ── DB-bound floors ─────────────────────────────────────────────────

/// REQ-S4: subject cooldown.
///
/// If any `actions` row exists in the last N days (`N` =
/// `POLARIS_AUTONOMOUS_SUBJECT_COOLDOWN_DAYS` or 30) against this
/// subject with `actor_kind = 'human'` AND `kind IN ('no_action',
/// 'reverse')`, the dispatcher refuses autonomous emission. The
/// human said "this is fine" or "the prior action was wrong" — the
/// agent does not overturn that without human re-review.
///
/// Soft downgrade (`downgrade_to_manual = false`) — the moderator
/// can still approve via the assisted-queue path; that re-review
/// flow is the explicit override pattern the design names.
///
/// # Errors
///
/// `sqlx::Error` on any DB failure.
pub async fn check_s4_subject_cooldown(
    pool: &PgPool,
    subject_id: Uuid,
) -> Result<Option<FloorTripped>, sqlx::Error> {
    let days = cooldown_days();
    let count: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) AS "count!"
        FROM actions
        WHERE subject_id = $1
          AND actor_kind = 'human'
          AND kind IN ('no_action', 'reverse')
          AND created_at >= now() - make_interval(days => $2::INT)
        "#,
        subject_id,
        days,
    )
    .fetch_one(pool)
    .await?;

    if count == 0 {
        return Ok(None);
    }
    Ok(Some(FloorTripped {
        which: SafetyFloor::SubjectCooldown,
        detail: format!(
            "subject has {count} human no_action/reverse action(s) in \
             the last {days} day(s); cooldown active"
        ),
        downgrade_to_manual: false,
    }))
}

/// REQ-S5: per-policy rate limit.
///
/// Counts autonomous actions on this policy in the last hour
/// (joined through `action_policy_citations`) and returns `Some` if
/// the count is at or above `policy.autonomous_rate_limit_per_hour`.
///
/// Soft downgrade — assisted queue is the right destination because
/// the limit is recovery-time, not a categorical refusal. When the
/// counter drains the policy can fire again at its natural cadence.
///
/// # Errors
///
/// `sqlx::Error` on any DB failure.
pub async fn check_s5_rate_limit(
    pool: &PgPool,
    policy: &ModPolicy,
) -> Result<Option<FloorTripped>, sqlx::Error> {
    let count: i64 = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) AS "count!"
        FROM actions a
        JOIN action_policy_citations c ON c.action_id = a.id
        WHERE c.policy_identifier = $1
          AND a.actor_kind = 'autonomous_agent'
          AND a.created_at >= now() - INTERVAL '1 hour'
        "#,
        policy.identifier,
    )
    .fetch_one(pool)
    .await?;

    let limit = i64::from(policy.autonomous_rate_limit_per_hour);
    if count < limit {
        return Ok(None);
    }
    Ok(Some(FloorTripped {
        which: SafetyFloor::RateLimit,
        detail: format!(
            "policy {identifier} has emitted {count} autonomous action(s) \
             in the last hour; rate limit is {limit}/hour",
            identifier = policy.identifier,
        ),
        downgrade_to_manual: false,
    }))
}

/// REQ-S6: reversal-rate circuit breaker.
///
/// Computes the 7-day human-reversal rate for autonomous actions on
/// this policy. When the rate exceeds the policy's
/// `autonomous_reversal_breaker_threshold`, this function:
///
/// 1. Writes a successor `mod_policies` row via
///    [`mod_policies::pause_for_circuit_breaker`] with
///    `autonomous_paused_until = now() + 24h` and
///    `change_summary = "auto-paused by reversal-rate circuit breaker"`.
/// 2. Emits a `warn!` structured log event for incident-response
///    triage.
/// 3. Returns `Some` with `downgrade_to_manual = true` — the policy
///    is now paused outright, queueing a draft would be
///    inconsistent.
///
/// The window is fixed at 7 days per the design's Q3 resolution. The
/// threshold is per-policy with a workspace default of 0.15.
///
/// # Errors
///
/// `sqlx::Error` on any DB failure (read OR the pause write).
pub async fn check_s6_reversal_breaker(
    pool: &PgPool,
    policy: &ModPolicy,
) -> Result<Option<FloorTripped>, sqlx::Error> {
    // One round trip: COUNT autonomous + COUNT reverses-of-autonomous
    // in the same projection.
    let row = sqlx::query!(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE a.actor_kind = 'autonomous_agent') AS "total!",
            COUNT(*) FILTER (
                WHERE a.kind = 'reverse'
                  AND a.actor_kind = 'human'
                  AND a.reverses_action_id IS NOT NULL
                  AND a.reverses_action_id IN (
                      SELECT a2.id
                      FROM actions a2
                      JOIN action_policy_citations c2 ON c2.action_id = a2.id
                      WHERE c2.policy_identifier = $1
                        AND a2.actor_kind = 'autonomous_agent'
                  )
            ) AS "reversed!"
        FROM actions a
        LEFT JOIN action_policy_citations c ON c.action_id = a.id
        WHERE (c.policy_identifier = $1 OR a.reverses_action_id IS NOT NULL)
          AND a.created_at >= now() - INTERVAL '7 days'
        "#,
        policy.identifier,
    )
    .fetch_one(pool)
    .await?;

    let total = row.total;
    let reversed = row.reversed;

    if total < REVERSAL_BREAKER_MIN_SAMPLES {
        return Ok(None);
    }

    // Convert via f64 for the ratio so the comparison is well-
    // defined even at small denominators; cast back through f32 to
    // match the policy field's precision.
    #[allow(
        clippy::cast_precision_loss,
        reason = "i64 → f64 for ratio; total is at most low-thousands"
    )]
    let rate = (reversed as f64) / (total as f64);
    let threshold = f64::from(policy.autonomous_reversal_breaker_threshold);
    if rate <= threshold {
        return Ok(None);
    }

    // Side effect: pause the policy for 24 hours. Run this in its
    // own short transaction; the evaluator is called from the
    // dispatcher which already manages its own (longer) tx, but
    // pausing should commit atomically irrespective of whether the
    // dispatcher's main tx commits — even if the recommendation
    // fails to land, the pause must stick.
    let mut tx = pool.begin().await?;
    if let Err(err) = mod_policies::pause_for_circuit_breaker(&mut tx, &policy.identifier, 24).await
    {
        // Treat a missing policy as "nothing to pause" — the
        // breaker still trips, just no side effect. Any other
        // failure escalates so the caller can decide.
        match err {
            mod_policies::ModPolicyError::UnknownIdentifier { .. } => {
                tracing::warn!(
                    policy_identifier = %policy.identifier,
                    "reversal-rate breaker tripped but policy not found for pause",
                );
            }
            mod_policies::ModPolicyError::Database(e) => return Err(e),
            other => {
                tracing::error!(
                    policy_identifier = %policy.identifier,
                    error = %other,
                    "reversal-rate breaker tripped; pause write failed unexpectedly",
                );
            }
        }
    } else {
        tx.commit().await?;
        tracing::warn!(
            policy_identifier = %policy.identifier,
            total_window = total,
            reversed_window = reversed,
            rate = rate,
            threshold = threshold,
            "reversal-rate circuit breaker tripped; policy paused for 24h",
        );
    }

    Ok(Some(FloorTripped {
        which: SafetyFloor::ReversalBreaker,
        detail: format!(
            "policy reversal rate {rate:.3} exceeds threshold \
             {threshold:.3} ({reversed} of {total} autonomous actions \
             reversed in the last 7 days); auto-paused 24h"
        ),
        downgrade_to_manual: true,
    }))
}

/// REQ-S7: global kill-switch.
///
/// Reads `polaris_setup_state.global_autonomous_pause_until`. NULL
/// or past-timestamp means "not paused"; a future timestamp means
/// "paused until that moment".
///
/// Hard downgrade (`downgrade_to_manual = true`) — the kill switch
/// is the operator's "stop everything" lever; queueing a draft is
/// inconsistent with that intent.
///
/// # Errors
///
/// `sqlx::Error` on any DB failure.
pub async fn check_s7_global_pause(pool: &PgPool) -> Result<Option<FloorTripped>, sqlx::Error> {
    let until: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar!(
        r#"
        SELECT global_autonomous_pause_until
        FROM polaris_setup_state
        WHERE id = TRUE
        "#,
    )
    .fetch_optional(pool)
    .await?
    .flatten();

    let Some(t) = until else { return Ok(None) };
    if t <= chrono::Utc::now() {
        return Ok(None);
    }
    Ok(Some(FloorTripped {
        which: SafetyFloor::GlobalPause,
        detail: format!("global autonomous pause active until {t}"),
        downgrade_to_manual: true,
    }))
}

/// `POLARIS_AUTONOMOUS_SUBJECT_COOLDOWN_DAYS` reader (Q2). Falls
/// back to 30 days on missing or unparsable env.
fn cooldown_days() -> i32 {
    env::var("POLARIS_AUTONOMOUS_SUBJECT_COOLDOWN_DAYS")
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .filter(|n| *n >= 0)
        .unwrap_or(30)
}

/// Helper for callers that need to drive S6's pause as a side-
/// effect inside a caller-managed transaction (e.g. the dispatcher
/// when it wants the pause to commit alongside the LLM observation
/// in a single tx). Not used by [`evaluate`] today — kept for
/// possible future refactoring.
#[allow(
    dead_code,
    reason = "future surface; the dispatcher's tx topology may want to drive \
              the breaker pause inside its main tx rather than the \
              standalone short tx evaluate() opens today."
)]
pub(crate) async fn pause_policy_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    identifier: &str,
    hours: i32,
) -> Result<(), mod_policies::ModPolicyError> {
    mod_policies::pause_for_circuit_breaker(tx, identifier, hours).await
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn fixture_policy() -> ModPolicy {
        ModPolicy {
            id: Uuid::new_v4(),
            identifier: "polaris.test".to_owned(),
            version: 1,
            name: "test".to_owned(),
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
            autonomy_mode: "autonomous".to_owned(),
            autonomous_action_kinds: vec!["label".to_owned(), "warn".to_owned()],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.7,
            autonomous_rate_limit_per_hour: 60,
            autonomous_reversal_breaker_threshold: 0.15,
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

    #[test]
    fn s1_above_threshold_passes() {
        let p = fixture_policy();
        assert!(check_s1_confidence(&p, 0.99).is_none());
    }

    #[test]
    fn s1_between_thresholds_downgrades_to_assisted() {
        let p = fixture_policy();
        let t = check_s1_confidence(&p, 0.80).expect("must trip");
        assert!(!t.downgrade_to_manual);
    }

    #[test]
    fn s1_below_both_thresholds_downgrades_to_manual() {
        let p = fixture_policy();
        let t = check_s1_confidence(&p, 0.50).expect("must trip");
        assert!(t.downgrade_to_manual);
    }

    #[test]
    fn s2_allowed_kind_passes() {
        let p = fixture_policy();
        assert!(check_s2_kind_gate(&p, "label").is_none());
    }

    #[test]
    fn s2_kind_not_in_policy_list_trips() {
        let p = fixture_policy();
        let t = check_s2_kind_gate(&p, "takedown").expect("must trip");
        assert!(t.downgrade_to_manual);
    }

    #[test]
    fn s2_escalate_always_trips_even_if_in_policy_list() {
        let mut p = fixture_policy();
        p.autonomous_action_kinds.push("escalate".to_owned());
        let t = check_s2_kind_gate(&p, "escalate").expect("must trip");
        assert!(t.downgrade_to_manual);
    }

    #[test]
    fn s3_takedown_post_passes() {
        assert!(check_s3_account_takedown("takedown", "post").is_none());
    }

    #[test]
    fn s3_takedown_account_trips() {
        let t = check_s3_account_takedown("takedown", "account").expect("must trip");
        assert!(t.downgrade_to_manual);
    }

    #[test]
    fn s3_label_account_passes() {
        // The gate only fires for takedowns; labels on accounts are fine.
        assert!(check_s3_account_takedown("label", "account").is_none());
    }

    #[test]
    fn s8_human_required_trips() {
        let mut p = fixture_policy();
        p.human_required_always = true;
        let t = check_s8_human_required(&p).expect("must trip");
        assert!(t.downgrade_to_manual);
    }

    #[test]
    fn s8_not_required_passes() {
        let p = fixture_policy();
        assert!(check_s8_human_required(&p).is_none());
    }

    #[test]
    fn cooldown_days_default_is_30() {
        // Sanity: documented default in Q2 of the design.
        // The env-aware path is integration-tested under
        // tests/llm_safety_floors.rs (S4 cases) where setting an
        // env var is safe.
        // SAFETY: tests run with `--test-threads` defaulting to
        // cores; we read but never mutate the env here.
        let stored = std::env::var("POLARIS_AUTONOMOUS_SUBJECT_COOLDOWN_DAYS").ok();
        if stored.is_none() {
            assert_eq!(cooldown_days(), 30);
        }
    }
}
