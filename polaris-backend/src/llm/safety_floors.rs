//! Safety-floor evaluation for the LLM recommendation dispatcher
//! (`.design/llm-moderation-assist.md` REQ-S1..S8).
//!
//! # STATUS: STUB
//!
//! REQ-S1..S8 are owned by issue **#235** (LLM-6). This module currently
//! returns [`EffectiveMode::Autonomous`] **unconditionally** so the
//! LLM-5 dispatcher pipeline (#242) can be written and tested
//! end-to-end while #235 is in flight.
//!
//! DO NOT ship a production build with this stub. Flipping any policy
//! to `autonomy_mode = 'autonomous'` before #235 lands would bypass
//! every one of the safety invariants the design enumerates:
//!
//! | Floor   | Rule                                                       |
//! | ------- | ---------------------------------------------------------- |
//! | REQ-S1  | Confidence floor (`confidence ≥ autonomous_confidence_threshold`). |
//! | REQ-S2  | Action-kind gate (`{label, warn, takedown}` only).         |
//! | REQ-S3  | Account-takedown gate (post-only autonomous).              |
//! | REQ-S4  | Subject cooldown (30-day human `no_action`/`reverse`).     |
//! | REQ-S5  | Per-policy rate limit (60/hour default).                   |
//! | REQ-S6  | Reversal-rate circuit breaker (15% / 7-day window).        |
//! | REQ-S7  | Global kill-switch (`POST /api/admin/llm/pause`).          |
//! | REQ-S8  | `human_required_always` hard block.                        |
//!
//! TODO(#235): replace [`evaluate`] with the real evaluator that walks
//! every rule above. The dispatcher already plumbs the inputs each
//! rule needs through this function's signature; expanding the body
//! is local to this file.

use uuid::Uuid;

/// The mode the dispatcher actually applies to a recommendation, AFTER
/// the safety-floor evaluation downgrades (or leaves intact) the
/// policy's declared `autonomy_mode`.
///
/// The dispatcher routes per this value, not per the policy column:
/// a policy declared `autonomous` may be downgraded to `Assisted` if
/// a floor trips, and `Assisted` may degrade further to `Manual` if
/// confidence is below `assisted_confidence_threshold` (REQ-S1).
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

/// Decide which [`EffectiveMode`] the dispatcher should apply to a
/// single `RecommendedAction` against a cited policy.
///
/// # STUB BEHAVIOUR (today, until #235 lands)
///
/// Returns [`EffectiveMode::Autonomous`] unconditionally. The
/// dispatcher's autonomous-path code is exercised under this stub;
/// the manual / assisted paths are reachable through other
/// short-circuits (`NoAutonomyEnabled`, etc.) in the dispatcher
/// itself.
///
/// # Real implementation (LLM-6 #235)
///
/// REQ-S1..S8 will be evaluated in this order:
///
/// 1. REQ-S7 — global kill-switch (admin pause).
/// 2. REQ-S8 — `human_required_always` policy.
/// 3. REQ-S2 — action-kind gate.
/// 4. REQ-S3 — account-takedown gate.
/// 5. REQ-S1 — confidence floors.
/// 6. REQ-S4 — subject cooldown.
/// 7. REQ-S5 — per-policy rate limit.
/// 8. REQ-S6 — reversal-rate circuit breaker.
///
/// Any trip downgrades autonomous → assisted; assisted with confidence
/// below `assisted_confidence_threshold` further downgrades to manual.
#[allow(
    clippy::unused_async,
    reason = "stub: the real impl in #235 will run DB-bound checks (subject \
              cooldown, per-policy rate limit, reversal-rate breaker, global \
              pause). Keeping the signature `async` here so #235 lands as a \
              body-only change without rippling through every call site that \
              already `.await`s this function."
)]
pub async fn evaluate(
    _policy_identifier: &str,
    _policy_version: i32,
    _recommended_action_kind: &str,
    _confidence: f32,
    _subject_id: Uuid,
    _pool: &sqlx::PgPool,
) -> EffectiveMode {
    // STUB — see module-level docs. Real impl in #235.
    EffectiveMode::Autonomous
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    /// Documents the stub contract: until #235 lands, every call
    /// resolves to `Autonomous`. A real impl that flips this will
    /// break this test deliberately so the changelog notes that the
    /// floors are now live.
    #[tokio::test]
    async fn stub_returns_autonomous_unconditionally() {
        // The stub never touches the pool, so a lazy / unconnected
        // pool is fine. `PgPool::connect_lazy` does not actually
        // connect until the first query.
        let pool = PgPool::connect_lazy("postgres://stub").unwrap();
        let outcome = evaluate("polaris.spam", 1, "label", 0.99, Uuid::new_v4(), &pool).await;
        assert!(matches!(outcome, EffectiveMode::Autonomous));
    }
}
