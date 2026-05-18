//! LLM moderation-assist feedback loop (LLM-10 / #239 / REQ-G1..G4).
//!
//! Closes the autonomous-action learning cycle the LLM substrate
//! ([`.design/llm-moderation-assist.md`]) needs to improve its
//! decisions over time. Three paths emit a `Feedback` RPC into the
//! classifier transport that backs the dispatcher; each path carries
//! a single bit of outcome signal plus optional free-text reasoning.
//!
//! | Path                                | Trigger                                                       | `was_recommendation_taken` | `reversal_reasoning`            |
//! |-------------------------------------|---------------------------------------------------------------|----------------------------|---------------------------------|
//! | [`fire_reversal_feedback`]          | Moderator reverses an `actor_kind = 'autonomous_agent'` row.  | `false`                    | Moderator's stated reason.      |
//! | [`fire_assisted_reject_feedback`]   | Moderator rejects a `pending_auto_actions` draft.             | `false`                    | Moderator's stated reason.      |
//! | [`fire_confirmation_feedback`]      | Daily batch finds an autonomous action whose                  | `true`                     | `""` (no intervention occurred).|
//! |                                     | `reversible_until` window elapsed unreversed.                 |                            |                                 |
//!
//! Each path is **fire-and-forget**: the call is wrapped in a
//! `tokio::spawn` and the delivery future runs to completion outside
//! the user-facing request path. Failures log at WARN and never block
//! the moderator's reversal / reject / expiry workflow. This mirrors
//! the existing [`crate::classifier::spawn_feedback`] discipline.
//!
//! # Privacy invariant (REQ-G4)
//!
//! NO moderator identity flows into the wire envelope. The build path
//! ([`crate::classifier::build_feedback_with_outcome`]) takes
//! `&str` for the reasoning — there is no `ModeratorId`, handle, or
//! DID parameter in the signature. The three `fire_*` functions
//! below take a `&str` reasoning argument; the caller (the
//! action-create handler, the queue-reject handler, the daily batch)
//! is responsible for passing the moderator's stated *reason* with
//! no identity columns concatenated in. Regression tests in
//! `polaris-backend/tests/llm_feedback_privacy.rs` encode each
//! path's payload and scan for DID / handle / `did:` prefixes.
//!
//! # Daily batch (REQ-G3)
//!
//! [`run_daily_confirmation_batch`] is scheduled on a 24-hour
//! `tokio::time::interval` tick wired from `polaris-backend/src/main.rs`.
//! The query finds every `actor_kind = 'autonomous_agent'` action
//! whose `reversible_until` has passed AND for which no row in
//! `actions` exists with `kind = 'reverse'` AND
//! `reverses_action_id = this.id`. For each matched action, a
//! confirmation `Feedback` RPC is spawned.
//!
//! Idempotency: the batch reads each action's `llm_observation_id`
//! and uses that observation's row id as the wire `event_id`. The
//! batch does NOT persist a "confirmed" marker — re-running the
//! batch against the same data would re-emit the same feedback. This
//! is acceptable for the LLM substrate (RAG corpora and fine-tuning
//! pipelines dedupe on event_id), and avoids a second write path
//! that the append-only `actions` table is hostile to. If the LLM
//! substrate becomes sensitive to duplicates, a `confirmed_at`
//! column on `actions` is the right next step — out of scope for
//! LLM-10.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{info, warn};
use uuid::Uuid;

use crate::classifier::{ClassifierClient, build_feedback_with_outcome};
use polaris_types::ActionKind;

/// Errors surfaced by the LLM feedback loop.
///
/// The fire-and-forget call sites log+drop these — the
/// learning-loop signal is not action-critical (per design REQ-G4
/// the moderator's action proceeds regardless of feedback delivery).
/// The variant set exists so the batch runner can return a typed
/// error from the spawned task and the daily-tick wiring can count
/// failures distinctly from successes.
#[derive(Debug, Error)]
pub enum FeedbackError {
    /// SQL failure reading the action / observation row that backs a
    /// feedback envelope.
    #[error("feedback database query failed: {0}")]
    Database(#[from] sqlx::Error),

    /// The action referenced by the feedback path does not have a
    /// non-NULL `llm_observation_id`. This is a logic error at the
    /// call site — the reversal-feedback path should only fire when
    /// the reversed action is autonomous, and an autonomous action
    /// MUST carry the audit envelope (DB CHECK
    /// `actions_autonomous_audit_complete`, migration 51).
    #[error(
        "action {action_id} has no llm_observation_id but the caller asserted autonomous origin"
    )]
    MissingObservation {
        /// The action row that failed the audit-envelope precondition.
        action_id: Uuid,
    },
}

/// One row of the autonomous-action backing data the feedback paths
/// need: the LLM observation id (becomes the wire `event_id`), the
/// model's classifier_label hint, the model's confidence, and the
/// human-facing `ActionKind` (so the feedback envelope's
/// `moderator_action_kind` aligns with the wire vocabulary in
/// [`crate::classifier::action_kind_wire_string`]).
///
/// Populated by [`load_feedback_context`] from a single SELECT
/// against `actions` (with the LLM audit columns) so the spawned
/// feedback task does not race the row away.
#[derive(Debug, Clone)]
pub struct FeedbackContext {
    /// The LLM observation row id — the wire `event_id` on the
    /// feedback envelope. Aligns with the LLM substrate's correlation
    /// key (the same id appears in the `LlmRecommendation`
    /// observation's `evidence` JSONB).
    pub event_id: Uuid,
    /// The model's recommended-action-kind label (e.g. `"takedown"`).
    /// Threaded into the envelope as `classifier_label`.
    pub classifier_label: String,
    /// The model's reported confidence in its recommendation, in
    /// `[0.0, 1.0]`.
    pub classifier_confidence: f32,
    /// The wire moderator-action-kind. For the reversal path this is
    /// `Reverse`; for the assisted-reject path it is `NoAction`; for
    /// the confirmation path it is the *original* autonomous action's
    /// kind (the LLM's recommendation stood, so the moderator's
    /// "implicit" action_kind matches the agent's).
    pub moderator_action_kind: ActionKind,
}

/// Fire a reversal-feedback `Feedback` RPC (REQ-G1).
///
/// Spawned fire-and-forget from
/// [`crate::api::cases::submit_action`] when a moderator submits a
/// `kind = Reverse` action targeting an autonomous-agent action row.
/// The reversed action's audit envelope (LLM observation id, model,
/// model_version, prompt_template_id, recommendation_confidence,
/// input_hash) is loaded via [`load_feedback_context`].
///
/// # Privacy
///
/// `reversal_reasoning` is the moderator's stated reason in free
/// text. NO identity is carried. See module-level docs.
///
/// # Errors
///
/// Returns [`FeedbackError`] for DB-read or precondition failures.
/// The spawn site logs and drops — the user's reversal has already
/// committed.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use polaris_backend::classifier::FixtureClassifierClient;
/// use polaris_backend::classifier::ClassifierClient;
/// use polaris_backend::llm::feedback::{FeedbackContext, fire_reversal_feedback};
/// use polaris_types::ActionKind;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client: Arc<dyn ClassifierClient> =
///     Arc::new(FixtureClassifierClient::new());
/// let ctx = FeedbackContext {
///     event_id: uuid::Uuid::new_v4(),
///     classifier_label: "takedown".to_owned(),
///     classifier_confidence: 0.91,
///     moderator_action_kind: ActionKind::Reverse,
/// };
/// fire_reversal_feedback(
///     client,
///     "llm-autonomous".to_owned(),
///     ctx,
///     "subject was satire, not endorsement",
/// );
/// # Ok(()) }
/// ```
pub fn fire_reversal_feedback(
    client: Arc<dyn ClassifierClient>,
    classifier_name: String,
    ctx: FeedbackContext,
    reversal_reasoning: &str,
) {
    let request = build_feedback_with_outcome(
        ctx.event_id.to_string(),
        ctx.classifier_label,
        ctx.classifier_confidence,
        ctx.moderator_action_kind,
        false,
        reversal_reasoning,
    );
    tokio::spawn(async move {
        if let Err(err) = client.feedback(request).await {
            warn!(
                classifier = %classifier_name,
                error = %err,
                "LLM reversal feedback delivery failed; reversal proceeded normally",
            );
        }
    });
}

/// Fire an assisted-reject-feedback `Feedback` RPC (REQ-G2).
///
/// Spawned fire-and-forget from the assisted-mode draft-reject
/// handler in `polaris-backend/src/api/queue/pending_auto_actions.rs`
/// when a moderator rejects a draft. Carries
/// `was_recommendation_taken = false` and the moderator's stated
/// rejection reason as free text.
///
/// The `event_id` here is the `LlmRecommendation` observation id the
/// draft pins to (the same id stored on
/// `pending_auto_actions.llm_observation_id`).
///
/// # Privacy
///
/// `rejection_reasoning` is the moderator's stated reason in free
/// text. NO identity is carried. See module-level docs.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use polaris_backend::classifier::FixtureClassifierClient;
/// use polaris_backend::classifier::ClassifierClient;
/// use polaris_backend::llm::feedback::{FeedbackContext, fire_assisted_reject_feedback};
/// use polaris_types::ActionKind;
///
/// let client: Arc<dyn ClassifierClient> =
///     Arc::new(FixtureClassifierClient::new());
/// let ctx = FeedbackContext {
///     event_id: uuid::Uuid::new_v4(),
///     classifier_label: "label".to_owned(),
///     classifier_confidence: 0.62,
///     moderator_action_kind: ActionKind::NoAction,
/// };
/// fire_assisted_reject_feedback(
///     client,
///     "llm-assisted".to_owned(),
///     ctx,
///     "model's reasoning didn't account for the parody context",
/// );
/// ```
pub fn fire_assisted_reject_feedback(
    client: Arc<dyn ClassifierClient>,
    classifier_name: String,
    ctx: FeedbackContext,
    rejection_reasoning: &str,
) {
    let request = build_feedback_with_outcome(
        ctx.event_id.to_string(),
        ctx.classifier_label,
        ctx.classifier_confidence,
        ctx.moderator_action_kind,
        false,
        rejection_reasoning,
    );
    tokio::spawn(async move {
        if let Err(err) = client.feedback(request).await {
            warn!(
                classifier = %classifier_name,
                error = %err,
                "LLM assisted-reject feedback delivery failed; reject proceeded normally",
            );
        }
    });
}

/// Fire a positive-confirmation-feedback `Feedback` RPC (REQ-G3).
///
/// Spawned fire-and-forget from [`run_daily_confirmation_batch`] for
/// each autonomous action whose `reversible_until` window has lapsed
/// with no reversal. Carries `was_recommendation_taken = true` and
/// empty reasoning (the action stood without intervention; there is
/// no reasoning to carry).
///
/// # Privacy
///
/// Confirmation feedback is outcome-only. The envelope's
/// `reversal_reasoning` is the empty string — never populated with
/// any moderator metadata. See module-level docs.
///
/// # Examples
///
/// ```rust,no_run
/// use std::sync::Arc;
/// use polaris_backend::classifier::FixtureClassifierClient;
/// use polaris_backend::classifier::ClassifierClient;
/// use polaris_backend::llm::feedback::{FeedbackContext, fire_confirmation_feedback};
/// use polaris_types::ActionKind;
///
/// let client: Arc<dyn ClassifierClient> =
///     Arc::new(FixtureClassifierClient::new());
/// let ctx = FeedbackContext {
///     event_id: uuid::Uuid::new_v4(),
///     classifier_label: "takedown".to_owned(),
///     classifier_confidence: 0.97,
///     moderator_action_kind: ActionKind::Takedown,
/// };
/// fire_confirmation_feedback(client, "llm-autonomous".to_owned(), ctx);
/// ```
pub fn fire_confirmation_feedback(
    client: Arc<dyn ClassifierClient>,
    classifier_name: String,
    ctx: FeedbackContext,
) {
    let request = build_feedback_with_outcome(
        ctx.event_id.to_string(),
        ctx.classifier_label,
        ctx.classifier_confidence,
        ctx.moderator_action_kind,
        true,
        "",
    );
    tokio::spawn(async move {
        if let Err(err) = client.feedback(request).await {
            warn!(
                classifier = %classifier_name,
                error = %err,
                "LLM confirmation feedback delivery failed; expiry was idempotent",
            );
        }
    });
}

/// Load the feedback context for a single action row.
///
/// SELECTs the autonomous-audit columns on `actions`:
///
///   * `llm_observation_id` → wire `event_id`
///   * `recommendation_confidence` → wire `classifier_confidence`
///   * The action's own `kind` → wire `classifier_label` (the model
///     recommended `kind`; the wire `classifier_label` is the
///     recommended-action-kind string).
///   * `moderator_action_kind` is the caller's responsibility — the
///     reversal path passes `Reverse`, the confirmation path passes
///     the original kind.
///
/// # Errors
///
/// Returns [`FeedbackError::Database`] on SQL failure, or
/// [`FeedbackError::MissingObservation`] if the row has a NULL
/// `llm_observation_id` (which violates the audit-envelope CHECK
/// for autonomous rows — see migration 51).
pub async fn load_feedback_context(
    pool: &PgPool,
    action_id: Uuid,
    moderator_action_kind: ActionKind,
) -> Result<FeedbackContext, FeedbackError> {
    let row = sqlx::query!(
        r#"
        SELECT
            kind                       AS "kind!",
            llm_observation_id         AS "llm_observation_id?",
            recommendation_confidence  AS "recommendation_confidence?"
        FROM actions
        WHERE id = $1
        "#,
        action_id,
    )
    .fetch_one(pool)
    .await?;

    let event_id = row
        .llm_observation_id
        .ok_or(FeedbackError::MissingObservation { action_id })?;
    let classifier_confidence = row.recommendation_confidence.unwrap_or(0.0);
    Ok(FeedbackContext {
        event_id,
        classifier_label: row.kind,
        classifier_confidence,
        moderator_action_kind,
    })
}

/// One row matched by the daily confirmation sweep.
#[derive(Debug, Clone)]
struct ExpiredAutonomousAction {
    action_id: Uuid,
    /// The original action kind — the recommendation that stood.
    kind: String,
    /// The LLM observation id that backed the action.
    llm_observation_id: Uuid,
    /// Confidence the model reported.
    recommendation_confidence: f32,
    /// When the action's reversal window lapsed. Used for the
    /// tracing record only.
    #[allow(dead_code, reason = "carried for log/diagnostic structure")]
    reversible_until: DateTime<Utc>,
}

/// Run one tick of the daily confirmation batch (REQ-G3).
///
/// Finds every `actor_kind = 'autonomous_agent'` action whose
/// `reversible_until` has lapsed AND for which no reversal exists,
/// then spawns a [`fire_confirmation_feedback`] for each. Returns
/// the count of confirmations fired.
///
/// # Errors
///
/// Returns [`FeedbackError::Database`] on SQL failure. The caller
/// (the daily-tick worker in `main.rs`) logs+continues — a transient
/// DB error on one tick is recoverable on the next.
///
/// # Idempotency
///
/// See the module-level "Daily batch" section. Each tick re-emits
/// feedback for every matched action because the batch does NOT
/// persist a confirmation marker. The LLM substrate dedupes on
/// `event_id` (the `llm_observation_id`).
pub async fn run_daily_confirmation_batch(
    pool: PgPool,
    classifier_client: Arc<dyn ClassifierClient>,
    classifier_name: String,
) -> Result<usize, FeedbackError> {
    let expired = find_expired_unreversed_autonomous_actions(&pool).await?;
    let count = expired.len();
    if count == 0 {
        return Ok(0);
    }
    info!(
        batch_size = count,
        "LLM confirmation batch: firing positive-signal feedback for \
         expired-unreversed autonomous actions",
    );
    for row in expired {
        let ctx = FeedbackContext {
            event_id: row.llm_observation_id,
            classifier_label: row.kind.clone(),
            classifier_confidence: row.recommendation_confidence,
            moderator_action_kind: action_kind_from_db_string(&row.kind),
        };
        fire_confirmation_feedback(Arc::clone(&classifier_client), classifier_name.clone(), ctx);
        tracing::debug!(
            action_id = %row.action_id,
            llm_observation_id = %row.llm_observation_id,
            "confirmation feedback fired",
        );
    }
    Ok(count)
}

/// SELECT every autonomous action whose `reversible_until` has lapsed
/// and which has not been reversed. NOT EXISTS is the idiomatic
/// anti-join shape here — the partial index on
/// `actions.reverses_action_id WHERE reverses_action_id IS NOT NULL`
/// (migration 4) covers the subquery.
async fn find_expired_unreversed_autonomous_actions(
    pool: &PgPool,
) -> Result<Vec<ExpiredAutonomousAction>, FeedbackError> {
    let rows = sqlx::query!(
        r#"
        SELECT
            a.id                          AS "id!",
            a.kind                        AS "kind!",
            a.llm_observation_id          AS "llm_observation_id!",
            a.recommendation_confidence   AS "recommendation_confidence!",
            a.reversible_until            AS "reversible_until!"
        FROM actions a
        WHERE a.actor_kind = 'autonomous_agent'
          AND a.reversible_until < now()
          AND NOT EXISTS (
              SELECT 1 FROM actions r
              WHERE r.kind = 'reverse'
                AND r.reverses_action_id = a.id
          )
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ExpiredAutonomousAction {
            action_id: r.id,
            kind: r.kind,
            llm_observation_id: r.llm_observation_id,
            recommendation_confidence: r.recommendation_confidence,
            reversible_until: r.reversible_until,
        })
        .collect())
}

/// Decode a DB `actions.kind` string into the typed [`ActionKind`]
/// enum the wire envelope uses. Mirrors the repo's decoder; the
/// fallback to `NoAction` here is defensive — the migration-4 CHECK
/// constraint guarantees one of the known strings, but a future
/// schema drift would otherwise hard-panic the batch.
fn action_kind_from_db_string(s: &str) -> ActionKind {
    match s {
        "label" => ActionKind::Label,
        "takedown" => ActionKind::Takedown,
        "mute" => ActionKind::Mute,
        "warn" => ActionKind::Warn,
        "escalate" => ActionKind::Escalate,
        "reverse" => ActionKind::Reverse,
        "comment" => ActionKind::Comment,
        _ => ActionKind::NoAction,
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
    use crate::classifier::FixtureClassifierClient;

    /// Reversal feedback emits a request with the LLM-10 outcome
    /// envelope populated correctly (was_recommendation_taken=false,
    /// reasoning carried).
    #[tokio::test]
    async fn fire_reversal_feedback_emits_negative_signal_with_reasoning() {
        let fixture = FixtureClassifierClient::new();
        let client: Arc<dyn ClassifierClient> = Arc::new(fixture.clone());

        let event_id = Uuid::new_v4();
        let ctx = FeedbackContext {
            event_id,
            classifier_label: "takedown".to_owned(),
            classifier_confidence: 0.91,
            moderator_action_kind: ActionKind::Reverse,
        };
        fire_reversal_feedback(
            client,
            "llm-autonomous".to_owned(),
            ctx,
            "satire context the model missed",
        );

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let log = fixture.feedback_calls();
        let entry = log
            .get(&event_id.to_string())
            .expect("reversal feedback was delivered");
        assert!(!entry.was_recommendation_taken);
        assert_eq!(entry.reversal_reasoning, "satire context the model missed");
        assert_eq!(entry.classifier_label, "takedown");
    }

    /// Assisted-reject feedback also emits a negative signal with
    /// reasoning attached.
    #[tokio::test]
    async fn fire_assisted_reject_feedback_emits_negative_signal_with_reasoning() {
        let fixture = FixtureClassifierClient::new();
        let client: Arc<dyn ClassifierClient> = Arc::new(fixture.clone());

        let event_id = Uuid::new_v4();
        let ctx = FeedbackContext {
            event_id,
            classifier_label: "label".to_owned(),
            classifier_confidence: 0.62,
            moderator_action_kind: ActionKind::NoAction,
        };
        fire_assisted_reject_feedback(
            client,
            "llm-assisted".to_owned(),
            ctx,
            "parody context the model didn't recognize",
        );

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let log = fixture.feedback_calls();
        let entry = log
            .get(&event_id.to_string())
            .expect("assisted-reject feedback was delivered");
        assert!(!entry.was_recommendation_taken);
        assert_eq!(
            entry.reversal_reasoning,
            "parody context the model didn't recognize",
        );
    }

    /// Confirmation feedback emits a positive signal with empty
    /// reasoning (REQ-G3 — outcome-only).
    #[tokio::test]
    async fn fire_confirmation_feedback_emits_positive_signal_with_empty_reasoning() {
        let fixture = FixtureClassifierClient::new();
        let client: Arc<dyn ClassifierClient> = Arc::new(fixture.clone());

        let event_id = Uuid::new_v4();
        let ctx = FeedbackContext {
            event_id,
            classifier_label: "takedown".to_owned(),
            classifier_confidence: 0.97,
            moderator_action_kind: ActionKind::Takedown,
        };
        fire_confirmation_feedback(client, "llm-autonomous".to_owned(), ctx);

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let log = fixture.feedback_calls();
        let entry = log
            .get(&event_id.to_string())
            .expect("confirmation feedback was delivered");
        assert!(entry.was_recommendation_taken);
        assert!(entry.reversal_reasoning.is_empty());
        assert_eq!(entry.moderator_action_kind, "takedown");
    }

    /// The DB-string decoder covers every variant the migration-4
    /// CHECK admits.
    #[test]
    fn action_kind_from_db_string_round_trip() {
        for (s, expected) in [
            ("label", ActionKind::Label),
            ("takedown", ActionKind::Takedown),
            ("mute", ActionKind::Mute),
            ("warn", ActionKind::Warn),
            ("escalate", ActionKind::Escalate),
            ("reverse", ActionKind::Reverse),
            ("no_action", ActionKind::NoAction),
        ] {
            assert_eq!(action_kind_from_db_string(s), expected);
        }
    }
}
