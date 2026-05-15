//! Moderator-behavior anomaly detector — T1 mitigation (issue #73).
//!
//! # Why this exists
//!
//! `design.md` §9 #1 names "anomaly detection on moderator action
//! patterns (a moderator suddenly labeling 1000 accounts at 3am is itself
//! an incident)" as one of four T1 (compromised-moderator) mitigations.
//! This module implements that detector: after every `actions` insert,
//! query the count of actions the same moderator has committed in a
//! rolling window; if the count exceeds the configured threshold, emit
//! a typed [`polaris_types::ObservationKind::ModeratorBehaviorAnomaly`]
//! against a synthetic per-moderator subject.
//!
//! # Subject shape
//!
//! `observations.subject_id` is a `NOT NULL` FK on `subjects(id)`, so the
//! emission needs a subject row. The detector creates a *synthetic
//! subject* per moderator on first emit, with `kind = 'account'` and
//! `did = 'did:polaris:moderator-anomaly:<moderator_uuid>'`. The DID is
//! deterministic per moderator, so the same moderator's emissions all
//! land on the same subject row (one stream of `ModeratorBehaviorAnomaly`
//! observations per moderator). This piggybacks on the existing FK,
//! risk-signals trigger, and observation read paths without inventing a
//! parallel `moderator_alerts` table.
//!
//! # Hook placement
//!
//! The hook fires inside the action-insert transaction in
//! [`crate::repo::action::PgActionRepo::insert`]. Running the check
//! inside the same transaction makes the action row and any anomaly
//! observation commit atomically — if the count query or the
//! observation insert fails, the action also rolls back. The trade-off
//! is that the action-insert path grows by one count query plus (rarely)
//! one INSERT; the count query is indexed on
//! `(moderator_id, created_at)` (migration `00000000000004_actions.sql`
//! indexes `moderator_id`, and Postgres uses a bitmap + recheck for
//! the `created_at` filter) so the overhead is bounded.
//!
//! # Error discipline
//!
//! Every fallible path returns [`crate::repo::RepoError`] so the caller
//! sees the same error category as any other repo failure. The
//! detector never panics or uses unchecked unwrap/expect outside test
//! code. The synchronous emission inside the action transaction is
//! required by the atomicity story; a fire-and-forget `tokio::spawn`
//! would let the action commit while the observation insert silently
//! fails.

use chrono::{DateTime, Utc};
use polaris_types::{ModeratorId, NewObservation, ObservationId, ObservationKind, SubjectId};
use sqlx::{Postgres, Transaction};

use crate::repo::RepoError;

/// Configuration for the moderator-behavior-anomaly detector.
///
/// Validation lives in [`ModeratorAnomalyConfig::new`] so the per-action
/// hot path never has to re-check. The defaults
/// ([`ModeratorAnomalyConfig::default`]) match the architect's
/// pre-flight: 50 actions in 3600 seconds (one hour).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeratorAnomalyConfig {
    threshold: u32,
    window_secs: u32,
}

impl ModeratorAnomalyConfig {
    /// Build a new configuration.
    ///
    /// # Errors
    ///
    /// Returns [`super::PatternError::InvalidConfig`] when `threshold == 0`
    /// (every action would trip a zero threshold — degenerate) or when
    /// `window_secs == 0` (the count query would always return zero).
    pub fn new(threshold: u32, window_secs: u32) -> Result<Self, super::PatternError> {
        if threshold == 0 {
            return Err(super::PatternError::InvalidConfig(
                "moderator-anomaly threshold must be > 0",
            ));
        }
        if window_secs == 0 {
            return Err(super::PatternError::InvalidConfig(
                "moderator-anomaly window_secs must be > 0",
            ));
        }
        Ok(Self {
            threshold,
            window_secs,
        })
    }

    /// Threshold — emit when the moderator's action count strictly
    /// exceeds this value within the rolling window.
    #[must_use]
    pub const fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Rolling-window size in seconds.
    #[must_use]
    pub const fn window_secs(&self) -> u32 {
        self.window_secs
    }
}

impl Default for ModeratorAnomalyConfig {
    fn default() -> Self {
        Self {
            threshold: 50,
            window_secs: 3600,
        }
    }
}

/// Per-event input to the pure detector function.
///
/// Modelling the input as a `created_at` timestamp (rather than the
/// full `polaris_types::Action`) keeps [`detect_moderator_anomaly`] a
/// pure function of the rolling-window count — the database layer
/// supplies whatever shape is cheapest to query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionWindowEvent {
    /// When the action was created.
    pub created_at: DateTime<Utc>,
}

/// Typed output of the detector before it crosses the persistence
/// boundary.
///
/// Mirrors the wire-form payload of
/// [`polaris_types::ObservationKind::ModeratorBehaviorAnomaly`] without
/// dragging in the `ObservationId` / `evidence` fields the repo layer
/// populates. The integration boundary
/// ([`check_and_emit`]) wraps this into a
/// [`polaris_types::NewObservation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeratorAnomaly {
    /// Moderator whose behaviour tripped the detector.
    pub moderator_id: ModeratorId,
    /// Number of actions inside the window.
    pub action_count: i64,
    /// Window size (seconds) used by the detector.
    pub window_secs: i64,
}

/// Pure detector: returns `Some(ModeratorAnomaly)` iff `actions.len()`
/// strictly exceeds `cfg.threshold()`.
///
/// `actions` is the moderator's actions inside the rolling window; the
/// caller (`check_and_emit`) is responsible for the windowing — this
/// function is the algorithm itself, separated from the SQL so it can
/// be tested in isolation.
///
/// # Determinism
///
/// The decision is `actions.len() > threshold` — no time-of-day
/// heuristics, no per-action weighting. Operators tune the noise floor
/// via [`ModeratorAnomalyConfig`].
#[must_use]
pub fn detect_moderator_anomaly(
    actions: &[ActionWindowEvent],
    cfg: &ModeratorAnomalyConfig,
    moderator_id: ModeratorId,
) -> Option<ModeratorAnomaly> {
    let count_usize = actions.len();
    if count_usize <= cfg.threshold() as usize {
        return None;
    }
    // `actions.len()` is `usize`; the wire form is `i64`. Saturate on
    // overflow rather than cast-wrapping — an action count of `i64::MAX`
    // is operationally indistinguishable from "extremely large."
    let action_count = i64::try_from(count_usize).unwrap_or(i64::MAX);
    Some(ModeratorAnomaly {
        moderator_id,
        action_count,
        window_secs: i64::from(cfg.window_secs()),
    })
}

/// Synthetic-subject DID for a given moderator.
///
/// Deterministic per moderator so every emission for the same moderator
/// lands on the same `subjects` row.
fn moderator_anomaly_did(moderator_id: ModeratorId) -> String {
    format!("did:polaris:moderator-anomaly:{}", moderator_id.into_uuid())
}

/// Run the detector against the action history inside the caller's
/// transaction; if it fires, insert the observation and return the
/// resulting [`ObservationId`].
///
/// # Errors
///
/// Returns [`RepoError::Database`] when the count query or any of the
/// follow-up writes fail; [`RepoError::Decode`] when the synthetic-
/// subject lookup encounters a row whose stored shape contradicts the
/// expected invariants (defence-in-depth — the helper writes the row
/// itself).
///
/// # Transaction semantics
///
/// Executes inside the caller's `Transaction<Postgres>`. The
/// observation insert fires the per-statement `risk_signals` trigger;
/// the trigger runs in the same transaction, so a `tx.rollback()` undoes
/// the trigger's effect on `subjects.risk_signals` along with the
/// observation row.
pub async fn check_and_emit(
    tx: &mut Transaction<'_, Postgres>,
    moderator_id: ModeratorId,
    cfg: &ModeratorAnomalyConfig,
) -> Result<Option<ObservationId>, RepoError> {
    let window_secs_i64 = i64::from(cfg.window_secs());
    let count = count_actions_in_window(tx, moderator_id, window_secs_i64).await?;

    let threshold_i64 = i64::from(cfg.threshold());
    if count <= threshold_i64 {
        return Ok(None);
    }

    let subject_id = ensure_synthetic_subject(tx, moderator_id).await?;
    let kind = ObservationKind::ModeratorBehaviorAnomaly {
        moderator_id,
        action_count: count,
        window_secs: window_secs_i64,
    };
    let new = NewObservation {
        subject_id,
        kind,
        // Confidence saturates at 1.0 once the count crosses the
        // threshold; the count itself is in the typed payload for
        // operators that want a magnitude.
        confidence: 1.0,
        evidence: serde_json::Value::Null,
    };
    let observation_id = insert_observation_in_tx(tx, &new).await?;
    Ok(Some(observation_id))
}

/// Count actions the moderator committed in the last `window_secs`
/// seconds.
async fn count_actions_in_window(
    tx: &mut Transaction<'_, Postgres>,
    moderator_id: ModeratorId,
    window_secs: i64,
) -> Result<i64, RepoError> {
    // `make_interval(secs := $2)` accepts a `double precision` value;
    // we bind `window_secs` as the corresponding `f64` so sqlx encodes
    // it correctly. Window bounds are exclusive ("strictly after now -
    // window") which matches the architect's "in last N seconds"
    // wording.
    #[allow(
        clippy::cast_precision_loss,
        reason = "i64 window_secs is bounded by u32::MAX (~136 years); \
                  the f64 mantissa preserves the value exactly for any \
                  realistic operator configuration."
    )]
    let secs_f64 = window_secs as f64;
    let row = sqlx::query!(
        r#"
        SELECT COUNT(*)::bigint AS "count!: i64"
        FROM actions
        WHERE moderator_id = $1
          AND created_at > now() - make_interval(secs => $2)
        "#,
        moderator_id.0,
        secs_f64,
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(row.count)
}

/// Look up (or create) the synthetic subject for `moderator_id`.
///
/// The subject is `kind = 'account'` and `did =
/// 'did:polaris:moderator-anomaly:<uuid>'`. The lookup uses the existing
/// `subjects_kind_did_idx` partial index; the FK from
/// `observations.subject_id` ensures the row must exist before an
/// observation can be inserted.
async fn ensure_synthetic_subject(
    tx: &mut Transaction<'_, Postgres>,
    moderator_id: ModeratorId,
) -> Result<SubjectId, RepoError> {
    let did = moderator_anomaly_did(moderator_id);
    if let Some(existing) = sqlx::query!(
        r#"
        SELECT id
        FROM subjects
        WHERE kind = 'account' AND did = $1
        LIMIT 1
        "#,
        did,
    )
    .fetch_optional(&mut **tx)
    .await?
    {
        return Ok(SubjectId(existing.id));
    }
    let row = sqlx::query!(
        r#"
        INSERT INTO subjects (kind, did, uri, created_at)
        VALUES ('account', $1, NULL, now())
        RETURNING id
        "#,
        did,
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(SubjectId(row.id))
}

/// Insert an observation inside the caller's transaction.
///
/// Mirrors [`crate::repo::PgObservationRepo::insert`] but operates on a
/// `Transaction<Postgres>` so the action-insert path can emit the
/// anomaly observation atomically with the action row. The duplication
/// is intentional: the pool-based repo insert is what
/// non-transactional callers (the pattern-engine driver, the upstream-
/// label ingest worker) hold, and refactoring it to optionally accept a
/// transaction would force its trait surface to bleed sqlx types.
async fn insert_observation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    new: &NewObservation,
) -> Result<ObservationId, RepoError> {
    let discriminator = new.kind.discriminator();
    let envelope = serde_json::to_value(&new.kind).map_err(|e| RepoError::Decode {
        message: format!("ObservationKind serialize failed: {e}"),
    })?;
    let payload = match envelope {
        serde_json::Value::Object(mut map) => map
            .remove("data")
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
        other => {
            return Err(RepoError::Decode {
                message: format!("ObservationKind serialized to non-object: {other}"),
            });
        }
    };
    let serde_json::Value::Object(mut merged) = payload else {
        return Err(RepoError::Decode {
            message: format!("ObservationKind payload not a JSON object: {new:?}"),
        });
    };
    match &new.evidence {
        serde_json::Value::Object(extra_map) => {
            for (k, v) in extra_map {
                merged.insert(k.clone(), v.clone());
            }
        }
        serde_json::Value::Null => {}
        other => {
            merged.insert("extra".to_owned(), other.clone());
        }
    }
    let evidence = serde_json::Value::Object(merged);
    let row = sqlx::query!(
        r#"
        INSERT INTO observations (subject_id, kind, confidence, evidence)
        VALUES ($1, $2, $3, $4)
        RETURNING id
        "#,
        new.subject_id.0,
        discriminator,
        new.confidence,
        evidence,
    )
    .fetch_one(&mut **tx)
    .await?;
    Ok(ObservationId(row.id))
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

    fn ev(secs_ago: i64) -> ActionWindowEvent {
        ActionWindowEvent {
            created_at: Utc::now() - chrono::Duration::seconds(secs_ago),
        }
    }

    #[test]
    fn config_rejects_zero_threshold() {
        let err = ModeratorAnomalyConfig::new(0, 60).unwrap_err();
        match err {
            super::super::PatternError::InvalidConfig(msg) => {
                assert!(msg.contains("threshold"), "msg = {msg}");
            }
        }
    }

    #[test]
    fn config_rejects_zero_window() {
        let err = ModeratorAnomalyConfig::new(10, 0).unwrap_err();
        match err {
            super::super::PatternError::InvalidConfig(msg) => {
                assert!(msg.contains("window"), "msg = {msg}");
            }
        }
    }

    #[test]
    fn config_accessors_round_trip() {
        let cfg = ModeratorAnomalyConfig::new(50, 3600).expect("valid");
        assert_eq!(cfg.threshold(), 50);
        assert_eq!(cfg.window_secs(), 3600);
    }

    #[test]
    fn defaults_match_architect_preflight() {
        let cfg = ModeratorAnomalyConfig::default();
        assert_eq!(cfg.threshold(), 50);
        assert_eq!(cfg.window_secs(), 3600);
    }

    #[test]
    fn detect_returns_none_when_count_at_threshold() {
        let cfg = ModeratorAnomalyConfig::new(5, 60).expect("valid");
        let mod_id = ModeratorId::new();
        let events: Vec<ActionWindowEvent> = (0..5).map(ev).collect();
        assert!(detect_moderator_anomaly(&events, &cfg, mod_id).is_none());
    }

    #[test]
    fn detect_returns_none_when_count_below_threshold() {
        let cfg = ModeratorAnomalyConfig::new(5, 60).expect("valid");
        let mod_id = ModeratorId::new();
        let events: Vec<ActionWindowEvent> = (0..3).map(ev).collect();
        assert!(detect_moderator_anomaly(&events, &cfg, mod_id).is_none());
    }

    #[test]
    fn detect_returns_some_when_count_strictly_exceeds_threshold() {
        let cfg = ModeratorAnomalyConfig::new(5, 60).expect("valid");
        let mod_id = ModeratorId::new();
        let events: Vec<ActionWindowEvent> = (0..6).map(ev).collect();
        let anomaly = detect_moderator_anomaly(&events, &cfg, mod_id)
            .expect("count above threshold must fire");
        assert_eq!(anomaly.moderator_id, mod_id);
        assert_eq!(anomaly.action_count, 6);
        assert_eq!(anomaly.window_secs, 60);
    }

    #[test]
    fn detect_carries_window_seconds_through_to_emission() {
        let cfg = ModeratorAnomalyConfig::new(1, 7_200).expect("valid");
        let mod_id = ModeratorId::new();
        let events: Vec<ActionWindowEvent> = (0..2).map(ev).collect();
        let anomaly = detect_moderator_anomaly(&events, &cfg, mod_id).expect("must fire");
        assert_eq!(anomaly.window_secs, 7_200);
    }

    #[test]
    fn synthetic_did_is_deterministic_per_moderator() {
        let mod_id = ModeratorId::new();
        let did1 = moderator_anomaly_did(mod_id);
        let did2 = moderator_anomaly_did(mod_id);
        assert_eq!(did1, did2);
        assert!(did1.starts_with("did:polaris:moderator-anomaly:"));
        assert!(did1.contains(&mod_id.into_uuid().to_string()));
    }

    #[test]
    fn synthetic_dids_differ_across_moderators() {
        let a = moderator_anomaly_did(ModeratorId::new());
        let b = moderator_anomaly_did(ModeratorId::new());
        assert_ne!(a, b);
    }
}
