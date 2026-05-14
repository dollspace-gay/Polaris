//! [`AppealStatus`] state machine + [`AppealId`] / [`AppealDecision`] types.
//!
//! Per `design.md` §5.8, appeals are a separate workflow attached to a
//! prior moderator action. The status field is an enum, never a raw
//! `String`, and transitions are validated through
//! [`AppealStatus::transition_to`] — invalid transitions return a typed
//! [`InvalidTransition`] error rather than silently succeeding or
//! panicking.
//!
//! # State machine
//!
//! Legal transitions:
//!
//! ```text
//!     Open ─→ Assigned ─→ DecidedReversed
//!                      └→ DecidedUpheld
//! ```
//!
//! No back-edges; the two `Decided*` states are terminal. A submission
//! enters at `Open`, the routing engine moves it to `Assigned`, the
//! reviewing moderator's `decide` call moves it to one of the two
//! terminals.
//!
//! # AC-8 invariant
//!
//! This module is plain serde + thiserror Rust. No `proto-blue`, no
//! `sqlx`. The wire form is `snake_case` (matching the DB CHECK
//! constraint in migration `00000000000010_appeals.sql`).

use crate::ids::ModeratorId;
use uuid::Uuid;

/// Identifier for an appeal row.
///
/// Defined here (rather than in [`crate::ids`] alongside the other UUID
/// newtypes) because appeals are a §5.8 concept landing in #24, and
/// every appeal-flavoured type lives in this module by design.
///
/// Shape matches the other typed UUIDs: `new()` mints a fresh `v4`,
/// `Display` forwards to the wrapped UUID's canonical form, `serde` is
/// transparent so the wire form is the bare UUID string.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct AppealId(pub Uuid);

impl AppealId {
    /// Mint a fresh v4 UUID-backed appeal id.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Borrow the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Consume the id and return the inner UUID.
    #[must_use]
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for AppealId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AppealId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<Uuid> for AppealId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl From<AppealId> for Uuid {
    fn from(value: AppealId) -> Self {
        value.0
    }
}

/// Workflow state for an appeal.
///
/// Values are `snake_case` on the wire and in the DB column
/// (`appeals.status`). Transition legality is enforced by
/// [`Self::transition_to`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AppealStatus {
    /// Submitted but not yet assigned to a reviewer.
    Open,
    /// A reviewer has been routed and the appeal is awaiting a decision.
    Assigned,
    /// Terminal: the reviewer reversed the original action.
    DecidedReversed,
    /// Terminal: the reviewer upheld the original action.
    DecidedUpheld,
}

impl AppealStatus {
    /// DB / wire string. Matches the CHECK constraint in migration
    /// `00000000000010_appeals.sql`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Assigned => "assigned",
            Self::DecidedReversed => "decided_reversed",
            Self::DecidedUpheld => "decided_upheld",
        }
    }

    /// Parse from wire / DB string. Returns `None` on unknown values.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "assigned" => Some(Self::Assigned),
            "decided_reversed" => Some(Self::DecidedReversed),
            "decided_upheld" => Some(Self::DecidedUpheld),
            _ => None,
        }
    }

    /// Whether the state is terminal — no further transitions are legal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::DecidedReversed | Self::DecidedUpheld)
    }

    /// Apply a transition. Returns the new state on success or
    /// [`InvalidTransition`] when the move is not legal in the §5.8
    /// state machine.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransition`] when the `(self, new_status)` edge
    /// is not in the legal transition set documented at the module
    /// level.
    pub fn transition_to(self, new_status: Self) -> Result<Self, InvalidTransition> {
        let legal = matches!(
            (self, new_status),
            (Self::Open, Self::Assigned)
                | (Self::Assigned, Self::DecidedReversed | Self::DecidedUpheld)
        );
        if legal {
            Ok(new_status)
        } else {
            Err(InvalidTransition {
                from: self,
                to: new_status,
            })
        }
    }
}

impl std::fmt::Display for AppealStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Terminal decision a reviewer can record on an appeal.
///
/// Distinct from [`AppealStatus`] so the API request body carries the
/// caller's intent (`Reversed` / `Upheld`) without exposing the
/// non-terminal `Open` / `Assigned` states the wire form should never
/// see on a decide call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppealDecision {
    /// Reverse the original action. Triggers a [`CalibrationEvent`]
    /// on the original moderator's stream (design.md §5.8 + §5.7).
    ///
    /// [`CalibrationEvent`]: crate::appeal::CalibrationEvent
    Reversed,
    /// Uphold the original action. No reversal is inserted; the appeal
    /// closes at [`AppealStatus::DecidedUpheld`].
    Upheld,
}

impl AppealDecision {
    /// Map a decision to the matching terminal [`AppealStatus`].
    #[must_use]
    pub const fn to_status(self) -> AppealStatus {
        match self {
            Self::Reversed => AppealStatus::DecidedReversed,
            Self::Upheld => AppealStatus::DecidedUpheld,
        }
    }
}

/// Illegal-transition error from [`AppealStatus::transition_to`].
///
/// Both endpoints of the rejected edge are carried so the caller can
/// render a useful diagnostic without re-deriving the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("illegal appeal status transition: {from} -> {to}")]
pub struct InvalidTransition {
    /// State the appeal was in before the rejected transition.
    pub from: AppealStatus,
    /// State the transition tried to move it to.
    pub to: AppealStatus,
}

/// Calibration-event kind.
///
/// The full set is declared up-front (mirroring the DB CHECK constraint)
/// so a later issue extending the calibration view does not require a
/// schema-version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationEventKind {
    /// An action by this moderator was reversed on appeal. Surfaces as
    /// feedback on the moderator's personal calibration view; not
    /// surfaced to management (design.md §5.7).
    AppealReversal,
    /// Placeholder for the agreement signal that lands with the
    /// per-moderator agreement-rate tracking in a future issue.
    AgreementWithSenior,
    /// Placeholder for the disagreement signal.
    DisagreementWithSenior,
}

impl CalibrationEventKind {
    /// DB / wire string. Matches the `calibration_events.kind` CHECK
    /// constraint in migration `00000000000010_appeals.sql`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppealReversal => "appeal_reversal",
            Self::AgreementWithSenior => "agreement_with_senior",
            Self::DisagreementWithSenior => "disagreement_with_senior",
        }
    }

    /// Parse from wire / DB string. Returns `None` on unknown values.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "appeal_reversal" => Some(Self::AppealReversal),
            "agreement_with_senior" => Some(Self::AgreementWithSenior),
            "disagreement_with_senior" => Some(Self::DisagreementWithSenior),
            _ => None,
        }
    }
}

/// A row from the `calibration_events` table.
///
/// Surfaced to the moderator's personal calibration view (design.md
/// §5.7). The referenced-action and referenced-appeal fields are both
/// optional — the schema accommodates the future agreement-with-senior
/// variants which reference a senior review, not a per-action reversal.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CalibrationEvent {
    /// Calibration-event row identifier.
    pub id: Uuid,
    /// Moderator the event belongs to.
    pub moderator_id: ModeratorId,
    /// Discriminator for the event variant.
    pub kind: CalibrationEventKind,
    /// Original action referenced by `AppealReversal`. `None` for
    /// future variants that do not target a per-action decision.
    pub referenced_action_id: Option<crate::ids::ActionId>,
    /// Appeal referenced by `AppealReversal`. `None` for variants
    /// unrelated to the appeals workflow.
    pub referenced_appeal_id: Option<AppealId>,
    /// When the event was recorded.
    pub created_at: chrono::DateTime<chrono::Utc>,
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
    fn appeal_status_round_trips_through_wire_form() {
        for s in [
            AppealStatus::Open,
            AppealStatus::Assigned,
            AppealStatus::DecidedReversed,
            AppealStatus::DecidedUpheld,
        ] {
            assert_eq!(AppealStatus::from_wire(s.as_str()), Some(s));
        }
    }

    #[test]
    fn appeal_status_serializes_snake_case() {
        let json = serde_json::to_string(&AppealStatus::DecidedReversed).expect("serialize");
        assert_eq!(json, "\"decided_reversed\"");
    }

    #[test]
    fn open_transitions_to_assigned() {
        let next = AppealStatus::Open
            .transition_to(AppealStatus::Assigned)
            .expect("open -> assigned is legal");
        assert_eq!(next, AppealStatus::Assigned);
    }

    #[test]
    fn assigned_transitions_to_either_terminal() {
        assert!(
            AppealStatus::Assigned
                .transition_to(AppealStatus::DecidedReversed)
                .is_ok()
        );
        assert!(
            AppealStatus::Assigned
                .transition_to(AppealStatus::DecidedUpheld)
                .is_ok()
        );
    }

    #[test]
    fn open_cannot_skip_to_decided_reversed() {
        let err = AppealStatus::Open
            .transition_to(AppealStatus::DecidedReversed)
            .expect_err("open must not skip to decided");
        assert_eq!(err.from, AppealStatus::Open);
        assert_eq!(err.to, AppealStatus::DecidedReversed);
    }

    #[test]
    fn open_cannot_skip_to_decided_upheld() {
        let err = AppealStatus::Open
            .transition_to(AppealStatus::DecidedUpheld)
            .expect_err("open must not skip to decided");
        assert_eq!(err.from, AppealStatus::Open);
    }

    #[test]
    fn terminal_states_cannot_transition_anywhere() {
        for terminal in [AppealStatus::DecidedReversed, AppealStatus::DecidedUpheld] {
            for target in [
                AppealStatus::Open,
                AppealStatus::Assigned,
                AppealStatus::DecidedReversed,
                AppealStatus::DecidedUpheld,
            ] {
                let result = terminal.transition_to(target);
                assert!(
                    result.is_err(),
                    "terminal {terminal:?} must not transition to {target:?}",
                );
            }
        }
    }

    #[test]
    fn is_terminal_matches_expected_states() {
        assert!(!AppealStatus::Open.is_terminal());
        assert!(!AppealStatus::Assigned.is_terminal());
        assert!(AppealStatus::DecidedReversed.is_terminal());
        assert!(AppealStatus::DecidedUpheld.is_terminal());
    }

    #[test]
    fn decision_maps_to_terminal_status() {
        assert_eq!(
            AppealDecision::Reversed.to_status(),
            AppealStatus::DecidedReversed
        );
        assert_eq!(
            AppealDecision::Upheld.to_status(),
            AppealStatus::DecidedUpheld
        );
    }

    #[test]
    fn invalid_transition_display_includes_both_endpoints() {
        let err = InvalidTransition {
            from: AppealStatus::Open,
            to: AppealStatus::DecidedUpheld,
        };
        let s = err.to_string();
        assert!(s.contains("open"));
        assert!(s.contains("decided_upheld"));
    }

    #[test]
    fn calibration_event_kind_round_trips() {
        for k in [
            CalibrationEventKind::AppealReversal,
            CalibrationEventKind::AgreementWithSenior,
            CalibrationEventKind::DisagreementWithSenior,
        ] {
            assert_eq!(CalibrationEventKind::from_wire(k.as_str()), Some(k));
        }
    }

    #[test]
    fn appeal_id_round_trips_through_serde() {
        let id = AppealId::new();
        let json = serde_json::to_string(&id).expect("serialize");
        let back: AppealId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(id, back);
    }
}
