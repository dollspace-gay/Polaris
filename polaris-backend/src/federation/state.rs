//! Federation escalation state machine (issue #108 / M5 PR 2).
//!
//! # States
//!
//! ```text
//! Proposed ─┬──────────────────────→ Acknowledged ─┬──────────────────→ Active
//!           │                                       │                     │
//!           ├──────────────────────→ RejectedByTarget (terminal)          │
//!           │                                                             │
//!           └──→ WithdrawnBySource ←────────────────────────────────────┘
//!                 (terminal)                                              │
//!                                                                         │
//!                                   Resolved ←─────────────────────────┘
//!                                   (terminal)
//! ```
//!
//! Terminal states: `Resolved`, `WithdrawnBySource`, `RejectedByTarget`.
//! No further transitions are valid from a terminal state.
//!
//! # Validation
//!
//! Call [`validate_transition`] before every state update. The repo layer
//! (`repo::federation`) always calls this before issuing a Postgres UPDATE.
//!
//! # Design choice: runtime enum, not typestate
//!
//! The state machine is encoded as a **runtime enum** (`EscalationState`)
//! rather than a typestate pattern (phantom-type–parameterised structs).
//! Typestate is attractive for compile-time transition enforcement but
//! requires the state to be statically known — our states come from the
//! database at runtime, so the value must be a runtime discriminant anyway.
//! A runtime enum is simpler, directly serialisable to/from the DB `TEXT`
//! column, and passes `Send + Sync + 'static` without any ceremony.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── state enum ───────────────────────────────────────────────────────────

/// The lifecycle state of a [`federation_escalations`] row.
///
/// The CHECK constraint in migration 0028 mirrors the string values below.
/// Every DB write must go through [`validate_transition`] first.
///
/// `EscalationState` is `Copy`, `Send`, `Sync`, and `'static` — safe to hold
/// across `.await` points and to pass between threads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationState {
    /// Source has proposed the escalation; awaiting target acknowledgment.
    Proposed,
    /// Target has acknowledged; awaiting first message exchange.
    Acknowledged,
    /// First message exchanged; conversation is active.
    Active,
    /// Both sides agree the matter is resolved. **Terminal.**
    Resolved,
    /// Source withdrew the escalation before resolution. **Terminal.**
    WithdrawnBySource,
    /// Target rejected the escalation. **Terminal.**
    RejectedByTarget,
}

impl EscalationState {
    /// Return the DB-level string representation (must match the CHECK
    /// constraint in `00000000000028_federation_state_machine.sql`).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Acknowledged => "acknowledged",
            Self::Active => "active",
            Self::Resolved => "resolved",
            Self::WithdrawnBySource => "withdrawn_by_source",
            Self::RejectedByTarget => "rejected_by_target",
        }
    }

    /// Parse a DB-level string back into an `EscalationState`.
    ///
    /// # Errors
    ///
    /// Returns `Err(s)` when `s` does not match any known state discriminant.
    ///
    /// Note: this is a plain associated function, not the `std::str::FromStr`
    /// trait impl. We do not implement `FromStr` to avoid importing it at
    /// every call site — callers that need the trait can add
    /// `use std::str::FromStr as _` locally.
    #[allow(clippy::should_implement_trait, reason = "intentionally not FromStr")]
    pub fn from_str(s: &str) -> Result<Self, UnknownStateError> {
        match s {
            "proposed" => Ok(Self::Proposed),
            "acknowledged" => Ok(Self::Acknowledged),
            "active" => Ok(Self::Active),
            "resolved" => Ok(Self::Resolved),
            "withdrawn_by_source" => Ok(Self::WithdrawnBySource),
            "rejected_by_target" => Ok(Self::RejectedByTarget),
            other => Err(UnknownStateError(other.to_owned())),
        }
    }

    /// Returns `true` when the state is terminal (no further transitions).
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Resolved | Self::WithdrawnBySource | Self::RejectedByTarget
        )
    }
}

impl fmt::Display for EscalationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── errors ────────────────────────────────────────────────────────────────

/// An unrecognised state discriminant from the database.
///
/// Indicates schema drift (a new state value was added to the DB but the
/// application code was not updated).
#[derive(Debug, thiserror::Error)]
#[error("unknown escalation state: {0:?}")]
pub struct UnknownStateError(String);

/// Errors produced by the state machine.
#[derive(Debug, thiserror::Error)]
pub enum FederationStateError {
    /// The requested transition is not allowed by the state machine definition.
    ///
    /// The `from` → `to` pair is not in the valid edge set.
    #[error("invalid state transition: {from} → {to}")]
    InvalidTransition {
        /// The current state.
        from: EscalationState,
        /// The requested next state.
        to: EscalationState,
    },

    /// The source state is terminal; no further transitions are possible.
    ///
    /// Callers should treat this as a logic error — once terminal, the
    /// escalation should never be mutated again.
    #[error("cannot transition out of terminal state {0}")]
    TerminalState(EscalationState),
}

// ── transition validator ──────────────────────────────────────────────────

/// Validate a state-machine transition.
///
/// Returns `Ok(())` when the transition is legal. Returns `Err` when:
/// - `from` is a terminal state ([`FederationStateError::TerminalState`]).
/// - The `from → to` edge is not in the valid edge set
///   ([`FederationStateError::InvalidTransition`]).
///
/// The valid edges are:
///
/// | from                 | to (set)                                               |
/// |----------------------|--------------------------------------------------------|
/// | `Proposed`           | `Acknowledged`, `RejectedByTarget`, `WithdrawnBySource` |
/// | `Acknowledged`       | `Active`, `WithdrawnBySource`                           |
/// | `Active`             | `Resolved`, `WithdrawnBySource`                         |
/// | `Resolved`           | *(terminal — no edges)*                                 |
/// | `WithdrawnBySource`  | *(terminal — no edges)*                                 |
/// | `RejectedByTarget`   | *(terminal — no edges)*                                 |
///
/// # Errors
///
/// Returns [`FederationStateError::TerminalState`] when `from` is terminal.
/// Returns [`FederationStateError::InvalidTransition`] for any illegal edge.
pub fn validate_transition(
    from: EscalationState,
    to: EscalationState,
) -> Result<(), FederationStateError> {
    if from.is_terminal() {
        return Err(FederationStateError::TerminalState(from));
    }

    let allowed = match from {
        EscalationState::Proposed => &[
            EscalationState::Acknowledged,
            EscalationState::RejectedByTarget,
            EscalationState::WithdrawnBySource,
        ][..],
        EscalationState::Acknowledged => {
            &[EscalationState::Active, EscalationState::WithdrawnBySource][..]
        }
        EscalationState::Active => &[
            EscalationState::Resolved,
            EscalationState::WithdrawnBySource,
        ][..],
        // Terminal states are handled above; this arm is unreachable.
        EscalationState::Resolved
        | EscalationState::WithdrawnBySource
        | EscalationState::RejectedByTarget => &[][..],
    };

    if allowed.contains(&to) {
        Ok(())
    } else {
        Err(FederationStateError::InvalidTransition { from, to })
    }
}

// ── unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code — rust-quality §7"
)]
mod tests {
    use super::*;

    // ── as_str / from_str round-trip ──────────────────────────────────────

    #[test]
    fn state_round_trip() {
        for state in [
            EscalationState::Proposed,
            EscalationState::Acknowledged,
            EscalationState::Active,
            EscalationState::Resolved,
            EscalationState::WithdrawnBySource,
            EscalationState::RejectedByTarget,
        ] {
            let s = state.as_str();
            let parsed = EscalationState::from_str(s).expect("round-trip parse failed");
            assert_eq!(state, parsed, "round-trip failed for {state}");
        }
    }

    #[test]
    fn from_str_unknown_returns_err() {
        assert!(EscalationState::from_str("bogus").is_err());
        assert!(EscalationState::from_str("").is_err());
        assert!(EscalationState::from_str("PROPOSED").is_err()); // case-sensitive
    }

    // ── terminal state detection ──────────────────────────────────────────

    #[test]
    fn terminal_states_identified() {
        assert!(!EscalationState::Proposed.is_terminal());
        assert!(!EscalationState::Acknowledged.is_terminal());
        assert!(!EscalationState::Active.is_terminal());
        assert!(EscalationState::Resolved.is_terminal());
        assert!(EscalationState::WithdrawnBySource.is_terminal());
        assert!(EscalationState::RejectedByTarget.is_terminal());
    }

    // ── validate_transition: legal edges ─────────────────────────────────

    #[test]
    fn proposed_legal_transitions() {
        assert!(
            validate_transition(EscalationState::Proposed, EscalationState::Acknowledged).is_ok()
        );
        assert!(
            validate_transition(EscalationState::Proposed, EscalationState::RejectedByTarget)
                .is_ok()
        );
        assert!(
            validate_transition(
                EscalationState::Proposed,
                EscalationState::WithdrawnBySource
            )
            .is_ok()
        );
    }

    #[test]
    fn acknowledged_legal_transitions() {
        assert!(
            validate_transition(EscalationState::Acknowledged, EscalationState::Active).is_ok()
        );
        assert!(
            validate_transition(
                EscalationState::Acknowledged,
                EscalationState::WithdrawnBySource
            )
            .is_ok()
        );
    }

    #[test]
    fn active_legal_transitions() {
        assert!(validate_transition(EscalationState::Active, EscalationState::Resolved).is_ok());
        assert!(
            validate_transition(EscalationState::Active, EscalationState::WithdrawnBySource)
                .is_ok()
        );
    }

    // ── validate_transition: illegal edges ───────────────────────────────

    #[test]
    fn proposed_cannot_skip_to_active() {
        assert!(validate_transition(EscalationState::Proposed, EscalationState::Active).is_err());
    }

    #[test]
    fn proposed_cannot_go_to_resolved() {
        assert!(validate_transition(EscalationState::Proposed, EscalationState::Resolved).is_err());
    }

    #[test]
    fn acknowledged_cannot_go_to_rejected() {
        assert!(
            validate_transition(
                EscalationState::Acknowledged,
                EscalationState::RejectedByTarget
            )
            .is_err()
        );
    }

    #[test]
    fn active_cannot_go_backwards() {
        assert!(validate_transition(EscalationState::Active, EscalationState::Proposed).is_err());
        assert!(
            validate_transition(EscalationState::Active, EscalationState::Acknowledged).is_err()
        );
        assert!(
            validate_transition(EscalationState::Active, EscalationState::RejectedByTarget)
                .is_err()
        );
    }

    // ── validate_transition: terminal states reject all transitions ───────

    #[test]
    fn terminal_states_reject_all_transitions() {
        let terminals = [
            EscalationState::Resolved,
            EscalationState::WithdrawnBySource,
            EscalationState::RejectedByTarget,
        ];
        let all_states = [
            EscalationState::Proposed,
            EscalationState::Acknowledged,
            EscalationState::Active,
            EscalationState::Resolved,
            EscalationState::WithdrawnBySource,
            EscalationState::RejectedByTarget,
        ];
        for terminal in terminals {
            for target in all_states {
                let result = validate_transition(terminal, target);
                assert!(
                    result.is_err(),
                    "expected Err for {terminal} → {target}, got Ok"
                );
                // Specifically expect TerminalState, not InvalidTransition
                assert!(
                    matches!(result, Err(FederationStateError::TerminalState(_))),
                    "expected TerminalState error for {terminal} → {target}"
                );
            }
        }
    }

    // ── Display ──────────────────────────────────────────────────────────

    #[test]
    fn display_matches_as_str() {
        for state in [
            EscalationState::Proposed,
            EscalationState::Acknowledged,
            EscalationState::Active,
            EscalationState::Resolved,
            EscalationState::WithdrawnBySource,
            EscalationState::RejectedByTarget,
        ] {
            assert_eq!(format!("{state}"), state.as_str());
        }
    }

    // ── error message smoke tests ─────────────────────────────────────────

    #[test]
    fn error_messages_are_readable() {
        let e = FederationStateError::InvalidTransition {
            from: EscalationState::Proposed,
            to: EscalationState::Resolved,
        };
        let msg = e.to_string();
        assert!(msg.contains("proposed"), "expected 'proposed' in {msg:?}");
        assert!(msg.contains("resolved"), "expected 'resolved' in {msg:?}");

        let e = FederationStateError::TerminalState(EscalationState::Resolved);
        let msg = e.to_string();
        assert!(msg.contains("resolved"), "expected 'resolved' in {msg:?}");
    }
}
