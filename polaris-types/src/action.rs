//! [`Action`] — every moderator decision.
//!
//! Per `design.md` §4 and §5.5:
//!
//! - Every action requires non-trivial free-text `reasoning`.
//! - Every action is reversible (24h for the original moderator, indefinitely
//!   for seniors). Reversal writes a *new* action with `kind = Reverse` and
//!   `reverses_action_id` pointing at the original.
//! - The `actions` table is **append-only**. There is no `reversed_by` column
//!   on the Action struct — that fact is derived at read time by joining
//!   against `actions WHERE reverses_action_id = $1`. This keeps the
//!   "no UPDATE on actions" invariant complete: no row ever mutates after
//!   insert.
//!
//! See migration `00000000000004_actions.sql` for the storage schema and the
//! Postgres trigger that rejects `UPDATE` outright.

use chrono::{DateTime, Utc};

use crate::ids::{ActionId, IncidentId, LabelValue, ModeratorId, PolicyId, SubjectId};

/// The set of action verbs a moderator can record.
///
/// Per `design.md` §4 plus the §5.5 `Reverse` variant: a reversal is itself an
/// `Action` row with `kind = Reverse` and a non-null `reverses_action_id`.
/// The original row never mutates.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Apply an ATProto label to the subject.
    Label,
    /// Takedown the subject (label `!takedown`-class).
    Takedown,
    /// Mute-from-discover.
    Mute,
    /// Issue a warning to the account.
    Warn,
    /// Escalate the incident for senior review.
    Escalate,
    /// Explicitly record that no action is warranted (closes the incident
    /// without acting). Counts toward the moderator's calibration view.
    NoAction,
    /// Reverse a prior action. Must carry a non-null `reverses_action_id`.
    Reverse,
    /// Moderator note attached to the subject. No state change; the
    /// `reasoning` text is the note itself. Ozone-parity (`#modEventComment`).
    /// Use when a moderator wants to record context for future reviewers
    /// without taking an enforcement action.
    Comment,
}

impl ActionKind {
    /// Wire form. Matches the Postgres `CHECK (kind IN (...))` constraint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::Takedown => "takedown",
            Self::Mute => "mute",
            Self::Warn => "warn",
            Self::Escalate => "escalate",
            Self::NoAction => "no_action",
            Self::Reverse => "reverse",
            Self::Comment => "comment",
        }
    }

    /// Parse from wire form. Returns `None` on an unknown value.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "label" => Some(Self::Label),
            "takedown" => Some(Self::Takedown),
            "mute" => Some(Self::Mute),
            "warn" => Some(Self::Warn),
            "escalate" => Some(Self::Escalate),
            "no_action" => Some(Self::NoAction),
            "reverse" => Some(Self::Reverse),
            "comment" => Some(Self::Comment),
            _ => None,
        }
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single moderator decision.
///
/// Maps 1:1 with the `actions` table in `00000000000004_actions.sql`.
///
/// # Append-only contract
///
/// `Action` is logically immutable after insert. Polaris does not provide an
/// `update` method on the action repo (`ActionRepo` exposes only `insert` /
/// `get` / `list_by_incident`). The Postgres-side trigger raises an exception
/// on any `UPDATE` against the `actions` table. Reversal writes a new row.
///
/// # The missing `reversed_by` field
///
/// `design.md` §4 lists a `reversed_by: Option<ActionId>` field. We deliberately
/// drop it from the persisted struct: storing it would require mutating the
/// original row when the reversal is recorded, which violates append-only.
/// Reverse-relations are derived at read time by joining `actions a LEFT JOIN
/// actions r ON r.reverses_action_id = a.id`. See
/// [`Action::reverses_action_id`] for the in-row direction (a reverse row
/// points to the row it reverses; the reversed row carries no back-pointer).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Action {
    /// Polaris-internal identifier.
    pub id: ActionId,
    /// The incident this action belongs to.
    pub incident_id: IncidentId,
    /// The subject this action targets.
    pub subject_id: SubjectId,
    /// The moderator who recorded the action.
    pub moderator_id: ModeratorId,
    /// What kind of action this is.
    pub kind: ActionKind,
    /// Label value, when `kind = Label`. `None` for non-label actions.
    pub label: Option<LabelValue>,
    /// Free-text reasoning — required, searchable, non-trivial (the database
    /// enforces `length(reasoning) >= 10`).
    pub reasoning: String,
    /// Policy clauses cited by the moderator.
    pub policy_refs: Vec<PolicyId>,
    /// The window during which this action can still be reversed by its
    /// original moderator without senior co-sign. Per `design.md` §5.5,
    /// this is `created_at + 24h` for non-senior moderators.
    pub reversible_until: DateTime<Utc>,
    /// When `kind = Reverse`, the action this row reverses. `None` otherwise.
    ///
    /// On a non-reverse row this is always `None`. The reverse relation is
    /// stored only on the reverse row, never as a back-pointer on the
    /// original — that's how we satisfy append-only.
    pub reverses_action_id: Option<ActionId>,
    /// When this action was recorded.
    pub created_at: DateTime<Utc>,
    /// When the action's label was successfully streamed to ATProto
    /// subscribers (the labeler `subscribeLabels` endpoint).
    pub emitted_to_atproto: Option<DateTime<Utc>>,
    /// Content hash (hex-encoded SHA-256) of the CAR file the evidence
    /// worker (issue #33 / REQ-10 / AC-11) wrote to object storage.
    ///
    /// Populated only after the worker successfully snapshots the
    /// upstream record + MST proof path. `None` while the evidence job
    /// is `pending` / `running`, or when the action targets an account
    /// (only record-shaped subjects enqueue an evidence job). See
    /// `.design/polaris-proto-blue-integration.md` §H.
    pub evidence_car_cid: Option<String>,
}

/// Caller-supplied fields for inserting a new [`Action`].
///
/// The repo populates `id`, `created_at`, and `emitted_to_atproto` (which
/// starts `None` and is set by the label-emit pipeline in a later issue).
///
/// `reversible_until` is supplied by the caller because the policy on its
/// computation (`created_at + 24h` for non-senior, longer for seniors) is a
/// service-layer concern; the repo just stores what it's told.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NewAction {
    /// Incident this action belongs to.
    pub incident_id: IncidentId,
    /// Subject this action targets.
    pub subject_id: SubjectId,
    /// Moderator recording the action.
    pub moderator_id: ModeratorId,
    /// Action verb.
    pub kind: ActionKind,
    /// Label value, when `kind = Label`.
    pub label: Option<LabelValue>,
    /// Reasoning. Must be at least 10 chars (DB CHECK constraint).
    pub reasoning: String,
    /// Policy refs.
    pub policy_refs: Vec<PolicyId>,
    /// When this action stops being reversible without senior co-sign.
    pub reversible_until: DateTime<Utc>,
    /// When `kind = Reverse`, the action being reversed.
    ///
    /// A `NewAction` with `kind = Reverse` and `reverses_action_id == None`
    /// will be rejected by the repo with `RepoError::InvalidInput`. A
    /// non-reverse action with `Some(_)` is similarly rejected.
    pub reverses_action_id: Option<ActionId>,
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
    fn action_kind_round_trips_through_wire_form() {
        for k in [
            ActionKind::Label,
            ActionKind::Takedown,
            ActionKind::Mute,
            ActionKind::Warn,
            ActionKind::Escalate,
            ActionKind::NoAction,
            ActionKind::Reverse,
            ActionKind::Comment,
        ] {
            assert_eq!(ActionKind::from_wire(k.as_str()), Some(k));
        }
    }

    #[test]
    fn action_kind_serializes_snake_case() {
        let json = serde_json::to_string(&ActionKind::NoAction).expect("serialize");
        assert_eq!(json, "\"no_action\"");
    }
}
