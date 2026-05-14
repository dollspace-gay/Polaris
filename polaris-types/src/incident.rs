//! [`Incident`] — a cluster of reports + observations bound to one or more
//! subjects.
//!
//! Per `design.md` §4: incidents (not reports) are the unit moderators act on.
//! Twelve reports against one account become one incident with twelve attached
//! reports, not twelve cases.
//!
//! The `reports` and `pattern_observations` vectors are populated by the
//! repo layer via secondary queries — they are not stored as columns on the
//! `incidents` table. Treat them as the "hydrated" view; the bare row carries
//! just the metadata.

use chrono::{DateTime, Utc};

use crate::ids::{IncidentId, ModeratorId, SubjectId};
use crate::observation::Observation;
use crate::report::Report;

/// Workflow state for an [`Incident`].
///
/// The five-state machine is taken verbatim from `design.md` §4. Allowed
/// transitions are enforced at the API/service layer, not in the type — the
/// repo trusts whatever `IncidentStatus` value the service hands it.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    /// Newly created, not yet picked up.
    Open,
    /// A moderator has the case lock; review in progress.
    InReview,
    /// One or more actions have been recorded.
    Actioned,
    /// Resolved.
    Closed,
    /// Escalated for senior review.
    Escalated,
}

impl IncidentStatus {
    /// Lowercase-snake wire form. See [`crate::subject::SubjectKind::as_str`]
    /// for the rationale on a hand-rolled conversion.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InReview => "in_review",
            Self::Actioned => "actioned",
            Self::Closed => "closed",
            Self::Escalated => "escalated",
        }
    }

    /// Parse from wire form. Returns `None` on an unknown value.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "in_review" => Some(Self::InReview),
            "actioned" => Some(Self::Actioned),
            "closed" => Some(Self::Closed),
            "escalated" => Some(Self::Escalated),
            _ => None,
        }
    }
}

impl std::fmt::Display for IncidentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Severity tier. `Critical` is reserved for CSAM/CSEM-class material and
/// known-bad-actor matches; everything else is moderator-set.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Top tier; routed to specialty queue.
    Critical,
    /// Pattern-action-eligible; co-sign-required.
    High,
    /// Standard moderation tier.
    Medium,
    /// Low-signal — pattern engine background.
    Low,
}

impl Severity {
    /// Lowercase wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Parse from wire form. Returns `None` on an unknown value.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "critical" => Some(Self::Critical),
            "high" => Some(Self::High),
            "medium" => Some(Self::Medium),
            "low" => Some(Self::Low),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A cluster of reports + observations bound to one or more subjects.
///
/// The `reports` and `pattern_observations` vectors are hydrated by the repo
/// layer via secondary queries; a "bare" incident as stored in the
/// `incidents` table has empty vectors. Use
/// [`crate::incident::Incident::new_bare`] when constructing the
/// repo-decoded variant; the API layer composes the full hydrated record by
/// running follow-up queries.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Incident {
    /// Polaris-internal identifier.
    pub id: IncidentId,
    /// The primary subject this incident is about.
    pub primary_subject: SubjectId,
    /// Other subjects implicated (sock-puppet ring, brigade members, etc.).
    pub related_subjects: Vec<SubjectId>,
    /// Aggregated reports attached to this incident.
    ///
    /// Populated by the repo's "hydrated" read path. Empty on a bare row read.
    pub reports: Vec<Report>,
    /// Pattern-engine observations attached to this incident's subjects.
    ///
    /// Populated by the repo's hydrated read. Empty on a bare row read.
    pub pattern_observations: Vec<Observation>,
    /// Severity tier.
    pub severity: Severity,
    /// Workflow state.
    pub status: IncidentStatus,
    /// Moderator currently assigned (if any).
    pub assigned_to: Option<ModeratorId>,
    /// Moderator currently holding the case lock (if any).
    pub locked_by: Option<ModeratorId>,
    /// When the incident was opened.
    pub opened_at: DateTime<Utc>,
    /// When the incident was closed (if it has been).
    pub closed_at: Option<DateTime<Utc>>,
}

impl Incident {
    /// Construct an `Incident` with empty hydrated collections.
    ///
    /// Convenience for repo-layer decoders that produce one row per
    /// incident; the API layer then hydrates `reports` and
    /// `pattern_observations` from secondary queries.
    #[must_use]
    #[allow(clippy::too_many_arguments)] // mirrors §4 struct fields 1:1
    pub fn new_bare(
        id: IncidentId,
        primary_subject: SubjectId,
        severity: Severity,
        status: IncidentStatus,
        assigned_to: Option<ModeratorId>,
        locked_by: Option<ModeratorId>,
        opened_at: DateTime<Utc>,
        closed_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            id,
            primary_subject,
            related_subjects: Vec::new(),
            reports: Vec::new(),
            pattern_observations: Vec::new(),
            severity,
            status,
            assigned_to,
            locked_by,
            opened_at,
            closed_at,
        }
    }
}

/// Caller-supplied fields for creating a new [`Incident`].
///
/// `id`, `opened_at`, `closed_at`, and the hydrated vectors are managed by
/// the repo / API layers.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NewIncident {
    /// Primary subject.
    pub primary_subject: SubjectId,
    /// Severity tier at creation.
    pub severity: Severity,
    /// Starting status. Most incidents open at [`IncidentStatus::Open`]; the
    /// pattern-engine may directly create incidents in `Escalated` for
    /// auto-routed critical hits.
    pub status: IncidentStatus,
    /// Initial assignee (typically `None`; populated by the router).
    pub assigned_to: Option<ModeratorId>,
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
    fn incident_status_round_trips_through_wire_form() {
        for s in [
            IncidentStatus::Open,
            IncidentStatus::InReview,
            IncidentStatus::Actioned,
            IncidentStatus::Closed,
            IncidentStatus::Escalated,
        ] {
            assert_eq!(IncidentStatus::from_wire(s.as_str()), Some(s));
        }
    }

    #[test]
    fn severity_round_trips_through_wire_form() {
        for s in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ] {
            assert_eq!(Severity::from_wire(s.as_str()), Some(s));
        }
    }

    #[test]
    fn incident_status_serializes_snake_case() {
        let json = serde_json::to_string(&IncidentStatus::InReview).expect("serialize");
        assert_eq!(json, "\"in_review\"");
    }
}
