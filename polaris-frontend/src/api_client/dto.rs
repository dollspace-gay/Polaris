//! Wire DTOs for the Polaris first-party HTTP API.
//!
//! These structs duplicate the backend's [`polaris_backend::api::dto`] types
//! verbatim (field names, field order, `serde` attributes) so the wire form
//! deserialises identically on both sides. The duplication is deliberate
//! for this milestone — splitting the shapes into a shared
//! `polaris-api-types` crate is logged as a follow-up to revisit once the
//! API surface actually starts drifting.
//!
//! # Type sourcing
//!
//! Inner domain types (`Subject`, `Action`, `Report`, `Observation`,
//! `IncidentId`, `SubjectId`, `IncidentStatus`, `Severity`, `ModeratorId`,
//! `ActionId`, `LabelValue`, `PolicyId`, `ActionKind`) come from the shared
//! [`polaris_types`] workspace crate which both backend and frontend
//! already depend on, so the wire shapes match by construction — there is
//! nothing to keep in sync at this layer.
//!
//! # `serde_json::Value` exception
//!
//! `CaseView::network_context` is an M1 placeholder until the network
//! context panel lands in M2. The backend ships `serde_json::Value::Null`;
//! the frontend matches the wire shape exactly so deserialisation does
//! not break when M2 starts populating it. This is the ONE allowed use
//! of `serde_json::Value` on the wire surface — see the forbidden-pattern
//! checklist on issue #15.

use chrono::{DateTime, Utc};
use polaris_types::{
    Action, ActionId, ActionKind, IncidentId, IncidentStatus, LabelValue, ModeratorId, Observation,
    PolicyId, Report, Severity, Subject, SubjectId,
};
use serde::{Deserialize, Serialize};

/// Aggregate response for `GET /api/cases/:subject_id`.
///
/// Mirrors [`polaris_backend::api::dto::CaseView`] field-for-field. The
/// network context panel is a placeholder until M2 populates it; the field
/// is reserved here so the wire shape is stable across the milestone
/// boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseView {
    /// The subject the case view is centred on.
    pub subject: Subject,
    /// Full action history against the subject's incidents.
    pub history: Vec<Action>,
    /// User reports filed against the subject.
    pub reports: Vec<Report>,
    /// Pattern-engine observations attached to the subject.
    pub observations: Vec<Observation>,
    /// Placeholder Value, typed in M2 when network context lands.
    pub network_context: serde_json::Value,
}

/// Slim summary projection of an incident for queue listings.
///
/// Mirrors [`polaris_backend::api::dto::IncidentSummary`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentSummary {
    /// Incident identifier.
    pub id: IncidentId,
    /// Primary subject this incident is about.
    pub primary_subject: SubjectId,
    /// Workflow state.
    pub status: IncidentStatus,
    /// Severity tier.
    pub severity: Severity,
    /// Moderator currently assigned (if any).
    pub assigned_to: Option<ModeratorId>,
    /// When the incident was opened.
    pub opened_at: DateTime<Utc>,
}

/// Aggregate response for `GET /api/cases?status=...`.
///
/// Mirrors [`polaris_backend::api::dto::IncidentList`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentList {
    /// The incident summaries on this page.
    pub incidents: Vec<IncidentSummary>,
    /// Total row count returned.
    pub total: u64,
}

/// Request body for `POST /api/cases/:subject_id/actions`.
///
/// Mirrors [`polaris_backend::api::dto::SubmitAction`]. `moderator_id` is
/// intentionally absent — the backend reads it from the authenticated
/// session, not the wire.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubmitAction {
    /// Incident this action belongs to.
    pub incident_id: IncidentId,
    /// Verb.
    pub kind: ActionKind,
    /// Label value, when `kind = Label`.
    pub label: Option<LabelValue>,
    /// Free-text reasoning. Must be >= 10 chars (server enforces).
    pub reasoning: String,
    /// Policy clauses cited. Must be non-empty.
    pub policy_refs: Vec<PolicyId>,
    /// When this action stops being reversible without senior co-sign.
    pub reversible_until: DateTime<Utc>,
    /// When `kind = Reverse`, the action being reversed.
    pub reverses_action_id: Option<ActionId>,
}

/// Request body for `POST /api/cases/:incident_id/escalate`.
///
/// Mirrors [`polaris_backend::api::dto::Escalate`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Escalate {
    /// Free-text reasoning for the escalation. Must be >= 10 chars.
    pub reasoning: String,
}

/// Request body for `POST /api/actions/:action_id/reverse`.
///
/// Mirrors `polaris_backend::api::reversal::ReverseBody`. Only the
/// reasoning is on the wire — the moderator identity comes from the
/// authenticated session and the target action id comes from the URL.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReverseBody {
    /// Free-text reasoning for the reversal. Must be >= 10 chars per
    /// the backend's `validate_reasoning`.
    pub reasoning: String,
}

// ── Pattern dashboard (issue #20) ───────────────────────────────────────

/// Aggregate response for `GET /api/dashboard`.
///
/// Mirrors the backend's `polaris_backend::api::dto::DashboardSnapshot`
/// field-for-field. Every sub-field is a typed vector — no
/// `serde_json::Value` on the wire per the issue #20 pre-flight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// Hourly report-volume buckets (trailing 24h, hour-aligned).
    pub report_volume: Vec<ReportVolumeBucket>,
    /// Top incident clusters by `severity × reach`.
    pub clusters: Vec<IncidentClusterSummary>,
    /// Recent coordinated-action observations.
    pub coordinated_signals: Vec<CoordinatedSignal>,
    /// Queue depth per category.
    pub moderator_load: Vec<ModeratorLoad>,
    /// Server wall-clock timestamp of snapshot composition.
    pub fetched_at: DateTime<Utc>,
}

/// One hourly bucket of report volume.
///
/// `expected_mean` / `expected_stddev` are `0.0` until the live anomaly
/// detector (#19) is wired in. The sparkline draws the anomaly band only
/// when stddev is non-zero, so no client change is required when those
/// fields begin to carry real values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportVolumeBucket {
    /// Hour-aligned UTC bucket start.
    pub bucket_start: DateTime<Utc>,
    /// Report count in the bucket.
    pub count: i64,
    /// Trailing-baseline mean (0.0 placeholder for #20).
    pub expected_mean: f64,
    /// Trailing-baseline standard deviation (0.0 placeholder for #20).
    pub expected_stddev: f64,
}

/// Slim cluster summary for the dashboard's cluster-list panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentClusterSummary {
    /// Incident identifier (drill-down target).
    pub incident_id: IncidentId,
    /// Primary subject the cluster is centred on.
    pub primary_subject: SubjectId,
    /// Severity tier.
    pub severity: Severity,
    /// Workflow state.
    pub status: IncidentStatus,
    /// Count of related subjects implicated in this incident.
    pub related_subject_count: i64,
    /// When the incident was opened.
    pub opened_at: DateTime<Utc>,
}

/// Discriminator for [`CoordinatedSignal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatedSignalKind {
    /// Image-hash cluster.
    ImageHashCluster,
    /// Account cohort match.
    AccountCohort,
    /// Reply-brigade match.
    ReplyBrigade,
    /// Report-volume anomaly.
    ReportVolumeAnomaly,
}

impl CoordinatedSignalKind {
    /// Short human-readable label rendered in the panel header.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::ImageHashCluster => "image hash",
            Self::AccountCohort => "account cohort",
            Self::ReplyBrigade => "reply brigade",
            Self::ReportVolumeAnomaly => "volume anomaly",
        }
    }

    /// A short unicode glyph rendered alongside the label. Used as an
    /// at-a-glance icon — color is never the sole signal (`design.md`
    /// §7) so the glyph carries the discriminator on its own.
    #[must_use]
    pub const fn icon(self) -> &'static str {
        match self {
            Self::ImageHashCluster => "#",
            Self::AccountCohort => "@",
            Self::ReplyBrigade => "↩",
            Self::ReportVolumeAnomaly => "▲",
        }
    }
}

/// One coordinated-action observation projected for the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatedSignal {
    /// Detector kind.
    pub kind: CoordinatedSignalKind,
    /// Human-readable label (hash prefix / cohort id / thread URI / category).
    pub label: String,
    /// Count of distinct subjects contributing to the signal.
    pub subject_count: i64,
    /// When the pattern engine first emitted the observation.
    pub detected_at: DateTime<Utc>,
}

/// Queue-depth summary per moderation category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeratorLoad {
    /// Category label (`"all"` until categorical routing lands in M2).
    pub category: String,
    /// Incidents in `IncidentStatus::Open`.
    pub open_count: i64,
    /// Incidents in `IncidentStatus::InReview`.
    pub in_review_count: i64,
}

// ── Live dashboard feed (issue #57) ─────────────────────────────────────

/// Diff payload received from `GET /api/dashboard/live`.
///
/// Mirrors the backend's `polaris_backend::api::dto::DashboardEvent`
/// shape. Each variant carries a DTO that matches the corresponding
/// field on [`DashboardSnapshot`], so applying an event is a single
/// `match` on `kind` + a swap on the local signal.
///
/// Serde tag `kind` (`snake_case`) matches the wire convention used by
/// every other tagged enum in this module.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DashboardEvent {
    /// A new incident cluster surfaces to the top-clusters panel.
    NewCluster {
        /// The cluster summary, ready to push onto `clusters`.
        cluster: IncidentClusterSummary,
    },
    /// A new coordinated-action observation surfaces to the signals panel.
    NewSignal {
        /// The signal summary, ready to push onto `coordinated_signals`.
        signal: CoordinatedSignal,
    },
    /// One hourly report-volume bucket changed. The frontend keys by
    /// `bucket_start` against the local `report_volume` vector and
    /// either replaces the matching row or pushes a new one.
    VolumeBucketUpdated {
        /// The replacement bucket.
        bucket: ReportVolumeBucket,
    },
    /// The per-category queue depth changed. The frontend keys by
    /// `category` against the local `moderator_load` vector.
    ModeratorLoadDelta {
        /// The replacement row.
        load: ModeratorLoad,
    },
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn submit_action_round_trips_through_serde() {
        let body = SubmitAction {
            incident_id: IncidentId::new(),
            kind: ActionKind::Label,
            label: Some(LabelValue::new("spam")),
            reasoning: "Reasoning at least ten chars.".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now(),
            reverses_action_id: None,
        };
        let json = serde_json::to_string(&body).expect("serialize");
        let back: SubmitAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.reasoning, body.reasoning);
        assert_eq!(back.policy_refs.len(), 1);
    }

    #[test]
    fn case_view_accepts_null_network_context() {
        // The backend emits `null` for `network_context` in M1; the frontend
        // DTO must accept that shape verbatim.
        let json = serde_json::json!({
            "subject": {
                "id": SubjectId::new(),
                "kind": "account",
                "did": null,
                "uri": null,
                "created_at": "2026-01-01T00:00:00Z",
                "first_seen_by_mod": "2026-01-01T00:00:00Z",
                "risk_signals": []
            },
            "history": [],
            "reports": [],
            "observations": [],
            "network_context": null
        });
        let view: CaseView = serde_json::from_value(json).expect("deserialize");
        assert!(view.network_context.is_null());
    }
}
