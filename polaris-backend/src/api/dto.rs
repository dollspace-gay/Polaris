//! HTTP-surface Data Transfer Objects.
//!
//! Per the forbidden-pattern checklist for #14, response bodies must
//! serialize from `polaris_types::*` (the canonical domain model) or from
//! DTOs defined here. Raw `sqlx::query!`-row types never appear on the wire.
//!
//! Two kinds of types live in this module:
//!
//! 1. **Response DTOs** — composite views the API assembles from multiple
//!    repo calls. [`CaseView`] aggregates a subject with its history,
//!    reports, and observations; [`IncidentList`] / [`IncidentSummary`]
//!    provide the slim queue-fallback projection.
//! 2. **Request payloads** — the `serde`-decoded bodies of POST endpoints.
//!    [`SubmitAction`] / [`Escalate`] are deliberately separate from
//!    `polaris_types::NewAction` because the moderator id comes from the
//!    session, not the request body (forbidden-pattern §8: handlers MUST
//!    read `moderator_id` from `Extension<ModeratorAuthCtx>` and NOT from
//!    the wire).

use chrono::{DateTime, Utc};
use polaris_types::{
    Action, ActionId, ActionKind, IncidentId, IncidentStatus, LabelValue, ModeratorId, Observation,
    PolicyId, Report, Severity, Subject, SubjectId,
};
use serde::{Deserialize, Serialize};

/// Aggregate response for `GET /api/cases/:subject_id`.
///
/// Composes everything the case view (design.md §5.2) renders for a single
/// subject:
///
/// - `subject` — the row from `subjects`, including denormalized risk signals.
/// - `history` — every [`Action`] taken against the subject's incidents,
///   chronologically ordered (the audit timeline).
/// - `reports` — user reports filed against the subject.
/// - `observations` — pattern-engine signals attached to the subject.
/// - `network_context` — placeholder for the follow / reply / cohort graph
///   panel (design.md §5.2 "Network context panel"). M2 populates this from
///   the network-graph service; the field is reserved here so the wire
///   shape is stable.
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
    /// Network-context panel placeholder. `Value::Null` until M2 populates.
    pub network_context: serde_json::Value,
}

/// Slim summary projection of a [`polaris_types::Incident`] for queue
/// listings.
///
/// Distinct from the full [`polaris_types::Incident`] shape because the
/// queue UI does not need the hydrated `reports` / `pattern_observations`
/// vectors. Carrying only the metadata keeps the response body bounded.
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

impl IncidentSummary {
    /// Project a full [`polaris_types::Incident`] down to the slim summary.
    #[must_use]
    pub fn from_incident(incident: &polaris_types::Incident) -> Self {
        Self {
            id: incident.id,
            primary_subject: incident.primary_subject,
            status: incident.status,
            severity: incident.severity,
            assigned_to: incident.assigned_to,
            opened_at: incident.opened_at,
        }
    }
}

/// Aggregate response for `GET /api/cases?status=...`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentList {
    /// The incident summaries on this page.
    pub incidents: Vec<IncidentSummary>,
    /// Total row count returned. Today this equals `incidents.len()`; once
    /// pagination lands (issue TBD) it will be the count before the page
    /// slice, so clients can render a "page X of Y" indicator.
    pub total: u64,
}

/// Request body for `POST /api/cases/:subject_id/actions`.
///
/// `moderator_id` is **intentionally absent** — the handler reads the
/// authenticated moderator from `Extension<ModeratorAuthCtx>`. Submitting an
/// action does not let the caller forge an attribution.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SubmitAction {
    /// Incident this action belongs to.
    pub incident_id: IncidentId,
    /// Verb (`label` / `takedown` / `mute` / `warn` / `escalate` / `no_action` / `reverse`).
    pub kind: ActionKind,
    /// Label value, when `kind = Label`.
    pub label: Option<LabelValue>,
    /// Free-text reasoning. Must be ≥ 10 chars per design.md §5.5.
    pub reasoning: String,
    /// Policy clauses cited. Must be non-empty and each entry must be in
    /// [`crate::api::policy::KNOWN_POLICY_REFS`].
    pub policy_refs: Vec<PolicyId>,
    /// When this action stops being reversible without senior co-sign.
    pub reversible_until: DateTime<Utc>,
    /// When `kind = Reverse`, the action being reversed.
    pub reverses_action_id: Option<ActionId>,
}

/// Query string for `GET /api/cases?status=...`.
///
/// `status` is optional; the default returns incidents in any status. Wire
/// values match the [`IncidentStatus`] serde representation (`open`,
/// `in_review`, `actioned`, `closed`, `escalated`).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IncidentListQuery {
    /// Filter by status. Omit to return all statuses.
    pub status: Option<IncidentStatus>,
}

/// Request body for `POST /api/cases/:incident_id/escalate`.
///
/// Reasoning is mandatory per design.md §5.5 — escalation is itself a
/// decision and inherits the same audit requirement as any other action.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Escalate {
    /// Free-text reasoning for the escalation. Must be ≥ 10 chars.
    pub reasoning: String,
}

// ── Pattern dashboard (issue #20) ───────────────────────────────────────

/// Aggregate response for `GET /api/dashboard`.
///
/// The four panels of the pattern dashboard described in `design.md` §5.1.
/// Each subfield is a typed vector — `serde_json::Value` is forbidden on
/// the wire surface per the issue #20 pre-flight, so every detector-specific
/// payload is reduced to a stable DTO shape here.
///
/// `fetched_at` is the wall-clock timestamp at which the snapshot was
/// composed on the server. The frontend renders it next to the panel as
/// the "as of …" indicator and uses it to detect stale frames when polling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    /// Hourly report-volume buckets over the trailing 24 hours.
    pub report_volume: Vec<ReportVolumeBucket>,
    /// Top incident clusters by `severity × reach`.
    pub clusters: Vec<IncidentClusterSummary>,
    /// Recent coordinated-action observations (cohort + image-hash bursts).
    pub coordinated_signals: Vec<CoordinatedSignal>,
    /// Queue depth per category, projected from incident status counts.
    pub moderator_load: Vec<ModeratorLoad>,
    /// Server wall-clock timestamp at the moment the snapshot was composed.
    pub fetched_at: DateTime<Utc>,
}

/// One hourly bucket of report volume.
///
/// `expected_mean` and `expected_stddev` are placeholders for issue #20 —
/// integration with the live anomaly detector (#19) is a separate concern;
/// the handler emits `0.0` for both fields today. The frontend's sparkline
/// renders the anomaly band when stddev is non-zero, so once the detector
/// is wired in no client change is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportVolumeBucket {
    /// Lower bound of the hourly window (UTC, hour-aligned).
    pub bucket_start: DateTime<Utc>,
    /// Number of reports filed inside the window.
    pub count: i64,
    /// Trailing-baseline mean for the bucket (0.0 until #19 is wired in).
    pub expected_mean: f64,
    /// Trailing-baseline standard deviation (0.0 until #19 is wired in).
    pub expected_stddev: f64,
}

/// Slim summary of an incident cluster for the dashboard's cluster panel.
///
/// Distinct from [`IncidentSummary`] used by the queue list: the cluster
/// panel renders the `related_subject_count` alongside the primary subject
/// so the moderator sees the *pattern* (one incident, N implicated
/// subjects), not just the canonical row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentClusterSummary {
    /// Incident identifier.
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

/// Discriminator for [`CoordinatedSignal`] — names which pattern detector
/// produced the row.
///
/// Wire form is `lowercase_snake` to match the existing
/// [`polaris_types::ObservationKind`] serde tagging convention; the values
/// are a strict subset of the observation kinds that surface to the
/// coordinated-signals panel (the panel intentionally hides `external_label`
/// and `classifier_signal` — those are subject-level, not pattern-level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinatedSignalKind {
    /// Image-hash cluster (SimHash / perceptual-hash match burst).
    ImageHashCluster,
    /// Account-cohort burst (creation-window-correlated accounts).
    AccountCohort,
    /// Reply-brigade match (coordinated reply burst on a thread).
    ReplyBrigade,
    /// Report-volume anomaly (incoming reports above baseline).
    ReportVolumeAnomaly,
}

/// One coordinated-action observation, projected for the dashboard.
///
/// The full [`polaris_types::Observation`] carries detector-specific
/// payloads — for the dashboard we collapse to a stable shape: kind,
/// human-readable `label`, contributing-subject count, and detection time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatedSignal {
    /// Which detector produced the signal.
    pub kind: CoordinatedSignalKind,
    /// Short human-readable identifier (e.g. a hash prefix, cohort id,
    /// thread URI suffix). Free-form text — the frontend renders verbatim.
    pub label: String,
    /// Count of distinct subjects contributing to the signal.
    pub subject_count: i64,
    /// When the pattern engine first emitted the observation.
    pub detected_at: DateTime<Utc>,
}

/// Queue-depth summary per moderation category.
///
/// `open_count` and `in_review_count` are read off the `incidents` table
/// grouped by category. M2 introduces an `incidents.category` column; until
/// then the handler projects across status tiers and reports the
/// placeholder category `"all"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeratorLoad {
    /// Category label. Free-form string — `"all"` until a category column
    /// lands on `incidents`.
    pub category: String,
    /// Incidents currently in [`IncidentStatus::Open`].
    pub open_count: i64,
    /// Incidents currently in [`IncidentStatus::InReview`].
    pub in_review_count: i64,
}
