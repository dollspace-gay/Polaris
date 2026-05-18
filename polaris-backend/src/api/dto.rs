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
    PolicyId, Report, ReportId, Severity, Subject, SubjectId,
};
use serde::{Deserialize, Serialize};

// Workbook policy DTO re-exports (WB-3 / #225). The canonical
// shape lives in `crate::api::admin_policies::dto`; we re-export
// here so other modules (and the wasm frontend's `api_client/dto.rs`,
// WB-4 / #226) import from a single, stable path per REQ-C3.
pub use crate::api::admin_policies::dto::{
    CreatePolicyDto, DiffChangeDto, ModPolicyDto, ModPolicyEditDto, ModPolicyHistoryEntryDto,
    ModPolicySummaryDto, PausePolicyDto, PolicyDiffDto,
};

/// Aggregate response for `GET /api/cases/:subject_id`.
///
/// Composes everything the case view (design.md §5.2) renders for a single
/// subject:
///
/// - `subject` — the row from `subjects`, including denormalized risk signals.
/// - `history` — every [`Action`] taken against the subject's incidents,
///   chronologically ordered (the audit timeline).
/// - `reports` — user reports filed against the subject.
/// - `reporter_contexts` — per-reporter reputation context for the reports
///   above. Design.md §5.2 calls for "reporter context: new account vs.
///   established, prior false-report rate"; this is that data, joined
///   from the `reporter_stats` table (issue #37).
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
    /// Per-reporter reputation context for the reports above (issue #37,
    /// design.md §5.2 + §9.3). One entry per distinct `reporter_did` seen
    /// in `reports`. Reporters with no `reporter_stats` row (never-before-
    /// seen) are present with `reports_filed = 0` and the neutral score.
    pub reporter_contexts: Vec<ReporterContext>,
    /// Pattern-engine observations attached to the subject.
    pub observations: Vec<Observation>,
    /// Distinct image blobs the network-context handler has observed
    /// for this subject (one row per blob CID, with the most-recent
    /// post URI). Surfaces media for blur-by-default preview in the
    /// case-view media panel (issue #95). The list is empty until the
    /// network-context handler runs at least once for this subject —
    /// it populates `subject_image_blobs` lazily on case-view load.
    pub media_blobs: Vec<SubjectMediaBlob>,
    /// All Polaris moderation actions taken against ANY other subject
    /// owned by this DID (account-kind subjects under the same DID,
    /// plus post-kind subjects authored by this DID). The case view's
    /// timeline groups these alongside `history` so the moderator sees
    /// every action ever taken against this account or any of its
    /// posts — not just the actions on the current exact subject row.
    ///
    /// Each entry carries the related subject's metadata so the
    /// timeline can label it ("action on post @rkey", "action on
    /// related account row") and provide a click-through to that
    /// subject's case view. Ordered newest-first.
    ///
    /// Empty when this subject's row has no `did` populated (list /
    /// feed-kind subjects don't have a DID to expand on).
    pub related_actions: Vec<RelatedAction>,
    /// Network-context panel placeholder. `Value::Null` because the
    /// rich network-graph data is served by a sibling endpoint
    /// (`/api/cases/{subject_id}/network-context`) and rendered by the
    /// frontend's `NetworkPanel` on mount.
    pub network_context: serde_json::Value,
}

/// One Polaris moderation action targeting a subject related to the
/// case-view's current subject (same DID owner; different row).
///
/// Wire fields:
///
/// - `action` — the full [`Action`] row (kind, `label_value`, moderator,
///   timestamps, etc.). Rendered by the same timeline template the
///   primary `history` field uses.
/// - `target_subject_id` — the related subject's UUID; the timeline
///   makes the row clickable so a moderator can pivot to that
///   subject's case view.
/// - `target_subject_kind` — `"account"` / `"post"` / `"list"` /
///   `"feed"` so the timeline can label the row ("action on post",
///   "action on related account row").
/// - `target_subject_uri` — the AT-URI of the related subject when
///   the kind is record-shaped; `None` for account-kind subjects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelatedAction {
    /// The action row itself, hydrated with every field the timeline
    /// renders.
    pub action: Action,
    /// UUID of the subject the action targets (NOT this case view's
    /// subject).
    pub target_subject_id: SubjectId,
    /// Wire form of the related subject's `kind` column
    /// (`"account"`/`"post"`/`"list"`/`"feed"`).
    pub target_subject_kind: String,
    /// AT-URI of the related subject, when the kind is record-shaped.
    pub target_subject_uri: Option<String>,
}

/// Distinct image blob attached to a subject. Mirrors a row from
/// `subject_image_blobs` (migration 0026; `alt_text` added by
/// migration 0031; `owner_did` + `walked_at` added by migration
/// 0032).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectMediaBlob {
    /// ATProto blob CID (content-address). Same bytes produce the
    /// same CID, which is the load-bearing property for the
    /// shared-image-cluster signal that the network-context handler
    /// builds on top of this table.
    pub blob_cid: String,
    /// AT-URI of a post that embedded this blob. When the same blob
    /// is embedded across multiple posts, the most-recent URI is
    /// surfaced (`ORDER BY first_seen_at DESC` in the case-view
    /// query).
    pub post_uri: String,
    /// Author-provided alternative text for the image, when the
    /// post's `embed.images[].alt` field was populated. `None`
    /// means the author did not provide alt text (a moderator
    /// signal in its own right — missing alt text on spam imagery
    /// is common). Captured lazily on each case-view load from
    /// `app.bsky.feed.getAuthorFeed`.
    pub alt_text: Option<String>,
    /// DID of the repo that owns the blob (the post's authoring
    /// repo). The frontend uses this verbatim as the CDN-URL
    /// authority so the image fetch resolves regardless of
    /// provenance. `None` for rows persisted before migration
    /// 0032 — the frontend falls back to the subject's DID,
    /// which is correct for any subject-authored post.
    pub owner_did: Option<String>,
    /// AppView-indexed timestamp of the post that embedded this
    /// blob (`post.indexedAt` from `getAuthorFeed`). The case-view
    /// media gallery orders the carousel by this descending, so
    /// the moderator sees the subject's newest images first.
    /// `None` for rows persisted before migration 0033 — those
    /// rows fall to the tail of the carousel via `NULLS LAST`.
    pub post_indexed_at: Option<DateTime<Utc>>,
    /// First time the network-context handler observed this
    /// (subject, blob) pair.
    pub first_seen_at: DateTime<Utc>,
}

/// Reporter-context row attached to [`CaseView::reporter_contexts`].
///
/// Issue #37 / design.md §5.2 — "reporter context: new account vs.
/// established, prior false-report rate." The moderator should see, on
/// every reported subject, who the reporters are and how credible their
/// past reports have been.
///
/// Wire fields:
///
/// - `did` — the reporter's DID.
/// - `reports_filed` — total reports ever filed by this DID.
/// - `reports_actioned` — subset that produced a Label/Takedown.
/// - `reputation_score` — the cached score from `reporter_stats` (range
///   `[0.0, 1.0]`). A score around 0.5 is "no strong signal" (either
///   no history or a balanced track record); above 0.95 is "highly
///   credible"; below 0.05 is "serial false-reporter".
/// - `account_age_days` — days between `first_seen` (the reporter's
///   first report Polaris saw) and `Utc::now()` at case-view assembly.
///   Surfaces the "new account vs. established" signal directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReporterContext {
    /// The reporter's DID.
    pub did: String,
    /// Lifetime reports filed by this reporter.
    pub reports_filed: i64,
    /// Lifetime reports that produced a Label / Takedown action.
    pub reports_actioned: i64,
    /// Cached reputation score in `[0.0, 1.0]`.
    pub reputation_score: f32,
    /// Days since the reporter was first seen by Polaris.
    pub account_age_days: i64,
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
    /// When the action is being taken against a specific report (the
    /// Acknowledge / Dismiss / Escalate buttons on the case-view's
    /// report card all pass this), the report's id is carried here.
    ///
    /// Setting this field opts the request into the per-report
    /// idempotency path (issue #202): the handler row-locks the report
    /// (`SELECT … FOR UPDATE`), returns the existing action if the
    /// report has already been actioned, and inserts a new action
    /// otherwise. The action insert + the `reports.actioned_at` /
    /// `reports.actioned_by_action_id` update commit atomically.
    ///
    /// Leaving the field `None` (the action-composer's per-subject
    /// submission path; the Mute-Reporter button; bulk-action workflows)
    /// preserves the pre-#202 behavior: one row inserted per call, no
    /// report-state side effect.
    ///
    /// `#[serde(default)]` makes the field backwards-compatible — older
    /// clients that omit it still parse.
    #[serde(default)]
    pub report_id: Option<ReportId>,
}

/// Query string for `GET /api/cases?status=...&limit=...&offset=...`.
///
/// `status` is optional; the default returns incidents in any status. Wire
/// values match the [`IncidentStatus`] serde representation (`open`,
/// `in_review`, `actioned`, `closed`, `escalated`).
///
/// `limit` and `offset` are optional pagination controls. Defaults are
/// `limit = 50`, `offset = 0`. The handler clamps `limit` to the
/// [`crate::api::cases::MAX_ROWS_PER_LIST`] hard ceiling so a malicious
/// caller cannot request a 100k-row response. Negative `offset` is
/// clamped to 0; `limit <= 0` falls back to the default.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct IncidentListQuery {
    /// Filter by status. Omit to return all statuses.
    pub status: Option<IncidentStatus>,
    /// Page size. Defaults to 50; clamped to the handler's hard
    /// ceiling.
    pub limit: Option<i64>,
    /// Number of rows to skip. Defaults to 0.
    pub offset: Option<i64>,
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
///
/// `weighted_count` (issue #37) is the sum of per-report
/// reputation scores. With the default `(1.0, 1.0)` prior an all-new-
/// reporter bucket gives `weighted_count ≈ 0.5 * count`; an all-
/// established-good bucket gives `weighted_count ≈ count`. The frontend
/// renders both: `count` is the raw activity volume; `weighted_count` is
/// the credibility-adjusted signal the anomaly detector should track.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportVolumeBucket {
    /// Lower bound of the hourly window (UTC, hour-aligned).
    pub bucket_start: DateTime<Utc>,
    /// Number of reports filed inside the window.
    pub count: i64,
    /// Reputation-weighted sum of reports filed inside the window
    /// (issue #37). Each report contributes its reporter's cached
    /// reputation score; the result is bounded by `[0.0, count as f64]`.
    pub weighted_count: f64,
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

// ── Live dashboard feed (issue #57) ─────────────────────────────────────

/// Diff payload pushed to subscribers of `GET /api/dashboard/live`.
///
/// Each variant carries the same DTO shape the full
/// [`DashboardSnapshot`] uses for the corresponding panel, so the frontend
/// can patch its local snapshot signal without a second deserialisation
/// step. The serde tag `kind` matches [`CoordinatedSignalKind`]'s
/// convention — JSON looks like `{"kind": "new_cluster", "cluster": {…}}`,
/// which is the wire shape the architect's pre-flight pins.
///
/// New variants are purely additive: the frontend's `match` on `kind`
/// already ignores wire values it does not recognise (serde rejects an
/// unknown tag with a typed error the WS task surfaces, falls back to
/// polling, and the operator sees a structured tracing event). When a
/// new dashboard panel ships, add a variant here and a matching arm on
/// the frontend.
///
/// # Why diff and not snapshot
///
/// `GET /api/dashboard` already returns the whole snapshot — the live
/// feed is a latency optimisation, not a transport. Sending the full
/// snapshot on every event would bottleneck on the same SQL aggregate
/// the polling endpoint guards against (incident counts + report-volume
/// rollups). Diff payloads keep each WS frame O(1) in the data each
/// detector contributed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DashboardEvent {
    /// A new incident cluster is now in the top-clusters panel. Sent
    /// when the pattern engine opens an incident whose
    /// `severity × related_subject_count` ranks above the panel cut-off.
    NewCluster {
        /// The cluster summary — same shape as
        /// [`DashboardSnapshot::clusters`] entries.
        cluster: IncidentClusterSummary,
    },
    /// A new coordinated-action observation landed. Sent when a detector
    /// (image-hash, account-cohort, reply-brigade, report-volume anomaly)
    /// emits an observation that surfaces to the coordinated-signals
    /// panel.
    NewSignal {
        /// The signal summary — same shape as
        /// [`DashboardSnapshot::coordinated_signals`] entries.
        signal: CoordinatedSignal,
    },
    /// One hourly report-volume bucket changed. Sent when a report
    /// commits into a bucket the dashboard currently renders (typically
    /// the trailing-most bucket); the frontend swaps the matching
    /// `bucket_start` entry in its local `report_volume` vector.
    VolumeBucketUpdated {
        /// The replacement bucket — keyed by `bucket_start` against the
        /// snapshot vector on the frontend.
        bucket: ReportVolumeBucket,
    },
    /// The per-category queue depth changed. Sent when an incident
    /// transitions through `Open` / `InReview` / closed so the
    /// moderator-load panel reflects the new counts without a refetch.
    ModeratorLoadDelta {
        /// The replacement load row — keyed by `category` against the
        /// snapshot vector on the frontend.
        load: ModeratorLoad,
    },
}
