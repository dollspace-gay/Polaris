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
    PolicyId, Report, ReportId, Severity, Subject, SubjectId,
};
use serde::{Deserialize, Serialize};

/// Aggregate response for `GET /api/cases/:subject_id`.
///
/// Mirrors [`polaris_backend::api::dto::CaseView`] field-for-field.
///
/// `network_context` is intentionally kept as a `Value` here because the
/// rich shape is owned by the `/api/cases/{subject_id}/network-context`
/// endpoint and rendered by [`crate::components::network_panel::NetworkPanel`];
/// the field on this DTO is reserved for the initial-render path only.
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
    /// in `reports`. Reporters with no `reporter_stats` row are present
    /// with `reports_filed = 0` and the neutral score so the case-view
    /// shape is stable. Optional on the wire so legacy backend deployments
    /// that don't emit the field still deserialize.
    #[serde(default)]
    pub reporter_contexts: Vec<ReporterContext>,
    /// Pattern-engine observations attached to the subject.
    pub observations: Vec<Observation>,
    /// Distinct image blobs observed on this subject's authored posts
    /// (one row per blob CID, most-recent post URI). Empty until the
    /// network-context handler has run at least once for this subject —
    /// the table is populated lazily on case-view load. Optional on
    /// the wire so legacy backend deployments without the field still
    /// deserialize.
    #[serde(default)]
    pub media_blobs: Vec<SubjectMediaBlob>,
    /// Polaris moderation actions targeting OTHER subjects owned by
    /// the same DID — accounts under the same DID plus posts authored
    /// by it. The timeline groups these alongside `history` so the
    /// moderator sees every action ever taken against this user, not
    /// just actions on the exact case-view subject row. Empty when
    /// the subject has no `did` populated. Optional on the wire so
    /// legacy backend deployments without the field still deserialize.
    #[serde(default)]
    pub related_actions: Vec<RelatedAction>,
    /// Network-context placeholder. The real signal surface lives in the
    /// sidebar's `NetworkPanel` which fetches `/api/cases/{subject_id}/network-context`.
    pub network_context: serde_json::Value,
}

/// Mirror of `polaris_backend::api::dto::RelatedAction` — one
/// moderation action targeting a subject related to the current
/// case-view subject (same DID, different subject row).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RelatedAction {
    /// The full action row, ready to feed the timeline renderer.
    pub action: Action,
    /// UUID of the related subject the action targeted.
    pub target_subject_id: SubjectId,
    /// `"account"`/`"post"`/`"list"`/`"feed"` — used by the timeline
    /// to label the row ("action on post", "action on related account
    /// row").
    pub target_subject_kind: String,
    /// AT-URI of the related subject when the kind is record-shaped.
    #[serde(default)]
    pub target_subject_uri: Option<String>,
}

/// Mirror of `polaris_backend::api::media::MediaGalleryResponse` —
/// the wire shape returned by `GET /api/cases/{subject_id}/media`.
///
/// Carries the full deduped media list (one entry per unique blob
/// CID, newest-first) plus an `upstream_ok` flag the frontend uses
/// to render a "could not refresh" hint when the AppView walk
/// failed but the cache still had rows.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MediaGalleryResponse {
    /// Distinct image-blob entries for this subject.
    pub blobs: Vec<SubjectMediaBlob>,
    /// `true` when the AppView walk returned at least one page;
    /// `false` when the upstream failed and `blobs` (if any) is
    /// the cached set from a prior successful walk.
    #[serde(default)]
    pub upstream_ok: bool,
}

/// Mirror of [`polaris_backend::api::dto::SubjectMediaBlob`] —
/// one image blob attached to this subject for case-view media preview.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubjectMediaBlob {
    /// ATProto blob CID (content-address).
    pub blob_cid: String,
    /// AT-URI of a post that embedded this blob.
    pub post_uri: String,
    /// Author-provided alternative text for the image (from the
    /// post's `embed.images[].alt` field). `None` when the author
    /// did not supply alt text. Optional on the wire so legacy
    /// backends without the column still deserialize.
    #[serde(default)]
    pub alt_text: Option<String>,
    /// DID of the repo that owns the blob — used by the gallery
    /// as the CDN-URL authority. `None` for legacy rows persisted
    /// before the owner-DID column landed; the frontend falls
    /// back to the subject's own DID in that case (correct for
    /// any subject-authored post, which is the only kind that
    /// reaches the gallery after the post-filter walker is in
    /// place).
    #[serde(default)]
    pub owner_did: Option<String>,
    /// AppView-indexed timestamp of the post that embedded this
    /// blob. The backend already orders the response newest-first
    /// by this field; the frontend renders it as a "Posted: …"
    /// line on the carousel so a moderator can correlate each
    /// image with when it appeared. `None` for legacy rows.
    #[serde(default)]
    pub post_indexed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When the network-context handler first observed this blob
    /// for this subject.
    pub first_seen_at: chrono::DateTime<chrono::Utc>,
}

/// Per-reporter reputation context — mirror of
/// [`polaris_backend::api::dto::ReporterContext`].
///
/// Powers the "new account vs. established reporter" signal in the
/// case view's report list (issue #37 / design.md §9.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReporterContext {
    /// The reporter's DID.
    pub did: String,
    /// Lifetime reports filed by this reporter.
    pub reports_filed: i64,
    /// Lifetime reports that produced a Label / Takedown action.
    pub reports_actioned: i64,
    /// Cached reputation score in `[0.0, 1.0]`. 0.0 = no actionable
    /// reports yet; 1.0 = every report this reporter filed produced
    /// an action.
    pub reputation_score: f32,
    /// Days since the reporter was first seen by Polaris. `0` for
    /// brand-new reporters (the "new account" signal).
    pub account_age_days: i64,
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
    /// Per-report idempotency key (issue #202). The report-card buttons
    /// (Acknowledge / Dismiss / Escalate) pass `Some(report.id)` so the
    /// backend dedupes per report — a second click with the same
    /// `report_id` returns the existing action instead of inserting a
    /// duplicate row, and the case-view's report list filters the
    /// actioned row out so the card stops appearing.
    ///
    /// The action-composer (per-subject submission) and the
    /// Mute-Reporter button leave this `None`. `#[serde(default)]` keeps
    /// the field backwards-compatible — older backends that don't know
    /// about it still parse the body.
    #[serde(default)]
    pub report_id: Option<ReportId>,
}

/// Request body for `POST /api/cases/:incident_id/escalate`.
///
/// Mirrors [`polaris_backend::api::dto::Escalate`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Escalate {
    /// Free-text reasoning for the escalation. Must be >= 10 chars.
    pub reasoning: String,
}

/// Request body for `POST /api/bulk-actions`.
///
/// Mirrors `polaris_backend::api::cases::BulkSubmitAction`. One
/// `SubmitAction` body is applied per subject in `subject_ids`; the
/// embedded `incident_id` is shared across all subjects in the batch.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BulkSubmitAction {
    /// Subject IDs to apply the action to.
    pub subject_ids: Vec<polaris_types::SubjectId>,
    /// Per-subject action payload (shape identical to single-subject submit).
    pub body: SubmitAction,
}

/// Response shape for `POST /api/bulk-actions`.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BulkActionOutcome {
    /// Subjects whose action persisted.
    #[serde(default)]
    pub succeeded: Vec<polaris_types::SubjectId>,
    /// Subjects whose action failed, with per-row reason.
    #[serde(default)]
    pub failed: Vec<BulkActionFailure>,
}

/// One row of [`BulkActionOutcome::failed`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BulkActionFailure {
    /// Subject that failed.
    pub subject_id: polaris_types::SubjectId,
    /// Operator-readable failure cause.
    pub reason: String,
}

/// Request body for `POST /api/moderation/muted-reporters` (#192).
///
/// Mirrors `polaris_backend::api::moderator_controls::MuteReporterBody`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MuteReporterBody {
    /// DID to mute (`did:plc:...` / `did:web:...`).
    pub reporter_did: String,
    /// Operator-readable reason (10-2000 chars).
    pub reason: String,
    /// Optional auto-unmute timestamp (RFC3339). `None` = mute
    /// indefinitely.
    pub until: Option<String>,
}

/// Response shape for `POST /api/moderation/muted-reporters`.
/// Mirrors `polaris_backend::api::moderator_controls::MutedReporterRow`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MutedReporterRow {
    /// DID being muted.
    pub reporter_did: String,
    /// Moderator who applied the mute.
    pub muted_by: uuid::Uuid,
    /// Operator-supplied reason.
    pub reason: String,
    /// Wall-clock the mute was applied.
    pub muted_at: chrono::DateTime<chrono::Utc>,
    /// Auto-unmute deadline; `None` = permanent.
    #[serde(default)]
    pub until: Option<chrono::DateTime<chrono::Utc>>,
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

/// Faceted-filter request shape for `GET /api/dashboard` (issue #94 /
/// mod-workstation feature #4).
///
/// Every field is optional. The frontend builds this from the
/// dashboard's [`FilterState`] signal and threads it through
/// [`crate::api_client::PolarisApiClient::dashboard`]. Empty fields
/// are omitted from the URL — the backend's `Query<DashboardQuery>`
/// extractor treats absent and empty-string identically.
///
/// `status` is a wire string (`open` / `in_review` / `actioned` /
/// `closed` / `escalated`) rather than the typed
/// [`polaris_types::IncidentStatus`] so the filter bar can surface
/// dropdown options without coupling to backend enum naming.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DashboardFilters {
    /// Filter incidents to those with at least one report from this
    /// reporter DID. The backend validates against
    /// `proto_blue::syntax::Did`.
    pub reporter_did: Option<String>,
    /// Filter incidents to those with at least one report in this
    /// category (free-form string).
    pub category: Option<String>,
    /// Filter incidents by [`polaris_types::IncidentStatus`] wire
    /// form (e.g. `"open"`, `"escalated"`).
    pub status: Option<String>,
    /// Lower bound on `incidents.opened_at` (inclusive). RFC3339.
    pub since: Option<String>,
    /// Upper bound on `incidents.opened_at` (inclusive). RFC3339.
    pub until: Option<String>,
}

/// Serialise [`DashboardFilters`] into a percent-encoded URL query
/// string (without the leading `?`).
///
/// Empty / `None` fields are omitted entirely so a default-constructed
/// `DashboardFilters` produces an empty string — call sites use that
/// to decide whether to append `?…` to `/api/dashboard` at all (AC-6:
/// the unfiltered request must match the pre-#94 URL shape).
///
/// Encoding is RFC3986 `application/x-www-form-urlencoded` over the
/// reserved-character set: every byte that is not `A-Za-z0-9-._~` is
/// percent-encoded. This is the wire shape axum's `Query<…>` extractor
/// decodes by default, so the round-trip is symmetric.
#[must_use]
pub fn dashboard_filters_to_query_string(filters: &DashboardFilters) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(value) = filters.reporter_did.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("reporter_did={}", percent_encode(value)));
    }
    if let Some(value) = filters.category.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("category={}", percent_encode(value)));
    }
    if let Some(value) = filters.status.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("status={}", percent_encode(value)));
    }
    if let Some(value) = filters.since.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("since={}", percent_encode(value)));
    }
    if let Some(value) = filters.until.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("until={}", percent_encode(value)));
    }
    parts.join("&")
}

/// Percent-encode a single value per RFC3986's unreserved-character
/// rule. Pulled out as a free function so the test module can drive it
/// independently of the full filter struct.
///
/// Keeps `A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, `~` verbatim; every other
/// byte becomes `%HH` (uppercase hex). Sufficient for the wire
/// vocabulary we send (DIDs, RFC3339 timestamps, lowercase-snake
/// status tokens).
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            // `byte` is always 0..=255; the cast is lossless.
            use std::fmt::Write as _;
            // `write!` on a String never fails; ignoring the result is
            // intentional and the only way to satisfy the
            // no-`expect`/no-`unwrap` rule on non-test code.
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

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
    /// Trailing-baseline weighted mean over the prior 7 days of
    /// hourly buckets (Welford's algorithm, computed server-side in
    /// `polaris_backend::api::dashboard::baseline_stats`). Will be
    /// exactly `0.0` only when the baseline window has fewer than 2
    /// hours of data — the frontend hides the anomaly band in that
    /// case rather than rendering a fabricated band.
    pub expected_mean: f64,
    /// Trailing-baseline standard deviation over the prior 7 days.
    /// `0.0` when the baseline window is empty / insufficient; the
    /// frontend treats `stddev == 0.0` as "no anomaly band" and
    /// renders only the raw count line.
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

// ── First-run setup wizard (issue #84) ──────────────────────────────────

/// Response from `POST /api/setup/generate-key`.
///
/// The backend mints a fresh K-256 signing key, persists the private
/// half to its keystore, and returns the public half as a `did:key:z…`
/// multikey the wizard surfaces to the operator for cross-checking
/// against the labeler service record / DID document.
///
/// Mirrors the backend's `polaris_backend::api::setup::GenerateKeyResponse`
/// (lands in #85). The wire shape is pinned here so the frontend's UI
/// and the backend's handler agree on the JSON layout before the handler
/// exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeyResponse {
    /// `did:key:z…` multikey form of the freshly-minted public key.
    pub did_key: String,
}

/// Request body for `POST /api/setup/publish-labeler-record`.
///
/// The backend pairs `service_url` + `label_values` with the
/// already-minted signing key (from the previous step's
/// [`GenerateKeyResponse`]) plus the moderator's authenticated session
/// and submits the `app.bsky.labeler.service` record via the PDS.
///
/// `service_url` is a fully-qualified `https://…` URL (the labeler's
/// public hostname); the labeler-record CLI's validation rules apply
/// — see `polaris_publish_labeler_record::build_labeler_service_record`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishLabelerRecordRequest {
    /// HTTPS URL the labeler's WebSocket subscription endpoint lives at.
    pub service_url: String,
    /// Label values the labeler is declaring it emits (e.g. `["spam",
    /// "porn"]`). Must be non-empty server-side.
    pub label_values: Vec<String>,
}

/// Response from `POST /api/setup/publish-labeler-record`.
///
/// Echoes the AT-URI the record was written at plus the CID of the
/// committed record so the wizard can surface a "your labeler is now
/// published at … (cid …)" confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishLabelerRecordResponse {
    /// AT-URI of the published record
    /// (`at://<did>/app.bsky.labeler.service/self`).
    pub at_uri: String,
    /// CID of the committed record.
    pub cid: String,
}

/// Response from `POST /api/setup/request-plc-signature`.
///
/// The backend asks the operator's PDS to email a PLC operation token
/// to the operator's registered email address; the body returned here
/// is a human-readable message the wizard renders so the operator knows
/// to check their inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestPlcSignatureResponse {
    /// Human-readable instruction (e.g. `"Check your email at
    /// op@example.com for the PLC operation token"`). The wizard
    /// surfaces this verbatim — no client-side parsing.
    pub message: String,
}

/// Request body for `POST /api/setup/submit-plc-operation`.
///
/// `token` is the value the operator copy-pasted from the email the
/// PDS sent; `service_url` is the same `https://…` URL the previous
/// step pinned, written into the DID document's `#atproto_labeler`
/// service entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPlcOperationRequest {
    /// The PLC operation token the PDS emailed to the operator.
    pub token: String,
    /// HTTPS URL the labeler's service entry on the operator's DID
    /// document should point at. Conventionally the same value passed
    /// to the labeler-record publish step.
    pub service_url: String,
}

/// Response from `POST /api/setup/submit-plc-operation`.
///
/// The DID identifier whose document was updated. Surfaced to the
/// operator as confirmation that the PLC operation landed and the
/// labeler service entry is now resolvable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitPlcOperationResponse {
    /// The DID whose document was updated (e.g. `did:plc:abcd…`).
    pub did: String,
}

// ── Command palette / subject lookup (issue #92) ────────────────────────

/// Request body for `POST /api/subjects/lookup`.
///
/// Mirrors `polaris_backend::api::subjects::SubjectLookupRequest`.
/// The single field is a moderator-supplied identifier (URL, DID,
/// AT-URI, or handle); the backend parser folds every shape into a
/// typed payload before resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectLookupRequest {
    /// The pasted identifier. Any of:
    ///
    /// - `did:plc:...` / `did:web:...`
    /// - `at://did:plc:.../app.bsky.feed.post/<rkey>`
    /// - `at://handle.bsky.social/app.bsky.feed.post/<rkey>`
    /// - `https://bsky.app/profile/<handle-or-did>`
    /// - `https://bsky.app/profile/<handle-or-did>/post/<rkey>`
    /// - Bare handle (`alice.bsky.social`)
    pub identifier: String,
}

/// Response from `POST /api/subjects/lookup`.
///
/// Mirrors `polaris_backend::api::subjects::SubjectLookupResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubjectLookupResponse {
    /// Stable Polaris `subjects.id` as a hyphenated UUID string. The
    /// palette consumes this with `use_navigate()` to push
    /// `/cases/{subject_id}`.
    pub subject_id: String,
    /// Resolved DID — always populated.
    pub did: String,
    /// Canonical AT-URI when `kind == "post"`; `None` for accounts.
    pub uri: Option<String>,
    /// `"account"` or `"post"`.
    pub kind: String,
}

// ── /api/whoami (issue #83) ─────────────────────────────────────────────

/// Wire shape returned by `GET /api/whoami`.
///
/// Mirrors the backend's
/// [`polaris_backend::api::whoami::WhoamiResponse`] field-for-field.
/// The frontend uses [`Self::first_run`] to decide whether the root
/// route renders the dashboard or redirects to `/setup`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoamiResponse {
    /// Stable moderator UUID rendered as a hyphenated hex string.
    pub moderator_id: String,
    /// External identifier for the moderator — the DID for
    /// `auth_backend = "atproto"`, the `sub` claim for
    /// `auth_backend = "oidc"`.
    pub external_id: String,
    /// Discriminator from the `moderators.auth_backend` column
    /// (`"atproto"` or `"oidc"`).
    pub auth_backend: String,
    /// Role set granted to this moderator (stable role identifiers).
    pub roles: Vec<String>,
    /// `true` when the deployment is fresh (no committed actions, no
    /// emitted labels) — the frontend routes to `/setup` instead of
    /// `/` in that case.
    pub first_run: bool,
}

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

/// Response from `GET /api/cases/{subject_id}/network-context`
/// (issue #97 / M2 case-view network panel).
///
/// Wire-shape mirror of
/// `polaris_backend::api::network_context::NetworkContextResponse`.
/// Every sub-field is independently populated; an empty section is
/// the documented "this signal unavailable" state, surfaced
/// explicitly via [`SignalQuality`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    /// Subject DID. Echoed for the copy affordance.
    pub did: String,
    /// Subject handle (filtered for `handle.invalid`).
    #[serde(default)]
    pub handle: Option<String>,
    /// User-edited display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Self-authored bio.
    #[serde(default)]
    pub description: Option<String>,
    /// CDN URL of the avatar.
    #[serde(default)]
    pub avatar: Option<String>,
    /// Count of accounts following this subject.
    #[serde(default)]
    pub followers_count: Option<i64>,
    /// Count of accounts this subject follows.
    #[serde(default)]
    pub follows_count: Option<i64>,
    /// Count of posts the subject has published.
    #[serde(default)]
    pub posts_count: Option<i64>,
    /// Account creation timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Last AppView re-index timestamp.
    #[serde(default)]
    pub indexed_at: Option<String>,
    /// Days between `created_at` and `now()`.
    #[serde(default)]
    pub account_age_days: Option<i64>,
    /// Labels applied by labelers OTHER than Polaris.
    #[serde(default)]
    pub labels: Vec<NetworkContextLabel>,
    /// Pinned-post AT-URI.
    #[serde(default)]
    pub pinned_post_uri: Option<String>,
    /// Pinned-post CID.
    #[serde(default)]
    pub pinned_post_cid: Option<String>,
    /// Whether the AppView marks this account as a labeler.
    #[serde(default)]
    pub is_labeler: bool,
    /// Follow-graph signal.
    pub follow_graph: FollowGraph,
    /// Activity-pattern aggregate derived from the author-feed walk.
    /// Mirrors `polaris_backend::api::network_context::ActivityPattern`.
    pub activity_pattern: ActivityPattern,
    /// Reply-graph signal.
    pub reply_graph: ReplyGraph,
    /// Cohort signals.
    pub cohort: CohortSignals,
    /// Shared-image cluster signal.
    pub shared_images: SharedImageSignals,
    /// Source URL for the profile fetch.
    pub source_url: String,
    /// Per-section availability flags.
    pub signal_quality: SignalQuality,
}

/// One label on a subject's profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContextLabel {
    /// Label value.
    pub val: String,
    /// DID of the labeler that issued this label.
    pub src: String,
    /// Labeler display name (resolved server-side via
    /// `app.bsky.labeler.getServices`). `None` falls back to the
    /// raw DID on render.
    #[serde(default)]
    pub src_display_name: Option<String>,
    /// Labeler handle (e.g. `moderation.bsky.app`).
    #[serde(default)]
    pub src_handle: Option<String>,
    /// Target the label was applied to — either a DID (account)
    /// or an AT-URI (specific post / list / feed). Rendered as a
    /// clickable bsky.app link when it's a post URI so a moderator
    /// can pivot to the labeled content.
    pub uri: String,
    /// Content CID. Set for record-level labels; identifies the
    /// exact revision of the record that was labeled.
    #[serde(default)]
    pub cid: Option<String>,
    /// Negation flag. When `true` the row represents a labeler
    /// retracting a prior assertion — rendered as "removed at
    /// <date>" rather than "applied at <date>".
    #[serde(default)]
    pub neg: bool,
    /// Issuance timestamp (RFC3339). Frontend reformats for
    /// display.
    #[serde(default)]
    pub cts: Option<String>,
    /// Optional expiry timestamp.
    #[serde(default)]
    pub exp: Option<String>,
}

/// One actor entry — used in followers / follows / reply graph /
/// cohort lists.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NetworkActor {
    /// Actor DID.
    pub did: String,
    /// Handle.
    #[serde(default)]
    pub handle: Option<String>,
    /// Display name.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Avatar URL.
    #[serde(default)]
    pub avatar: Option<String>,
}

/// Aggregate post-activity signal derived from the author-feed walk.
/// Replaces the bulky recent-followers / recent-follows lists in the
/// case-view's follow-graph section with cadence + time-of-day +
/// weekday signals a moderator can read at a glance.
///
/// Mirrors `polaris_backend::api::network_context::ActivityPattern`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActivityPattern {
    /// Number of subject-authored, non-repost posts observed in the
    /// AppView walk window (~300 posts).
    #[serde(default)]
    pub total_posts_seen: i64,
    /// Posts whose `indexedAt` is in the most-recent 7 days.
    #[serde(default)]
    pub posts_last_7d: i64,
    /// Posts whose `indexedAt` is in the most-recent 30 days.
    #[serde(default)]
    pub posts_last_30d: i64,
    /// Most-recent post timestamp (RFC 3339), `None` when the walk
    /// returned nothing.
    #[serde(default)]
    pub latest_post_at: Option<String>,
    /// 30-day daily-post histogram, oldest → newest. Exactly 30
    /// entries when populated; empty Vec when the walk returned
    /// nothing.
    #[serde(default)]
    pub posts_per_day_30d: Vec<DailyPostCount>,
    /// Hour-of-day distribution (UTC). Index 0 = 00:00-00:59,
    /// index 23 = 23:00-23:59.
    #[serde(default = "default_24_zeros")]
    pub posts_per_hour_utc: [i64; 24],
    /// Day-of-week distribution. Index 0 = Monday, index 6 = Sunday.
    #[serde(default = "default_7_zeros")]
    pub posts_per_weekday: [i64; 7],
}

fn default_24_zeros() -> [i64; 24] {
    [0; 24]
}
fn default_7_zeros() -> [i64; 7] {
    [0; 7]
}

/// One bar of [`ActivityPattern::posts_per_day_30d`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyPostCount {
    /// Calendar day in `YYYY-MM-DD` (UTC).
    pub date: String,
    /// Number of posts on this day inside the walked window.
    pub count: i64,
}

/// Follow-graph surface.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FollowGraph {
    /// Most-recent followers.
    #[serde(default)]
    pub recent_followers: Vec<NetworkActor>,
    /// Most-recent follows.
    #[serde(default)]
    pub recent_follows: Vec<NetworkActor>,
    /// Mutual-follow intersection size.
    #[serde(default)]
    pub mutual_count: i64,
}

/// Reply-graph surface.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReplyGraph {
    /// Accounts the subject replies to.
    #[serde(default)]
    pub recent_replies_to: Vec<NetworkActor>,
    /// Accounts that reply to the subject's posts.
    #[serde(default)]
    pub recent_repliers: Vec<NetworkActor>,
}

/// Cohort surface.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CohortSignals {
    /// Top mutual-follow overlap.
    #[serde(default)]
    pub mutual_follow_overlap: Vec<NetworkActor>,
    /// Top interaction partners (follows ∩ replies-to).
    #[serde(default)]
    pub top_interaction_partners: Vec<NetworkActor>,
}

/// Shared-image cluster surface.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SharedImageSignals {
    /// Recent image CIDs the subject embedded.
    #[serde(default)]
    pub recent_image_cids: Vec<String>,
    /// Cross-subject matches.
    #[serde(default)]
    pub matched_subjects: Vec<MatchedSubject>,
}

/// One cross-subject shared-image match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedSubject {
    /// Matched subject UUID.
    pub subject_id: String,
    /// Matched subject DID, when set.
    #[serde(default)]
    pub did: Option<String>,
    /// Subset of `recent_image_cids` shared with the match.
    pub shared_cids: Vec<String>,
}

/// Per-section availability flags.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "four-section flag set mirrors the backend's SignalQuality verbatim — each \
              section is independent and the frontend NetworkPanel renders a per-section \
              'unavailable' state on a `false` flag"
)]
pub struct SignalQuality {
    /// Profile fetch succeeded.
    #[serde(default)]
    pub profile_loaded: bool,
    /// Follow-graph fetch succeeded.
    #[serde(default)]
    pub follow_graph_loaded: bool,
    /// Reply-graph fetch succeeded.
    #[serde(default)]
    pub reply_graph_loaded: bool,
    /// Shared-image upsert + match succeeded.
    #[serde(default)]
    pub shared_images_loaded: bool,
}

/// Response from `GET /api/labeler/policies` (issue #96 /
/// mod-workstation #6).
///
/// Mirrors the backend's `LabelerPoliciesResponse` field-for-field.
/// The wire shape is the same as the
/// `app.bsky.labeler.service::policies` object on the operator's
/// published service record. The frontend's
/// [`SubscriberEffectPreview`] component reads this to compute the
/// per-label hide/warn/ignore distribution displayed inline in the
/// `ActionComposer`.
///
/// [`SubscriberEffectPreview`]: crate::components::subscriber_effect_preview::SubscriberEffectPreview
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelerPoliciesResponse {
    /// The set of label values the labeler declares it may emit.
    /// Mirrors `policies.labelValues`.
    pub label_values: Vec<String>,
    /// Per-value rendering metadata. Each entry is a lexicon-shaped
    /// `LabelValueDefinition` JSON object (`identifier`, `severity`,
    /// `blurs`, `defaultSetting`, `adultOnly`, `locales`). Carried as
    /// `serde_json::Value` because the wire shape IS the lexicon
    /// shape — the backend validates on the persist path.
    pub label_value_definitions: serde_json::Value,
    /// Subscriber-count proxy (`app.bsky.labeler.getServices.likeCount`).
    /// `None` in v1 because the proxy cache is not yet wired; the
    /// preview renders percentages only.
    #[serde(default)]
    pub subscriber_likes: Option<u32>,
}

/// One moderator row as returned by `GET /api/admin/moderators` and the
/// other moderator-management endpoints (issue #214 / #217).
///
/// Mirrors the backend's
/// [`polaris_backend::api::admin_moderators::ModeratorDto`] field-for-field.
/// Field naming and `serde` defaults match the wire shape produced by the
/// backend's `#[derive(Serialize)]`; the DID is rendered as a bare string
/// (not a typed newtype) because the backend serialises the typed
/// `polaris_types::Did` as `transparent`, so the wire bytes are identical
/// to a plain `String` on either side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminModerator {
    /// External identifier — DID for `atproto`, OIDC `sub` for `oidc`.
    pub did: String,
    /// Auth backend the row was created under (`"atproto"` or
    /// `"oidc"`). Surfaced so the table can render a per-backend icon.
    pub auth_backend: String,
    /// Display name, if known.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Role set granted to this moderator. Snake-case strings matching
    /// the backend's `Role::as_db_str`. Sorted alphabetically by the
    /// backend for a stable UI rendering.
    pub roles: Vec<String>,
    /// `true` if this moderator is the hard-pinned bootstrap admin.
    /// Pinned admins cannot be deleted via the API and cannot lose
    /// their `admin` role.
    pub pinned_admin: bool,
    /// Last successful login timestamp, if any.
    #[serde(default)]
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Request body for `POST /api/admin/moderators`.
///
/// Mirrors the backend's
/// [`polaris_backend::api::admin_moderators::AddModeratorRequest`]. The
/// `handle` field accepts EITHER a bare ATProto handle (resolved to a
/// DID by the backend's identity resolver) OR a `did:` literal (trusted
/// verbatim). The brief originally documented this as `handle_or_did`,
/// but the live backend wire field is `handle` — keep the DTO field
/// name aligned with the source-of-truth Serialize derive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddModeratorRequest {
    /// Handle (`alice.example.com`) or DID (`did:plc:…`). The backend
    /// branches on the `did:` prefix to decide whether to resolve.
    pub handle: String,
    /// Role to grant on creation. One of `admin` / `senior_moderator`
    /// / `moderator` / `triage`.
    pub role: String,
}

/// Request body for `PATCH /api/admin/moderators/:did/roles`.
///
/// Mirrors the backend's
/// [`polaris_backend::api::admin_moderators::PatchRolesRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchModeratorRoleRequest {
    /// Role to toggle. One of `admin` / `senior_moderator` /
    /// `moderator` / `triage`.
    pub role: String,
    /// `true` to grant the role, `false` to revoke it.
    pub grant: bool,
}

// ── Mod policy workbook (issue #225 backend / #226 frontend) ────────────

/// Full wire shape for one `mod_policies` row.
///
/// Mirrors the backend's
/// [`polaris_backend::api::admin_policies::dto::ModPolicyDto`]
/// field-for-field. Field naming and serde defaults match the wire shape
/// produced by the backend's `#[derive(Serialize)]`. The frontend treats
/// `examples_positive` / `examples_negative` as `serde_json::Value`
/// because the wire shape IS the array-of-records lexicon shape — the
/// backend validates on persist (REQ-A2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModPolicyDto {
    /// Row identity (primary key).
    pub id: uuid::Uuid,
    /// Human-stable identifier (`polaris.harassment` etc.).
    pub identifier: String,
    /// Monotonic edit counter; 1 on initial insert.
    pub version: i32,
    /// Short human-readable title.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// `account` | `post` | `both`.
    pub scope: String,
    /// `inform` | `alert` | `hide` | `remove`.
    pub severity: String,
    /// Markdown-formatted decision criteria (≥ 64 chars).
    pub decision_criteria: String,
    /// Positive worked-example array.
    pub examples_positive: serde_json::Value,
    /// Negative worked-example array.
    pub examples_negative: serde_json::Value,
    /// Suggested action kinds for cases that violate this policy.
    pub suggested_action_kinds: Vec<String>,
    /// Optional default label value when the action is `label`.
    #[serde(default)]
    pub linked_label_value: Option<String>,
    /// Free-text "when this policy does not apply".
    #[serde(default)]
    pub exceptions: Option<String>,
    /// REQ-A2 hard-floor marker; `true` means autonomy cannot be set to
    /// `autonomous` (REQ-G3).
    pub human_required_always: bool,
    /// `manual` | `assisted` | `autonomous`.
    pub autonomy_mode: String,
    /// Subset of `actions.kind` allowed for auto-fire. Subset of
    /// `{label, warn, takedown}` (REQ-G1).
    pub autonomous_action_kinds: Vec<String>,
    /// Confidence floor for autonomous emission. `0.0..=1.0`.
    pub autonomous_confidence_threshold: f32,
    /// Confidence floor for assisted draft creation. `0.0..=1.0`.
    pub assisted_confidence_threshold: f32,
    /// When `Some(t)` and `t > now()`, autonomy is suspended.
    #[serde(default)]
    pub autonomous_paused_until: Option<DateTime<Utc>>,
    /// Tombstone marker — `true` means this version retires the policy
    /// (REQ-F1).
    pub is_retired: bool,
    /// When this row was inserted.
    pub created_at: DateTime<Utc>,
    /// Moderator who wrote this version.
    pub created_by_moderator_id: uuid::Uuid,
    /// When this version started binding decisions.
    pub effective_from: DateTime<Utc>,
    /// When this version stopped being current. `None` while current.
    #[serde(default)]
    pub effective_until: Option<DateTime<Utc>>,
    /// `Some(id)` of the prior version row, `None` for v1.
    #[serde(default)]
    pub supersedes_id: Option<uuid::Uuid>,
    /// "Why this version was written" — surfaced in history view.
    #[serde(default)]
    pub change_summary: Option<String>,
}

/// Slim list-projection of a policy, for the index endpoint.
///
/// Mirrors the backend's
/// [`polaris_backend::api::admin_policies::dto::ModPolicySummaryDto`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModPolicySummaryDto {
    /// Row identity.
    pub id: uuid::Uuid,
    /// Human-stable identifier.
    pub identifier: String,
    /// Current version number.
    pub version: i32,
    /// Short title.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// Scope vocabulary value.
    pub scope: String,
    /// Severity vocabulary value.
    pub severity: String,
    /// Autonomy mode (`manual` / `assisted` / `autonomous`).
    pub autonomy_mode: String,
    /// Tombstone marker.
    pub is_retired: bool,
    /// When this version started binding.
    pub effective_from: DateTime<Utc>,
}

/// Filters for `GET /api/policies` and `GET /api/admin/policies`.
///
/// All fields optional. Empty / `None` fields are omitted from the URL
/// entirely.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyListFilters {
    /// Filter to policies whose `scope` matches (`account` | `post` | `both`).
    pub scope: Option<String>,
    /// Filter to policies whose `autonomy_mode` matches.
    pub autonomy_mode: Option<String>,
    /// Free-text query over `name` + `description` + `decision_criteria`.
    pub q: Option<String>,
}

/// Serialise [`PolicyListFilters`] into a percent-encoded URL query
/// string (without the leading `?`). Empty / `None` fields are omitted.
#[must_use]
pub fn policy_filters_to_query_string(filters: &PolicyListFilters) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(value) = filters.scope.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("scope={}", percent_encode(value)));
    }
    if let Some(value) = filters.autonomy_mode.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("autonomy_mode={}", percent_encode(value)));
    }
    if let Some(value) = filters.q.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("q={}", percent_encode(value)));
    }
    parts.join("&")
}

/// One entry in the version-history response for a policy.
///
/// Mirrors the backend's
/// [`polaris_backend::api::admin_policies::dto::ModPolicyHistoryEntryDto`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModPolicyHistoryEntryDto {
    /// Row identity for this version.
    pub id: uuid::Uuid,
    /// Version number.
    pub version: i32,
    /// "Why this version was written".
    #[serde(default)]
    pub change_summary: Option<String>,
    /// Moderator who wrote this version.
    pub created_by_moderator_id: uuid::Uuid,
    /// When this version was inserted.
    pub created_at: DateTime<Utc>,
    /// When this version started binding decisions.
    pub effective_from: DateTime<Utc>,
    /// When this version stopped being current.
    #[serde(default)]
    pub effective_until: Option<DateTime<Utc>>,
    /// Tombstone marker.
    pub is_retired: bool,
    /// URL pointing at the per-version diff. `None` for v1.
    #[serde(default)]
    pub diff_url: Option<String>,
}

/// Request body for `POST /api/admin/policies` — create v1 of a new
/// policy.
///
/// Mirrors the backend's `CreatePolicyDto`. Optional fields omitted
/// here are filled with the backend's documented defaults (REQ-A3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePolicyDto {
    /// Human-stable identifier; must be unique at v1.
    pub identifier: String,
    /// Short title.
    pub name: String,
    /// One-paragraph description.
    pub description: String,
    /// `account` | `post` | `both`.
    pub scope: String,
    /// `inform` | `alert` | `hide` | `remove`.
    pub severity: String,
    /// Decision criteria (≥ 64 chars).
    pub decision_criteria: String,
    /// Optional positive worked examples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples_positive: Option<serde_json::Value>,
    /// Optional negative worked examples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples_negative: Option<serde_json::Value>,
    /// Suggested action kinds.
    pub suggested_action_kinds: Vec<String>,
    /// Optional default label value for `kind = label`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_label_value: Option<String>,
    /// Optional free-text exceptions block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<String>,
    /// REQ-A2 floor.
    #[serde(default)]
    pub human_required_always: bool,
    /// `manual` / `assisted` / `autonomous`. Defaults to `manual` on
    /// the backend when omitted.
    pub autonomy_mode: String,
    /// Subset of `{label, warn, takedown}` (REQ-G1).
    #[serde(default)]
    pub autonomous_action_kinds: Vec<String>,
    /// Confidence floor for autonomous emission.
    pub autonomous_confidence_threshold: f32,
    /// Confidence floor for assisted drafts.
    pub assisted_confidence_threshold: f32,
    /// Optional "why v1" note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_summary: Option<String>,
}

/// Request body for `PATCH /api/admin/policies/:identifier`.
///
/// Every field optional — omission means "carry forward from the prior
/// version" (REQ-C2). `change_summary` is the only required field.
/// Mirrors the backend's
/// [`polaris_backend::api::admin_policies::dto::ModPolicyEditDto`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModPolicyEditDto {
    /// New short title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// New description paragraph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// New scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// New severity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// New decision criteria text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_criteria: Option<String>,
    /// Replace positive-example array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples_positive: Option<serde_json::Value>,
    /// Replace negative-example array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples_negative: Option<serde_json::Value>,
    /// Replace suggested-action-kinds list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_action_kinds: Option<Vec<String>>,
    /// Replace linked label value. Frontend currently always carries
    /// forward (uses `None`); a future affordance can switch to
    /// `Some(None)` to clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_label_value: Option<String>,
    /// Replace exceptions text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exceptions: Option<String>,
    /// Flip the human-required-always floor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_required_always: Option<bool>,
    /// New autonomy mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomy_mode: Option<String>,
    /// Replace autonomous-action-kinds list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_action_kinds: Option<Vec<String>>,
    /// New autonomous confidence threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomous_confidence_threshold: Option<f32>,
    /// New assisted confidence threshold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assisted_confidence_threshold: Option<f32>,
    /// Retire the policy (writes a tombstone successor row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_retired: Option<bool>,
    /// REQUIRED — operator's note on why this version was written.
    pub change_summary: String,
}

/// Request body for `POST /api/admin/policies/:identifier/pause`.
///
/// Two shapes accepted by the backend:
/// - `{ "until": "<rfc3339>" }` — pause until a specific timestamp.
/// - `{ "forever": true }` or `{}` — pause until the `9999-12-31`
///   sentinel per the design's "forever" affordance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PausePolicyDto {
    /// Optional explicit timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<DateTime<Utc>>,
    /// Optional "forever" toggle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forever: Option<bool>,
}

// ── LLM recommendation panel (issue #237 / LLM-8) ────────────────────

/// Frontend mirror of the proto `RecommendResponse` shape
/// (`proto/polaris-classifier-v1.proto` `message RecommendResponse`).
///
/// The dispatcher persists the full `RecommendResponse` payload verbatim
/// into the `LlmRecommendation` observation's free-form `evidence` JSONB
/// column (per `.design/llm-moderation-assist.md` REQ-B2). The
/// case-view recommendation panel parses that JSON blob into this DTO
/// rather than re-fetching from the wire — the case-view payload
/// already carries the observation list, so no extra round-trip is
/// needed for the initial render.
///
/// # Wire shape
///
/// `snake_case` throughout to match prost's JSON convention and the
/// dispatcher's serde defaults (REQ-A3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecommendationDto {
    /// Echoed from `RecommendRequest.event_id` so a stored
    /// recommendation can be correlated with the originating case
    /// envelope.
    #[serde(default)]
    pub event_id: String,
    /// Model identifier as the adapter reports it
    /// (e.g. `"claude-sonnet-4-6"`, `"qwen-32b-q3km"`).
    pub model: String,
    /// Adapter-defined version string (semver, git SHA, training-run
    /// timestamp). Audited per REQ-A3.
    #[serde(default)]
    pub model_version: String,
    /// Opaque adapter-stable identifier for the prompt template the
    /// adapter ran. The adapter owns stable versioning; Polaris
    /// audits it without interpreting.
    #[serde(default)]
    pub prompt_template_id: String,
    /// The structured action recommendations. Usually one; multiple
    /// allowed when the LLM thinks several independent actions apply
    /// (e.g. "label the post AND warn the account").
    #[serde(default)]
    pub recommended_actions: Vec<RecommendedActionDto>,
    /// Optional synthesis paragraph framing multiple recommended
    /// actions. Markdown. Empty when there's only one recommended
    /// action.
    #[serde(default)]
    pub overall_reasoning: String,
    /// Observability: input token count for this call. Surfaced in
    /// admin audit views (REQ-F4); the case-view panel ignores it.
    #[serde(default)]
    pub input_tokens: i32,
    /// Observability: output token count for this call. Same role.
    #[serde(default)]
    pub output_tokens: i32,
}

/// One recommended action within a [`RecommendationDto`].
///
/// Mirrors the proto `RecommendedAction` message field-for-field.
/// Each field's contract matches the proto comments (REQ-A3) — the
/// dispatcher validates the shape before persisting, so a
/// [`RecommendedActionDto`] read out of an observation's `evidence`
/// blob has already passed the action-kind / label-value / scope /
/// citation gates on the way in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecommendedActionDto {
    /// One of `label` | `warn` | `takedown` | `escalate` | `no_action`.
    pub action_kind: String,
    /// Required when `action_kind == "label"`; empty otherwise.
    #[serde(default)]
    pub label_value: String,
    /// `"account"` or `"post"`.
    pub subject_scope: String,
    /// `[0.0, 1.0]`. Below the policy's
    /// `autonomous_confidence_threshold` downgrades to assisted; below
    /// `assisted_confidence_threshold` downgrades to manual.
    pub confidence: f32,
    /// At least one entry; every identifier must be present in the
    /// request's `policies` array (dispatcher validates on insert).
    #[serde(default)]
    pub cited_policy_identifiers: Vec<String>,
    /// The LLM's stated reasoning for this action. Markdown. ≥10
    /// chars per the `actions.reasoning` CHECK constraint.
    #[serde(default)]
    pub reasoning: String,
    /// Non-blocking notes the LLM wants the moderator to see.
    /// Surfaced in the case-view panel's caveats list (REQ-J1).
    #[serde(default)]
    pub caveats: Vec<String>,
}

/// Outcome of `POST /api/cases/:incident_id/llm-recommendation`.
///
/// Mirrors the backend's
/// [`polaris_backend::api::llm::case_endpoint::DispatchOutcomeDto`].
/// The tagged-enum wire form (`{"outcome":"advisory","observation_id":…}`)
/// matches the backend's `#[serde(tag = "outcome", rename_all =
/// "snake_case")]` exactly so the frontend can branch on the typed
/// variant without parsing strings by hand.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RequestRecommendationOutcome {
    /// LLM recommendation persisted as an advisory observation.
    Advisory {
        /// Observation row id.
        observation_id: uuid::Uuid,
    },
    /// Assisted-mode draft inserted into `pending_auto_actions`.
    AssistedDraft {
        /// First inserted draft id.
        draft_id: uuid::Uuid,
        /// Backing observation row id.
        observation_id: uuid::Uuid,
    },
    /// Autonomous-mode action emitted.
    AutonomousAction {
        /// Inserted action row id.
        action_id: uuid::Uuid,
        /// Backing observation row id.
        observation_id: uuid::Uuid,
    },
    /// Dispatcher tripped a gate. `reason` is a stable wire string
    /// (`debounce_hit` / `queue_depth_exceeded` / `no_autonomy_enabled`).
    Skipped {
        /// Operator-readable rationale.
        reason: String,
    },
}

// ── LLM admin audit (issue #238 / LLM-9 / REQ-F4) ────────────────────────

/// One row of the `GET /api/admin/llm/audit` response.
///
/// Mirrors the backend's [`polaris_backend::api::llm::admin_audit::LlmAuditEntryDto`]
/// field-for-field. The full LLM response payload is reachable via
/// `llm_observation_id` — fetching the row off `observations.evidence`
/// would be a second round-trip the row-expand UI makes on demand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmAuditEntryDto {
    /// The autonomous action's id.
    pub action_id: uuid::Uuid,
    /// `actions.kind` — one of `label` / `warn` / `takedown` / …
    pub action_kind: String,
    /// `actions.label_value` when the action is a label.
    #[serde(default)]
    pub label_value: Option<String>,
    /// Subject DID (when present).
    #[serde(default)]
    pub subject_did: Option<String>,
    /// Subject kind — one of `account` / `post` / `list` / `feed`.
    pub subject_kind: String,
    /// Subject AT-URI (when present).
    #[serde(default)]
    pub subject_uri: Option<String>,
    /// Always `"autonomous_agent"`.
    pub actor_kind: String,
    /// LLM model identifier (e.g. `qwen2.5-32b-instruct-q3_k_m`).
    pub model: String,
    /// LLM model version string.
    pub model_version: String,
    /// Adapter-stable prompt template identifier.
    pub prompt_template_id: String,
    /// Top recommendation's confidence (`[0.0, 1.0]`).
    pub recommendation_confidence: f32,
    /// SHA-256-hex of the canonicalised `RecommendRequest`.
    pub input_hash: String,
    /// Snapshotted `(identifier, version)` citations.
    pub cited_policies: Vec<LlmAuditCitedPolicyDto>,
    /// Top recommendation's reasoning string.
    #[serde(default)]
    pub reasoning: String,
    /// When the action was created.
    pub created_at: DateTime<Utc>,
    /// When the action's reversal window closes.
    pub reversible_until: DateTime<Utc>,
    /// Reversal info when one exists; `None` otherwise.
    #[serde(default)]
    pub reversal: Option<LlmAuditReversalDto>,
    /// Points at the `LlmRecommendation` observation row (its
    /// `evidence` JSONB carries the full LLM response payload per
    /// REQ-B2).
    pub llm_observation_id: uuid::Uuid,
}

/// One `(identifier, version)` pair on an audit-row's `cited_policies`
/// list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAuditCitedPolicyDto {
    /// Policy identifier (e.g. `polaris.spam`).
    pub identifier: String,
    /// Pinned version at action-create time.
    pub version: i32,
}

/// Reversal-side info on an audit row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmAuditReversalDto {
    /// The reversal action's id.
    pub action_id: uuid::Uuid,
    /// When the reversal was created.
    pub reversed_at: DateTime<Utc>,
    /// Moderator who issued the reversal.
    pub reversed_by_moderator_id: uuid::Uuid,
}

/// Full page shape returned by `GET /api/admin/llm/audit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmAuditPageDto {
    /// Rows in the page, newest-first.
    pub items: Vec<LlmAuditEntryDto>,
    /// Opaque cursor for the next page when more rows exist.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Client-supplied filters for `GET /api/admin/llm/audit`.
///
/// All fields optional. Empty / `None` fields are omitted from the URL
/// entirely — the backend's `Query<LlmAuditQuery>` extractor reads each
/// parameter as `Option<T>`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LlmAuditFilters {
    /// Filter to actions emitted by the named LLM model.
    pub model: Option<String>,
    /// Filter to actions citing this policy identifier.
    pub policy: Option<String>,
    /// `Some(true)` returns only reversed rows; `Some(false)` returns
    /// only non-reversed rows.
    pub reversed: Option<bool>,
    /// Earliest `actions.created_at` (RFC3339, inclusive).
    pub from: Option<DateTime<Utc>>,
    /// Latest `actions.created_at` (RFC3339, inclusive).
    pub to: Option<DateTime<Utc>>,
    /// Opaque cursor from a prior page.
    pub cursor: Option<String>,
    /// Page size. The backend defaults to 50 and clamps to `[1, 200]`.
    pub limit: Option<i64>,
}

/// Serialise [`LlmAuditFilters`] into a percent-encoded URL query
/// string (without the leading `?`). Empty / `None` fields are omitted.
#[must_use]
pub fn llm_audit_filters_to_query_string(filters: &LlmAuditFilters) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(value) = filters.model.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("model={}", percent_encode(value)));
    }
    if let Some(value) = filters.policy.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("policy={}", percent_encode(value)));
    }
    if let Some(value) = filters.reversed {
        parts.push(format!("reversed={value}"));
    }
    if let Some(value) = filters.from {
        parts.push(format!("from={}", percent_encode(&value.to_rfc3339())));
    }
    if let Some(value) = filters.to {
        parts.push(format!("to={}", percent_encode(&value.to_rfc3339())));
    }
    if let Some(value) = filters.cursor.as_deref().filter(|v| !v.is_empty()) {
        parts.push(format!("cursor={}", percent_encode(value)));
    }
    if let Some(value) = filters.limit {
        parts.push(format!("limit={value}"));
    }
    parts.join("&")
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
            // Issue #202: legacy serde round-trip — None matches the
            // pre-#202 wire shape (the field is `#[serde(default)]`).
            report_id: None,
        };
        let json = serde_json::to_string(&body).expect("serialize");
        let back: SubmitAction = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.reasoning, body.reasoning);
        assert_eq!(back.policy_refs.len(), 1);
    }

    #[test]
    fn generate_key_response_round_trips_through_serde() {
        let body = GenerateKeyResponse {
            did_key: "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme".to_owned(),
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert_eq!(
            json["did_key"],
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme"
        );
        let back: GenerateKeyResponse = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back.did_key, body.did_key);
    }

    #[test]
    fn publish_labeler_record_request_round_trips_through_serde() {
        let req = PublishLabelerRecordRequest {
            service_url: "https://labeler.example.com".to_owned(),
            label_values: vec!["spam".to_owned(), "porn".to_owned()],
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: PublishLabelerRecordRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.service_url, req.service_url);
        assert_eq!(back.label_values, req.label_values);
    }

    #[test]
    fn publish_labeler_record_response_round_trips_through_serde() {
        let resp = PublishLabelerRecordResponse {
            at_uri: "at://did:plc:test/app.bsky.labeler.service/self".to_owned(),
            cid: "bafyreigh2akiscaildc...".to_owned(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: PublishLabelerRecordResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.at_uri, resp.at_uri);
        assert_eq!(back.cid, resp.cid);
    }

    #[test]
    fn submit_plc_operation_request_round_trips_through_serde() {
        let req = SubmitPlcOperationRequest {
            token: "abcdef-1234".to_owned(),
            service_url: "https://labeler.example.com".to_owned(),
        };
        let json = serde_json::to_string(&req).expect("serialize");
        let back: SubmitPlcOperationRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.token, req.token);
        assert_eq!(back.service_url, req.service_url);
    }

    #[test]
    fn submit_plc_operation_response_round_trips_through_serde() {
        let resp = SubmitPlcOperationResponse {
            did: "did:plc:abc123".to_owned(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: SubmitPlcOperationResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.did, resp.did);
    }

    #[test]
    fn whoami_response_round_trips_through_serde() {
        let body = WhoamiResponse {
            moderator_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            external_id: "did:plc:test".to_owned(),
            auth_backend: "atproto".to_owned(),
            roles: vec!["admin".to_owned()],
            first_run: true,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        let back: WhoamiResponse = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back.moderator_id, body.moderator_id);
        assert_eq!(back.external_id, body.external_id);
        assert_eq!(back.auth_backend, body.auth_backend);
        assert_eq!(back.roles, body.roles);
        assert!(back.first_run);
    }

    #[test]
    fn admin_moderator_round_trips_through_serde() {
        // Matches the exact JSON the backend's `ModeratorDto`
        // Serialize derive emits — surfacing every field including
        // the optional `display_name` / `last_login_at` so a
        // deserialise failure surfaces as a test diff rather than a
        // runtime decode error inside the admin page.
        let body = AdminModerator {
            did: "did:plc:operator123".to_owned(),
            auth_backend: "atproto".to_owned(),
            display_name: Some("Operator Alice".to_owned()),
            roles: vec!["admin".to_owned(), "moderator".to_owned()],
            pinned_admin: true,
            last_login_at: Some(
                chrono::DateTime::parse_from_rfc3339("2026-05-01T12:34:56Z")
                    .expect("rfc3339")
                    .with_timezone(&Utc),
            ),
        };
        let json = serde_json::to_value(&body).expect("serialize");
        let back: AdminModerator = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, body);
    }

    #[test]
    fn admin_moderator_tolerates_missing_optional_fields() {
        // The backend emits `display_name: null` / `last_login_at:
        // null` rather than omitting the field, but the `#[serde(default)]`
        // attributes on the DTO mean a future backend that drops the
        // fields entirely still deserialises. Both shapes must
        // produce the same Rust value.
        let json = serde_json::json!({
            "did": "did:plc:bare",
            "auth_backend": "atproto",
            "roles": ["moderator"],
            "pinned_admin": false,
        });
        let back: AdminModerator = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back.did, "did:plc:bare");
        assert_eq!(back.display_name, None);
        assert_eq!(back.last_login_at, None);
        assert!(!back.pinned_admin);
    }

    #[test]
    fn add_moderator_request_uses_handle_field() {
        // Regression: the brief originally documented this as
        // `handle_or_did` but the live backend wire field is `handle`
        // (the backend branches on the `did:` prefix internally). Lock
        // the JSON-field name so a future rename has to update both
        // the DTO and this test.
        let req = AddModeratorRequest {
            handle: "alice.example.com".to_owned(),
            role: "moderator".to_owned(),
        };
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["handle"], "alice.example.com");
        assert_eq!(json["role"], "moderator");
        assert!(json.get("handle_or_did").is_none());
    }

    #[test]
    fn patch_moderator_role_request_uses_grant_bool() {
        let req = PatchModeratorRoleRequest {
            role: "admin".to_owned(),
            grant: false,
        };
        let json = serde_json::to_value(&req).expect("serialize");
        assert_eq!(json["role"], "admin");
        assert_eq!(json["grant"], false);
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

    #[test]
    fn recommendation_dto_round_trips_through_serde() {
        // Mirrors the canonical wire shape persisted in
        // `LlmRecommendation.evidence` (REQ-B2). A round-trip locks
        // the field order + serde defaults against drift from the
        // proto's RecommendResponse shape (REQ-A3).
        let dto = RecommendationDto {
            event_id: "evt-001".to_owned(),
            model: "qwen-32b-q3km".to_owned(),
            model_version: "2026-04-01".to_owned(),
            prompt_template_id: "polaris.case-review.v1".to_owned(),
            recommended_actions: vec![RecommendedActionDto {
                action_kind: "label".to_owned(),
                label_value: "spam".to_owned(),
                subject_scope: "post".to_owned(),
                confidence: 0.83,
                cited_policy_identifiers: vec!["polaris.spam".to_owned()],
                reasoning: "Looks like spam.".to_owned(),
                caveats: vec!["Could be satire.".to_owned()],
            }],
            overall_reasoning: String::new(),
            input_tokens: 1024,
            output_tokens: 96,
        };
        let json = serde_json::to_value(&dto).expect("serialize");
        let back: RecommendationDto = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, dto);
    }

    #[test]
    fn recommendation_dto_tolerates_missing_optional_fields() {
        // Adapters may omit `overall_reasoning` / `input_tokens` /
        // `output_tokens` entirely; the `#[serde(default)]` attributes
        // mean those shapes still deserialise. Locking the contract
        // here surfaces a future shape regression as a test diff.
        let json = serde_json::json!({
            "model": "fixture",
            "recommended_actions": [{
                "action_kind": "no_action",
                "subject_scope": "post",
                "confidence": 0.1,
                "cited_policy_identifiers": ["polaris.spam"],
            }],
        });
        let dto: RecommendationDto = serde_json::from_value(json).expect("deserialize");
        assert_eq!(dto.model, "fixture");
        assert_eq!(dto.recommended_actions.len(), 1);
        assert_eq!(dto.recommended_actions[0].action_kind, "no_action");
        assert_eq!(dto.recommended_actions[0].label_value, "");
        assert!(dto.recommended_actions[0].caveats.is_empty());
        assert_eq!(dto.input_tokens, 0);
    }

    #[test]
    fn request_recommendation_outcome_advisory_variant_round_trips() {
        let outcome = RequestRecommendationOutcome::Advisory {
            observation_id: uuid::Uuid::nil(),
        };
        let json = serde_json::to_value(&outcome).expect("serialize");
        assert_eq!(json["outcome"], "advisory");
        let back: RequestRecommendationOutcome = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, outcome);
    }

    #[test]
    fn request_recommendation_outcome_skipped_variant_round_trips() {
        let outcome = RequestRecommendationOutcome::Skipped {
            reason: "debounce_hit".to_owned(),
        };
        let json = serde_json::to_value(&outcome).expect("serialize");
        assert_eq!(json["outcome"], "skipped");
        assert_eq!(json["reason"], "debounce_hit");
        let back: RequestRecommendationOutcome = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, outcome);
    }

    #[test]
    fn llm_audit_filters_query_string_omits_empty_fields() {
        let filters = LlmAuditFilters::default();
        assert_eq!(llm_audit_filters_to_query_string(&filters), "");

        let filters = LlmAuditFilters {
            model: Some("qwen2.5-32b-instruct-q3_k_m".to_owned()),
            policy: Some("polaris.spam".to_owned()),
            reversed: Some(true),
            limit: Some(100),
            ..Default::default()
        };
        let qs = llm_audit_filters_to_query_string(&filters);
        assert!(qs.contains("model=qwen2.5-32b-instruct-q3_k_m"));
        assert!(qs.contains("policy=polaris.spam"));
        assert!(qs.contains("reversed=true"));
        assert!(qs.contains("limit=100"));
        assert!(!qs.contains("from="));
        assert!(!qs.contains("cursor="));
    }

    #[test]
    fn llm_audit_filters_query_string_percent_encodes_cursor() {
        let filters = LlmAuditFilters {
            cursor: Some("abc+/=".to_owned()),
            ..Default::default()
        };
        let qs = llm_audit_filters_to_query_string(&filters);
        // `+` and `=` are NOT in the unreserved set; they must be
        // percent-encoded so the wire string is router-safe.
        assert!(qs.starts_with("cursor=abc%2B%2F%3D"), "got: {qs}");
    }

    #[test]
    fn llm_audit_entry_round_trips_through_serde() {
        let entry = LlmAuditEntryDto {
            action_id: uuid::Uuid::nil(),
            action_kind: "label".to_owned(),
            label_value: Some("spam".to_owned()),
            subject_did: Some("did:plc:abc".to_owned()),
            subject_kind: "post".to_owned(),
            subject_uri: Some("at://did:plc:abc/app.bsky.feed.post/x".to_owned()),
            actor_kind: "autonomous_agent".to_owned(),
            model: "qwen2.5-32b-instruct-q3_k_m".to_owned(),
            model_version: "v1".to_owned(),
            prompt_template_id: "polaris.case-review.v1".to_owned(),
            recommendation_confidence: 0.94,
            input_hash: "deadbeef".to_owned(),
            cited_policies: vec![LlmAuditCitedPolicyDto {
                identifier: "polaris.spam".to_owned(),
                version: 3,
            }],
            reasoning: "the spam was conspicuous".to_owned(),
            created_at: Utc::now(),
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reversal: None,
            llm_observation_id: uuid::Uuid::nil(),
        };
        let json = serde_json::to_value(&entry).expect("serialize");
        let back: LlmAuditEntryDto = serde_json::from_value(json).expect("deserialize");
        assert_eq!(back, entry);
    }

    #[test]
    fn llm_audit_entry_decodes_legacy_payload_without_optional_fields() {
        // The backend uses `#[serde(skip_serializing_if = "Option::is_none")]`
        // on optional fields. Verify deserialize accepts a payload that
        // omits them entirely.
        let json = serde_json::json!({
            "action_id": "00000000-0000-0000-0000-000000000000",
            "action_kind": "warn",
            "subject_kind": "account",
            "actor_kind": "autonomous_agent",
            "model": "qwen-32b",
            "model_version": "v1",
            "prompt_template_id": "polaris.case-review.v1",
            "recommendation_confidence": 0.81,
            "input_hash": "abc123",
            "cited_policies": [],
            "created_at": "2026-05-18T00:00:00Z",
            "reversible_until": "2026-05-19T00:00:00Z",
            "llm_observation_id": "00000000-0000-0000-0000-000000000000",
        });
        let dto: LlmAuditEntryDto = serde_json::from_value(json).expect("deserialize");
        assert_eq!(dto.label_value, None);
        assert_eq!(dto.subject_did, None);
        assert_eq!(dto.subject_uri, None);
        assert_eq!(dto.reasoning, "");
        assert!(dto.reversal.is_none());
    }
}
