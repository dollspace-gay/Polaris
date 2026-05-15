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
