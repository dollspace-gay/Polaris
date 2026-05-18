//! Polaris first-party HTTP API client.
//!
//! Talks to the Axum backend at `/api/*` and `/healthz`. Carries the Polaris
//! session cookie via `credentials: "include"` (wasm) / `cookie_store(true)`
//! (native), so every authenticated request flows the moderator's session
//! without the frontend ever touching cookie storage directly.
//!
//! Transport selection happens at the module boundary:
//!
//! - On `wasm32-unknown-unknown` the [`wasm::WasmPolarisApiClient`] impl
//!   backed by `gloo-net` is compiled in.
//! - On every other target the [`native::NativePolarisApiClient`] impl
//!   backed by `reqwest` is compiled in.
//!
//! No `#[cfg(target_arch = "wasm32")]` appears below this module — the
//! gating is done by the `cfg!` attributes on `mod native;` and `mod wasm;`
//! plus the `pub use` re-exports at the bottom of this file.
//!
//! # Endpoint surface
//!
//! The [`PolarisApiClient`] trait carries one method per route in the
//! backend's [`polaris_backend::api`] surface:
//!
//! - [`healthz`](PolarisApiClient::healthz)        — `GET /healthz`.
//! - [`get_case`](PolarisApiClient::get_case)     — `GET /api/cases/{subject_id}`.
//! - [`list_incidents`](PolarisApiClient::list_incidents) — `GET /api/cases?status=…`.
//! - [`submit_action`](PolarisApiClient::submit_action)   — `POST /api/cases/{subject_id}/actions`.
//! - [`escalate`](PolarisApiClient::escalate)     — `POST /api/cases/{incident_id}/escalate`.

use polaris_types::{Action, ActionId, Incident, IncidentId, IncidentStatus, SubjectId};
use serde::{Deserialize, Serialize};

pub mod dto;

use dto::{
    AddModeratorRequest, AdminModerator, CaseView, CreatePolicyDto, DashboardFilters,
    DashboardSnapshot, Escalate, GenerateKeyResponse, IncidentList, LlmAuditFilters,
    LlmAuditPageDto, ModPolicyDto, ModPolicyEditDto, ModPolicyHistoryEntryDto,
    ModPolicySummaryDto, PatchModeratorRoleRequest, PausePolicyDto, PolicyListFilters,
    PublishLabelerRecordRequest, PublishLabelerRecordResponse, RecommendationDto,
    RequestPlcSignatureResponse, RequestRecommendationOutcome, ReverseBody, SubjectLookupResponse,
    SubmitAction, SubmitPlcOperationRequest, SubmitPlcOperationResponse, WhoamiResponse,
};

// The `#![cfg(...)]` inner attribute at the top of each impl file is the
// authoritative gate — declaring the modules unconditionally here lets
// `cargo doc --document-private-items` see both source files on every
// target while only compiling the matching one. Duplicate cfgs at both
// sites trip `clippy::duplicated_attributes`; concentrating the gate in
// the impl files alone keeps the clippy contract clean and matches the
// pre-flight requirement that target conditionals live at module
// boundaries rather than inside business logic.
pub mod native;
pub mod wasm;

#[cfg(not(target_arch = "wasm32"))]
pub use native::NativePolarisApiClient;
#[cfg(target_arch = "wasm32")]
pub use wasm::WasmPolarisApiClient;

/// Construct the platform-appropriate [`PolarisApiClient`] rooted at
/// `base` (e.g. `""` for same-origin or `"https://polaris.local"` when
/// the dev frontend talks to a remote backend).
///
/// On wasm this is infallible; on native the `reqwest` builder can fail
/// — both arms return [`ApiError`] so call sites have a uniform shape.
#[cfg(target_arch = "wasm32")]
pub fn default_client(base: &str) -> Result<WasmPolarisApiClient, ApiError> {
    Ok(WasmPolarisApiClient::new(base))
}

/// Construct the platform-appropriate [`PolarisApiClient`].
///
/// Native variant: see the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
pub fn default_client(base: &str) -> Result<NativePolarisApiClient, ApiError> {
    NativePolarisApiClient::new(base)
}

/// Trait every Polaris API client implementation satisfies.
///
/// Implementations are transport-specific (`reqwest` on native, `gloo-net`
/// on wasm). Each method maps 1:1 onto an axum route.
///
/// # Failure semantics
///
/// Every method returns [`ApiError`]. Transport-level failures (network
/// down, body cut, malformed response) become [`ApiError::Transport`].
/// Non-2xx responses become [`ApiError::Http`] with the numeric status
/// and best-effort textual body for the UI to render.
#[allow(async_fn_in_trait)] // CSR-only frontend, no Send-bound auto-trait need.
pub trait PolarisApiClient {
    /// Probe the backend's `GET /healthz` endpoint.
    async fn healthz(&self) -> Result<HealthStatus, ApiError>;

    /// `GET /api/cases/{subject_id}` — full case view for a subject.
    ///
    /// Returns the assembled [`CaseView`] (subject + history + reports +
    /// observations) on success. The `subject_id` is path-injected using
    /// its typed [`Display`](std::fmt::Display) impl, which produces the
    /// canonical hyphenated UUID form — URL-safe by construction.
    async fn get_case(&self, subject_id: SubjectId) -> Result<CaseView, ApiError>;

    /// `GET /api/cases?status=…` — slim incident list.
    ///
    /// `status` filters the result set by [`IncidentStatus`]; the wire
    /// value uses the type's lowercase-snake serde form so the call site
    /// never builds strings by hand.
    async fn list_incidents(&self, status: IncidentStatus) -> Result<IncidentList, ApiError>;

    /// `POST /api/cases/{subject_id}/actions` — submit a new action.
    async fn submit_action(
        &self,
        subject_id: SubjectId,
        body: SubmitAction,
    ) -> Result<Action, ApiError>;

    /// `POST /api/bulk-actions` — apply one action body to N subjects
    /// (issue #195). Returns the per-subject succeeded/failed split.
    async fn bulk_action(
        &self,
        body: crate::api_client::dto::BulkSubmitAction,
    ) -> Result<crate::api_client::dto::BulkActionOutcome, ApiError>;

    /// `POST /api/moderation/muted-reporters` — add a reporter DID
    /// to the silent-drop list (issue #192). Idempotent: muting an
    /// already-muted DID updates reason / `until` / `muted_by`.
    async fn mute_reporter(
        &self,
        body: crate::api_client::dto::MuteReporterBody,
    ) -> Result<crate::api_client::dto::MutedReporterRow, ApiError>;

    /// `POST /api/cases/{incident_id}/escalate` — escalate an incident.
    async fn escalate(&self, incident_id: IncidentId, body: Escalate)
    -> Result<Incident, ApiError>;

    /// `POST /api/actions/{action_id}/reverse` — reverse a prior action.
    ///
    /// Returns the newly-inserted reversal [`Action`] (a row with
    /// `kind = Reverse` and `reverses_action_id = action_id`).
    /// Authorization is server-side per `design.md` §5.5; the frontend
    /// mirrors the rules in `history_timeline` to hide the affordance
    /// when the requester is not eligible, but the backend is the source
    /// of truth.
    async fn reverse_action(
        &self,
        action_id: ActionId,
        body: ReverseBody,
    ) -> Result<Action, ApiError>;

    /// `GET /api/whoami` — the authenticated moderator's own context.
    ///
    /// Returns the moderator's id, external identifier, auth backend,
    /// role set, and a `first_run` flag the frontend uses to decide
    /// whether the root route renders the dashboard or redirects to
    /// `/setup` (issue #84).
    async fn whoami(&self) -> Result<WhoamiResponse, ApiError>;

    /// `POST /api/setup/generate-key` — mint a fresh K-256 signing key.
    ///
    /// First step of the first-run setup wizard (#84). The backend (#85)
    /// generates the key, persists the private half, and returns the
    /// public half as a `did:key:z…` multikey. The wizard surfaces the
    /// returned `did_key` to the operator for cross-checking against
    /// the labeler service record / DID document.
    async fn setup_generate_key(&self) -> Result<GenerateKeyResponse, ApiError>;

    /// `POST /api/setup/publish-labeler-record` — publish the
    /// `app.bsky.labeler.service` record on the operator's PDS.
    ///
    /// Second step of the first-run setup wizard. The backend pairs
    /// the operator-supplied `service_url` + `label_values` with the
    /// signing key minted by [`setup_generate_key`](Self::setup_generate_key)
    /// and writes the record. The returned AT-URI + CID confirm the
    /// commit landed.
    async fn setup_publish_labeler_record(
        &self,
        req: PublishLabelerRecordRequest,
    ) -> Result<PublishLabelerRecordResponse, ApiError>;

    /// `POST /api/setup/request-plc-signature` — ask the PDS to email
    /// the operator a PLC operation token.
    ///
    /// First half of the third step of the first-run setup wizard.
    /// The operator copy-pastes the emailed token into the wizard's
    /// follow-up form and the wizard calls
    /// [`setup_submit_plc_operation`](Self::setup_submit_plc_operation)
    /// to commit the DID document update.
    async fn setup_request_plc_signature(&self) -> Result<RequestPlcSignatureResponse, ApiError>;

    /// `POST /api/setup/submit-plc-operation` — submit the signed PLC
    /// operation to the PLC directory.
    ///
    /// Second half of the third step of the first-run setup wizard.
    /// The backend builds the PLC operation that adds the
    /// `#atproto_labeler` service entry pointing at `service_url`,
    /// signs it with the emailed token, and submits to the PLC
    /// directory. The returned DID confirms the operation landed.
    async fn setup_submit_plc_operation(
        &self,
        req: SubmitPlcOperationRequest,
    ) -> Result<SubmitPlcOperationResponse, ApiError>;

    /// `POST /api/subjects/lookup` — command-palette subject lookup
    /// (issue #92).
    ///
    /// Resolves a moderator-pasted identifier (URL, DID, AT-URI, or
    /// handle) to a canonical Polaris `subjects` row. The handler
    /// inserts a new row when the identifier resolves but no
    /// existing row matches; otherwise it returns the existing row's
    /// id. The frontend's command-palette overlay uses the returned
    /// `subject_id` to navigate to `/cases/{subject_id}`.
    async fn lookup_subject(&self, identifier: &str) -> Result<SubjectLookupResponse, ApiError>;

    /// `GET /api/dashboard` — composite snapshot for the pattern dashboard.
    ///
    /// Returns the four-panel [`DashboardSnapshot`] described in
    /// `design.md` §5.1: report-volume timeline, incident clusters,
    /// coordinated-action signals, and moderator-load summary. The
    /// frontend polls this endpoint on a 5-second interval and uses
    /// the WebSocket live feed (#57) for incremental diffs in
    /// between.
    ///
    /// This is the backward-compatible variant: it issues the
    /// pre-#94 unfiltered request (no facet query parameters). New
    /// call sites should prefer
    /// [`dashboard`](Self::dashboard).
    async fn get_dashboard(&self) -> Result<DashboardSnapshot, ApiError> {
        self.dashboard(&DashboardFilters::default()).await
    }

    /// `GET /api/dashboard?<facet>=...` — composite snapshot for the
    /// pattern dashboard with optional facet filters (issue #94 /
    /// mod-workstation feature #4).
    ///
    /// Each `Some` field on [`DashboardFilters`] is serialised as a
    /// URL query parameter (percent-encoded). Empty fields are omitted
    /// from the URL entirely. The backend's `Query<DashboardQuery>`
    /// extractor decodes the parameters and applies them as an
    /// AND-composed predicate over the clusters panel; an empty
    /// `DashboardFilters` (the default) is identical on the wire to
    /// the bare `/api/dashboard` request (AC-6 backward compat).
    async fn dashboard(&self, filters: &DashboardFilters) -> Result<DashboardSnapshot, ApiError>;

    /// `GET /api/labeler/policies` — fetch the operator's declared
    /// label policies for the subscriber-effect preview (issue #96 /
    /// mod-workstation #6).
    ///
    /// Returns the same `LabelerPolicies` shape the labeler service
    /// record carries on the operator's PDS: `label_values` plus the
    /// per-value `label_value_definitions`. The frontend reads the
    /// matching definition for the moderator's in-progress label
    /// value and computes a published-default distribution over
    /// hide / warn / ignore to render the inline forecast bar.
    ///
    /// Returns [`ApiError::Http`] with status 404 when the operator
    /// has not yet completed the publish-labeler-record step (no
    /// policies to preview). The frontend renders an
    /// "Open setup wizard" prompt in that case.
    async fn labeler_policies(
        &self,
    ) -> Result<crate::api_client::dto::LabelerPoliciesResponse, ApiError>;

    /// `GET /api/cases/{subject_id}/network-context` — fetch the
    /// subject's network-context signals (issue #97 / M2 panel).
    ///
    /// Returns the full [`NetworkContext`] shape: profile counts,
    /// follow graph, reply graph, cohort signals, shared-image
    /// matches. Each section's availability is surfaced via the
    /// [`SignalQuality`] flags so the frontend can render
    /// per-section "unavailable" states on partial upstream
    /// failures.
    ///
    /// Returns [`ApiError::Http`] with status 404 when the subject
    /// id does not match a row; 400 (`subject_has_no_did`) when the
    /// subject has no DID populated; 502 when every upstream fetch
    /// failed (the handler degrades to an empty shell otherwise).
    ///
    /// [`NetworkContext`]: crate::api_client::dto::NetworkContext
    /// [`SignalQuality`]: crate::api_client::dto::SignalQuality
    async fn network_context(
        &self,
        subject_id: &str,
    ) -> Result<crate::api_client::dto::NetworkContext, ApiError>;

    /// `GET /api/cases/{subject_id}/media` — fetch the case-view
    /// media gallery (issue #95).
    ///
    /// The backend triggers an on-demand deep walk of the
    /// subject's `app.bsky.feed.getAuthorFeed` (paginated, alt-text
    /// aware), persists every new blob row into
    /// `subject_image_blobs`, and returns the full deduped list
    /// for this subject — one entry per unique blob CID, ordered
    /// newest-first.
    ///
    /// The `upstream_ok` flag on the response indicates whether
    /// the walk reached the AppView. A `false` flag with a
    /// non-empty `blobs` Vec means the cache survived an upstream
    /// failure; the frontend renders the cached set and surfaces
    /// an inline "could not refresh" hint.
    ///
    /// Returns [`ApiError::Http`] with status 404 when the subject
    /// id does not match a row; 400 (`subject_has_no_did`) when
    /// the subject has no DID populated (list / feed-kind subjects
    /// have no media to walk).
    async fn media_gallery(
        &self,
        subject_id: SubjectId,
    ) -> Result<crate::api_client::dto::MediaGalleryResponse, ApiError>;

    /// `GET /api/admin/moderators` — list every moderator with their
    /// role set, pinned flag, and last-login timestamp (issue #214 /
    /// #217).
    ///
    /// Admin-only on the backend; callers without `Role::Admin` see
    /// [`ApiError::Http`] with status `403`. The frontend's
    /// admin-moderators page surfaces that case as a Forbidden banner.
    async fn list_admin_moderators(&self) -> Result<Vec<AdminModerator>, ApiError>;

    /// `POST /api/admin/moderators` — grant a role to a new (or
    /// existing) moderator.
    ///
    /// `body.handle` accepts a bare handle (resolved through the
    /// shared identity resolver) or a `did:` literal (trusted
    /// verbatim). The backend returns the canonical moderator row on
    /// success and a 4xx error code on a bad input shape, a handle
    /// that did not resolve, or an already-granted role pair.
    async fn add_admin_moderator(
        &self,
        body: AddModeratorRequest,
    ) -> Result<AdminModerator, ApiError>;

    /// `PATCH /api/admin/moderators/{did}/roles` — toggle a single
    /// role on a moderator.
    ///
    /// `body.grant = true` adds the role; `body.grant = false` revokes
    /// it. The backend refuses with `409 Conflict` when the change
    /// would remove the last admin or demote a pinned admin's `admin`
    /// row.
    async fn patch_admin_moderator_role(
        &self,
        did: &str,
        body: PatchModeratorRoleRequest,
    ) -> Result<AdminModerator, ApiError>;

    /// `DELETE /api/admin/moderators/{did}` — remove a moderator and
    /// cascade their role grants.
    ///
    /// The backend refuses with `409 Conflict` when the target is
    /// `pinned_admin = TRUE`. The frontend mirrors that rule in the
    /// row's "Remove" button (`disabled` + tooltip) so the click
    /// fails up-front rather than waiting on the round-trip.
    async fn delete_admin_moderator(&self, did: &str) -> Result<(), ApiError>;

    // ── Mod policy workbook (issue #226 / WB-4) ─────────────────────

    /// `GET /api/policies` — list current versions (moderator-readable).
    ///
    /// Returns the slim [`ModPolicySummaryDto`] projection (no examples,
    /// no `decision_criteria` body) — used by both the admin two-pane
    /// page and the read-only browse view. Backend gates this on
    /// `Role::Moderator` or higher.
    async fn list_policies(
        &self,
        filters: &PolicyListFilters,
    ) -> Result<Vec<ModPolicySummaryDto>, ApiError>;

    /// `GET /api/policies/:identifier` — fetch the current version of a
    /// policy, full payload including examples. Moderator-readable.
    async fn get_policy(&self, identifier: &str) -> Result<ModPolicyDto, ApiError>;

    /// `GET /api/admin/policies/:identifier/history` — admin-only.
    /// Returns the full version chain (oldest first).
    async fn get_policy_history(
        &self,
        identifier: &str,
    ) -> Result<Vec<ModPolicyHistoryEntryDto>, ApiError>;

    /// `GET /api/admin/policies/:identifier/:version` — admin-only.
    /// Specific historical version, full payload.
    async fn get_policy_at_version(
        &self,
        identifier: &str,
        version: i32,
    ) -> Result<ModPolicyDto, ApiError>;

    /// `POST /api/admin/policies` — admin-only. Create v1 of a new
    /// policy.
    async fn create_policy(&self, body: CreatePolicyDto) -> Result<ModPolicyDto, ApiError>;

    /// `PATCH /api/admin/policies/:identifier` — admin-only. Amend the
    /// policy, bumping the version. `body.change_summary` is required.
    async fn amend_policy(
        &self,
        identifier: &str,
        body: ModPolicyEditDto,
    ) -> Result<ModPolicyDto, ApiError>;

    /// `POST /api/admin/policies/:identifier/pause` — admin-only. Set
    /// `autonomous_paused_until`.
    async fn pause_policy(
        &self,
        identifier: &str,
        body: PausePolicyDto,
    ) -> Result<ModPolicyDto, ApiError>;

    /// `DELETE /api/admin/policies/:identifier/pause` — admin-only.
    /// Clear `autonomous_paused_until` (resume autonomy).
    async fn resume_policy(&self, identifier: &str) -> Result<ModPolicyDto, ApiError>;

    // ── LLM moderation-assist (issue #237 / LLM-8) ──────────────────

    /// Pull the latest LLM recommendation for a case.
    ///
    /// Fetches the case-view DTO and walks the observation list for
    /// the most-recent [`polaris_types::ObservationKind::LlmRecommendation`]
    /// row, then deserialises that row's `evidence` JSONB blob into a
    /// [`RecommendationDto`] (the dispatcher persists the full
    /// `RecommendResponse` payload verbatim per
    /// `.design/llm-moderation-assist.md` REQ-B2).
    ///
    /// Returns `Ok(None)` when no `LlmRecommendation` observation
    /// exists for this case yet — the panel surfaces that state with
    /// a "Request advisor opinion" button.
    ///
    /// Returns `Err` only on transport / non-2xx upstream — a present
    /// observation whose `evidence` payload does not deserialise is a
    /// classifier-contract violation and surfaces as
    /// [`ApiError::Transport`].
    ///
    /// The default implementation reuses [`get_case`](Self::get_case)
    /// so transports do not need to implement a new HTTP method — the
    /// case-view payload already carries the observation list.
    async fn fetch_recommendation(
        &self,
        case_id: SubjectId,
    ) -> Result<Option<RecommendationDto>, ApiError> {
        let case = self.get_case(case_id).await?;
        latest_llm_recommendation(&case.observations)
    }

    /// `POST /api/cases/:incident_id/llm-recommendation` — moderator-
    /// initiated "Request advisor opinion" trigger
    /// (`.design/llm-moderation-assist.md` REQ-C2 "Pull" trigger; LLM-5
    /// / #242 wires the dispatcher).
    ///
    /// The backend hands the case envelope to the LLM dispatcher,
    /// which evaluates autonomy + safety floors and returns one of
    /// four [`RequestRecommendationOutcome`] variants. The panel
    /// branches on the variant to re-fetch the recommendation (and
    /// any newly-inserted draft / action) so the moderator sees the
    /// dispatcher's verdict without a manual refresh.
    async fn request_recommendation(
        &self,
        incident_id: IncidentId,
    ) -> Result<RequestRecommendationOutcome, ApiError>;

    // ── LLM admin audit (issue #238 / LLM-9) ────────────────────────

    /// `GET /api/admin/llm/audit` — admin-only list of autonomous-agent
    /// actions with their LLM audit envelope, cited policies, and
    /// reversal state (`.design/llm-moderation-assist.md` REQ-F4).
    ///
    /// Admin-only on the backend; callers without `Role::Admin` see
    /// [`ApiError::Http`] with status 403. The frontend audit page
    /// surfaces that as a Forbidden banner.
    ///
    /// Pagination is keyset on `(created_at, action_id)` — pass the
    /// `next_cursor` from a previous page through `filters.cursor`
    /// to fetch the next page.
    async fn list_llm_audit(
        &self,
        filters: &LlmAuditFilters,
    ) -> Result<LlmAuditPageDto, ApiError>;
}

/// Walk an observation list and parse the most-recent
/// [`polaris_types::ObservationKind::LlmRecommendation`] row's
/// `evidence` blob into a [`RecommendationDto`].
///
/// Lives in the trait module (not `dto`) because it bridges the typed
/// [`polaris_types::Observation`] domain with the wire shape. Used by
/// the default [`PolarisApiClient::fetch_recommendation`]
/// implementation and exposed to the case-view panel so it can hydrate
/// the same way from a case-view DTO it already holds.
///
/// # Errors
///
/// * [`ApiError::Transport`] — a recommendation observation was
///   present but its `evidence` blob did not deserialise as a
///   [`RecommendationDto`] (classifier-contract violation).
pub fn latest_llm_recommendation(
    observations: &[polaris_types::Observation],
) -> Result<Option<RecommendationDto>, ApiError> {
    let latest = observations
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                polaris_types::ObservationKind::LlmRecommendation { .. }
            )
        })
        .max_by_key(|o| o.detected_at);
    let Some(obs) = latest else {
        return Ok(None);
    };
    let dto = serde_json::from_value::<RecommendationDto>(obs.evidence.clone()).map_err(|e| {
        ApiError::Transport(format!(
            "llm_recommendation observation evidence did not deserialise: {e}"
        ))
    })?;
    Ok(Some(dto))
}

/// Typed wire shape of `GET /healthz`.
///
/// Mirrors the JSON body the backend handler builds via
/// `serde_json::json!({...})`, so any drift between backend and frontend is
/// caught at deserialisation time rather than silently swallowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Process-level liveness — `"ok"` when the pool can hand out a
    /// connection, `"degraded"` otherwise.
    pub status: String,
    /// Database reachability — `"ok"` on success, `"error: <msg>"` on
    /// failure (the backend embeds the underlying error message into the
    /// string; the frontend renders it verbatim).
    pub db: String,
}

/// Errors a Polaris API call can produce.
///
/// Two variants:
///
/// - [`Transport`](Self::Transport) — the request could not be sent or the
///   response could not be read (network down, CORS rejected, body cut
///   mid-stream). The string carries the lower-level error message so a
///   tracing log preserves the context without leaking transport types
///   through the public API.
/// - [`Http`](Self::Http) — the request reached the server and the server
///   replied with a non-2xx status. The numeric status and the response
///   body (if it parsed as UTF-8) are preserved so the UI can render a
///   sensible error.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ApiError {
    /// Underlying transport failure (network, TLS, body framing).
    #[error("transport error: {0}")]
    Transport(String),
    /// HTTP non-2xx response.
    #[error("HTTP {status}: {message}")]
    Http {
        /// Numeric HTTP status code returned by the server.
        status: u16,
        /// Best-effort textual body — empty when the body was not UTF-8.
        message: String,
    },
}
