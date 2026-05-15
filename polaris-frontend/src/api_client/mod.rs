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
    CaseView, DashboardSnapshot, Escalate, GenerateKeyResponse, IncidentList,
    PublishLabelerRecordRequest, PublishLabelerRecordResponse, RequestPlcSignatureResponse,
    ReverseBody, SubmitAction, SubmitPlcOperationRequest, SubmitPlcOperationResponse,
    WhoamiResponse,
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

    /// `GET /api/dashboard` — composite snapshot for the pattern dashboard.
    ///
    /// Returns the four-panel [`DashboardSnapshot`] described in
    /// `design.md` §5.1: report-volume timeline, incident clusters,
    /// coordinated-action signals, and moderator-load summary. The
    /// frontend polls this endpoint on a 5-second interval; a WebSocket
    /// live feed is a follow-up (#20-followup) to keep this issue's scope
    /// tight.
    async fn get_dashboard(&self) -> Result<DashboardSnapshot, ApiError>;
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
