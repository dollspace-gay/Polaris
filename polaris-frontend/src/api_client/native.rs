//! Native (`reqwest`-backed) Polaris API client.
//!
//! Used by `cargo check` / `cargo test` / `cargo doc` on the host
//! toolchain. The real frontend runtime is wasm; this impl exists so the
//! crate has a single source tree that compiles on both targets.

#![cfg(not(target_arch = "wasm32"))]

use polaris_types::{Action, ActionId, Incident, IncidentId, IncidentStatus, SubjectId};
use reqwest::Client;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::dto::{
    CaseView, DashboardSnapshot, Escalate, GenerateKeyResponse, IncidentList,
    PublishLabelerRecordRequest, PublishLabelerRecordResponse, RequestPlcSignatureResponse,
    ReverseBody, SubmitAction, SubmitPlcOperationRequest, SubmitPlcOperationResponse,
    WhoamiResponse,
};
use super::{ApiError, HealthStatus, PolarisApiClient};

/// `reqwest`-backed [`PolarisApiClient`] impl.
///
/// `cookie_store(true)` enables the in-memory cookie jar so any
/// `Set-Cookie` returned by the backend rides on subsequent requests.
/// That parity with the browser's automatic cookie handling is what lets
/// the same client code drive headless tests and the browser bundle.
#[derive(Debug, Clone)]
pub struct NativePolarisApiClient {
    base: String,
    client: Client,
}

impl NativePolarisApiClient {
    /// Construct a new client rooted at `base` (e.g. `https://polaris.local`).
    ///
    /// Fails if `reqwest` cannot build its internal client — typically only
    /// on a TLS-stack misconfiguration. The error string preserves the
    /// underlying cause for diagnostics.
    pub fn new(base: impl Into<String>) -> Result<Self, ApiError> {
        let client = Client::builder()
            .cookie_store(true)
            .build()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Ok(Self {
            base: base.into(),
            client,
        })
    }

    /// Compose `base` with `path`, trimming any stray trailing slash on
    /// `base` so the result never contains `//`.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base.trim_end_matches('/'))
    }

    /// Run a `GET` against `path` and decode the JSON response.
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self
            .client
            .get(self.url(path))
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }

    /// Run a `POST` with a JSON body and decode the JSON response.
    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let resp = self
            .client
            .post(self.url(path))
            .json(body)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }
}

/// Map a `reqwest::Response` to either the decoded JSON body or an
/// [`ApiError`]. Non-2xx is [`ApiError::Http`]; everything else is
/// [`ApiError::Transport`].
async fn decode_response<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T, ApiError> {
    let status = resp.status();
    if !status.is_success() {
        let message = resp.text().await.unwrap_or_default();
        return Err(ApiError::Http {
            status: status.as_u16(),
            message,
        });
    }
    resp.json::<T>()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))
}

impl PolarisApiClient for NativePolarisApiClient {
    async fn healthz(&self) -> Result<HealthStatus, ApiError> {
        self.get_json("/healthz").await
    }

    async fn get_case(&self, subject_id: SubjectId) -> Result<CaseView, ApiError> {
        // `SubjectId`'s `Display` impl forwards to `Uuid`, which produces
        // the canonical hyphenated form. No percent-encoding needed.
        let path = format!("/api/cases/{subject_id}");
        self.get_json(&path).await
    }

    async fn list_incidents(&self, status: IncidentStatus) -> Result<IncidentList, ApiError> {
        // `IncidentStatus::as_str` returns the wire form the backend's
        // query-string deserialiser expects (`open`, `in_review`, …).
        let path = format!("/api/cases?status={}", status.as_str());
        self.get_json(&path).await
    }

    async fn submit_action(
        &self,
        subject_id: SubjectId,
        body: SubmitAction,
    ) -> Result<Action, ApiError> {
        let path = format!("/api/cases/{subject_id}/actions");
        self.post_json(&path, &body).await
    }

    async fn escalate(
        &self,
        incident_id: IncidentId,
        body: Escalate,
    ) -> Result<Incident, ApiError> {
        let path = format!("/api/cases/{incident_id}/escalate");
        self.post_json(&path, &body).await
    }

    async fn reverse_action(
        &self,
        action_id: ActionId,
        body: ReverseBody,
    ) -> Result<Action, ApiError> {
        let path = format!("/api/actions/{action_id}/reverse");
        self.post_json(&path, &body).await
    }

    async fn get_dashboard(&self) -> Result<DashboardSnapshot, ApiError> {
        self.get_json("/api/dashboard").await
    }

    async fn whoami(&self) -> Result<WhoamiResponse, ApiError> {
        self.get_json("/api/whoami").await
    }

    async fn setup_generate_key(&self) -> Result<GenerateKeyResponse, ApiError> {
        // Empty JSON body — the endpoint takes no input; everything it
        // needs (the moderator identity, the keystore handle) comes
        // from the authenticated session and the API state.
        self.post_json("/api/setup/generate-key", &serde_json::json!({}))
            .await
    }

    async fn setup_publish_labeler_record(
        &self,
        req: PublishLabelerRecordRequest,
    ) -> Result<PublishLabelerRecordResponse, ApiError> {
        self.post_json("/api/setup/publish-labeler-record", &req)
            .await
    }

    async fn setup_request_plc_signature(&self) -> Result<RequestPlcSignatureResponse, ApiError> {
        self.post_json("/api/setup/request-plc-signature", &serde_json::json!({}))
            .await
    }

    async fn setup_submit_plc_operation(
        &self,
        req: SubmitPlcOperationRequest,
    ) -> Result<SubmitPlcOperationResponse, ApiError> {
        self.post_json("/api/setup/submit-plc-operation", &req)
            .await
    }
}
