//! Browser (`gloo-net`-backed) Polaris API client.
//!
//! Drives the browser's native `fetch()` API via `gloo-net`. Every request
//! sets `credentials: "include"` via [`RequestCredentials::Include`] so the
//! Polaris session cookie flows on cross-origin deployments (Trunk's dev
//! server lives on `127.0.0.1:8081` while the backend lives on
//! `127.0.0.1:3000`; in production both share the same origin and the
//! credentials hint is a no-op).

#![cfg(target_arch = "wasm32")]

use gloo_net::http::Request;
use polaris_types::{Action, ActionId, Incident, IncidentId, IncidentStatus, SubjectId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use web_sys::RequestCredentials;

use super::dto::{CaseView, DashboardSnapshot, Escalate, IncidentList, ReverseBody, SubmitAction};
use super::{ApiError, HealthStatus, PolarisApiClient};

/// `gloo-net`-backed [`PolarisApiClient`] impl.
#[derive(Debug, Clone)]
pub struct WasmPolarisApiClient {
    base: String,
}

impl WasmPolarisApiClient {
    /// Construct a new client rooted at `base`.
    ///
    /// `base` is typically the empty string (same-origin deploys) or a
    /// scheme+host pair when the frontend runs against a remote backend.
    /// No I/O — construction cannot fail on this transport.
    #[must_use]
    pub fn new(base: impl Into<String>) -> Self {
        Self { base: base.into() }
    }

    /// Compose `base` with `path`, trimming any stray trailing slash on
    /// `base` so the result never contains `//`.
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base.trim_end_matches('/'))
    }

    /// Send a `GET` and decode the JSON response.
    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = Request::get(&self.url(path))
            .credentials(RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }

    /// Send a `POST` with a JSON body and decode the JSON response.
    async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let req = Request::post(&self.url(path))
            .credentials(RequestCredentials::Include)
            .json(body)
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }
}

/// Map a `gloo_net::http::Response` to either the decoded JSON body or an
/// [`ApiError`]. Non-2xx is [`ApiError::Http`]; everything else is
/// [`ApiError::Transport`].
async fn decode_response<T: DeserializeOwned>(
    resp: gloo_net::http::Response,
) -> Result<T, ApiError> {
    let status = resp.status();
    if !(200..300).contains(&status) {
        let message = resp.text().await.unwrap_or_default();
        return Err(ApiError::Http { status, message });
    }
    resp.json::<T>()
        .await
        .map_err(|e| ApiError::Transport(e.to_string()))
}

impl PolarisApiClient for WasmPolarisApiClient {
    async fn healthz(&self) -> Result<HealthStatus, ApiError> {
        self.get_json("/healthz").await
    }

    async fn get_case(&self, subject_id: SubjectId) -> Result<CaseView, ApiError> {
        let path = format!("/api/cases/{subject_id}");
        self.get_json(&path).await
    }

    async fn list_incidents(&self, status: IncidentStatus) -> Result<IncidentList, ApiError> {
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
}
