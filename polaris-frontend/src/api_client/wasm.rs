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

use super::dto::{
    AddModeratorRequest, AdminModerator, CaseView, CreatePolicyDto, DashboardFilters,
    DashboardSnapshot, Escalate, GenerateKeyResponse, IncidentList, LlmAuditFilters,
    LlmAuditPageDto, ModPolicyDto, ModPolicyEditDto, ModPolicyHistoryEntryDto, ModPolicySummaryDto,
    PatchModeratorRoleRequest, PausePolicyDto, PolicyListFilters, PublishLabelerRecordRequest,
    PublishLabelerRecordResponse, RequestPlcSignatureResponse, RequestRecommendationOutcome,
    ReverseBody, SubjectLookupRequest, SubjectLookupResponse, SubmitAction,
    SubmitPlcOperationRequest, SubmitPlcOperationResponse, WhoamiResponse,
    dashboard_filters_to_query_string, llm_audit_filters_to_query_string,
    policy_filters_to_query_string,
};
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

    /// Send a `PATCH` with a JSON body and decode the JSON response.
    ///
    /// Used by the admin-moderators role-toggle endpoint (issue #214 /
    /// #217). `gloo-net` 0.6 ships `Request::patch`; the same
    /// `credentials(Include)` and JSON-body discipline as
    /// [`Self::post_json`] applies.
    async fn patch_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let req = Request::patch(&self.url(path))
            .credentials(RequestCredentials::Include)
            .json(body)
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let resp = req
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }

    /// Send a `DELETE` and accept any 2xx without parsing a JSON body
    /// — the admin-moderators delete endpoint returns
    /// `204 No Content`. Non-2xx maps onto [`ApiError::Http`] so the
    /// admin page can surface the conflict message (pinned-admin
    /// guard, etc.) verbatim.
    async fn delete_no_content(&self, path: &str) -> Result<(), ApiError> {
        let resp = Request::delete(&self.url(path))
            .credentials(RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let status = resp.status();
        if !(200..300).contains(&status) {
            let message = resp.text().await.unwrap_or_default();
            return Err(ApiError::Http { status, message });
        }
        Ok(())
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

    async fn bulk_action(
        &self,
        body: crate::api_client::dto::BulkSubmitAction,
    ) -> Result<crate::api_client::dto::BulkActionOutcome, ApiError> {
        self.post_json("/api/bulk-actions", &body).await
    }

    async fn mute_reporter(
        &self,
        body: crate::api_client::dto::MuteReporterBody,
    ) -> Result<crate::api_client::dto::MutedReporterRow, ApiError> {
        self.post_json("/api/moderation/muted-reporters", &body)
            .await
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

    async fn dashboard(&self, filters: &DashboardFilters) -> Result<DashboardSnapshot, ApiError> {
        let query = dashboard_filters_to_query_string(filters);
        let path = if query.is_empty() {
            "/api/dashboard".to_owned()
        } else {
            format!("/api/dashboard?{query}")
        };
        self.get_json(&path).await
    }

    async fn whoami(&self) -> Result<WhoamiResponse, ApiError> {
        self.get_json("/api/whoami").await
    }

    async fn labeler_policies(
        &self,
    ) -> Result<crate::api_client::dto::LabelerPoliciesResponse, ApiError> {
        self.get_json("/api/labeler/policies").await
    }

    async fn network_context(
        &self,
        subject_id: &str,
    ) -> Result<crate::api_client::dto::NetworkContext, ApiError> {
        let path = format!("/api/cases/{subject_id}/network-context");
        self.get_json(&path).await
    }

    async fn media_gallery(
        &self,
        subject_id: SubjectId,
    ) -> Result<crate::api_client::dto::MediaGalleryResponse, ApiError> {
        let path = format!("/api/cases/{subject_id}/media");
        self.get_json(&path).await
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

    async fn lookup_subject(&self, identifier: &str) -> Result<SubjectLookupResponse, ApiError> {
        let body = SubjectLookupRequest {
            identifier: identifier.to_owned(),
        };
        self.post_json("/api/subjects/lookup", &body).await
    }

    async fn list_admin_moderators(&self) -> Result<Vec<AdminModerator>, ApiError> {
        self.get_json("/api/admin/moderators").await
    }

    async fn add_admin_moderator(
        &self,
        body: AddModeratorRequest,
    ) -> Result<AdminModerator, ApiError> {
        self.post_json("/api/admin/moderators", &body).await
    }

    async fn patch_admin_moderator_role(
        &self,
        did: &str,
        body: PatchModeratorRoleRequest,
    ) -> Result<AdminModerator, ApiError> {
        let path = format!("/api/admin/moderators/{did}/roles");
        self.patch_json(&path, &body).await
    }

    async fn delete_admin_moderator(&self, did: &str) -> Result<(), ApiError> {
        let path = format!("/api/admin/moderators/{did}");
        self.delete_no_content(&path).await
    }

    async fn list_policies(
        &self,
        filters: &PolicyListFilters,
    ) -> Result<Vec<ModPolicySummaryDto>, ApiError> {
        let query = policy_filters_to_query_string(filters);
        let path = if query.is_empty() {
            "/api/policies".to_owned()
        } else {
            format!("/api/policies?{query}")
        };
        self.get_json(&path).await
    }

    async fn get_policy(&self, identifier: &str) -> Result<ModPolicyDto, ApiError> {
        let path = format!("/api/policies/{identifier}");
        self.get_json(&path).await
    }

    async fn get_policy_history(
        &self,
        identifier: &str,
    ) -> Result<Vec<ModPolicyHistoryEntryDto>, ApiError> {
        let path = format!("/api/admin/policies/{identifier}/history");
        self.get_json(&path).await
    }

    async fn get_policy_at_version(
        &self,
        identifier: &str,
        version: i32,
    ) -> Result<ModPolicyDto, ApiError> {
        let path = format!("/api/admin/policies/{identifier}/{version}");
        self.get_json(&path).await
    }

    async fn create_policy(&self, body: CreatePolicyDto) -> Result<ModPolicyDto, ApiError> {
        self.post_json("/api/admin/policies", &body).await
    }

    async fn amend_policy(
        &self,
        identifier: &str,
        body: ModPolicyEditDto,
    ) -> Result<ModPolicyDto, ApiError> {
        let path = format!("/api/admin/policies/{identifier}");
        self.patch_json(&path, &body).await
    }

    async fn pause_policy(
        &self,
        identifier: &str,
        body: PausePolicyDto,
    ) -> Result<ModPolicyDto, ApiError> {
        let path = format!("/api/admin/policies/{identifier}/pause");
        self.post_json(&path, &body).await
    }

    async fn resume_policy(&self, identifier: &str) -> Result<ModPolicyDto, ApiError> {
        // `DELETE /api/admin/policies/:identifier/pause` returns the
        // updated policy as JSON, so we cannot reuse `delete_no_content`.
        let path = format!("/api/admin/policies/{identifier}/pause");
        let resp = Request::delete(&self.url(&path))
            .credentials(RequestCredentials::Include)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        decode_response(resp).await
    }

    async fn request_recommendation(
        &self,
        incident_id: IncidentId,
    ) -> Result<RequestRecommendationOutcome, ApiError> {
        // Mirrors the native impl: empty JSON body, so the request
        // advertises `application/json` and the axum extractor
        // resolves the empty `Json(_)` shape without an Unsupported
        // Media Type bounce.
        let path = format!("/api/cases/{incident_id}/llm-recommendation");
        self.post_json(&path, &serde_json::json!({})).await
    }

    async fn list_llm_audit(&self, filters: &LlmAuditFilters) -> Result<LlmAuditPageDto, ApiError> {
        let query = llm_audit_filters_to_query_string(filters);
        let path = if query.is_empty() {
            "/api/admin/llm/audit".to_owned()
        } else {
            format!("/api/admin/llm/audit?{query}")
        };
        self.get_json(&path).await
    }
}
