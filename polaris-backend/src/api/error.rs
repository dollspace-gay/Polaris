//! Typed API error → JSON `IntoResponse` contract.
//!
//! Every fallible HTTP handler in `polaris-backend` returns
//! `Result<_, ApiError>`. The single `IntoResponse` impl here renders the
//! variant to a `(StatusCode, Json)` pair with the on-the-wire shape
//!
//! ```json
//! { "error": "<message>", "code": "<machine-readable code>" }
//! ```
//!
//! The `code` field is the contract for clients; the `error` text is for
//! humans and may evolve in wording between releases. Both come from a single
//! `match` so the two stay in sync.
//!
//! # `anyhow` placement
//!
//! [`ApiError::Internal`] carries an inner `anyhow::Error` via `#[source]` —
//! this is the workspace's only library-side use of `anyhow`. The public API
//! surface is *still* `ApiError` (a typed enum); `anyhow` is contained inside
//! one variant so the cause chain on a generic 500 path stays informative
//! without leaking `anyhow::Error` into a public signature. Per the
//! rust-quality skill, anyhow may live at the binary glue or inside a
//! `#[source]` field on a thiserror variant — both apply here.

use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde_json::json;

use crate::repo::RepoError;

/// Public error type for every handler under `polaris-backend/src/api/`.
///
/// Each variant maps to exactly one `(status, code, message)` triple in
/// [`ApiError::into_response`]. Repository failures arrive via
/// [`From<RepoError> for ApiError`]; unique-violations and `NotFound`
/// originating from the repo layer are mapped explicitly so handlers do not
/// need to pre-classify them.
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    /// No valid session cookie was presented. Surfaced from the auth
    /// middleware via this variant when a handler chooses to raise the
    /// error itself (the middleware also has its own short-circuit path).
    #[error("not authenticated")]
    Unauthorized,

    /// The requested resource does not exist (subject id, incident id, …).
    #[error("resource not found")]
    NotFound,

    /// The caller is authenticated but not authorized for this action.
    ///
    /// Distinct from [`ApiError::Unauthorized`] (no valid session). The
    /// reversal endpoint (issue #36) is the first user of this variant:
    /// the original moderator outside the 24h window or a non-senior who
    /// did not author the original action both surface here. The wire
    /// shape is `403 forbidden` with code `"forbidden"`; the body
    /// deliberately does not disclose which authorization rule rejected
    /// the call (we do not want to teach an attacker the rule edges).
    #[error("forbidden")]
    Forbidden,

    /// The request payload failed validation (length, allow-list,
    /// well-formedness). The static message names the offending rule.
    #[error("invalid request: {0}")]
    BadRequest(&'static str),

    /// A conflict with existing state (typically a unique-constraint
    /// violation). The static message names the offending invariant.
    #[error("conflict: {0}")]
    Conflict(&'static str),

    /// The caller is rate-limited. The static message names the limit.
    ///
    /// Introduced for the appeals workflow (issue #24): the public
    /// `POST /api/appeals` endpoint is un-authenticated and IP-rate-limited;
    /// this variant is the typed exit it returns when an appellant IP hits
    /// its hourly quota. The wire shape is `429 Too Many Requests` with
    /// code `"rate_limited"`.
    #[error("rate limited: {0}")]
    TooManyRequests(&'static str),

    /// An internal error not attributable to caller input. Wraps an
    /// `anyhow::Error` so the cause chain is preserved for logs; the
    /// outward shape is a generic 500.
    #[error("internal error")]
    Internal(#[source] anyhow::Error),

    /// A repository-layer failure. The `IntoResponse` impl classifies
    /// `RepoError::NotFound` as 404, `RepoError::UniqueViolation` as 409,
    /// and the remainder as 500.
    #[error("repository error")]
    Repo(#[from] RepoError),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, msg) = match &self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "not authenticated",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "resource not found"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden", "forbidden"),
            // BadRequest / Conflict embed their static message in the
            // thiserror `#[error("…: {0}")]` format. Render that whole string
            // (via Display) into the JSON body so the wire format matches the
            // declared Display contract, not a bare interior fragment.
            Self::BadRequest(_) | Self::Conflict(_) => {
                let code = if matches!(self, Self::BadRequest(_)) {
                    "bad_request"
                } else {
                    "conflict"
                };
                let status = if matches!(self, Self::BadRequest(_)) {
                    StatusCode::BAD_REQUEST
                } else {
                    StatusCode::CONFLICT
                };
                let msg = self.to_string();
                let body = serde_json::json!({ "error": msg, "code": code });
                return (status, axum::Json(body)).into_response();
            }
            Self::TooManyRequests(_) => {
                // Same body-construction path as BadRequest / Conflict: the
                // static message is part of the Display impl, so re-render
                // through `to_string()` to keep the wire format consistent
                // with the declared contract.
                let msg = self.to_string();
                let body = serde_json::json!({ "error": msg, "code": "rate_limited" });
                return (StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
            }
            Self::Repo(RepoError::NotFound) => {
                (StatusCode::NOT_FOUND, "not_found", "resource not found")
            }
            Self::Repo(RepoError::UniqueViolation(_)) => {
                (StatusCode::CONFLICT, "unique_violation", "already exists")
            }
            Self::Repo(_) | Self::Internal(_) => {
                tracing::error!(error = ?self, "api error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error",
                )
            }
        };
        let body = json!({ "error": msg, "code": code });
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    /// Pull the `(StatusCode, Value)` pair out of an `ApiError` response.
    /// Keeps the per-variant assertions readable.
    async fn render(err: ApiError) -> (StatusCode, serde_json::Value) {
        let resp = err.into_response();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        (status, body)
    }

    #[tokio::test]
    async fn unauthorized_maps_to_401_unauthorized() {
        let (status, body) = render(ApiError::Unauthorized).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "unauthorized");
        assert_eq!(body["error"], "not authenticated");
    }

    #[tokio::test]
    async fn not_found_maps_to_404() {
        let (status, body) = render(ApiError::NotFound).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "not_found");
    }

    #[tokio::test]
    async fn forbidden_maps_to_403() {
        let (status, body) = render(ApiError::Forbidden).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["code"], "forbidden");
        assert_eq!(body["error"], "forbidden");
    }

    #[tokio::test]
    async fn bad_request_carries_static_message() {
        let (status, body) = render(ApiError::BadRequest("reasoning too short")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["code"], "bad_request");
        assert_eq!(body["error"], "invalid request: reasoning too short");
    }

    #[tokio::test]
    async fn conflict_carries_static_message() {
        let (status, body) = render(ApiError::Conflict("duplicate subject")).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "conflict");
    }

    #[tokio::test]
    async fn repo_not_found_maps_to_404_not_internal() {
        let (status, body) = render(ApiError::Repo(RepoError::NotFound)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["code"], "not_found");
    }

    #[tokio::test]
    async fn too_many_requests_maps_to_429_rate_limited() {
        let (status, body) = render(ApiError::TooManyRequests("appeals: 5/hour per IP")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["code"], "rate_limited");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("appeals: 5/hour"),
            "static message must round-trip in the body, got {body}",
        );
    }
}
