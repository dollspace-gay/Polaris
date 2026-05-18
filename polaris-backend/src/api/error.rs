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

    /// A required precondition on the server's state was not met
    /// (REQ-A3 / AC-A3). Surfaces as `412 Precondition Failed`. The
    /// first user is the action-submission path's "labeler not yet
    /// provisioned" check: an emit-shaped action (Label / Takedown)
    /// submitted before `polaris_setup_state.signing_pubkey_did` is
    /// populated must not reach the emitter. The body's `code` is
    /// carried in the variant so different preconditions can share
    /// the variant without collapsing onto one generic code.
    #[error("precondition failed: {message}")]
    PreconditionFailed {
        /// Machine-readable code (`labeler_not_provisioned`, …) that
        /// the client matches on.
        code: &'static str,
        /// Operator-readable description of the failing precondition.
        message: &'static str,
    },

    /// The caller is rate-limited. The static message names the limit.
    ///
    /// Introduced for the appeals workflow (issue #24): the public
    /// `POST /api/appeals` endpoint is un-authenticated and IP-rate-limited;
    /// this variant is the typed exit it returns when an appellant IP hits
    /// its hourly quota. The wire shape is `429 Too Many Requests` with
    /// code `"rate_limited"`.
    #[error("rate limited: {0}")]
    TooManyRequests(&'static str),

    /// An upstream dependency Polaris consumed on the caller's behalf
    /// failed. Surfaced from the network-context handler (issue #97)
    /// when the Bluesky AppView profile / followers / follows /
    /// author-feed fetch produced a non-2xx or unparseable body.
    /// The wire shape is `502 Bad Gateway` with the static message
    /// embedded as the response `error` so the frontend can render
    /// a deterministic inline failure state.
    #[error("upstream unavailable: {0}")]
    BadGateway(&'static str),

    /// A login attempt's handle resolution failed — typically a
    /// mistyped handle, the PLC directory being unreachable, or DNS
    /// starvation. Distinguished from the generic [`Self::Internal`]
    /// because the cause is user-attributable (their input or their
    /// network's view of the upstream directory); collapsing it into
    /// `internal error` made the login screen unable to render an
    /// actionable message. Wire shape: `502 Bad Gateway` with code
    /// `handle_resolution_failed` and a human message naming the
    /// handle so the frontend can render it inline.
    ///
    /// This does *not* leak whether the failure was DNS, PLC, AS
    /// discovery, or alsoKnownAs mismatch — the body says only that
    /// the handle could not be resolved, which is sufficient
    /// information for a logged-out user.
    #[error("handle resolution failed: {handle}")]
    HandleResolutionFailed {
        /// The handle the moderator submitted. Echoed back so the
        /// frontend can render an inline error like "Couldn't resolve
        /// `polarislabeler.bsky.social` — check the handle and try
        /// again."
        handle: String,
    },

    /// The moderator's DID is not on the operator-managed allow-list
    /// (issue #214 / Ozone-style ACL). Surfaces from the OAuth
    /// callback when the resolved DID has no `moderator_roles` row
    /// and the deployment is past the first-user-bootstrap window.
    /// The wire shape is `403 Forbidden` with code `unauthorized`;
    /// the `auth_atproto::callback` handler intercepts this variant
    /// and turns it into a `303 See Other` to
    /// `/login?error=unauthorized&handle=<echoed>` so the browser
    /// hits the login form instead of an opaque JSON body. The
    /// `Forbidden` arm is kept distinct from
    /// [`Self::Forbidden`] (the generic "logged in but not
    /// authorised for this action") so an attacker probing the wire
    /// shape cannot collapse the two.
    #[error("login not allowed: {handle}")]
    LoginNotAllowed {
        /// The handle the moderator submitted (or the DID, when no
        /// handle was in scope). Echoed back so the login form can
        /// render an inline message.
        handle: String,
    },

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
            Self::PreconditionFailed { code, message } => {
                // 412 carries both the wire `code` (matched on by the
                // frontend) and the human `message`. The body shape
                // matches every other typed error variant so the
                // client's `{ "code", "error" }` deserialiser does not
                // need a special case.
                let body = serde_json::json!({ "error": *message, "code": *code });
                return (StatusCode::PRECONDITION_FAILED, axum::Json(body)).into_response();
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
            Self::BadGateway(reason) => {
                // 502 carries the static `code` (`upstream_unavailable`,
                // …) so the frontend can match on it deterministically,
                // and a human-readable `error` so log scrapers and the
                // tracing chain see the failure reason without an
                // opaque generic.
                let body = serde_json::json!({
                    "error": *reason,
                    "code": "upstream_unavailable",
                });
                return (StatusCode::BAD_GATEWAY, axum::Json(body)).into_response();
            }
            Self::HandleResolutionFailed { handle } => {
                // 502 with a typed `handle_resolution_failed` code +
                // a message naming the handle. The frontend's login
                // form matches on `code` and renders the handle
                // inline. Logged at WARN (not ERROR) because the
                // failure mode is user input or upstream weather,
                // not a Polaris bug.
                tracing::warn!(handle = %handle, "login: handle resolution failed");
                let body = serde_json::json!({
                    "error": format!("could not resolve handle `{handle}`"),
                    "code": "handle_resolution_failed",
                });
                return (StatusCode::BAD_GATEWAY, axum::Json(body)).into_response();
            }
            Self::LoginNotAllowed { handle } => {
                // 403 with a typed `unauthorized` code so the OAuth
                // callback handler can intercept and turn this into
                // a 303 redirect to /login. Other call sites that
                // bubble the JSON shape (no redirect available) get
                // the same `{ code, error }` envelope every typed
                // error variant uses.
                tracing::warn!(handle = %handle, "login: DID not on allow-list");
                let body = serde_json::json!({
                    "error": format!("login not allowed for `{handle}`"),
                    "code": "unauthorized",
                });
                return (StatusCode::FORBIDDEN, axum::Json(body)).into_response();
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
    async fn precondition_failed_maps_to_412_with_code_and_message() {
        let (status, body) = render(ApiError::PreconditionFailed {
            code: "labeler_not_provisioned",
            message: "complete /setup before recording labelling actions",
        })
        .await;
        assert_eq!(status, StatusCode::PRECONDITION_FAILED);
        assert_eq!(body["code"], "labeler_not_provisioned");
        assert_eq!(
            body["error"],
            "complete /setup before recording labelling actions",
        );
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

    #[tokio::test]
    async fn handle_resolution_failed_maps_to_502_typed_code() {
        // The login path that previously surfaced as `{code:internal,
        // error:"internal error"}` must now produce a typed shape the
        // frontend can render inline.
        let (status, body) = render(ApiError::HandleResolutionFailed {
            handle: "polarislabeler.bsky.social".to_owned(),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["code"], "handle_resolution_failed");
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("polarislabeler.bsky.social"),
            "handle must appear in the message so the form can render it; got {body}",
        );
        // Pin the exact wording so the frontend's regex match (if any)
        // doesn't bit-rot silently.
        assert_eq!(
            body["error"],
            "could not resolve handle `polarislabeler.bsky.social`",
        );
    }
}
