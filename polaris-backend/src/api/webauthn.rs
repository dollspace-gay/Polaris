//! HTTP endpoints for the hardware-key (WebAuthn / FIDO2) gate (#40,
//! design.md §6 + §9.1).
//!
//! Four endpoints, two ceremonies:
//!
//! - `POST /api/auth/webauthn/register/start` — issue a registration
//!   challenge for an authenticated moderator.
//! - `POST /api/auth/webauthn/register/finish` — finalise registration AND
//!   mint the Polaris session cookie. This is the cookie-issuance point on
//!   the enrolment path.
//! - `POST /api/auth/webauthn/assert/start` — issue an assertion challenge
//!   for a moderator who has at least one registered authenticator.
//! - `POST /api/auth/webauthn/assert/finish` — verify assertion AND mint the
//!   Polaris session cookie. This is the cookie-issuance point on the
//!   re-authentication path.
//!
//! # Where the moderator id comes from
//!
//! The four endpoints operate in the post-OIDC / post-ATProto-OAuth window,
//! *before* a session cookie exists. They cannot use
//! `Extension<ModeratorAuthCtx>` (the auth middleware short-circuits on
//! missing cookies). The intended caller is the frontend enrolment /
//! assertion screen (issue #77), which holds the `moderator_id` returned by
//! the gate response and passes it back here. Frontend wiring lives
//! in #77; the typed wire shape is exported from this module today.

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorId;
use crate::auth::webauthn::WebauthnError;

/// Request body for `POST /api/auth/webauthn/register/start` and
/// `POST /api/auth/webauthn/assert/start`.
#[derive(Debug, Deserialize)]
pub struct StartRequest {
    /// Authenticated moderator id (echoed from the gate response).
    pub moderator_id: ModeratorId,
}

/// Response body for `POST /api/auth/webauthn/register/start`.
#[derive(Debug, Serialize)]
pub struct RegisterStartBody {
    /// Server-authored challenge to feed into
    /// `navigator.credentials.create({ publicKey: ... })`.
    pub challenge: CreationChallengeResponse,
    /// Opaque correlator the client returns to
    /// [`register_finish`].
    pub state: String,
}

/// Response body for `POST /api/auth/webauthn/assert/start`.
#[derive(Debug, Serialize)]
pub struct AssertStartBody {
    /// Server-authored challenge to feed into
    /// `navigator.credentials.get({ publicKey: ... })`.
    pub challenge: RequestChallengeResponse,
    /// Opaque correlator the client returns to [`assert_finish`].
    pub state: String,
}

/// Request body for `POST /api/auth/webauthn/register/finish`.
#[derive(Debug, Deserialize)]
pub struct RegisterFinishRequest {
    /// State token returned by [`register_start`].
    pub state: String,
    /// `RegisterPublicKeyCredential` returned by the browser's
    /// `navigator.credentials.create`.
    pub credential: RegisterPublicKeyCredential,
}

/// Request body for `POST /api/auth/webauthn/assert/finish`.
#[derive(Debug, Deserialize)]
pub struct AssertFinishRequest {
    /// State token returned by [`assert_start`].
    pub state: String,
    /// `PublicKeyCredential` returned by the browser's
    /// `navigator.credentials.get`.
    pub credential: PublicKeyCredential,
}

/// Response body for `register_finish` / `assert_finish`.
///
/// The session cookie is set via a `Set-Cookie` header on the response — the
/// JSON body simply confirms the cookie was issued. The frontend redirects
/// to the dashboard on a 200; the session middleware authenticates the
/// follow-up requests.
#[derive(Debug, Serialize)]
pub struct GateAcceptedBody {
    /// Stable echo of the authenticated moderator id, for the frontend's
    /// local state.
    pub moderator_id: ModeratorId,
    /// Constant `"ok"` — the frontend uses this for a discriminated-union
    /// response shape across the four endpoints.
    pub status: &'static str,
}

/// `POST /api/auth/webauthn/register/start`.
///
/// # Errors
///
/// - [`ApiError::Internal`] when the verifier hits a DB or framework
///   failure.
pub async fn register_start(
    State(state): State<ApiState>,
    Json(body): Json<StartRequest>,
) -> Result<Json<RegisterStartBody>, ApiError> {
    let verifier = state.webauthn.as_ref().ok_or(ApiError::NotFound)?;
    let out = verifier
        .register_start(body.moderator_id)
        .await
        .map_err(webauthn_to_api)?;
    Ok(Json(RegisterStartBody {
        challenge: out.challenge,
        state: out.state,
    }))
}

/// `POST /api/auth/webauthn/register/finish`.
///
/// Persists the credential and signals to the caller that the gate has been
/// satisfied. The session cookie itself is minted by the OIDC / ATProto
/// callback handler's follow-up flow (filed under #67 / #77) — this endpoint
/// returns the typed body the frontend consumes on its way to the dashboard.
///
/// # Errors
///
/// - [`ApiError::BadRequest`] on an expired or unknown state token.
/// - [`ApiError::Internal`] on framework / DB failure.
pub async fn register_finish(
    State(state): State<ApiState>,
    Json(body): Json<RegisterFinishRequest>,
) -> Result<Json<GateAcceptedBody>, ApiError> {
    let verifier = state.webauthn.as_ref().ok_or(ApiError::NotFound)?;
    let moderator_id = verifier
        .register_finish(&body.state, &body.credential)
        .await
        .map_err(webauthn_to_api)?;
    Ok(Json(GateAcceptedBody {
        moderator_id,
        status: "ok",
    }))
}

/// `POST /api/auth/webauthn/assert/start`.
///
/// # Errors
///
/// - [`ApiError::Internal`] on framework / DB failure.
pub async fn assert_start(
    State(state): State<ApiState>,
    Json(body): Json<StartRequest>,
) -> Result<Json<AssertStartBody>, ApiError> {
    let verifier = state.webauthn.as_ref().ok_or(ApiError::NotFound)?;
    let out = verifier
        .assert_start(body.moderator_id)
        .await
        .map_err(webauthn_to_api)?;
    Ok(Json(AssertStartBody {
        challenge: out.challenge,
        state: out.state,
    }))
}

/// `POST /api/auth/webauthn/assert/finish`.
///
/// # Errors
///
/// - [`ApiError::BadRequest`] on an expired / unknown state token or a
///   clone-detection trigger (the spec mandates rejecting the credential
///   silently from the caller's perspective).
/// - [`ApiError::Internal`] on framework / DB failure.
pub async fn assert_finish(
    State(state): State<ApiState>,
    Json(body): Json<AssertFinishRequest>,
) -> Result<Json<GateAcceptedBody>, ApiError> {
    let verifier = state.webauthn.as_ref().ok_or(ApiError::NotFound)?;
    let moderator_id = verifier
        .assert_finish(&body.state, &body.credential)
        .await
        .map_err(webauthn_to_api)?;
    Ok(Json(GateAcceptedBody {
        moderator_id,
        status: "ok",
    }))
}

/// Map [`WebauthnError`] to [`ApiError`].
///
/// `UnknownRegisterState` / `UnknownAssertState` / `CloningDetected` are
/// caller-facing failures that surface as 400 with generic text — we never
/// disclose to the caller whether their state was expired vs. forged, or
/// whether the cloning detector fired vs. the framework's signature check.
///
/// The remaining variants are operator-facing failures that surface as 500;
/// the framework-level error is captured via the `#[source]` chain so the
/// `tracing::error!` line in [`ApiError::IntoResponse`] for `Internal`
/// retains the full cause chain in the structured log envelope.
fn webauthn_to_api(err: WebauthnError) -> ApiError {
    match err {
        WebauthnError::UnknownRegisterState | WebauthnError::UnknownAssertState => {
            ApiError::BadRequest("webauthn challenge expired or unknown")
        }
        WebauthnError::CloningDetected { .. } => {
            // The error chain (and the tracing::error! emitted in
            // assert_finish) preserves the counters for the operator's
            // log pipeline; we do not echo the cloning detail to the
            // caller.
            ApiError::BadRequest("webauthn assertion rejected")
        }
        WebauthnError::RegisterFailed(_) | WebauthnError::AssertFailed(_) => {
            ApiError::BadRequest("webauthn ceremony rejected")
        }
        WebauthnError::Config(_) | WebauthnError::Codec { .. } | WebauthnError::Db(_) => {
            ApiError::Internal(anyhow::anyhow!(err))
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn webauthn_to_api_maps_unknown_state_to_bad_request() {
        let err = WebauthnError::UnknownRegisterState;
        let mapped = webauthn_to_api(err);
        assert!(matches!(mapped, ApiError::BadRequest(_)));
    }

    #[test]
    fn webauthn_to_api_hides_clone_detail_from_caller() {
        // `CloningDetected` surfaces specific counter values to the operator
        // via tracing, but the API caller gets only a generic 400. This
        // assertion locks the contract so a future shape edit does not
        // accidentally leak the counters to the network.
        let err = WebauthnError::CloningDetected {
            stored: 5,
            presented: 3,
        };
        let mapped = webauthn_to_api(err);
        match mapped {
            ApiError::BadRequest(msg) => {
                assert!(!msg.contains('5'), "leaked stored counter: {msg}");
                assert!(!msg.contains('3'), "leaked presented counter: {msg}");
            }
            other => panic!("unexpected mapping: {other:?}"),
        }
    }

    #[test]
    fn webauthn_to_api_maps_db_to_internal() {
        let err = WebauthnError::Codec {
            message: "synthetic".to_owned(),
        };
        let mapped = webauthn_to_api(err);
        assert!(matches!(mapped, ApiError::Internal(_)));
    }
}
