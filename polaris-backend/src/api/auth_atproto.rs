//! HTTP handlers for the ATProto OAuth moderator login flow (issue #67).
//!
//! Two endpoints, mirroring the OIDC route shape promised in
//! [`crate::middleware::auth::is_exempt`]:
//!
//! - `POST /auth/atproto/login` — accepts a JSON body `{ "handle": "..." }`,
//!   drives [`AtprotoOauthAuthVerifier::start_login`] with
//!   [`LoginHint::AtprotoHandle`], and returns a `303 See Other` with a
//!   `Location` header pointing at the authorization-server's authorize
//!   URL.
//! - `GET /auth/atproto/callback?state=...&code=...` — drives
//!   [`AtprotoOauthAuthVerifier::complete_login`], mints a Polaris session
//!   via [`SessionStore::create`] (the verifier itself does this inside
//!   `complete_login`), and returns a `303 See Other` with `Location: /`
//!   plus a `Set-Cookie: polaris_session=…` carrying the freshly-minted
//!   opaque session token.
//!
//! Both endpoints are middleware-exempt — they operate in the
//! pre-session-cookie window and would otherwise short-circuit on the
//! missing cookie. The exemption is encoded in
//! [`crate::middleware::auth::is_exempt`].
//!
//! # Why a typed handler module
//!
//! The pre-flight plan mirrors `api/auth_oidc.rs` (not yet authored); the
//! atproto half lands here as the first of the two. Mirroring the OIDC
//! shape ahead of time keeps the future OIDC handler a direct rename
//! exercise: same `LoginRequest` body, same `CallbackQuery`, same
//! cookie-emission helper.
//!
//! # Forbidden patterns observed
//!
//! - No `unwrap()` / `expect()` on the production path.
//! - No raw JSON construction — request body deserialises via `serde`,
//!   response cookies are built through [`build_session_cookie`] which
//!   composes constant attribute strings.
//! - The session cookie is minted via [`SessionStore::create`] (called
//!   inside [`AtprotoOauthAuthVerifier::complete_login`]); this handler
//!   never touches `sessions.refresh_token_enc` directly.
//! - `Set-Cookie` carries `HttpOnly; Secure; SameSite=Lax; Path=/` plus
//!   a `Max-Age` derived from the session row's `expires_at` so a
//!   middle-box that ignores cookie expiry still respects the session
//!   window.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::session::{DEFAULT_SESSION_TTL, SessionToken};
use crate::auth::{AnyModeratorAuth, AuthError, LoginHint, LoginResult, ModeratorAuth};
use crate::middleware::auth::SESSION_COOKIE;

/// Request body for `POST /auth/atproto/login`.
///
/// `handle` is the moderator's ATProto handle (e.g. `alice.example.com`)
/// — or, for the integration-test path, a PDS URL that `proto-blue`'s
/// `resolve_input` will treat as the discovery target. Validation lives
/// in the verifier; we surface a 400 on an empty string here so the
/// handler does not call into `start_login` with garbage.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// ATProto handle the moderator is logging in with.
    pub handle: String,
}

/// Query parameters for `GET /auth/atproto/callback`.
///
/// The authorization server redirects the moderator's browser back to
/// the configured `redirect_uri` with these two parameters (plus an
/// `iss` parameter we deliberately ignore — proto-blue re-discovers the
/// AS from the persisted issuer string inside the state row).
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    /// State token echoed back by the authorization server. The verifier
    /// uses this to look up the row in `auth_atproto_login_states`.
    pub state: String,
    /// Authorization code issued by the AS.
    pub code: String,
}

/// `POST /auth/atproto/login`.
///
/// On success returns a `303 See Other` with a `Location` header
/// pointing at the authorization server's authorize URL. The browser
/// follows the redirect; the AS in turn redirects the moderator back to
/// `/auth/atproto/callback?state=…&code=…`.
///
/// # Errors
///
/// - [`ApiError::BadRequest`] when the request body's `handle` is empty
///   or the configured moderator-auth backend is not ATProto (so this
///   route should not have been called against this deployment).
/// - [`ApiError::Internal`] when the verifier hits a transport,
///   crypto, or DB failure mid-dance. The variant text is generic so an
///   attacker cannot distinguish "AS rejected the PAR" from "the
///   moderator's handle does not resolve" from network failures.
pub async fn login(
    State(state): State<ApiState>,
    Json(req): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    if req.handle.trim().is_empty() {
        return Err(ApiError::BadRequest("handle must not be empty"));
    }
    let verifier = state
        .moderator_auth
        .as_deref()
        .and_then(AnyModeratorAuth::as_atproto)
        .ok_or(ApiError::BadRequest(
            "atproto backend not enabled for this deployment",
        ))?;
    let redirect = verifier
        .start_login(LoginHint::AtprotoHandle(req.handle))
        .await
        .map_err(auth_error_to_api)?;
    let location = HeaderValue::from_str(&redirect.authorize_url).map_err(|err| {
        // proto-blue's `OAuthClient::authorize` URLs are always
        // RFC-3986-conformant; an invalid HeaderValue here would mean a
        // proto-blue contract violation. Surface as 500 so the operator
        // sees it in logs.
        ApiError::Internal(anyhow::anyhow!(
            "authorize URL is not a valid HTTP header value: {err}"
        ))
    })?;
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response())
}

/// `GET /auth/atproto/callback`.
///
/// On success returns a `303 See Other` with `Location: /` plus a
/// `Set-Cookie: polaris_session=…` carrying the freshly-minted opaque
/// session token. The browser follows the redirect to the moderator
/// dashboard; the auth middleware authenticates every follow-up
/// request from the cookie.
///
/// # Errors
///
/// - [`ApiError::BadRequest`] when the `state` token is unknown, expired,
///   or the configured moderator-auth backend is not ATProto. The
///   variant text is generic so a probing attacker cannot distinguish
///   `StateMismatch` from a backend-routing miss.
/// - [`ApiError::Internal`] for every other verifier failure (OAuth
///   exchange rejected, crypto failure, DB failure, malformed AS
///   response).
pub async fn callback(
    State(state): State<ApiState>,
    Query(q): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    let verifier = state
        .moderator_auth
        .as_deref()
        .and_then(AnyModeratorAuth::as_atproto)
        .ok_or(ApiError::BadRequest(
            "atproto backend not enabled for this deployment",
        ))?;
    let login_result = verifier
        .complete_login(&q.state, &q.code)
        .await
        .map_err(auth_error_to_api)?;
    response_with_session_cookie(&login_result, "/")
}

/// Build the `303 See Other` response that carries the freshly-minted
/// session cookie and the redirect location.
///
/// Extracted so a future OIDC handler can reuse the same shape without
/// re-deriving the cookie-attribute glue.
fn response_with_session_cookie(
    login_result: &LoginResult,
    location_path: &'static str,
) -> Result<Response, ApiError> {
    let cookie = build_session_cookie(&login_result.session_token, login_result.expires_at);
    let cookie_header = HeaderValue::from_str(&cookie).map_err(|err| {
        ApiError::Internal(anyhow::anyhow!(
            "session cookie value is not a valid HTTP header value: {err}"
        ))
    })?;
    let location_header = HeaderValue::from_static(location_path);
    Ok((
        StatusCode::SEE_OTHER,
        [
            (header::LOCATION, location_header),
            (header::SET_COOKIE, cookie_header),
        ],
    )
        .into_response())
}

/// Assemble the `Set-Cookie` header value for the Polaris session.
///
/// The cookie carries the opaque [`SessionToken`] (43 base64url chars,
/// no padding) with the attributes mandated by design.md §6:
/// `HttpOnly` (no JS access), `Secure` (HTTPS-only), `SameSite=Lax`
/// (the maximum strictness compatible with the OIDC / ATProto redirect
/// dance), and `Path=/` (every endpoint sees the cookie). `Max-Age`
/// is derived from `expires_at` so a middle-box ignoring cookie
/// expiration still respects the session window; a non-positive
/// remaining lifetime falls back to `0` (a delete-the-cookie hint)
/// rather than emitting a negative value the user-agent may reject.
fn build_session_cookie(token: &SessionToken, expires_at: DateTime<Utc>) -> String {
    let max_age = expires_at
        .signed_duration_since(Utc::now())
        .num_seconds()
        .max(0);
    format!(
        "{name}={value}; {attrs}; Max-Age={max_age}",
        name = SESSION_COOKIE,
        value = token.as_str(),
        attrs = SessionToken::cookie_attrs(),
    )
}

/// Map a verifier-level [`AuthError`] to the HTTP-level [`ApiError`].
///
/// `StateMismatch` is the one variant a caller-facing 400 fits: it is
/// the predictable outcome of a forged, replayed, or expired callback.
/// Every other variant — missing claims, OAuth-server rejection, crypto
/// failure, DB failure, handle resolution — is operator-facing 500. The
/// generic message keeps the error variant out of the response body so
/// an attacker cannot distinguish "wrong state" from "expired state"
/// from "wrong key" from response shape alone. The full cause chain is
/// preserved through `ApiError::Internal`'s `#[source]` so the
/// structured-log envelope still carries the diagnostic.
fn auth_error_to_api(err: AuthError) -> ApiError {
    match err {
        AuthError::StateMismatch => ApiError::BadRequest("invalid or expired login state"),
        AuthError::Config { .. }
        | AuthError::OidcDiscoveryFailed { .. }
        | AuthError::OidcExchangeFailed { .. }
        | AuthError::OidcUserinfoFailed { .. }
        | AuthError::IdTokenInvalid { .. }
        | AuthError::MissingClaims
        | AuthError::SessionNotFound
        | AuthError::SessionExpired
        | AuthError::Storage { .. }
        | AuthError::Crypto { .. }
        | AuthError::UnknownRole { .. }
        | AuthError::OauthPar { .. }
        | AuthError::OauthExchange { .. }
        | AuthError::DpopBindingFailed { .. }
        | AuthError::HandleResolutionFailed { .. }
        | AuthError::OauthRefreshFailed { .. } => ApiError::Internal(anyhow::anyhow!(err)),
    }
}

// Silence the unused-import diagnostic on the `DEFAULT_SESSION_TTL`
// constant: the cookie's `Max-Age` is derived from the per-row
// `expires_at` rather than the static default, but the TTL constant is
// part of the module's public surface and a future change that wants to
// emit `Max-Age=<DEFAULT_SESSION_TTL>` as a fallback would re-introduce
// the import. Keeping the explicit `use` documents the relationship.
const _: std::time::Duration = DEFAULT_SESSION_TTL;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn session_cookie_contains_required_attributes() {
        let token = SessionToken::generate();
        let expires_at = Utc::now() + chrono::Duration::seconds(3600);
        let cookie = build_session_cookie(&token, expires_at);
        assert!(cookie.starts_with("polaris_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("Max-Age="));
        // The token must appear verbatim (it's already base64url-safe,
        // so no escaping is needed).
        assert!(cookie.contains(token.as_str()));
    }

    #[test]
    fn session_cookie_max_age_floors_to_zero_for_past_expiry() {
        let token = SessionToken::generate();
        let expires_at = Utc::now() - chrono::Duration::seconds(5);
        let cookie = build_session_cookie(&token, expires_at);
        assert!(
            cookie.contains("Max-Age=0"),
            "expected non-negative Max-Age fallback, got: {cookie}",
        );
    }

    #[test]
    fn state_mismatch_maps_to_bad_request() {
        let mapped = auth_error_to_api(AuthError::StateMismatch);
        assert!(matches!(mapped, ApiError::BadRequest(_)));
    }

    #[test]
    fn other_auth_errors_map_to_internal() {
        // A representative non-StateMismatch variant.
        let mapped = auth_error_to_api(AuthError::MissingClaims);
        assert!(matches!(mapped, ApiError::Internal(_)));
    }
}
