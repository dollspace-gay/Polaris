//! Cookie-driven auth middleware.
//!
//! Extracts the Polaris session cookie via `axum_extra`'s `CookieJar`,
//! looks the session up in [`crate::auth::session::SessionStore`], and
//! attaches the resulting [`ModeratorAuthCtx`] to the request as an
//! `Extension<ModeratorAuthCtx>`. Downstream handlers consume that extension
//! to learn who is calling them.
//!
//! On any failure (missing cookie, malformed cookie, expired session, DB
//! error) the middleware short-circuits with `401 Unauthorized` and the
//! constant JSON body `{"error":"unauthorized"}`. The error variant is
//! deliberately not surfaced: tests should never be able to learn whether
//! the cookie was missing vs. wrong vs. expired from response status alone.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use serde_json::json;

use crate::auth::ModeratorAuthCtx;
use crate::auth::session::SessionStore;

/// Cookie name used for the Polaris session.
///
/// Public so the OIDC callback handler can construct a `Set-Cookie` header
/// with the matching name. The frontend never reads or writes this cookie
/// directly; `HttpOnly` blocks JS access.
pub const SESSION_COOKIE: &str = "polaris_session";

/// Routes that bypass the auth middleware.
///
/// `/healthz` is a liveness probe; the OIDC routes are the entry point of
/// the login flow and would themselves require a session if they were not
/// exempt. The frontend's WASM bundle is served on a different prefix in
/// production (an external file-server / CDN); we do not list a frontend
/// route here because that boundary belongs to the operator's deployment.
fn is_exempt(path: &str) -> bool {
    matches!(
        path,
        "/healthz" | "/auth/oidc/login" | "/auth/oidc/callback"
    )
}

/// Axum middleware function. Wire via `axum::middleware::from_fn_with_state`
/// against a `SessionStore`.
///
/// # Errors
///
/// Returns `401 Unauthorized` with `{"error":"unauthorized"}` on any auth
/// failure. The error variant is deliberately collapsed at the response
/// layer; a `tracing::warn!` records the variant for operators.
pub async fn auth_middleware(
    State(store): State<SessionStore>,
    jar: CookieJar,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if is_exempt(path) {
        return next.run(request).await;
    }

    let Some(cookie) = jar.get(SESSION_COOKIE) else {
        tracing::warn!(path, "auth: missing session cookie");
        return unauthorized();
    };

    let ctx = match store.lookup(cookie.value()).await {
        Ok(ctx) => ctx,
        Err(err) => {
            // Log the variant for operators but do NOT echo it to the client.
            tracing::warn!(
                path,
                error = %err,
                "auth: session lookup failed"
            );
            return unauthorized();
        }
    };

    let mut request = request;
    request.extensions_mut().insert::<ModeratorAuthCtx>(ctx);
    next.run(request).await
}

/// Build the canonical 401 response. Single source of truth so no handler
/// accidentally leaks a different shape.
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "unauthorized" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exempt_paths_match_design() {
        assert!(is_exempt("/healthz"));
        assert!(is_exempt("/auth/oidc/login"));
        assert!(is_exempt("/auth/oidc/callback"));
        assert!(!is_exempt("/api/incidents"));
        assert!(!is_exempt("/healthz/extra"));
    }

    #[test]
    fn session_cookie_name_is_stable() {
        // If this ever changes, every existing session is invalidated. That
        // is by design — bumping the cookie name is the recovery path after
        // a cookie-key rotation. This test exists so the change is
        // deliberate, not accidental.
        assert_eq!(SESSION_COOKIE, "polaris_session");
    }
}
