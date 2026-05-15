//! Browser login page (#82).
//!
//! Single-field form (Bluesky handle) that posts to
//! `/auth/atproto/login`. The backend (issue #67) returns a 303 to the
//! ATProto Authorization Server; the browser follows the redirect, the
//! operator completes consent in their account UI, and `bsky.social`
//! redirects back to `/auth/atproto/callback` which mints the Polaris
//! session cookie and 303s back to `/`.
//!
//! # Why a real `<form>` and not a `fetch()` call
//!
//! This page is intentionally a pure HTML form submission — NOT a
//! `fetch()` / `XHR` call — because the backend's `303 See Other` must
//! propagate to the browser's location bar, which only happens for
//! browser-initiated navigations. A `fetch()` call would follow the
//! redirect inside the JS engine and resolve at the AS's authorize
//! page, leaving the user staring at the Polaris tab while the
//! AS-controlled consent UI loads invisibly into the response body.
//!
//! Form-encoded bodies (rather than JSON) are the natural shape for an
//! HTML form submit; the backend's [`login`] handler accepts
//! `application/x-www-form-urlencoded` for exactly this reason (see
//! `polaris-backend/src/api/auth_atproto.rs`).
//!
//! # 401 redirect contract
//!
//! When any authenticated Polaris API call returns `401 Unauthorized`
//! (the session cookie is absent or expired), the frontend must
//! redirect the operator to `/login` so they can re-authenticate. The
//! cookie itself is `HttpOnly` (design.md §6), so the frontend cannot
//! observe its presence directly — instead each page that issues a
//! gated fetch checks the resulting [`ApiError`] for an
//! [`ApiError::Http`] with status `401` and calls
//! [`redirect_to_login`] to bounce the operator. See
//! [`is_unauthorized`] for the predicate.
//!
//! [`login`]: ../../../../polaris_backend/api/auth_atproto/fn.login.html
//! [`ApiError`]: crate::api_client::ApiError
//! [`ApiError::Http`]: crate::api_client::ApiError::Http

use leptos::prelude::*;

use crate::api_client::ApiError;

/// Path the login page is mounted at.
///
/// Centralising the constant keeps the router declaration in
/// [`crate::app`] and the 401-redirect helper in [`redirect_to_login`]
/// in sync — a future move (e.g. `/auth/login`) lands at one site.
pub const LOGIN_PATH: &str = "/login";

/// HTTP status code that triggers a redirect to [`LOGIN_PATH`].
pub const UNAUTHORIZED_STATUS: u16 = 401;

/// Pure predicate: does this [`ApiError`] represent a 401 Unauthorized
/// response from the Polaris backend?
///
/// Used by page-level fetch sites to decide whether to bounce the
/// operator to [`LOGIN_PATH`]. Non-401 errors render inline so the
/// operator sees the actual failure (network down, server error, etc.)
/// rather than a silent redirect that masks the diagnostic.
#[must_use]
pub fn is_unauthorized(err: &ApiError) -> bool {
    matches!(
        err,
        ApiError::Http {
            status: UNAUTHORIZED_STATUS,
            ..
        }
    )
}

/// Redirect the browser to [`LOGIN_PATH`] via a hard navigation.
///
/// We deliberately use a full-page navigation (`window.location.assign`)
/// rather than the Leptos client-side router so the session-cookie-less
/// state is established before the login form renders — a client-side
/// route swap would leave the dashboard's signals alive in memory and
/// the next fetch would re-trip the 401 path immediately.
///
/// No-op on native (test, IDE) builds: the navigation side effect only
/// makes sense in a browser context and the call site is
/// target-agnostic by design.
#[cfg(target_arch = "wasm32")]
pub fn redirect_to_login() {
    if let Some(window) = web_sys::window() {
        let _ = window.location().assign(LOGIN_PATH);
    }
}

/// Native stub — page redirects are a browser concern. See the wasm
/// variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
pub fn redirect_to_login() {
    // Intentionally empty: the navigation side effect only makes sense
    // in a browser context. Native callers are exercising the predicate
    // and DTO surfaces; they do not need a real redirect.
}

/// Browser login page: single-field form posting the operator's
/// ATProto handle to `/auth/atproto/login`.
///
/// Renders as a real HTML form (`method="POST"`, plain `action="…"`,
/// no `onsubmit` handler) so the backend's `303 See Other` propagates
/// to `window.location` and the browser drives the AS authorize-page
/// hop without any JS in the loop. See the module doc for the full
/// rationale.
// The `#[component]` proc macro replaces the function body and drops
// outer attributes, so `clippy::must_use_candidate` cannot be honored
// at this site. The component's return value is always consumed by
// `view!`, which makes the "dropped return value" hazard the lint
// guards against impossible — mirror the narrow allow used at every
// other `#[component]` site in this crate.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn LoginPage() -> impl IntoView {
    view! {
        <main class="login-page" id="login-page-root">
            <h1>"Polaris"</h1>
            <p class="login-page__tagline">
                "Sign in with your Bluesky account to access the moderation dashboard."
            </p>
            <form
                class="login-page__form"
                method="POST"
                action="/auth/atproto/login"
            >
                <label for="handle">"Bluesky handle"</label>
                <input
                    id="handle"
                    name="handle"
                    type="text"
                    placeholder="example.bsky.social"
                    required
                    autocomplete="username"
                    autofocus
                />
                <button type="submit">"Continue"</button>
            </form>
            <p class="login-page__hint">
                "You'll be redirected to Bluesky to confirm, then back here."
            </p>
        </main>
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
    fn login_path_is_slash_login() {
        // Regression: the 401-redirect helper, the route declaration in
        // `crate::app`, and a future setup-wizard hop all key off this
        // constant. A drift would silently break the bounce contract.
        assert_eq!(LOGIN_PATH, "/login");
    }

    #[test]
    fn is_unauthorized_matches_401_http() {
        let err = ApiError::Http {
            status: 401,
            message: "unauthenticated".to_owned(),
        };
        assert!(is_unauthorized(&err));
    }

    #[test]
    fn is_unauthorized_rejects_other_statuses() {
        for status in [200_u16, 400, 403, 404, 500, 502] {
            let err = ApiError::Http {
                status,
                message: String::new(),
            };
            assert!(
                !is_unauthorized(&err),
                "is_unauthorized must reject status {status}",
            );
        }
    }

    #[test]
    fn is_unauthorized_rejects_transport_errors() {
        let err = ApiError::Transport("net down".to_owned());
        assert!(!is_unauthorized(&err));
    }

    /// Smoke test: the `#[component]` constructor type-checks.
    ///
    /// Mounting requires a Leptos runtime, which lives in the
    /// wasm-bindgen-test harness — that lives in
    /// `tests/login_page.rs` for the form-attribute contract.
    #[test]
    fn login_page_builds() {
        // Type-check only; mounting needs a reactive runtime.
        let _ = LoginPage;
    }
}
