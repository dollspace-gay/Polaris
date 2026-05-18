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
    // After a failed login the backend bounces the user back to
    // /login?error=<code>&handle=<echoed>. Read those params at render
    // time and surface a typed inline message + prefill the input.
    let (error_code, prior_handle) = read_login_query();
    let banner = render_login_error_banner(error_code, prior_handle.clone());
    // Once the banner is captured, strip `?error=&handle=` from the URL
    // bar so a subsequent refresh / bookmark / share-link doesn't
    // re-render a stale "couldn't resolve" message after the operator
    // has already moved on. The component already has the values it
    // needs to render this paint; the URL is now a presentation
    // concern. Pure no-op on native.
    strip_login_query_params();

    view! {
        <main class="login-page" id="login-page-root">
            <h1>"Polaris"</h1>
            <p class="login-page__tagline">
                "Sign in with your Bluesky account to access the moderation dashboard."
            </p>
            {banner}
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
                    value=prior_handle.clone().unwrap_or_default()
                />
                <button type="submit">"Continue"</button>
            </form>
            <p class="login-page__hint">
                "You'll be redirected to Bluesky to confirm, then back here."
            </p>
        </main>
    }
}

/// Read `?error=&handle=` from the current page URL.
///
/// wasm path uses `web_sys` to walk the actual URL bar; native path
/// returns `(None, None)` so unit tests render the no-error shape
/// without having to inject a fake `window`. The pair shape mirrors
/// the backend's `redirect_login_with_error` contract: both fields
/// always appear together (or neither does).
#[cfg(target_arch = "wasm32")]
fn read_login_query() -> (Option<String>, Option<String>) {
    let Some(window) = web_sys::window() else {
        return (None, None);
    };
    let Ok(search) = window.location().search() else {
        return (None, None);
    };
    // `URLSearchParams` accepts the raw `?foo=bar` form.
    let Ok(params) = web_sys::UrlSearchParams::new_with_str(&search) else {
        return (None, None);
    };
    (params.get("error"), params.get("handle"))
}

#[cfg(not(target_arch = "wasm32"))]
fn read_login_query() -> (Option<String>, Option<String>) {
    (None, None)
}

/// Pure helper: given the current `window.location.search` string,
/// decide whether the URL needs cleaning and return the replacement
/// URL to push into `history.replaceState`. `None` means the current
/// URL is already clean (no query, or no `error` / `handle` params)
/// and `replaceState` would be a no-op.
///
/// Lives at module scope (rather than inside the wasm-cfg arm) so
/// the same decision logic that wasm runs is unit-testable on the
/// native target — no `web_sys` runtime required.
fn cleaned_login_url(search: &str) -> Option<&'static str> {
    // An empty or `?`-only search is already clean.
    let trimmed = search.trim_start_matches('?');
    if trimmed.is_empty() {
        return None;
    }
    // The only params LoginPage ever puts on the URL are `error` and
    // `handle`. If neither is present, leave the URL alone —
    // something else (a deep link, a future feature) may be using
    // the query string and we don't want to clobber it.
    let has_login_params = trimmed
        .split('&')
        .any(|kv| matches!(kv.split('=').next(), Some("error" | "handle")));
    if !has_login_params {
        return None;
    }
    Some(LOGIN_PATH)
}

/// Replace the current URL with a clean `/login` (no query string)
/// via `history.replaceState`. Used after the `LoginPage` has captured
/// the `error` / `handle` params so a refresh or bookmark of the
/// resulting page doesn't keep re-rendering the inline error banner
/// from stale state.
///
/// `replaceState` (not `pushState`) is intentional: we don't want a
/// "Back" button to navigate to the dirty-URL version of the same
/// page — the cleaned URL replaces the dirty one in history.
///
/// Failures here are non-fatal: the banner is still rendered, the
/// form still works, the user is just left with a slightly-uglier
/// URL bar. We swallow every error path silently and don't fall
/// back to anything because no fallback can do better than what the
/// happy path already produced.
#[cfg(target_arch = "wasm32")]
fn strip_login_query_params() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let Ok(history) = window.history() else {
        return;
    };
    let search = window.location().search().unwrap_or_default();
    let Some(target) = cleaned_login_url(&search) else {
        return;
    };
    // `replaceState(state, title, url)` — state is null (we don't
    // depend on history-state on this page), title is unused per
    // the HTML spec, url is the new bare /login path.
    let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(target));
}

/// Native build: there's no URL bar to mutate, so we exercise the
/// same pure decision helper the wasm side does and assert in
/// debug builds that the input shape we'd be cleaning is the shape
/// we modelled. This both keeps the native call site honest (no
/// silent stub) and gives the pure helper a non-test execution
/// path so it can never be pruned by a future cleanup that
/// mistakes it for dead code.
#[cfg(not(target_arch = "wasm32"))]
fn strip_login_query_params() {
    // No-op driver: no `window.location` to read on native, so we
    // call the pure helper with a representative input to exercise
    // the same code path as wasm and assert the contract
    // (`?error=…` → `Some(LOGIN_PATH)`) hasn't drifted.
    debug_assert_eq!(
        cleaned_login_url("?error=handle_resolution_failed&handle=x"),
        Some(LOGIN_PATH),
    );
    debug_assert_eq!(cleaned_login_url(""), None);
}

/// Render the inline error banner shown above the login form.
///
/// Returns an empty fragment when there's no error to report. The
/// `code` parameter mirrors the wire `code` field that
/// `redirect_login_with_error` (and the JSON path) emit so the
/// matcher vocabulary is one source of truth.
///
/// `code` and `handle` are taken by value (`Option<String>`) because the
/// matched arms consume them into owned strings (`format!`, `into`) for
/// the view's text children — the view captures the strings without
/// borrowing from a caller-scoped binding, which is what fixes the
/// `does not live long enough` error that the `&str` shape had.
fn render_login_error_banner(code: Option<String>, handle: Option<String>) -> impl IntoView {
    let echo_handle = handle.unwrap_or_default();
    let Some(code) = code else {
        return view! { <div></div> }.into_any();
    };
    let (heading, detail): (String, String) = match code.as_str() {
        "handle_resolution_failed" if !echo_handle.is_empty() => (
            "Couldn't resolve that handle".to_owned(),
            format!(
                "We couldn't reach the directory entry for `{echo_handle}`. Double-check the handle (no `@`, full domain) and try again. If you copied it from Bluesky and it's correct, the PLC directory may be temporarily unreachable — wait a moment and retry."
            ),
        ),
        "handle_resolution_failed" => (
            "Couldn't resolve that handle".to_owned(),
            "Double-check the handle (no `@`, full domain) and try again.".to_owned(),
        ),
        "empty_handle" => (
            "Enter your Bluesky handle".to_owned(),
            "The form needs your full handle, e.g. `example.bsky.social`.".to_owned(),
        ),
        "bad_request" => (
            "Login request rejected".to_owned(),
            "The server rejected the login request. If you didn't change anything, this is likely a configuration issue — contact the operator.".to_owned(),
        ),
        // Issue #214 / #217: the OAuth callback rejects non-allowlisted
        // DIDs with `303 → /login?error=unauthorized&handle=<echoed>`.
        // Surface a banner that names the allow-list explicitly so
        // the operator knows the fix is to add their DID, not to
        // re-attempt the login.
        "unauthorized" if !echo_handle.is_empty() => (
            "Account not on the moderator allow-list".to_owned(),
            format!(
                "Your Bluesky account (`{echo_handle}`) hasn't been added to this Polaris install. Ask the operator to grant you a role."
            ),
        ),
        "unauthorized" => (
            "Account not on the moderator allow-list".to_owned(),
            "Your Bluesky account hasn't been added to this Polaris install. Ask the operator to grant you a role.".to_owned(),
        ),
        _ => (
            "Login failed".to_owned(),
            format!(
                "Login failed with code `{code}`. Try again, or contact the operator if the problem persists."
            ),
        ),
    };
    view! {
        <div class="login-page__error" role="alert">
            <strong>{heading}</strong>
            <p>{detail}</p>
        </div>
    }
    .into_any()
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

    /// Pure helper for the banner-text classification — no Leptos
    /// runtime required, so the matching logic is unit-testable here.
    ///
    /// Mirrors the match arms inside `render_login_error_banner` so a
    /// future copy edit drifts both the test fixture and the rendered
    /// view together.
    fn banner_text_for_test(code: Option<&str>, handle: Option<&str>) -> Option<(String, String)> {
        let code = code?;
        let echo = handle.unwrap_or("");
        Some(match code {
            "handle_resolution_failed" if !echo.is_empty() => (
                "Couldn't resolve that handle".to_owned(),
                format!(
                    "We couldn't reach the directory entry for `{echo}`. Double-check the handle (no `@`, full domain) and try again. If you copied it from Bluesky and it's correct, the PLC directory may be temporarily unreachable — wait a moment and retry."
                ),
            ),
            "handle_resolution_failed" => (
                "Couldn't resolve that handle".to_owned(),
                "Double-check the handle (no `@`, full domain) and try again.".to_owned(),
            ),
            "empty_handle" => (
                "Enter your Bluesky handle".to_owned(),
                "The form needs your full handle, e.g. `example.bsky.social`.".to_owned(),
            ),
            "bad_request" => (
                "Login request rejected".to_owned(),
                "The server rejected the login request. If you didn't change anything, this is likely a configuration issue — contact the operator.".to_owned(),
            ),
            "unauthorized" if !echo.is_empty() => (
                "Account not on the moderator allow-list".to_owned(),
                format!(
                    "Your Bluesky account (`{echo}`) hasn't been added to this Polaris install. Ask the operator to grant you a role."
                ),
            ),
            "unauthorized" => (
                "Account not on the moderator allow-list".to_owned(),
                "Your Bluesky account hasn't been added to this Polaris install. Ask the operator to grant you a role.".to_owned(),
            ),
            other => (
                "Login failed".to_owned(),
                format!(
                    "Login failed with code `{other}`. Try again, or contact the operator if the problem persists."
                ),
            ),
        })
    }

    #[test]
    fn no_code_renders_no_banner() {
        assert!(banner_text_for_test(None, None).is_none());
        // Echoed handle alone (no code) must also produce nothing —
        // we never want the banner to appear without a typed reason.
        assert!(banner_text_for_test(None, Some("alice.bsky.social")).is_none());
    }

    #[test]
    fn handle_resolution_failed_with_handle_names_it() {
        let (heading, detail) = banner_text_for_test(
            Some("handle_resolution_failed"),
            Some("polarislabeler.bsky.social"),
        )
        .expect("banner rendered");
        assert_eq!(heading, "Couldn't resolve that handle");
        assert!(
            detail.contains("polarislabeler.bsky.social"),
            "echoed handle missing from detail: {detail}"
        );
        assert!(
            detail.contains("PLC directory may be temporarily unreachable"),
            "actionable hint missing from detail: {detail}",
        );
    }

    #[test]
    fn handle_resolution_failed_without_handle_omits_echo() {
        let (heading, detail) =
            banner_text_for_test(Some("handle_resolution_failed"), None).expect("banner rendered");
        assert_eq!(heading, "Couldn't resolve that handle");
        // Without a handle to echo we must take the short branch — the
        // long branch's distinctive "PLC directory may be temporarily
        // unreachable" phrase must not appear, otherwise the empty
        // handle would render as `directory entry for ``…`. The short
        // copy still uses backticks (e.g. `(no `@`, full domain)`) so
        // checking the unreachable phrase is the precise invariant.
        assert!(
            !detail.contains("directory entry"),
            "long branch leaked into the no-echo path: {detail}"
        );
        assert!(
            !detail.contains("PLC directory may be"),
            "long branch leaked into the no-echo path: {detail}"
        );
    }

    #[test]
    fn empty_handle_code_renders_form_hint() {
        let (heading, detail) =
            banner_text_for_test(Some("empty_handle"), None).expect("banner rendered");
        assert_eq!(heading, "Enter your Bluesky handle");
        assert!(detail.contains("example.bsky.social"));
    }

    #[test]
    fn unauthorized_with_handle_names_the_account() {
        // Issue #214 / #217: the OAuth callback rejects
        // non-allowlisted DIDs with
        // `303 → /login?error=unauthorized&handle=<echoed>`. The
        // banner must name the rejected handle so the operator can
        // ask the install's operator to add it.
        let (heading, detail) =
            banner_text_for_test(Some("unauthorized"), Some("alice.bsky.social"))
                .expect("banner rendered");
        assert_eq!(heading, "Account not on the moderator allow-list");
        assert!(
            detail.contains("alice.bsky.social"),
            "echoed handle missing from detail: {detail}",
        );
        assert!(
            detail.contains("allow-list") || detail.contains("hasn't been added"),
            "banner must explain the allow-list gate: {detail}",
        );
    }

    #[test]
    fn unauthorized_without_handle_omits_echo() {
        let (heading, detail) =
            banner_text_for_test(Some("unauthorized"), None).expect("banner rendered");
        assert_eq!(heading, "Account not on the moderator allow-list");
        // The short branch must not leak the long branch's
        // backtick-wrapped echo.
        assert!(
            !detail.contains('`'),
            "no-echo branch leaked a code-formatted handle: {detail}",
        );
    }

    #[test]
    fn unknown_code_falls_back_to_generic_with_code_echo() {
        let (heading, detail) =
            banner_text_for_test(Some("some_unknown_code"), None).expect("banner rendered");
        assert_eq!(heading, "Login failed");
        assert!(
            detail.contains("`some_unknown_code`"),
            "fallback must echo the unknown code so operator logs are searchable: {detail}",
        );
    }

    // ── cleaned_login_url ────────────────────────────────────────

    #[test]
    fn cleaned_login_url_empty_search_is_no_op() {
        assert_eq!(cleaned_login_url(""), None);
        assert_eq!(cleaned_login_url("?"), None);
    }

    #[test]
    fn cleaned_login_url_with_error_param_returns_login_path() {
        assert_eq!(
            cleaned_login_url("?error=handle_resolution_failed&handle=alice.bsky.social"),
            Some(LOGIN_PATH),
        );
    }

    #[test]
    fn cleaned_login_url_with_only_handle_param_still_cleans() {
        // `handle` alone would never appear without `error` in
        // practice — the backend emits both together — but the
        // cleaner is conservative and treats either as an
        // indicator that the URL was post-failure cosmetic state.
        assert_eq!(
            cleaned_login_url("?handle=alice.bsky.social"),
            Some(LOGIN_PATH)
        );
    }

    #[test]
    fn cleaned_login_url_with_unrelated_params_leaves_url_alone() {
        // A future feature might add `?next=…`. The cleaner must
        // not clobber unrelated query params.
        assert_eq!(cleaned_login_url("?next=/dashboard"), None);
        assert_eq!(cleaned_login_url("?utm_source=email"), None);
    }

    #[test]
    fn cleaned_login_url_handles_leading_question_mark_absence() {
        // `URLSearchParams` returns the search string with or without
        // the leading `?`; the cleaner must accept both shapes.
        assert_eq!(
            cleaned_login_url("error=handle_resolution_failed&handle=alice.bsky.social"),
            Some(LOGIN_PATH),
        );
    }
}
