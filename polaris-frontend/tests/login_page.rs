//! Wasm-bindgen browser test: the login page renders a real HTML form
//! (issue #82).
//!
//! The contract is "the page is a plain `<form method="POST" action="…">`
//! the browser submits natively" — NOT a `fetch()` / XHR call. The
//! backend's `303 See Other` only propagates to `window.location` for a
//! browser-initiated navigation; a `fetch()` call would follow the
//! redirect inside the JS engine and leave the operator stranded on
//! the Polaris tab while the AS consent UI loaded invisibly into the
//! response body.
//!
//! # Strategy
//!
//! Mount the [`LoginPage`] component into a fresh DOM node, then query
//! the resulting tree for the `<form>` element and assert the three
//! attributes that guarantee a real-form submit:
//!
//! 1. `method="POST"` — the backend handler is `POST /auth/atproto/login`.
//! 2. `action="/auth/atproto/login"` — same-origin, no scheme/host
//!    leakage so the form survives a re-hosting of the dashboard.
//! 3. A single `<input name="handle">` — the backend's `LoginRequest`
//!    deserialises one field, and the form must shape its body to
//!    match.
//!
//! # Runtime gating
//!
//! `#[wasm_bindgen_test]` expands to a no-op (`#[allow(dead_code)]`) on
//! non-wasm targets and a registered browser test on
//! `wasm32-unknown-unknown`. CI runs the suite as a dedicated
//! browser-driver job (`wasm-pack test --headless`); the done-when
//! criterion for the sandbox is **compile-time correctness** verified
//! via `cargo build --target wasm32-unknown-unknown --tests
//! -p polaris-frontend`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use polaris_frontend::pages::login::LoginPage;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// The mounted login page is a real `<form method="POST"
/// action="/auth/atproto/login">` — not a fetch() handler.
#[wasm_bindgen_test]
fn login_page_renders_real_form() {
    use leptos::mount::mount_to;
    use wasm_bindgen::JsCast as _;
    use web_sys::{HtmlFormElement, HtmlInputElement};

    let document = web_sys::window()
        .expect("window must exist in the browser test runtime")
        .document()
        .expect("document must exist in the browser test runtime");
    let host = document
        .create_element("div")
        .expect("create_element must succeed");
    document
        .body()
        .expect("document.body must exist")
        .append_child(&host)
        .expect("append_child must succeed");

    let host_el: web_sys::HtmlElement = host
        .clone()
        .dyn_into()
        .expect("the host element is an HtmlElement");
    let _mounted = mount_to(host_el, LoginPage);

    let form: HtmlFormElement = host
        .query_selector("form")
        .expect("query_selector must not throw")
        .expect("LoginPage must render a <form> element")
        .dyn_into()
        .expect("the selected element is a <form>");

    assert_eq!(
        form.method().to_ascii_lowercase(),
        "post",
        "form method must be POST so the backend's 303 propagates to window.location",
    );
    assert!(
        form.action().ends_with("/auth/atproto/login"),
        "form action must target /auth/atproto/login; got `{}`",
        form.action(),
    );

    let input: HtmlInputElement = host
        .query_selector("input[name=\"handle\"]")
        .expect("query_selector must not throw")
        .expect("LoginPage must render an <input name=\"handle\">")
        .dyn_into()
        .expect("the selected element is an <input>");
    assert_eq!(
        input.name(),
        "handle",
        "the input must be named `handle` to match the backend's LoginRequest",
    );
    assert!(
        input.required(),
        "the handle input must be `required` so the browser blocks empty submits",
    );

    // Tear down the host node so subsequent tests start clean.
    if let Some(parent) = host.parent_node() {
        let _ = parent.remove_child(&host);
    }
}
