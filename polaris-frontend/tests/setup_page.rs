//! Wasm-bindgen browser test: the setup wizard renders the right
//! top-level structure for the first step (issue #84).
//!
//! Mounts the [`SetupWizard`] component into a fresh DOM node and
//! asserts:
//!
//! 1. The wizard's root `<main id="setup-wizard-root">` exists.
//! 2. An `<ol>` step list is rendered (the three-step container).
//! 3. The first step's "Generate signing key" button is present and
//!    enabled — that is the operator's first interaction.
//!
//! # Runtime gating
//!
//! `#[wasm_bindgen_test]` expands to a no-op (`#[allow(dead_code)]`)
//! on non-wasm targets and a registered browser test on
//! `wasm32-unknown-unknown`. CI runs the suite as a dedicated
//! browser-driver job (`wasm-pack test --headless`); the done-when
//! criterion for this sandbox is **compile-time correctness**
//! verified via `cargo build --target wasm32-unknown-unknown --tests
//! -p polaris-frontend`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use polaris_frontend::pages::setup::SetupWizard;
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

/// The mounted setup wizard renders its root container, the three-step
/// `<ol>` skeleton, and the step-1 "Generate signing key" button.
#[wasm_bindgen_test]
fn setup_wizard_renders_step_one_structure() {
    use leptos::mount::mount_to;
    use wasm_bindgen::JsCast as _;
    use web_sys::{HtmlButtonElement, HtmlOListElement};

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
    let _mounted = mount_to(host_el, SetupWizard);

    // The wizard's root container is the single anchor every wasm
    // integration uses to scope DOM queries — a regression here would
    // break the page-mount contract for every follow-up test.
    let root = host
        .query_selector("#setup-wizard-root")
        .expect("query_selector must not throw")
        .expect("SetupWizard must render a `#setup-wizard-root` element");
    let _: web_sys::HtmlElement = root.dyn_into().expect("the root element is an HtmlElement");

    let ol: HtmlOListElement = host
        .query_selector("ol.setup-wizard__steps")
        .expect("query_selector must not throw")
        .expect("SetupWizard must render an <ol class=\"setup-wizard__steps\">")
        .dyn_into()
        .expect("the selected element is an <ol>");
    let steps = ol.children().length();
    assert_eq!(
        steps, 3,
        "the wizard must render exactly three <li> steps; got {steps}",
    );

    // Step 1's primary button drives the operator's first interaction
    // — the click hands off to `setup_generate_key`. A regression that
    // hides / disables it on first mount would silently break the
    // first-run flow.
    let button: HtmlButtonElement = host
        .query_selector("button.setup-wizard__primary-button")
        .expect("query_selector must not throw")
        .expect("SetupWizard must render a primary button on step 1")
        .dyn_into()
        .expect("the selected element is a <button>");
    assert!(
        !button.disabled(),
        "the step-1 primary button must be enabled on initial mount",
    );

    // Tear down the host node so subsequent tests start clean.
    if let Some(parent) = host.parent_node() {
        let _ = parent.remove_child(&host);
    }
}
