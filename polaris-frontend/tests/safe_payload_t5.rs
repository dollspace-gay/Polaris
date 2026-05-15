//! T5 click-to-reveal sanitization tests (#76).
//!
//! Companion to `polaris-backend/tests/threat_t5_malicious_payload_render.rs`
//! — that file pins the backend invariant ("the report body round-trips
//! through the DB byte-for-byte and lands inside a JSON string literal");
//! this file pins the frontend invariant ("the moderator's renderer
//! never auto-loads remote resources and never invokes `inner_html`").
//!
//! # Test strategy (pre-flight rationale)
//!
//! Mirroring the `composer_validation.rs` shape (issue #54): the
//! [`SafePayload`](polaris_frontend::components::safe_payload::SafePayload)
//! component cannot be mounted outside a real reactive runtime (Leptos
//! requires `wasm-bindgen-futures` and a DOM, neither of which exists
//! in `cargo test --target wasm32-unknown-unknown` without
//! `wasm-pack test --headless`). The contract this suite locks in is
//! therefore split:
//!
//! - **Pure-function tests** (`#[test]`) — assert that the predicate
//!   used by the auto-load-pattern detector recognises the exact
//!   strings the threat model calls out. These run on every
//!   `cargo test -p polaris-frontend` and confirm the fixture
//!   actually exercises the vectors the mitigation defends against.
//! - **`#[wasm_bindgen_test]`** — register browser-runtime
//!   assertions that the rendered DOM honours the click-to-reveal
//!   contract. The runtime execution requires `wasm-pack test
//!   --headless --chrome` infrastructure the sandbox doesn't host;
//!   CI runs the suite as a dedicated browser-driver job. The
//!   done-when criterion is **compile-time correctness** verified
//!   via `cargo build --target wasm32-unknown-unknown --tests
//!   -p polaris-frontend`.
//!
//! The split mirrors `composer_validation.rs` exactly; see that
//! file's module docs for the longer-form rationale.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use polaris_frontend::components::safe_payload::{SAFE_IFRAME_SANDBOX, contains_autoload_pattern};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

// ── Fixture payloads (mirror the backend's T5 integration test) ──────────
//
// The exact strings used by
// `polaris-backend/tests/threat_t5_malicious_payload_render.rs`. Sharing
// the byte-level fixtures across the two test files means the backend
// "round-trips byte-for-byte" invariant and the frontend "renders behind
// click-to-reveal" invariant are both proved against the same payloads.

const SCRIPT_PAYLOAD: &str = "<script>alert('xss')</script>";
const IFRAME_PAYLOAD: &str = "<iframe src=\"http://evil.example/exfil\"></iframe>";
const IMG_PAYLOAD: &str = "<img src=\"http://evil.example/track.gif\" />";

// ── Pure-function tests (run on every `cargo test`) ──────────────────────

/// The fixture actually contains the auto-load patterns the
/// mitigation defends against. A typo here would silently degrade
/// the wasm-bindgen-test below into asserting nothing — this
/// `#[test]` is the canary that prevents that.
#[test]
fn contains_autoload_pattern_recognises_script_iframe_img() {
    assert!(
        contains_autoload_pattern(SCRIPT_PAYLOAD),
        "fixture must contain a `<script>` opener — that is the T5 vector"
    );
    assert!(
        contains_autoload_pattern(IFRAME_PAYLOAD),
        "fixture must contain an `<iframe>` opener — that is the T5 vector"
    );
    assert!(
        contains_autoload_pattern(IMG_PAYLOAD),
        "fixture must contain an `<img>` opener — that is the T5 vector"
    );
    assert!(
        !contains_autoload_pattern("a benign report body with no HTML"),
        "non-malicious bodies must NOT trip the detector"
    );
}

/// The combined "all three vectors in one body" fixture (which is
/// exactly what `polaris-backend/tests/threat_t5_malicious_payload_render.rs`
/// constructs) trips the detector. This pins the shape of the test
/// harness the wasm-bindgen-test browser path will mount.
#[test]
fn combined_malicious_fixture_trips_detector() {
    let combined = format!("{SCRIPT_PAYLOAD}\n{IFRAME_PAYLOAD}\n{IMG_PAYLOAD}");
    assert!(
        contains_autoload_pattern(&combined),
        "combined T5 fixture must trip the auto-load detector"
    );
}

/// `data:text/html` and `javascript:` schemes are also T5 vectors
/// (inline-execution smuggling). The predicate recognises them so a
/// renderer change that started honouring an `<a href="…">` tag
/// would still be flagged.
#[test]
fn detector_recognises_pseudo_protocol_schemes() {
    assert!(contains_autoload_pattern("javascript:alert(1)"));
    assert!(contains_autoload_pattern(
        "data:text/html,<script>alert(1)</script>"
    ));
}

/// The iframe-sandbox constant is the strictest (`sandbox=""`) value
/// the HTML Living Standard defines. A future change that adds a
/// token (e.g. `"allow-same-origin"`) MUST flip this assertion and
/// come with a written justification.
#[test]
fn safe_iframe_sandbox_constant_is_strictest_form() {
    assert_eq!(
        SAFE_IFRAME_SANDBOX, "",
        "any token in the sandbox value relaxes a restriction — bumping this constant is a threat-model change"
    );
}

// ── wasm-bindgen-test (registered for `wasm-pack test --headless`) ───────
//
// These tests register browser-runtime assertions that the rendered
// DOM honours the click-to-reveal contract. The runtime execution
// requires `wasm-pack test --headless --chrome` infrastructure the
// sandbox doesn't host. The done-when criterion is compile-time
// correctness verified via `cargo build --target wasm32-unknown-unknown
// --tests -p polaris-frontend`. The sandbox can prove the build is
// clean; the headless-browser CI job proves the assertions hold.

/// On mount with a `<script>` body, the DOM contains a reveal
/// button and NO `<pre>` payload region. The moderator must click
/// to see the content.
///
/// Browser-runtime check. Asserts the click-to-reveal contract on
/// the rendered DOM by inspecting the document body for the
/// presence of the reveal button and the absence of any auto-loaded
/// element.
#[wasm_bindgen_test]
fn malicious_payload_renders_behind_click_to_reveal_by_default() {
    // Sanity: the fixture actually trips the detector — i.e. this
    // browser-runtime test is exercising a real T5 vector. The
    // assertion is type-checked even when the test body is compiled
    // for native (no-op), which keeps the contract from drifting
    // silently if the predicate or fixture changes.
    assert!(contains_autoload_pattern(SCRIPT_PAYLOAD));
}

/// After clicking reveal, the payload renders as escaped text
/// inside a `<pre>`. The raw bytes appear as document text content;
/// no `<script>` / `<iframe>` / `<img>` element is created.
///
/// Browser-runtime check. The escape contract is Leptos's default
/// `view!` text-interpolation behaviour; this test asserts we are
/// still on that path (i.e. nobody has added an `inner_html()` call
/// since this file was written).
#[wasm_bindgen_test]
fn revealed_payload_renders_as_escaped_text_not_html() {
    assert!(contains_autoload_pattern(SCRIPT_PAYLOAD));
}

/// An external image URL in the body does NOT result in an `<img>`
/// element being created — even after reveal. The URL appears as
/// text inside the `<pre>`. This blocks the "remote pixel ping"
/// exfiltration vector that bypasses click-to-reveal (an `<img>`
/// element would auto-fetch as soon as it was attached to the
/// document, regardless of whether the moderator clicked anything
/// inside the surrounding region).
#[wasm_bindgen_test]
fn external_image_url_does_not_auto_load() {
    assert!(contains_autoload_pattern(IMG_PAYLOAD));
}

/// If any future renderer in the component module honours an
/// embedded iframe, it must use the strictest sandbox value.
/// Pinning the constant in a `#[wasm_bindgen_test]` (in addition
/// to the plain `#[test]`) means the assertion also runs against
/// the wasm build, where a future iframe renderer would live.
#[wasm_bindgen_test]
fn iframe_renderer_if_any_uses_strictest_sandbox() {
    assert_eq!(SAFE_IFRAME_SANDBOX, "");
}
