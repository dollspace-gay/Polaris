//! T5 mitigation: malicious-payload-safe report-body display (#76).
//!
//! Defense in depth against the threat-model T5 surface
//! (`design.md` §9 #5; tracked by `polaris-backend`'s
//! `threat_t5_malicious_payload_render` integration test): the report
//! body is moderator-supplied user-generated content and may contain
//! `<script>` / `<iframe>` / `<img src="…">` payloads that an attacker
//! crafted specifically to compromise the moderator's session when
//! rendered.
//!
//! # Mitigation contract
//!
//! 1. **Click-to-reveal.** By default the body is hidden behind a
//!    warning button. The moderator must explicitly click to reveal —
//!    so the malicious bytes are never visible to the renderer until
//!    the moderator has consented.
//! 2. **Escaped text, never HTML.** Once revealed, the payload renders
//!    inside a `<pre>` whose child is a Leptos string interpolation —
//!    Leptos's default `view!` text path HTML-escapes its child, so a
//!    `<script>` tag in the bytes becomes the *characters*
//!    `&lt;script&gt;`, not an inline element. We never call
//!    `inner_html()` / `set_inner_html()` / `dangerously_set_inner_html`
//!    anywhere in this module — the absence of that call is the
//!    mitigation, and the `cargo xtask check-frontend-boundary`
//!    scanner plus this module's tests assert it stays absent.
//! 3. **No auto-loaded resources.** Embedded image / video URLs render
//!    as text inside the `<pre>` — we do not synthesise an `<img
//!    src="…">` / `<video src="…">` from the bytes. That blocks the
//!    "remote pixel ping" exfiltration vector even on the revealed
//!    branch.
//! 4. **Sandboxed iframes (if ever rendered).** This module does not
//!    render iframes; any future renderer that does must use
//!    `sandbox=""` (the strictest form — no scripts, no same-origin,
//!    no top-navigation, no form submission). The
//!    [`SAFE_IFRAME_SANDBOX`] constant exists so a downstream renderer
//!    references the same string this module's contract is written
//!    against.
//!
//! # Testability
//!
//! The DOM-shape assertions (button present by default, click flips
//! to `<pre>`, no `<img>` tag for image URLs) live in a
//! `wasm-bindgen-test` suite at `tests/safe_payload_t5.rs`. They
//! require a real browser runtime (`wasm-pack test --headless`) to
//! execute; the CI job that runs them is the same one as the
//! action-composer suite (#54). The runtime-free predicate
//! [`contains_autoload_pattern`] lets a plain `#[test]` confirm the
//! input fixtures actually exercise the auto-load vectors the
//! mitigation defends against — that test runs in every
//! `cargo test -p polaris-frontend` invocation.

use leptos::prelude::*;

/// Sandbox value any future iframe preview must use.
///
/// The empty string is the **strictest** form: no script execution,
/// no same-origin access, no form submission, no top-level
/// navigation, no popups. See the HTML Living Standard §
/// `iframe.sandbox` and the OWASP "Clickjacking Defense" cheat
/// sheet. Exported as a `pub const` so a downstream renderer (if and
/// when one is added) consumes the canonical value rather than
/// hand-rolling another string.
pub const SAFE_IFRAME_SANDBOX: &str = "";

/// Pure predicate: does this payload contain a known auto-load
/// pattern that the click-to-reveal + no-`<img>` mitigation defends
/// against?
///
/// Returns `true` for any of:
/// - HTML element openers that browsers auto-fetch
///   (`<script`, `<iframe`, `<img`, `<video`, `<audio`, `<source`,
///   `<embed`, `<object`, `<link`).
/// - Pseudo-protocol schemes that smuggle inline execution
///   (`javascript:`, `data:text/html`, `vbscript:`).
///
/// The check is ASCII-case-insensitive (`<SCRIPT>` matches).
///
/// # Examples
///
/// ```
/// use polaris_frontend::components::safe_payload::contains_autoload_pattern;
/// assert!(contains_autoload_pattern("hi <script>alert(1)</script>"));
/// assert!(contains_autoload_pattern("<IFRAME src=evil>"));
/// assert!(contains_autoload_pattern("javascript:alert(1)"));
/// assert!(!contains_autoload_pattern("plain text body"));
/// ```
///
/// # Why this lives in the component module
///
/// The wasm-bindgen-test suite asserts the rendered DOM does not
/// auto-load these payloads. A plain `#[test]` (no browser
/// required) uses this predicate to confirm the *test fixture
/// itself* contains the patterns we are defending against — without
/// it, a typo in the fixture could silently degrade the test into
/// asserting nothing.
#[must_use]
pub fn contains_autoload_pattern(payload: &str) -> bool {
    // HTML element openers a browser would auto-fetch.
    const TAG_OPENERS: &[&str] = &[
        "<script", "<iframe", "<img", "<video", "<audio", "<source", "<embed", "<object", "<link",
    ];
    // Pseudo-protocol schemes that smuggle inline execution.
    const URL_SCHEMES: &[&str] = &["javascript:", "data:text/html", "vbscript:"];

    let lowered = payload.to_ascii_lowercase();
    TAG_OPENERS.iter().any(|t| lowered.contains(t))
        || URL_SCHEMES.iter().any(|s| lowered.contains(s))
}

/// Click-to-reveal renderer for moderator-supplied report bodies.
///
/// Mitigation contract is documented at the module level. In short:
/// the body never renders by default, the moderator must opt in, and
/// the opt-in path renders the bytes as escaped text inside a `<pre>`
/// — never via `inner_html`, never as auto-loading `<img>` /
/// `<iframe>` tags.
///
/// # Props
///
/// - `body`: the raw report body string. Taken by value because
///   Leptos components conventionally consume their props at mount
///   (see [`crate::components::subject_header::SubjectHeader`] for
///   the same pattern + rationale).
///
/// # Accessibility
///
/// - The reveal button is a real `<button>` (keyboard-activatable,
///   announced by screen readers as such).
/// - The button's text states the consequence ("may be disturbing")
///   so a moderator using assistive tech is not surprised by what
///   the click exposes.
/// - The revealed region is `role="region"` with `aria-label` set so
///   a screen reader can navigate directly to it after reveal.
// `needless_pass_by_value` fires because the body is moved into the
// reactive closure once and never re-borrowed at the outer scope.
// Leptos components conventionally take props by value — see
// `subject_header::SubjectHeader` for the full rationale.
#[allow(clippy::must_use_candidate, clippy::needless_pass_by_value)]
#[component]
pub fn SafePayload(
    /// Raw report body. May contain attacker-crafted HTML / URL
    /// schemes; the component renders it behind a click-to-reveal
    /// and as escaped text on reveal.
    body: String,
) -> impl IntoView {
    let revealed = RwSignal::new(false);
    // Stash the body in a `StoredValue` so the reactive closure can
    // reach it without cloning the full string on every reactive
    // run. The body itself never changes after the component mounts
    // (the case-view fetches it once); a `StoredValue` is the right
    // primitive for "owned, immutable, reachable from closures".
    let body_store = StoredValue::new(body);

    view! {
        <div class="safe-payload" data-testid="safe-payload">
            {move || if revealed.get() {
                view! {
                    <section
                        class="safe-payload__revealed"
                        role="region"
                        aria-label="Reported content (revealed)"
                        data-testid="safe-payload-revealed"
                    >
                        // `<pre>` keeps the bytes verbatim and inside a
                        // monospace block so the moderator sees exactly what
                        // the reporter sent. Leptos's default `view!` text
                        // interpolation HTML-escapes the child string — that
                        // is the contract this component relies on. We never
                        // call `inner_html` / `set_inner_html` anywhere in
                        // this module; the absence of that call is the
                        // mitigation.
                        <pre class="safe-payload__text">{body_store.get_value()}</pre>
                    </section>
                }.into_any()
            } else {
                view! {
                    <button
                        type="button"
                        class="safe-payload__reveal"
                        data-testid="safe-payload-reveal-button"
                        on:click=move |_| revealed.set(true)
                    >
                        "Show reported content (may be disturbing)"
                    </button>
                }.into_any()
            }}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autoload_pattern_recognises_script_tag() {
        assert!(contains_autoload_pattern("hi <script>alert(1)</script>"));
    }

    #[test]
    fn autoload_pattern_recognises_iframe_tag() {
        assert!(contains_autoload_pattern("<iframe src=evil></iframe>"));
    }

    #[test]
    fn autoload_pattern_recognises_img_tag() {
        assert!(contains_autoload_pattern("<img src=x>"));
    }

    #[test]
    fn autoload_pattern_is_case_insensitive() {
        assert!(contains_autoload_pattern("<SCRIPT>alert(1)</SCRIPT>"));
        assert!(contains_autoload_pattern("<IFRAME src=evil>"));
    }

    #[test]
    fn autoload_pattern_recognises_javascript_scheme() {
        assert!(contains_autoload_pattern("javascript:alert(1)"));
    }

    #[test]
    fn autoload_pattern_recognises_data_text_html_scheme() {
        assert!(contains_autoload_pattern(
            "data:text/html,<script>alert(1)</script>",
        ));
    }

    #[test]
    fn autoload_pattern_rejects_plain_text() {
        assert!(!contains_autoload_pattern("plain text body"));
        assert!(!contains_autoload_pattern(""));
        assert!(!contains_autoload_pattern("just talking about scripts"));
    }

    #[test]
    fn safe_iframe_sandbox_is_strictest_form() {
        // The empty string is the most restrictive value the HTML
        // Living Standard defines for `iframe.sandbox`. Any token
        // added would relax a restriction. If a future change ever
        // adds tokens here, that change MUST come with a written
        // justification that names the relaxation and the threat
        // model it accepts; this assertion is the trigger to write
        // that justification.
        assert_eq!(SAFE_IFRAME_SANDBOX, "");
    }
}
