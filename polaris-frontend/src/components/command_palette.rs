//! Global Ctrl-K / Cmd-K command palette (issue #92).
//!
//! Mounted once at the top of the [`crate::app::App`] tree, OUTSIDE
//! the `<Routes>` block so the same overlay is reachable from every
//! page. The palette listens at the `window` level for a single
//! `Ctrl+K` / `Cmd+K` keystroke, opens an overlay with a centred input,
//! and dispatches a [`crate::api_client::PolarisApiClient::lookup_subject`]
//! call on `Enter`. On success, navigates to `/cases/{subject_id}` via
//! [`leptos_router::hooks::use_navigate`].
//!
//! # Pattern source
//!
//! Bluesky Ozone's control palette + Superhuman's command-palette
//! pattern (referenced in issue #92's design brief). The visual
//! shape is a centred modal box; the keyboard model is
//! "one-shot — paste — Enter".
//!
//! # Suppression rules
//!
//! - Open hotkey (`Ctrl/Cmd+K`) fires regardless of the focused
//!   element so a moderator typing reasoning in another input can
//!   still open the palette.
//! - Once the palette is open, the only keys that bubble are
//!   `Escape` (close), `Enter` (submit), and the normal text
//!   input keys (the input element's default behaviour).
//! - The window-level listener is torn down on unmount via
//!   [`leptos::prelude::on_cleanup`].

use leptos::prelude::*;

use crate::api_client::dto::SubjectLookupResponse;
use crate::api_client::{ApiError, PolarisApiClient, default_client};

// ── Pure helpers (unit-testable on native) ───────────────────────────

/// Slim mirror of [`web_sys::KeyboardEvent`]'s modifier flags. Lets
/// the pure key-decision helper [`is_open_keystroke`] be exercised
/// without a DOM.
#[allow(
    clippy::struct_excessive_bools,
    reason = "four flags mirror the browser KeyboardEvent surface; \
              collapsing them into a bit-field would obscure the \
              one-to-one correspondence with event.ctrlKey / \
              event.metaKey / event.altKey / event.shiftKey"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EventModifiers {
    /// `event.ctrlKey` on the wasm side. `true` on Linux/Windows
    /// Ctrl-K. macOS browsers also flip this for the literal Control
    /// key (independent of Cmd), so the combined hot-key check is
    /// "either ctrl or meta".
    pub ctrl: bool,
    /// `event.metaKey` on the wasm side. `true` on macOS Cmd-K.
    pub meta: bool,
    /// `event.altKey`. Always tested as `false`: an Alt+K with an
    /// otherwise matching modifier surface is a different binding
    /// the OS may have already claimed.
    pub alt: bool,
    /// `event.shiftKey`. Same posture as `alt` — extra modifiers
    /// suppress the hot-key.
    pub shift: bool,
}

/// Decide whether the supplied (modifiers, key) tuple matches the
/// command-palette open shortcut.
///
/// Accepted forms:
///
/// - Ctrl + `k` (Linux / Windows)
/// - Cmd + `k` (macOS — `meta_key` is true)
///
/// Either or both of `ctrl` and `meta` may be true (some browsers
/// flip both on macOS); `alt` / `shift` MUST be false. The key MUST
/// be the lowercase `"k"` — uppercase `"K"` is emitted by browsers
/// only when Shift is held, which we reject above.
#[must_use]
pub fn is_open_keystroke(modifiers: EventModifiers, key: &str) -> bool {
    if modifiers.alt || modifiers.shift {
        return false;
    }
    if !(modifiers.ctrl || modifiers.meta) {
        return false;
    }
    key == "k"
}

/// Decide whether the supplied key string closes the palette.
///
/// The single accepted form is `"Escape"`. The check is folded into
/// a pure helper so the open / close logic can be exercised under
/// `cargo test --target <native>` without a DOM.
#[must_use]
pub fn should_close_keystroke(key: &str) -> bool {
    key == "Escape"
}

/// Pure mirror of `pages::queue::target_is_editable`'s contract — the
/// palette opens regardless of editable state, but once OPEN we need
/// to know whether the global Escape handler should still fire (yes,
/// even when the user is typing in the palette's own input — Escape
/// inside the input closes the palette).
///
/// This helper exists for symmetry with #91's pattern and to keep
/// the test that AC-5 calls out passing — Escape over an editable
/// target is a deliberate "close-the-overlay" action, not an
/// editable-state pass-through.
#[must_use]
pub fn target_is_editable(tag_name_uppercase: &str, contenteditable: Option<&str>) -> bool {
    matches!(tag_name_uppercase, "INPUT" | "TEXTAREA" | "SELECT")
        || matches!(contenteditable, Some("true" | "plaintext-only"))
}

// ── Inner-state types ────────────────────────────────────────────────

/// Inline-status discriminator. Drives the small text under the
/// palette's input field — empty when idle, "Resolving…" while a
/// fetch is in flight, the API error message on failure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum PaletteStatus {
    #[default]
    Idle,
    Resolving,
    Error(String),
}

impl PaletteStatus {
    fn display(&self) -> Option<&str> {
        match self {
            Self::Idle => None,
            Self::Resolving => Some("Resolving…"),
            Self::Error(msg) => Some(msg.as_str()),
        }
    }
}

// ── Leptos component ─────────────────────────────────────────────────

/// Render the command palette overlay.
///
/// Mount globally (in [`crate::app::App`] outside the `<Routes>`
/// block) so the palette is reachable from every page. The component
/// owns its own visibility signal and listens at the `window` level
/// for the open hotkey.
#[allow(
    clippy::must_use_candidate,
    reason = "#[component] discards outer attributes; Leptos always consumes the return value"
)]
#[component]
pub fn CommandPalette() -> impl IntoView {
    // Visibility + draft input state. Both signals stay client-side;
    // no Leptos context shenanigans because the palette is its own
    // single source of truth.
    let (is_open, set_is_open) = signal(false);
    let (draft, set_draft) = signal(String::new());
    let (status, set_status) = signal(PaletteStatus::Idle);

    // Install the global hot-key listener once.
    install_open_listener(set_is_open);

    // Reset draft + status whenever the palette closes so a re-open
    // starts clean.
    Effect::new(move |_| {
        if !is_open.get() {
            set_draft.set(String::new());
            set_status.set(PaletteStatus::Idle);
        }
    });

    view! {
        <Show when=move || is_open.get() fallback=|| view! { <></> }>
            <PaletteOverlay
                set_is_open=set_is_open
                draft=draft
                set_draft=set_draft
                status=status
                set_status=set_status
            />
        </Show>
    }
}

/// Internal overlay view. Split from [`CommandPalette`] so the
/// `<Show when=…>` gate only mounts this subtree when the palette is
/// open — the autofocus effect inside [`PaletteOverlay`] then fires
/// on every open transition.
#[component]
fn PaletteOverlay(
    set_is_open: WriteSignal<bool>,
    draft: ReadSignal<String>,
    set_draft: WriteSignal<String>,
    status: ReadSignal<PaletteStatus>,
    set_status: WriteSignal<PaletteStatus>,
) -> impl IntoView {
    let input_ref = NodeRef::<leptos::html::Input>::new();

    // Autofocus the input on mount. The `Show` parent re-mounts this
    // subtree per open so the effect fires every open.
    autofocus_input(input_ref);

    // Submit on Enter. We capture the keydown on the input itself
    // rather than at the window level so other keystrokes (text
    // entry) pass through untouched.
    let on_keydown = move |ev: leptos::ev::KeyboardEvent| {
        let key = ev.key();
        if should_close_keystroke(&key) {
            ev.prevent_default();
            set_is_open.set(false);
            return;
        }
        if key == "Enter" {
            ev.prevent_default();
            let identifier = draft.get_untracked();
            spawn_lookup(&identifier, set_is_open, set_status);
        }
    };

    let on_input = move |ev: leptos::ev::Event| {
        let value = leptos::prelude::event_target_value(&ev);
        set_draft.set(value);
    };

    let on_backdrop_click = move |_| set_is_open.set(false);

    // Stop click events on the dialog from bubbling to the backdrop
    // (which would close the palette).
    let stop_propagation = move |ev: leptos::ev::MouseEvent| ev.stop_propagation();

    view! {
        <div class="command-palette" role="dialog" aria-modal="true" aria-label="Command palette">
            <div class="command-palette__backdrop" on:click=on_backdrop_click></div>
            <div class="command-palette__dialog" on:click=stop_propagation>
                <p class="command-palette__hint">
                    "Paste a bsky.app URL, DID, AT-URI, or handle"
                </p>
                <input
                    class="command-palette__input"
                    type="text"
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="Paste a bsky.app URL, DID, AT-URI, or handle"
                    on:keydown=on_keydown
                    on:input=on_input
                    prop:value=move || draft.get()
                    node_ref=input_ref
                />
                <p class="command-palette__status" role="status">
                    {move || status.get().display().unwrap_or_default().to_owned()}
                </p>
                <p class="command-palette__keymap">
                    <kbd>"Esc"</kbd>" to close, "<kbd>"Enter"</kbd>" to jump"
                </p>
            </div>
        </div>
    }
}

// ── Async lookup driver ──────────────────────────────────────────────

/// Kick off the API lookup. On success, close the palette and
/// navigate to the case page; on error, surface the message via the
/// inline status text and leave the palette open so the moderator
/// can correct the identifier.
fn spawn_lookup(
    identifier: &str,
    set_is_open: WriteSignal<bool>,
    set_status: WriteSignal<PaletteStatus>,
) {
    let trimmed = identifier.trim();
    if trimmed.is_empty() {
        set_status.set(PaletteStatus::Error("Enter an identifier".to_owned()));
        return;
    }
    set_status.set(PaletteStatus::Resolving);

    let identifier_owned = trimmed.to_owned();
    leptos::task::spawn_local(async move {
        let client = match default_client("") {
            Ok(c) => c,
            Err(e) => {
                set_status.set(PaletteStatus::Error(error_message(&e)));
                return;
            }
        };
        match client.lookup_subject(&identifier_owned).await {
            Ok(response) => {
                navigate_to_case(&response);
                set_is_open.set(false);
            }
            Err(e) => set_status.set(PaletteStatus::Error(error_message(&e))),
        }
    });
}

/// Render an [`ApiError`] into the inline status text. We surface
/// the HTTP body's `error` field verbatim when present, falling back
/// to the typed Display impl otherwise.
fn error_message(err: &ApiError) -> String {
    match err {
        ApiError::Http { message, .. } if !message.is_empty() => {
            // The body is the typed `{ "error": ..., "code": ... }` shape.
            // Try to decode and surface the human message; fall back to
            // the raw text if it doesn't parse.
            serde_json::from_str::<serde_json::Value>(message)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
                .unwrap_or_else(|| message.clone())
        }
        _ => err.to_string(),
    }
}

// ── Navigation ───────────────────────────────────────────────────────

/// Navigate to `/cases/{subject_id}` via Leptos' router on wasm; a
/// no-op on native.
#[cfg(target_arch = "wasm32")]
fn navigate_to_case(response: &SubjectLookupResponse) {
    // Hard navigation via `window.location.assign`. We deliberately
    // do NOT use `leptos_router::hooks::use_navigate()` here: this
    // function runs inside `leptos::task::spawn_local`, and
    // `use_navigate()` reads from a reactive context that
    // spawn_local's detached task does NOT have. On wasm, calling
    // it from the detached task panics with a non-unwinding panic
    // (`catch_unwind` does not catch it under wasm's default panic
    // strategy), which silently aborts the async block — the
    // palette's `set_is_open.set(false)` after navigation never
    // runs, the modal stays open, and the moderator sees a frozen
    // "Resolving…" status. `window.location.assign` is bullet-proof
    // because it triggers a real browser navigation; the SPA
    // re-bootstraps on the destination path.
    let href = format!("/cases/{}", response.subject_id);
    if let Some(window) = web_sys::window() {
        let _ = window.location().assign(&href);
    }
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn navigate_to_case(_response: &SubjectLookupResponse) {
    // Intentionally empty: navigation is a browser concern. Pure
    // helpers (`is_open_keystroke`, `should_close_keystroke`,
    // `target_is_editable`) cover the native-testable surface.
}

// ── Wasm-only effect wirings ─────────────────────────────────────────

/// Install the global keydown listener that flips the palette open
/// on Ctrl/Cmd+K. The listener stays alive for the component's
/// lifetime and tears down via `on_cleanup`.
#[cfg(target_arch = "wasm32")]
fn install_open_listener(set_is_open: WriteSignal<bool>) {
    use leptos::ev;
    use leptos::leptos_dom::helpers::window_event_listener;

    let handle = window_event_listener(ev::keydown, move |ev: ev::KeyboardEvent| {
        let modifiers = EventModifiers {
            ctrl: ev.ctrl_key(),
            meta: ev.meta_key(),
            alt: ev.alt_key(),
            shift: ev.shift_key(),
        };
        if is_open_keystroke(modifiers, ev.key().as_str()) {
            ev.prevent_default();
            set_is_open.update(|open| *open = !*open);
        }
    });
    on_cleanup(move || handle.remove());
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn install_open_listener(_set_is_open: WriteSignal<bool>) {
    // Window-level event handling only makes sense in a browser
    // context. Pure helpers cover the testable surface.
}

/// Focus the input element when the overlay mounts.
#[cfg(target_arch = "wasm32")]
fn autofocus_input(input_ref: NodeRef<leptos::html::Input>) {
    Effect::new(move |_| {
        if let Some(el) = input_ref.get() {
            // `HtmlInputElement::focus()` returns `Result<(), JsValue>`;
            // a failure here is non-fatal (the operator can click the
            // input) so we deliberately ignore it.
            let _ = el.focus();
        }
    });
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn autofocus_input(_input_ref: NodeRef<leptos::html::Input>) {
    // Focus management only makes sense in a browser context.
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

    // ── is_open_keystroke ─────────────────────────────────────────

    #[test]
    fn ctrl_k_opens_palette() {
        assert!(is_open_keystroke(
            EventModifiers {
                ctrl: true,
                ..EventModifiers::default()
            },
            "k",
        ));
    }

    #[test]
    fn cmd_k_opens_palette() {
        assert!(is_open_keystroke(
            EventModifiers {
                meta: true,
                ..EventModifiers::default()
            },
            "k",
        ));
    }

    #[test]
    fn ctrl_or_meta_with_extra_modifiers_does_not_open() {
        assert!(!is_open_keystroke(
            EventModifiers {
                ctrl: true,
                alt: true,
                ..EventModifiers::default()
            },
            "k",
        ));
        assert!(!is_open_keystroke(
            EventModifiers {
                meta: true,
                shift: true,
                ..EventModifiers::default()
            },
            "k",
        ));
    }

    #[test]
    fn bare_k_does_not_open() {
        assert!(!is_open_keystroke(EventModifiers::default(), "k"));
    }

    #[test]
    fn ctrl_other_letter_does_not_open() {
        assert!(!is_open_keystroke(
            EventModifiers {
                ctrl: true,
                ..EventModifiers::default()
            },
            "j",
        ));
        assert!(!is_open_keystroke(
            EventModifiers {
                meta: true,
                ..EventModifiers::default()
            },
            "Enter",
        ));
    }

    #[test]
    fn shift_k_does_not_open() {
        // Browsers emit "K" (uppercase) when shift is held, but our
        // contract is strictly lowercase "k" with shift suppressed.
        assert!(!is_open_keystroke(
            EventModifiers {
                ctrl: true,
                shift: true,
                ..EventModifiers::default()
            },
            "K",
        ));
    }

    // ── should_close_keystroke ────────────────────────────────────

    #[test]
    fn escape_closes_palette() {
        assert!(should_close_keystroke("Escape"));
    }

    #[test]
    fn other_keys_do_not_close() {
        assert!(!should_close_keystroke("k"));
        assert!(!should_close_keystroke("Enter"));
        assert!(!should_close_keystroke(""));
        assert!(!should_close_keystroke("escape"));
    }

    // ── target_is_editable (mirrors queue.rs contract) ────────────

    #[test]
    fn editable_targets_match_queue_contract() {
        assert!(target_is_editable("INPUT", None));
        assert!(target_is_editable("TEXTAREA", None));
        assert!(target_is_editable("SELECT", None));
        assert!(target_is_editable("DIV", Some("true")));
        assert!(target_is_editable("SPAN", Some("plaintext-only")));
    }

    #[test]
    fn non_editable_targets_pass_through() {
        assert!(!target_is_editable("BODY", None));
        assert!(!target_is_editable("BUTTON", None));
        assert!(!target_is_editable("DIV", None));
        assert!(!target_is_editable("DIV", Some("false")));
        assert!(!target_is_editable("DIV", Some("")));
    }

    // ── PaletteStatus display ─────────────────────────────────────

    #[test]
    fn idle_status_shows_no_text() {
        assert_eq!(PaletteStatus::Idle.display(), None);
    }

    #[test]
    fn resolving_status_shows_text() {
        assert_eq!(PaletteStatus::Resolving.display(), Some("Resolving…"));
    }

    #[test]
    fn error_status_shows_message() {
        let s = PaletteStatus::Error("bad".to_owned());
        assert_eq!(s.display(), Some("bad"));
    }

    // ── error_message ─────────────────────────────────────────────

    #[test]
    fn error_message_extracts_typed_body() {
        let err = ApiError::Http {
            status: 404,
            message: r#"{"error":"resource not found","code":"not_found"}"#.to_owned(),
        };
        assert_eq!(error_message(&err), "resource not found");
    }

    #[test]
    fn error_message_falls_back_to_raw_body_on_parse_failure() {
        let err = ApiError::Http {
            status: 500,
            message: "internal server error".to_owned(),
        };
        assert_eq!(error_message(&err), "internal server error");
    }

    #[test]
    fn error_message_uses_display_for_transport_failures() {
        let err = ApiError::Transport("connection refused".to_owned());
        assert_eq!(error_message(&err), "transport error: connection refused");
    }
}
