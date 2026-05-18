//! `CaseDrawer` — right-side overlay that hosts a [`CaseViewBody`] for a
//! single subject, opened from the triage queue (issue #93,
//! mod-workstation feature #3).
//!
//! # Motivation
//!
//! The full-page `/cases/:subject_id` route destroys the moderator's
//! queue context: scroll position, keyboard focus, and the mental
//! "I am working through a stack" model all vanish on navigation.
//! Bluesky Ozone's split-view UX
//! ([userguide.md](https://github.com/bluesky-social/ozone/blob/main/docs/userguide.md))
//! solves this by sliding the case panel in from the right while the
//! queue stays mounted underneath; on close, the queue is exactly where
//! the moderator left it. This module ports that pattern to Polaris.
//!
//! # Composition
//!
//! - The drawer is a Leptos component parameterised on a
//!   `Signal<Option<String>>` of the subject id and an `on_close`
//!   callback. Open state is therefore owned by the caller (the queue
//!   page); the drawer is a pure consumer + render surface.
//! - The body content is [`crate::pages::case_view::CaseViewBody`] — the
//!   same component the full-page route renders. The fetch + composer
//!   wiring live there; the drawer adds only the overlay chrome,
//!   keyboard handling, and focus management.
//! - `<Show when=…>` gates the inner panel so the body remounts on each
//!   open. This means a moderator who opens subject A, closes, then
//!   opens subject B fetches the second case fresh — no stale data.
//!
//! # Focus management
//!
//! - On open: focus moves into the drawer's close button via a wasm
//!   effect that runs once per overlay mount.
//! - On close: the queue page is responsible for returning focus to the
//!   row that triggered the open (the queue tracks the row's index and
//!   re-focuses via the row element on the next render after
//!   `set_open_subject_id(None)`).
//!
//! # Keyboard
//!
//! The drawer installs a window-level `Escape` listener while open.
//! Unlike the queue's `j/k/Enter/o/r/?` handler, this listener fires
//! even when the event target is editable — a moderator typing
//! reasoning in the `ActionComposer` (nested inside the drawer body)
//! must still be able to press Escape to close. That asymmetry is
//! deliberate: only Escape gets the editable-target bypass; all other
//! keys reach the composer's input element untouched.

use leptos::prelude::*;

use crate::pages::case_view::CaseViewBody;
use polaris_types::SubjectId;
use uuid::Uuid;

// ── Pure helpers (unit-testable on native) ───────────────────────────

/// Decide whether the supplied key string closes the drawer.
///
/// The single accepted form is `"Escape"`. Surfaced as a pure helper so
/// the open / close logic can be exercised under `cargo test` without
/// a DOM. Mirrors the contract used by
/// [`crate::components::command_palette::should_close_keystroke`] —
/// keeping the two functions structurally identical means any future
/// drift (e.g. adding `"Esc"` as an alias) lands in one place.
#[must_use]
pub fn should_close_drawer(key: &str) -> bool {
    key == "Escape"
}

/// Pure state-transition helper for the queue-owned `Option<String>`
/// drawer-state signal.
///
/// The queue page mutates the signal via the high-level callbacks
/// (`set_open_subject_id.set(Some(id))` on row activation,
/// `set_open_subject_id.set(None)` on close). This helper expresses the
/// resulting `(old, intent) -> new` mapping so the table of transitions
/// can be exercised in unit tests without spinning a Leptos runtime.
///
/// # Intent semantics
///
/// - `DrawerIntent::Open(id)` — open the drawer on `id`. If the drawer
///   is already open on a different id, the new id REPLACES the old
///   (no second drawer is opened on top); if already open on the same
///   id, the transition is a no-op (idempotent).
/// - `DrawerIntent::Close` — close the drawer. A no-op when already
///   closed.
#[must_use]
pub fn next_drawer_state(current: Option<String>, intent: DrawerIntent) -> Option<String> {
    match (current, intent) {
        (_, DrawerIntent::Close) => None,
        (Some(existing), DrawerIntent::Open(new)) if existing == new => Some(existing),
        (_, DrawerIntent::Open(new)) => Some(new),
    }
}

/// Caller intent for [`next_drawer_state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrawerIntent {
    /// Open the drawer on the supplied subject id.
    Open(String),
    /// Close the drawer.
    Close,
}

// ── Leptos component ─────────────────────────────────────────────────

/// Right-side drawer hosting a [`CaseViewBody`].
///
/// # Props
///
/// - `subject_id`: `Signal<Option<String>>`. When `Some`, the drawer is
///   open on that subject; when `None`, hidden. The caller owns the
///   signal — the drawer never writes to it; it asks the caller to
///   close via `on_close`.
/// - `on_close`: callback fired on Escape, backdrop click, or close-
///   button click.
///
/// # Behaviour
///
/// - Slides in from the right via `transform: translateX(...)` +
///   `transition` (the panel is always mounted in the DOM when
///   `subject_id` is `Some`; the slide is a pure CSS transition on the
///   panel's transform).
/// - Backdrop click closes the drawer.
/// - `Escape` key closes the drawer even when the focused element is
///   editable (the composer's textarea). All other keys bubble.
/// - On open, focus moves to the close button so screen readers and
///   keyboard-only operators land somewhere predictable.
///
/// # SubjectId parse
///
/// The signal carries a `String` (matching what the queue snapshots
/// off the cluster summaries) so the drawer can be opened with the
/// same identifier shape the row-click handler already has. The
/// drawer parses it into a [`SubjectId`] before handing it to
/// [`CaseViewBody`]; a parse failure renders an inline error rather
/// than panicking (forbidden-pattern checklist on issue #93).
#[allow(
    clippy::must_use_candidate,
    reason = "#[component] discards outer attributes; Leptos always consumes the return value"
)]
#[component]
pub fn CaseDrawer(
    /// Signal carrying the currently-open subject id, or `None` when
    /// the drawer is closed.
    #[prop(into)]
    subject_id: Signal<Option<String>>,
    /// Fired when the user dismisses the drawer (Escape, backdrop,
    /// close button). The caller is expected to update its own
    /// open-state signal to `None`.
    on_close: Callback<()>,
) -> impl IntoView {
    // Window-level Escape handler — installed for the drawer's lifetime;
    // gated on the `subject_id.is_some()` check so the handler is a
    // no-op when closed. This keeps the installation cost to one
    // listener for the queue page's whole lifetime.
    install_escape_handler(subject_id, on_close);

    view! {
        <Show
            when=move || subject_id.with(Option::is_some)
            fallback=|| view! { <></> }
        >
            <CaseDrawerPanel
                subject_id=subject_id
                on_close=on_close
            />
        </Show>
    }
}

/// The drawer's inner overlay. Mounted only while `subject_id` is
/// `Some`; remounts on each open transition so the focus effect and
/// the `CaseViewBody` resource both re-fire cleanly.
#[component]
fn CaseDrawerPanel(subject_id: Signal<Option<String>>, on_close: Callback<()>) -> impl IntoView {
    let close_button_ref = NodeRef::<leptos::html::Button>::new();

    // Focus the close button when the panel mounts. Mirrors the
    // command palette's autofocus pattern — Leptos's `Show` parent
    // re-mounts this subtree per open, so the effect fires every time.
    autofocus_close_button(close_button_ref);

    // Click handlers. The backdrop closes; the panel itself stops
    // propagation so a click inside the body does not bubble through
    // to the backdrop.
    let on_backdrop_click = move |_| on_close.run(());
    let on_close_click = move |_| on_close.run(());
    let stop_propagation = move |ev: leptos::ev::MouseEvent| ev.stop_propagation();

    // Render the body using the current subject id. Parse once per
    // mount; a malformed id renders an inline error.
    let body_view = move || -> AnyView {
        // Snapshot the id off the signal. Inside the `<Show when=…>`
        // we know it is `Some` at mount time, but reading via `.get()`
        // keeps the type signature honest. The `None` branch is
        // unreachable at runtime (the `<Show when>` gate above
        // filters it out before body_view is invoked); we render a
        // hidden placeholder there rather than `unreachable!()` so
        // the production path stays panic-free per rust-quality §3.
        let Some(raw) = subject_id.get_untracked() else {
            return view! { <span class="case-drawer__body-empty" hidden=true></span> }.into_any();
        };
        match Uuid::parse_str(&raw) {
            Ok(uuid) => {
                let sid = SubjectId::from(uuid);
                view! { <CaseViewBody subject_id=sid/> }.into_any()
            }
            Err(e) => view! {
                <p class="case-view__route-error" role="alert">
                    "Invalid subject id `"{raw}"`: "{e.to_string()}
                </p>
            }
            .into_any(),
        }
    };

    // Title shows the subject id so a moderator scanning the panel
    // knows which subject the drawer targets. `CaseViewBody`'s
    // `SubjectHeader` reproduces this and adds the full metadata
    // table, but the drawer header carries its own copy so the title
    // is sticky even when the body has scrolled.
    let title_text = move || subject_id.with(|s| s.clone().unwrap_or_default());

    view! {
        <div
            class="case-drawer case-drawer--open"
            role="dialog"
            aria-modal="true"
            aria-label="Case detail"
        >
            <div class="case-drawer__backdrop" on:click=on_backdrop_click></div>
            <div class="case-drawer__panel" on:click=stop_propagation>
                <header class="case-drawer__header">
                    <h2 class="case-drawer__title">"Case · "{title_text}</h2>
                    <button
                        type="button"
                        class="case-drawer__close"
                        aria-label="Close case drawer"
                        on:click=on_close_click
                        node_ref=close_button_ref
                    >
                        "Close"
                    </button>
                </header>
                <div class="case-drawer__body">
                    {body_view}
                </div>
            </div>
        </div>
    }
}

// ── Wasm-only effect wirings ─────────────────────────────────────────

/// Install the window-level Escape handler that closes the drawer.
///
/// Listens for every keydown; only fires `on_close` when the drawer
/// is currently open AND the key is Escape. The listener is torn down
/// on the drawer's unmount via [`on_cleanup`]. Editable targets are
/// NOT suppressed here: a moderator typing inside the composer must
/// still be able to press Escape to close (see module docs).
#[cfg(target_arch = "wasm32")]
fn install_escape_handler(subject_id: Signal<Option<String>>, on_close: Callback<()>) {
    use leptos::ev;
    use leptos::leptos_dom::helpers::window_event_listener;

    let handle = window_event_listener(ev::keydown, move |ev: ev::KeyboardEvent| {
        // Cheap early-out: drawer closed → nothing to do.
        if subject_id.with_untracked(Option::is_none) {
            return;
        }
        if should_close_drawer(ev.key().as_str()) {
            ev.prevent_default();
            on_close.run(());
        }
    });
    on_cleanup(move || handle.remove());
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn install_escape_handler(_subject_id: Signal<Option<String>>, _on_close: Callback<()>) {
    // Window-level event handling only makes sense in a browser
    // context. Pure helpers (`should_close_drawer`,
    // `next_drawer_state`) cover the testable surface.
}

/// Move keyboard focus to the close button on mount.
#[cfg(target_arch = "wasm32")]
fn autofocus_close_button(button_ref: NodeRef<leptos::html::Button>) {
    Effect::new(move |_| {
        if let Some(el) = button_ref.get() {
            // `HtmlButtonElement::focus()` returns `Result<(), JsValue>`;
            // a failure here is non-fatal (the operator can still click
            // / tab to reach the button), so we deliberately ignore it.
            let _ = el.focus();
        }
    });
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn autofocus_close_button(_button_ref: NodeRef<leptos::html::Button>) {
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

    // ── should_close_drawer ───────────────────────────────────────

    #[test]
    fn escape_closes_drawer() {
        assert!(should_close_drawer("Escape"));
    }

    #[test]
    fn other_keys_do_not_close_drawer() {
        assert!(!should_close_drawer("k"));
        assert!(!should_close_drawer("Enter"));
        assert!(!should_close_drawer(""));
        assert!(!should_close_drawer("escape")); // lowercase rejected
        assert!(!should_close_drawer("Esc")); // browser emits "Escape"
        assert!(!should_close_drawer(" "));
    }

    // ── next_drawer_state transitions (AC-4) ──────────────────────

    #[test]
    fn drawer_open_state_transitions() {
        // Case 1 — open → close. The intent flips the state to None
        // regardless of which subject was open.
        let after_close = next_drawer_state(Some("a".to_owned()), DrawerIntent::Close);
        assert_eq!(after_close, None, "Close from open yields None");

        // Case 2 — close → close (no-op). Closing an already-closed
        // drawer is idempotent: the state stays None.
        let after_noop_close = next_drawer_state(None, DrawerIntent::Close);
        assert_eq!(after_noop_close, None, "Close from closed is a no-op");

        // Case 3 — open(A) → open(B). Opening with a different subject
        // REPLACES the current target; we do not double-open a second
        // drawer. The new id wins.
        let after_replace =
            next_drawer_state(Some("a".to_owned()), DrawerIntent::Open("b".to_owned()));
        assert_eq!(
            after_replace,
            Some("b".to_owned()),
            "Open(B) over Open(A) replaces with B",
        );

        // Bonus case — open(A) → open(A). Opening with the same id is
        // idempotent: the state is unchanged. (Belt-and-braces — the
        // queue's `Enter` handler may fire twice from a fast double-tap;
        // we do not want the body to remount on the second tap.)
        let after_idempotent =
            next_drawer_state(Some("a".to_owned()), DrawerIntent::Open("a".to_owned()));
        assert_eq!(
            after_idempotent,
            Some("a".to_owned()),
            "Open(A) over Open(A) is idempotent",
        );

        // Bonus case — closed → open(A). The fresh-open path.
        let after_fresh_open = next_drawer_state(None, DrawerIntent::Open("a".to_owned()));
        assert_eq!(
            after_fresh_open,
            Some("a".to_owned()),
            "Open(A) from closed transitions to Some(A)",
        );
    }
}
