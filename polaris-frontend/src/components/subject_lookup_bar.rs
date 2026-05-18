//! Visible subject-lookup search bar.
//!
//! Mounted at the top of [`PatternDashboard`] so the affordance is
//! discoverable without the keyboard shortcut. The
//! [`crate::components::command_palette::CommandPalette`] still
//! handles the `Ctrl/Cmd-K` global keystroke for power users; this
//! bar covers operators who haven't yet learned the chord (or who
//! prefer pointer-driven workflows).
//!
//! Both surfaces resolve through the same backend
//! `POST /api/subjects/lookup` endpoint, so the input shapes
//! supported here are the same: bare handle, full DID, AT-URI, or
//! a bsky.app profile/post URL. Resolver errors render inline in a
//! single status row below the input; success navigates to the
//! resolved subject's case page.
//!
//! Forbidden patterns (same as the command palette):
//!
//! - No `unwrap()` / `expect()` on production paths; `?` + signal
//!   updates are the failure surface.
//! - Editable-target suppression is NOT needed here — the input is
//!   the editable target itself, and the form only listens to its
//!   own submit event, not global keystrokes.

#![allow(
    clippy::must_use_candidate,
    reason = "Leptos #[component] attribute strips outer attributes; consumers always feed the return value into view!"
)]

use leptos::prelude::*;

use crate::api_client::ApiError;

/// Inline status surfaced beneath the input. `Idle` is the default;
/// the input row renders without any status text. `Resolving`
/// surfaces while the backend lookup is in flight. `Error` displays
/// the resolver error verbatim — the moderator typically corrects
/// the identifier and retries.
#[derive(Debug, Clone)]
enum LookupStatus {
    Idle,
    Resolving,
    Error(String),
}

/// Build the user-facing error message for a failed lookup. Pure so
/// it's unit-testable; mirrors the
/// `crate::components::command_palette::error_message` shape so the
/// two surfaces produce identical text for identical inputs.
#[must_use]
pub fn error_message(err: &ApiError) -> String {
    match err {
        ApiError::Http { status, message } if !message.is_empty() => {
            format!("Could not resolve identifier (HTTP {status}): {message}")
        }
        ApiError::Http { status, .. } => {
            format!("Could not resolve identifier (HTTP {status}).")
        }
        ApiError::Transport(msg) => {
            format!("Could not reach the labeler: {msg}")
        }
    }
}

/// Trim + light validation of the identifier the moderator typed.
/// Empty strings (after trimming) are rejected client-side; the
/// resolver would 400 on them anyway, but catching it before the
/// network hop keeps the keystroke loop snappy.
#[must_use]
pub fn normalise_identifier(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// The visible search affordance. Renders inline in the dashboard
/// header as a form with a single text input + submit button.
#[component]
pub fn SubjectLookupBar() -> impl IntoView {
    let (input_value, set_input_value) = signal(String::new());
    let (status, set_status) = signal(LookupStatus::Idle);

    let on_input = move |ev: leptos::ev::Event| {
        // Read the input's current value off the event target. The
        // signal then triggers the `prop:value` binding so the
        // controlled-input cycle stays clean.
        let target = event_target_value(&ev);
        set_input_value.set(target);
        // Clear any prior error the moment the moderator starts
        // editing — the previous text is what they're correcting.
        if matches!(status.get_untracked(), LookupStatus::Error(_)) {
            set_status.set(LookupStatus::Idle);
        }
    };

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let raw = input_value.get_untracked();
        let Some(identifier) = normalise_identifier(&raw) else {
            set_status.set(LookupStatus::Error(
                "Type a handle, DID, AT-URI, or bsky.app URL.".to_owned(),
            ));
            return;
        };
        set_status.set(LookupStatus::Resolving);
        spawn_lookup(identifier, set_status);
    };

    let status_view = move || match status.get() {
        LookupStatus::Idle => view! {
            <p class="subject-lookup-bar__hint" role="status">
                "Look up an account by handle, DID, AT-URI, or bsky.app URL — \
                 then act on it in the case view."
            </p>
        }
        .into_any(),
        LookupStatus::Resolving => view! {
            <p class="subject-lookup-bar__status" role="status">
                "Resolving…"
            </p>
        }
        .into_any(),
        LookupStatus::Error(msg) => view! {
            <p class="subject-lookup-bar__error" role="alert">{msg}</p>
        }
        .into_any(),
    };

    view! {
        <form class="subject-lookup-bar" role="search" on:submit=on_submit>
            <label for="subject-lookup-bar-input" class="subject-lookup-bar__label">
                "Look up account or post"
            </label>
            <div class="subject-lookup-bar__row">
                <input
                    id="subject-lookup-bar-input"
                    class="subject-lookup-bar__input"
                    type="text"
                    placeholder="alice.bsky.social / did:plc:… / at://… / bsky.app URL"
                    autocomplete="off"
                    spellcheck="false"
                    prop:value=move || input_value.get()
                    on:input=on_input
                />
                <button type="submit" class="subject-lookup-bar__submit">
                    "Open"
                </button>
            </div>
            {status_view}
        </form>
    }
}

/// Spawn the lookup-and-navigate task. wasm-only — the native build
/// stub keeps the signature symmetric so `on_submit`'s call site
/// compiles target-agnostic.
#[cfg(target_arch = "wasm32")]
fn spawn_lookup(identifier: String, set_status: WriteSignal<LookupStatus>) {
    use crate::api_client::{PolarisApiClient as _, default_client};
    leptos::task::spawn_local(async move {
        let client = match default_client("") {
            Ok(c) => c,
            Err(e) => {
                set_status.set(LookupStatus::Error(error_message(&e)));
                return;
            }
        };
        match client.lookup_subject(&identifier).await {
            Ok(response) => {
                crate::navigation::navigate_to_case(&response.subject_id);
                set_status.set(LookupStatus::Idle);
            }
            Err(e) => set_status.set(LookupStatus::Error(error_message(&e))),
        }
    });
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn_lookup(_identifier: String, _set_status: WriteSignal<LookupStatus>) {
    // Native test builds: navigation is a browser concern; pure
    // helpers (`error_message`, `normalise_identifier`) cover the
    // testable surface.
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn normalise_identifier_rejects_empty_string() {
        assert!(normalise_identifier("").is_none());
        assert!(normalise_identifier("   ").is_none());
        assert!(normalise_identifier("\t\n").is_none());
    }

    #[test]
    fn normalise_identifier_strips_outer_whitespace() {
        assert_eq!(
            normalise_identifier("  alice.bsky.social  "),
            Some("alice.bsky.social".to_owned())
        );
        assert_eq!(
            normalise_identifier("\tdid:plc:abc123\n"),
            Some("did:plc:abc123".to_owned())
        );
    }

    #[test]
    fn normalise_identifier_preserves_inner_content() {
        // No trimming inside the identifier itself: an AT-URI with
        // a path is preserved verbatim, and so is a bsky.app URL
        // with a query string.
        assert_eq!(
            normalise_identifier("at://did:plc:x/app.bsky.feed.post/abc"),
            Some("at://did:plc:x/app.bsky.feed.post/abc".to_owned())
        );
        assert_eq!(
            normalise_identifier("https://bsky.app/profile/alice.test?foo=bar"),
            Some("https://bsky.app/profile/alice.test?foo=bar".to_owned())
        );
    }

    #[test]
    fn error_message_includes_status_for_http_errors() {
        let err = ApiError::Http {
            status: 404,
            message: "no such account".to_owned(),
        };
        let msg = error_message(&err);
        assert!(msg.contains("404"));
        assert!(msg.contains("no such account"));
    }

    #[test]
    fn error_message_handles_empty_http_body() {
        let err = ApiError::Http {
            status: 500,
            message: String::new(),
        };
        let msg = error_message(&err);
        assert!(msg.contains("500"));
    }

    #[test]
    fn error_message_handles_transport_failures() {
        let err = ApiError::Transport("DNS resolution failed".to_owned());
        let msg = error_message(&err);
        assert!(msg.contains("DNS resolution failed"));
    }
}
