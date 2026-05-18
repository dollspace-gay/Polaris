//! `MediaPreview` — blur-by-default media tile for the case view
//! (issue #95 / mod-workstation feature #5).
//!
//! Renders a single subject media artifact (image / video / other)
//! behind a CSS `filter: blur(...)` veil with a centered "Click to
//! reveal" button. On click, the blur drops AND a global exposure-
//! counter signal is incremented; the moderator can re-blur the
//! content from a corner button after reveal.
//!
//! # Why blur-by-default?
//!
//! Das et al. (HCOMP 2020) found that blurring potentially-graphic
//! content by default reduces secondary-traumatic-stress symptoms in
//! moderators **without** any measurable loss of moderation accuracy
//! or throughput — moderators reliably click-to-reveal when the
//! context requires it. The default-blur prevents involuntary
//! exposure; the click-to-reveal is the moment we count.
//!
//! # Accessibility
//!
//! - The blurred state is announced as `Potentially graphic content
//!   (click to reveal)` via `aria-label`.
//! - Once revealed, the actual `alt` text drives announcement.
//! - The reveal button has `role="button"`, `tabindex="0"`, and an
//!   `Enter`/`Space` keydown handler — keyboard-only moderators can
//!   reveal without a mouse.
//! - The corner re-blur button is also keyboard-reachable.
//!
//! # Empty-state contract
//!
//! When the subject DTO does not carry media URIs (the current case
//! in M1 — `CaseView::network_context` is still placeholder and the
//! backend does not surface `media_blobs`), [`SubjectHeader`] renders
//! a single empty-state placeholder via the [`MediaPreviewEmpty`]
//! sibling component. That preserves the visual rhythm of the page
//! and ships the blur infrastructure ready for the data-plumbing
//! workstream without mocking content.

use leptos::ev;
use leptos::prelude::*;

use crate::components::exposure_counter::{ExposureState, current_exposure_signal, record_reveal};

// ── Pure helpers (native-testable) ──────────────────────────────────────

/// Discriminator for the media kind. Drives the icon glyph shown over
/// the blurred surface and (in a future revision) any
/// kind-specific reveal affordance (e.g. video would also offer
/// "blurred-with-audio-muted" once audio is wired).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaKind {
    /// A still image. Default — most subject media on Bluesky is image.
    Image,
    /// A video clip. Renders the same blur surface; the underlying
    /// `<video>` element is wired by the consumer when video plumbing
    /// lands.
    Video,
    /// Catch-all for anything that is neither image nor video (audio
    /// clips, embedded link cards, etc.). Renders the generic icon.
    Other,
}

/// Internal render state for the preview. A pure enum (not a struct)
/// so the [`should_show_reveal_overlay`] helper is trivially testable
/// on native.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewState {
    /// Default — the blur veil + reveal overlay is shown.
    Blurred,
    /// Moderator clicked reveal; the unblurred content is visible and
    /// a corner re-blur button is shown.
    Revealed,
}

/// Decide whether the reveal-overlay (the "Click to reveal" button +
/// blur veil) should be shown for the given preview state.
///
/// Pulled out as a free function so the test module can exercise the
/// predicate without mounting a Leptos component.
#[must_use]
pub fn should_show_reveal_overlay(state: PreviewState) -> bool {
    matches!(state, PreviewState::Blurred)
}

/// CSS class fragment for the kind-specific icon glyph in the overlay.
///
/// The icon glyph itself is unicode in the markup; the class is what
/// the CSS file styles. The mapping is small and stable so callers can
/// drive their own match if they need to keep it inline, but the
/// canonical mapping lives here so the unit test can pin the contract.
#[must_use]
pub const fn kind_icon_class(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Image => "media-preview__icon--image",
        MediaKind::Video => "media-preview__icon--video",
        MediaKind::Other => "media-preview__icon--other",
    }
}

/// Unicode glyph used in the overlay for each [`MediaKind`]. Pure
/// data; the [`kind_icon_class`] mapping pairs it with a styleable
/// class so colour (token-driven) and shape (glyph) are independent.
#[must_use]
pub const fn kind_icon_glyph(kind: MediaKind) -> &'static str {
    match kind {
        MediaKind::Image => "▦",
        MediaKind::Video => "▶",
        MediaKind::Other => "◆",
    }
}

// ── Component: empty-state placeholder ──────────────────────────────────

/// Empty-state placeholder rendered by [`SubjectHeader`] when the
/// subject DTO does not (yet) carry media URIs.
///
/// Surfaces a clearly-labelled "no media available" note so the layout
/// stays stable across subjects that do and do not carry media. The
/// blur-by-default infrastructure is identical; this component is what
/// renders instead of [`MediaPreview`] when there is nothing to blur.
#[allow(
    clippy::must_use_candidate,
    reason = "#[component] discards outer attributes; Leptos always consumes the return value"
)]
#[component]
pub fn MediaPreviewEmpty() -> impl IntoView {
    view! {
        <section
            class="media-preview media-preview--empty"
            aria-label="No media attached to this subject"
        >
            <p class="media-preview__empty-note">
                "No media attached to this subject. "
                "(Media URIs are not yet surfaced by the case-view DTO; the blur "
                "infrastructure is ready and will activate when media is plumbed in.)"
            </p>
        </section>
    }
}

// ── Component: the blur tile itself ─────────────────────────────────────

/// Render a single subject media artifact behind a blur-by-default
/// veil with a click-to-reveal overlay.
///
/// # Props
///
/// - `src`: URL of the media to render once revealed. Empty / unknown
///   URLs render the same overlay; the unblurred `<img>` simply
///   surfaces the browser's broken-image glyph, matching what would
///   happen for any external embed.
/// - `alt`: alt text for the unblurred state. The blurred state uses
///   the generic "potentially graphic content" announcement instead.
/// - `kind`: discriminator that drives the overlay's icon glyph + the
///   kind-specific CSS class.
///
/// # Exposure counting
///
/// Clicking reveal increments the global exposure counter via
/// [`record_reveal`]. Re-blurring does NOT decrement — the moderator
/// has already been exposed, the counter tracks cumulative reveals
/// for the session, not currently-visible content.
// `needless_pass_by_value` fires on the `String` props — Leptos
// components take props by value as the API convention (see
// `subject_header::SubjectHeader` for the full rationale). The body
// clones `src` / `alt` into the `<img>` element's attributes; the
// owning prop is the natural form to take at the API boundary.
#[allow(
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    reason = "#[component] discards outer attributes and Leptos prop convention is by-value; \
              see `subject_header::SubjectHeader` for the matching rationale"
)]
#[component]
pub fn MediaPreview(
    /// URL of the media to render once revealed.
    src: String,
    /// Alt text announced to screen readers once the blur is dropped.
    alt: String,
    /// Discriminator that drives the overlay icon + the kind-specific
    /// CSS class.
    kind: MediaKind,
) -> impl IntoView {
    let (state, set_state) = signal(PreviewState::Blurred);

    // Pull the global exposure signal off Leptos context. If the
    // ExposureCounter component has not been mounted (e.g. an isolated
    // test rendering this component without the app root), the reveal
    // still works — `record_reveal` just no-ops on a missing signal.
    let exposure_signal = current_exposure_signal();

    // The reveal click handler.
    //
    // FIRES THE GLOBAL EXPOSURE INCREMENT. This is the single point in
    // the codebase where reveal → counter is wired; any other media
    // surface that bypasses this handler would silently miss the
    // wellness counter, so we keep the call inline rather than
    // factoring it behind a separate trait.
    let on_reveal = move || {
        set_state.set(PreviewState::Revealed);
        if let Some(signal) = exposure_signal {
            signal.update(|s: &mut ExposureState| {
                record_reveal(s);
            });
        }
    };

    // The reveal closure captures only `Copy` types (a `WriteSignal`
    // and an `Option<RwSignal<_>>`), so it implements `Fn + Copy`
    // and can be captured into multiple handlers directly without a
    // per-handler rebinding.
    let on_reveal_click = move |_ev: ev::MouseEvent| on_reveal();

    let on_reveal_keydown = move |ev: ev::KeyboardEvent| {
        let key = ev.key();
        if key == "Enter" || key == " " {
            ev.prevent_default();
            on_reveal();
        }
    };

    let on_reblur = move |_ev: ev::MouseEvent| {
        set_state.set(PreviewState::Blurred);
    };

    // Reactive classes per state. Two consumers (the section's
    // wrapper and the inline media element) each need an
    // independently-callable closure.
    let section_class = move || match state.get() {
        PreviewState::Blurred => "media-preview media-preview--blurred",
        PreviewState::Revealed => "media-preview media-preview--revealed",
    };

    let media_class = move || match state.get() {
        PreviewState::Blurred => "media-preview__media media-preview__media--blurred",
        PreviewState::Revealed => "media-preview__media media-preview__media--revealed",
    };

    let icon_class = format!("media-preview__icon {extra}", extra = kind_icon_class(kind));
    let icon_glyph = kind_icon_glyph(kind);

    // Owned copies for the view! macro since they get moved into
    // different DOM positions across the conditional branches.
    let alt_for_img = alt.clone();
    let src_for_img = src.clone();

    view! {
        <section
            class=section_class
            aria-label=move || match state.get() {
                PreviewState::Blurred => "Potentially graphic content (click to reveal)",
                PreviewState::Revealed => "Media content revealed",
            }
        >
            // The underlying media element. Blurred-state uses
            // `aria-hidden=true` so screen readers do not announce
            // it before the moderator chooses to reveal — the
            // surrounding section's `aria-label` carries the cue.
            <img
                class=media_class
                src=src_for_img
                alt=alt_for_img
                aria-hidden=move || matches!(state.get(), PreviewState::Blurred).to_string()
            />

            // Reveal overlay — visible only when blurred. The
            // `tabindex=0` + explicit keydown handler give keyboard
            // users the same affordance as mouse users.
            <Show
                when=move || should_show_reveal_overlay(state.get())
                fallback=|| view! { <></> }
            >
                <button
                    type="button"
                    class="media-preview__reveal"
                    role="button"
                    tabindex="0"
                    aria-label="Click to reveal potentially graphic content"
                    on:click=on_reveal_click
                    on:keydown=on_reveal_keydown
                >
                    <span class=icon_class.clone() aria-hidden="true">{icon_glyph}</span>
                    <span class="media-preview__reveal-label">"Click to reveal"</span>
                </button>
            </Show>

            // Re-blur affordance — visible only after reveal so the
            // moderator can hide the content again. Keyboard
            // activation works via the native `<button>` element's
            // default Enter/Space behaviour.
            <Show
                when=move || matches!(state.get(), PreviewState::Revealed)
                fallback=|| view! { <></> }
            >
                <button
                    type="button"
                    class="media-preview__reblur"
                    aria-label="Re-blur this media"
                    on:click=on_reblur
                >
                    "Re-blur"
                </button>
            </Show>
        </section>
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
    fn should_show_reveal_overlay_true_when_blurred() {
        assert!(should_show_reveal_overlay(PreviewState::Blurred));
    }

    #[test]
    fn should_show_reveal_overlay_false_when_revealed() {
        assert!(!should_show_reveal_overlay(PreviewState::Revealed));
    }

    #[test]
    fn kind_icon_class_maps_each_variant() {
        assert_eq!(
            kind_icon_class(MediaKind::Image),
            "media-preview__icon--image"
        );
        assert_eq!(
            kind_icon_class(MediaKind::Video),
            "media-preview__icon--video"
        );
        assert_eq!(
            kind_icon_class(MediaKind::Other),
            "media-preview__icon--other"
        );
    }

    #[test]
    fn kind_icon_glyph_maps_each_variant() {
        assert_eq!(kind_icon_glyph(MediaKind::Image), "▦");
        assert_eq!(kind_icon_glyph(MediaKind::Video), "▶");
        assert_eq!(kind_icon_glyph(MediaKind::Other), "◆");
    }

    #[test]
    fn media_kind_distinguishes_variants() {
        // Sanity: the three variants are distinct so the icon mapping
        // is actually exhaustive.
        assert_ne!(MediaKind::Image, MediaKind::Video);
        assert_ne!(MediaKind::Video, MediaKind::Other);
        assert_ne!(MediaKind::Image, MediaKind::Other);
    }
}
