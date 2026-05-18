//! `MediaGallery` — interactive carousel of the subject's image-blob
//! attachments, with author-provided alt text surfaced inline.
//!
//! # Why a self-fetching component
//!
//! The case-view DTO's `media_blobs` field carries only what the
//! backend's `subject_image_blobs` table had cached at the time the
//! case-view was assembled. On a first visit the table is empty; on
//! subsequent visits it contains whatever a previous walk persisted,
//! which is rarely a complete image set.
//!
//! `MediaGallery` therefore mounts and hits the dedicated
//! `GET /api/cases/{subject_id}/media` endpoint independently of the
//! main case-view DTO. The endpoint triggers a deep paginated walk
//! of `app.bsky.feed.getAuthorFeed` (alt-text aware), persists every
//! new blob row, and returns the full deduped list. The case view
//! paints instantly; the gallery resolves a beat later with the
//! complete set.
//!
//! This mirrors how
//! [`crate::components::network_panel::NetworkPanel`] mounts and
//! fetches `/network-context` — same control flow, same partial-
//! failure surface.
//!
//! # Image source URL
//!
//! ATProto blob CIDs are content-addressable. The image fetches via
//! Bluesky's public CDN at:
//!
//! ```text
//! https://cdn.bsky.app/img/feed_thumbnail/plain/<owner-did>/<blob-cid>@jpeg
//! ```
//!
//! The owner DID is the subject's DID. If the subject has no DID
//! (list / feed-kind subjects), the gallery renders the
//! `subject_has_no_did` 400 hint instead of attempting the fetch.
//!
//! # Keyboard + screen-reader support
//!
//! The prev / next buttons are real `<button>` elements (keyboard-
//! focusable, announced as buttons), each dot indicator is a
//! `<button>` with `aria-current` set on the active one, and the
//! "Image N of M" counter is `aria-live="polite"` so screen
//! readers announce position changes. Each image's alt text is
//! rendered as visible body copy AND fed into the `<img alt="">`
//! attribute.

use leptos::prelude::*;
use polaris_types::{Subject, SubjectId};

#[cfg(target_arch = "wasm32")]
use crate::api_client::dto::{MediaGalleryResponse, SubjectMediaBlob};
#[cfg(target_arch = "wasm32")]
use crate::components::media_preview::{MediaKind, MediaPreview};

/// Render the subject's media gallery as a navigable carousel.
///
/// Mounts and fetches `GET /api/cases/{subject_id}/media`
/// independently of the parent case-view DTO. Renders four
/// distinct surfaces depending on the fetch state:
///
/// 1. **Loading** — a status row while the on-mount fetch is in
///    flight.
/// 2. **Failed** — an inline error with the upstream message.
///    The case view does NOT navigate away on a media failure.
/// 3. **Ready, no images** — the upstream walk succeeded but the
///    subject has not embedded any images in the walked range.
/// 4. **Ready, with images** — the carousel itself.
///
/// On the Ready-with-images surface the carousel exposes prev /
/// next nav, dot indicators, an "Image N of M" counter, and
/// per-image alt-text rendered prominently.
///
/// The wasm and native code paths split at the body — the fetch
/// state machine only exists on wasm where the AppView fetch
/// actually runs, so the native build neither defines nor checks
/// for dead variants.
#[component]
#[allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "Leptos #[component] macros accept props by value as the framework convention."
)]
pub fn MediaGallery(
    /// The subject the case view is centred on. The DID is the
    /// CDN-URL authority; the carousel hides itself when absent.
    subject: Subject,
    /// Subject identifier — used as the path parameter of the
    /// media-gallery fetch.
    subject_id: SubjectId,
) -> impl IntoView {
    // Subjects with no DID have no AppView posts to walk. Render
    // a single status row and skip the fetch entirely. List- and
    // feed-kind subjects fall into this bucket today — target-
    // agnostic precheck.
    let owner_did = subject.did.as_ref().map(ToString::to_string);
    let Some(owner_did) = owner_did else {
        return view! {
            <section class="media-gallery" role="region" aria-label="Subject media">
                <header class="media-gallery__header">
                    <h3 class="media-gallery__title">"Subject media"</h3>
                </header>
                <p class="media-gallery__empty" role="status">
                    "No media available — this subject has no DID, so no AppView posts can be walked."
                </p>
            </section>
        }
        .into_any();
    };

    #[cfg(target_arch = "wasm32")]
    {
        render_wasm(owner_did, subject_id)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = subject_id;
        let _ = owner_did;
        render_native_stub()
    }
}

/// Native (test / IDE check) stub render — the gallery shell plus
/// the same loading-state row the wasm path shows while the
/// fetch is in flight. Avoids the wasm-only fetch state machine
/// entirely.
#[cfg(not(target_arch = "wasm32"))]
fn render_native_stub() -> AnyView {
    view! {
        <section class="media-gallery" role="region" aria-label="Subject media">
            <header class="media-gallery__header">
                <h3 class="media-gallery__title">"Subject media"</h3>
            </header>
            <p class="media-gallery__loading" role="status">
                "Loading subject media…"
            </p>
        </section>
    }
    .into_any()
}

/// Fetch-state machine for the wasm render path. Lives behind the
/// `target_arch = "wasm32"` cfg gate because each variant is only
/// constructed by [`render_wasm`] below — gating the type at the
/// definition site lets us drop the `#[allow(dead_code)]`
/// annotation entirely.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "MediaGalleryResponse is much bigger than the `Loading` / `Failed(String)` \
              variants; boxing it would force every render to chase an extra pointer for \
              the common Ready case for no real win."
)]
enum FetchState {
    /// On-mount fetch in flight.
    Loading,
    /// Fetch completed; carry the typed response.
    Ready(MediaGalleryResponse),
    /// Fetch failed; surface the error inline.
    Failed(String),
}

/// wasm-only render path: drives the fetch state machine, runs the
/// AppView lookup via `spawn_local`, and dispatches on the
/// resulting [`FetchState`].
#[cfg(target_arch = "wasm32")]
fn render_wasm(owner_did: String, subject_id: SubjectId) -> AnyView {
    use crate::api_client::{PolarisApiClient as _, default_client};

    let (state, set_state) = signal(FetchState::Loading);
    leptos::task::spawn_local(async move {
        match default_client("") {
            Ok(client) => match client.media_gallery(subject_id).await {
                Ok(resp) => set_state.set(FetchState::Ready(resp)),
                Err(e) => set_state.set(FetchState::Failed(e.to_string())),
            },
            Err(e) => set_state.set(FetchState::Failed(e.to_string())),
        }
    });

    view! {
        <section class="media-gallery" role="region" aria-label="Subject media">
            {move || match state.get() {
                FetchState::Loading => view! {
                    <header class="media-gallery__header">
                        <h3 class="media-gallery__title">"Subject media"</h3>
                    </header>
                    <p class="media-gallery__loading" role="status">
                        "Loading subject media…"
                    </p>
                }.into_any(),
                FetchState::Failed(msg) => view! {
                    <header class="media-gallery__header">
                        <h3 class="media-gallery__title">"Subject media"</h3>
                    </header>
                    <p class="media-gallery__error" role="alert">
                        "Could not load media: "{msg}
                    </p>
                }.into_any(),
                FetchState::Ready(response) => render_ready(&owner_did, response).into_any(),
            }}
        </section>
    }
    .into_any()
}

/// Render the loaded-and-ready gallery surface.
///
/// Branches on `blobs.is_empty()` so the no-images case stays a
/// tight inline status row rather than rendering a single-dot
/// carousel that would be confusing. The `upstream_ok` flag, when
/// `false` with a non-empty blob list, surfaces a "could not
/// refresh" hint above the carousel — the moderator sees the
/// cached set with the staleness made explicit.
///
/// Called only from [`render_wasm`]; cfg-gated to the wasm target
/// so the lib build for native targets does not flag it as dead
/// code.
#[cfg(target_arch = "wasm32")]
#[allow(
    clippy::too_many_lines,
    reason = "Single cohesive carousel render — splitting it would push the reactive `index` \
              signal across helper boundaries and require each helper to re-capture the setter, \
              which is harder to follow than the inline shape."
)]
fn render_ready(owner_did: &str, response: MediaGalleryResponse) -> AnyView {
    let MediaGalleryResponse { blobs, upstream_ok } = response;

    if blobs.is_empty() {
        return view! {
            <header class="media-gallery__header">
                <h3 class="media-gallery__title">"Subject media"</h3>
            </header>
            <p class="media-gallery__empty" role="status">
                {if upstream_ok {
                    "Subject has not embedded any images in the recent posts walked."
                } else {
                    "Could not refresh media from the AppView, and no cached images are available."
                }}
            </p>
        }
        .into_any();
    }

    let total = blobs.len();
    let (index, set_index) = signal(0_usize);
    let blobs_for_view = blobs.clone();
    let owner_did_owned = owner_did.to_owned();

    let go_prev = move |_| {
        set_index.update(|i| {
            // Cyclic — last image wraps back to first and vice
            // versa. Subtraction-with-wraparound avoids usize
            // underflow at zero.
            *i = if *i == 0 { total - 1 } else { *i - 1 };
        });
    };
    let go_next = move |_| {
        set_index.update(|i| {
            *i = (*i + 1) % total;
        });
    };

    let dots: Vec<_> = (0..total)
        .map(|target| {
            let setter = set_index;
            view! {
                <button
                    type="button"
                    class=move || {
                        if index.get() == target {
                            "media-gallery__dot media-gallery__dot--active"
                        } else {
                            "media-gallery__dot"
                        }
                    }
                    aria-label=move || format!("Show image {}", target + 1)
                    aria-current=move || if index.get() == target { "true" } else { "false" }
                    on:click=move |_| setter.set(target)
                />
            }
        })
        .collect();

    let staleness_hint = if upstream_ok {
        None
    } else {
        Some(view! {
            <p class="media-gallery__staleness" role="status">
                "Could not refresh from the AppView — showing the most-recent cached set."
            </p>
        })
    };

    view! {
        <header class="media-gallery__header">
            <h3 class="media-gallery__title">"Subject media"</h3>
            <p class="media-gallery__counter" role="status" aria-live="polite">
                "Image "{move || index.get() + 1}" of "{total}
            </p>
        </header>

        {staleness_hint}

        <div class="media-gallery__stage">
            <button
                type="button"
                class="media-gallery__nav media-gallery__nav--prev"
                on:click=go_prev
                aria-label="Previous image"
                disabled=move || total <= 1
            >
                "◀"
            </button>

            <div class="media-gallery__frame">
                {move || {
                    let i = index.get();
                    let blob = blobs_for_view.get(i).or_else(|| blobs_for_view.first());
                    let Some(blob) = blob else { return ().into_any() };
                    render_active_frame(&owner_did_owned, blob)
                }}
            </div>

            <button
                type="button"
                class="media-gallery__nav media-gallery__nav--next"
                on:click=go_next
                aria-label="Next image"
                disabled=move || total <= 1
            >
                "▶"
            </button>
        </div>

        <div class="media-gallery__dots" role="tablist" aria-label="Image selector">
            {dots}
        </div>
    }
    .into_any()
}

/// Render the active image + its caption block.
///
/// Broken out so the reactive frame closure inside `render_ready`
/// stays small and the alt-text + post-link rendering can be
/// reasoned about independently of the carousel navigation.
///
/// `subject_did_fallback` is the subject's own DID — used as the
/// CDN-URL authority only when the row predates the
/// per-image-owner column (migration 0032). New rows persist the
/// authoring repo's DID on the blob itself; the fallback is the
/// safe-by-construction default for any subject-authored row.
///
/// Cfg-gated to wasm: only called from [`render_ready`].
#[cfg(target_arch = "wasm32")]
fn render_active_frame(subject_did_fallback: &str, blob: &SubjectMediaBlob) -> AnyView {
    let owner_did = blob.owner_did.as_deref().unwrap_or(subject_did_fallback);
    let src = bsky_cdn_image_url(owner_did, &blob.blob_cid);
    let bsky_web_url = at_post_uri_to_bsky_url(&blob.post_uri);
    let alt_text = blob.alt_text.clone();
    let original_at_uri = blob.post_uri.clone();
    let posted_label = blob.post_indexed_at.map(format_posted_at);
    // The `<img alt="">` attribute MUST be set even when the
    // author did not provide alt text. The fallback names the
    // surface so a screen-reader announces "image attached to
    // post …" rather than the raw blob CID.
    let alt_for_img = alt_text
        .clone()
        .unwrap_or_else(|| format!("Image attached to post {}", blob.post_uri));

    view! {
        <div class="media-gallery__image-wrap">
            <MediaPreview
                src=src
                alt=alt_for_img
                kind=MediaKind::Image
            />
        </div>
        <div class="media-gallery__caption">
            {match alt_text {
                Some(text) => view! {
                    <div class="media-gallery__alt media-gallery__alt--present">
                        <p class="media-gallery__alt-label">
                            "Alt text (author provided)"
                        </p>
                        <p class="media-gallery__alt-body">{text}</p>
                    </div>
                }.into_any(),
                None => view! {
                    <p class="media-gallery__alt media-gallery__alt--missing" role="status">
                        "No alt text provided by author."
                    </p>
                }.into_any(),
            }}
            {posted_label.map(|label| view! {
                <p class="media-gallery__posted-at" role="status">
                    {label}
                </p>
            })}
            <p class="media-gallery__post">
                <span class="media-gallery__post-label">"Original post: "</span>
                {match bsky_web_url {
                    Some(url) => view! {
                        <a
                            class="media-gallery__post-link"
                            href=url
                            target="_blank"
                            rel="noreferrer"
                        >
                            <code class="media-gallery__post-uri">
                                {original_at_uri.clone()}
                            </code>
                        </a>
                    }.into_any(),
                    None => view! {
                        <code class="media-gallery__post-uri">
                            {original_at_uri.clone()}
                        </code>
                    }.into_any(),
                }}
            </p>
        </div>
    }
    .into_any()
}

/// Format a post-indexed timestamp for the carousel caption.
///
/// Renders as `Posted YYYY-MM-DD HH:MM UTC` so the moderator can
/// correlate each image with its publication time without
/// pulling up a separate tool. UTC explicitly so the rendered
/// string does not silently depend on the browser's locale
/// (moderation forensics value timestamps that match server logs).
///
/// Cfg-gated to wasm: only called from [`render_active_frame`].
#[cfg(target_arch = "wasm32")]
fn format_posted_at(ts: chrono::DateTime<chrono::Utc>) -> String {
    format!("Posted {}", ts.format("%Y-%m-%d %H:%M UTC"))
}

/// Build the Bluesky-CDN thumbnail URL for an ATProto image blob.
///
/// Format reference:
/// `https://cdn.bsky.app/img/feed_thumbnail/plain/<did>/<blob_cid>@jpeg`
///
/// The CDN honours both `bafkrei…` content-addressed CIDs and the
/// legacy multibase-v1 form. The function does not URL-encode the
/// path components because DIDs and CIDs use a safe charset (the
/// ATProto spec restricts both to ASCII alphanumerics + a few
/// non-special punctuation marks).
///
/// Cfg-gated to wasm: only called from [`render_active_frame`].
#[cfg(target_arch = "wasm32")]
fn bsky_cdn_image_url(owner_did: &str, blob_cid: &str) -> String {
    format!("https://cdn.bsky.app/img/feed_thumbnail/plain/{owner_did}/{blob_cid}@jpeg")
}

/// Convert an ATProto post AT-URI to the browser-navigable Bluesky
/// web URL.
///
/// Same shape as the helper in
/// [`crate::components::network_panel`] — kept inline (rather than
/// re-exported) so the gallery has no inbound coupling on the
/// network-panel module's public surface. Returns `None` for
/// non-`at://` inputs or for collections other than
/// `app.bsky.feed.post`.
///
/// Cfg-gated to wasm: only called from [`render_active_frame`].
#[cfg(target_arch = "wasm32")]
fn at_post_uri_to_bsky_url(at_uri: &str) -> Option<String> {
    let rest = at_uri.strip_prefix("at://")?;
    let mut parts = rest.splitn(3, '/');
    let did = parts.next()?;
    let collection = parts.next()?;
    let rkey = parts.next()?;
    if did.is_empty() || rkey.is_empty() {
        return None;
    }
    if collection != "app.bsky.feed.post" {
        return None;
    }
    Some(format!("https://bsky.app/profile/{did}/post/{rkey}"))
}

#[cfg(all(test, target_arch = "wasm32"))]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn format_posted_at_renders_utc_explicitly() {
        // Locale-independent: the rendered string must include
        // "UTC" so a moderator reading the timestamp never has
        // to guess whether it matches server logs.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-15T12:34:56Z")
            .expect("RFC3339 parses")
            .with_timezone(&chrono::Utc);
        assert_eq!(format_posted_at(ts), "Posted 2026-05-15 12:34 UTC");
    }

    #[test]
    fn format_posted_at_uses_iso_date_shape() {
        // Year-Month-Day is unambiguous; en-US-style ordering
        // is not. Verify the leading segment is the year.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
            .expect("RFC3339 parses")
            .with_timezone(&chrono::Utc);
        let rendered = format_posted_at(ts);
        assert!(rendered.starts_with("Posted 2026-01-02"));
    }

    #[test]
    fn cdn_url_has_expected_shape() {
        let url = bsky_cdn_image_url("did:plc:abc", "bafkreiabc");
        assert_eq!(
            url,
            "https://cdn.bsky.app/img/feed_thumbnail/plain/did:plc:abc/bafkreiabc@jpeg"
        );
    }

    #[test]
    fn cdn_url_preserves_did_form_for_did_plc() {
        let url = bsky_cdn_image_url("did:plc:dzvxvsiy3maw4iarpvizsj67", "bafkreitest");
        assert!(url.contains("did:plc:dzvxvsiy3maw4iarpvizsj67"));
    }

    #[test]
    fn cdn_url_includes_jpeg_format_suffix() {
        let url = bsky_cdn_image_url("did:plc:x", "bafkreix");
        assert!(url.ends_with("@jpeg"));
    }

    #[test]
    fn at_post_uri_to_bsky_url_rewrites_canonical_shape() {
        let url = at_post_uri_to_bsky_url("at://did:plc:abc/app.bsky.feed.post/3kfoo");
        assert_eq!(
            url.as_deref(),
            Some("https://bsky.app/profile/did:plc:abc/post/3kfoo"),
        );
    }

    #[test]
    fn at_post_uri_to_bsky_url_rejects_non_post_collection() {
        assert!(at_post_uri_to_bsky_url("at://did:plc:x/app.bsky.graph.list/abc").is_none());
    }

    #[test]
    fn at_post_uri_to_bsky_url_rejects_non_atproto_scheme() {
        assert!(at_post_uri_to_bsky_url("https://example.com/x").is_none());
        assert!(at_post_uri_to_bsky_url("").is_none());
    }

    #[test]
    fn at_post_uri_to_bsky_url_rejects_missing_rkey() {
        assert!(at_post_uri_to_bsky_url("at://did:plc:x/app.bsky.feed.post/").is_none());
        assert!(at_post_uri_to_bsky_url("at://did:plc:x/app.bsky.feed.post").is_none());
    }
}
