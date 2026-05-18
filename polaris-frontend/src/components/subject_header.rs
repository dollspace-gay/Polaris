//! `SubjectHeader` — the top-of-page banner for a [`Subject`].
//!
//! Renders the subject's stable identifiers (id, kind, DID, AT-URI) plus
//! the two creation timestamps from `design.md` §5.2.
//!
//! Follower / following / posting-cadence are NOT rendered here — those
//! are network-context signals owned by [`crate::components::network_panel::NetworkPanel`]
//! which fetches them from `/api/cases/{subject_id}/network-context`
//! and renders them in the case-view sidebar. Putting them here too
//! would duplicate the data fetch and the visual real-estate.
//!
//! Media preview activates when the case-view DTO actually carries
//! media URIs; until that wire-up lands, the media section renders
//! nothing rather than a placeholder.

use leptos::prelude::*;
use polaris_types::Subject;

/// Subject metadata banner.
///
/// # Props
///
/// - `subject`: the [`Subject`] row from `GET /api/cases/{subject_id}`.
///
/// # Accessibility
///
/// The banner is a `<header role="banner">` for screen readers. Each
/// metadata field uses a `<dt>`/`<dd>` pairing so its label is announced
/// alongside the value.
// `#[component]` swallows outer attributes; the standard Leptos
// `must_use_candidate` workaround applies (see `crate::app::App`). The
// `#[component]` macro also generates a `…Props` struct whose fields we
// cannot document directly (the proc-macro consumes the function param
// list and reproduces it as struct fields); the `missing_docs` allow
// scopes the exception to this one component. `needless_pass_by_value`
// fires because the body only reads borrowed slices of `subject`, but
// Leptos components conventionally take props by value (the props struct
// itself is consumed at mount), so we accept ownership rather than
// breaking the API convention.
#[allow(clippy::must_use_candidate, clippy::needless_pass_by_value)]
#[component]
pub fn SubjectHeader(
    /// Subject row from `GET /api/cases/{subject_id}`.
    subject: Subject,
) -> impl IntoView {
    let kind = subject.kind.as_str();
    let did = subject.did.as_ref().map(ToString::to_string);
    let uri = subject.uri.as_ref().map(ToString::to_string);
    let created_at = subject.created_at.to_rfc3339();
    let first_seen = subject.first_seen_by_mod.to_rfc3339();
    let id = subject.id.to_string();

    view! {
        <header class="subject-header" role="banner" aria-label="Subject metadata">
            <h1 class="subject-header__title">
                "Subject "
                <code class="subject-header__id">{id}</code>
            </h1>
            <dl class="subject-header__meta">
                <dt>"Kind"</dt>
                <dd>{kind}</dd>

                <dt>"DID"</dt>
                <dd>
                    {did.map_or_else(
                        || view! { <span class="subject-header__placeholder">"—"</span> }.into_any(),
                        |d| view! { <code>{d}</code> }.into_any(),
                    )}
                </dd>

                <dt>"AT-URI"</dt>
                <dd>
                    {uri.map_or_else(
                        || view! { <span class="subject-header__placeholder">"—"</span> }.into_any(),
                        |u| view! { <code>{u}</code> }.into_any(),
                    )}
                </dd>

                <dt>"Upstream created"</dt>
                <dd>
                    <time>{created_at}</time>
                </dd>

                <dt>"First seen by Polaris"</dt>
                <dd>
                    <time>{first_seen}</time>
                </dd>
            </dl>
        </header>
    }
}
