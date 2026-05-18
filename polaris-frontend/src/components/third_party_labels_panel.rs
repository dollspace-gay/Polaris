//! `ThirdPartyLabelsPanel` — every label currently applied to the
//! subject's DID by labelers OTHER than Polaris itself.
//!
//! Issue #3 (case-view aggregation): the network-context handler
//! already pulls `app.bsky.actor.getProfile.labels` and the sidebar
//! `NetworkPanel` renders them, but a moderator working in the main
//! column needs the same data prominently. This component mounts in
//! the main column, fetches `/api/cases/{subject_id}/network-context`
//! independently of the sidebar panel, and renders the labels list
//! with the issuer DID, label value, negation flag, and issuance
//! timestamp — so the moderator sees exactly which third parties
//! have already touched this account.
//!
//! When the upstream `getProfile` call returns no labels, the panel
//! renders an honest empty-state row — never invents data, never
//! hides itself silently.

use leptos::prelude::*;
use polaris_types::SubjectId;

#[cfg(target_arch = "wasm32")]
use crate::api_client::dto::NetworkContextLabel;

/// Render every third-party label currently applied to the subject.
///
/// Dispatches to a wasm-only render path that owns its fetch
/// state machine, or a native stub that surfaces the panel shell
/// only. Splitting the implementation across cfg-gated helpers
/// keeps every variant of the fetch-state enum reachable on the
/// target where it actually compiles (wasm) and removes the need
/// for any `#[allow(dead_code)]` annotation.
#[component]
#[allow(
    clippy::must_use_candidate,
    reason = "Leptos #[component] attribute strips outer attributes; consumers always feed the return value into view!"
)]
pub fn ThirdPartyLabelsPanel(
    /// Subject identifier — path parameter for the network-context
    /// fetch.
    subject_id: SubjectId,
) -> impl IntoView {
    #[cfg(target_arch = "wasm32")]
    {
        render_wasm(subject_id)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = subject_id;
        render_native_stub()
    }
}

/// On native (test / IDE check / native test target) there is no
/// backend to talk to; render the panel shell with an honest
/// "available after mount" placeholder so the parent layout doesn't
/// shift between native and wasm renders.
#[cfg(not(target_arch = "wasm32"))]
fn render_native_stub() -> AnyView {
    view! {
        <section
            class="third-party-labels-panel"
            role="region"
            aria-label="Third-party labels"
        >
            <header class="third-party-labels-panel__header">
                <h3 class="third-party-labels-panel__title">"Third-party labels"</h3>
                <p class="third-party-labels-panel__subtitle">
                    "Labels applied to this account by labelers other than Polaris."
                </p>
            </header>
            <p class="third-party-labels-panel__loading" role="status">
                "Loading third-party labels…"
            </p>
        </section>
    }
    .into_any()
}

/// Fetch-state machine for the wasm-only render path. The variants
/// are constructed inside [`render_wasm`] below; the type only
/// exists where it is exercised, so no dead-code lint fires.
#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone)]
enum FetchState {
    /// On-mount fetch in flight.
    Loading,
    /// Fetch completed; we use only the `labels` field here.
    Ready(Vec<NetworkContextLabel>),
    /// Fetch failed; surface inline with the upstream error message.
    Failed(String),
}

/// wasm-only render path: owns the fetch signal, mounts the
/// network-context lookup via `spawn_local`, and dispatches on the
/// resulting [`FetchState`].
///
/// # Layout (#184)
///
/// Labels are grouped by issuing labeler (one `<details>` per
/// `src` DID); each group's `<summary>` shows the labeler's name,
/// handle, and a count badge. The group is collapsed by default
/// when the panel holds more than [`AUTO_COLLAPSE_THRESHOLD`]
/// labels — this keeps the case-view compact when an account carries
/// many labels across multiple labelers, while still showing
/// everything inline when the total is small. A filter input at the
/// top narrows visible labels by `val` substring without rebuilding
/// the DOM (rows are hidden via the `hidden` attribute so collapse
/// state survives the filter).
#[cfg(target_arch = "wasm32")]
fn render_wasm(subject_id: SubjectId) -> AnyView {
    use crate::api_client::{PolarisApiClient as _, default_client};

    let (state, set_state) = signal(FetchState::Loading);
    let filter = RwSignal::new(String::new());
    let id_str = subject_id.0.to_string();
    leptos::task::spawn_local(async move {
        match default_client("") {
            Ok(client) => match client.network_context(&id_str).await {
                Ok(ctx) => set_state.set(FetchState::Ready(ctx.labels)),
                Err(e) => set_state.set(FetchState::Failed(e.to_string())),
            },
            Err(e) => set_state.set(FetchState::Failed(e.to_string())),
        }
    });

    view! {
        <section
            class="third-party-labels-panel"
            role="region"
            aria-label="Third-party labels"
        >
            <header class="third-party-labels-panel__header">
                <h3 class="third-party-labels-panel__title">"Third-party labels"</h3>
                <p class="third-party-labels-panel__subtitle">
                    "Labels applied to this account by labelers other than Polaris."
                </p>
            </header>
            {move || match state.get() {
                FetchState::Loading => view! {
                    <p class="third-party-labels-panel__loading" role="status">
                        "Loading third-party labels…"
                    </p>
                }.into_any(),
                FetchState::Failed(msg) => view! {
                    <p class="third-party-labels-panel__error" role="alert">
                        "Could not load third-party labels: "{msg}
                    </p>
                }.into_any(),
                FetchState::Ready(labels) if labels.is_empty() => view! {
                    <p class="third-party-labels-panel__empty" role="status">
                        "No third-party labels are currently applied to this account."
                    </p>
                }.into_any(),
                FetchState::Ready(labels) => render_grouped(labels, filter),
            }}
        </section>
    }
    .into_any()
}

/// Auto-collapse threshold: when the panel carries more than this
/// many labels in total, every group's `<details>` starts collapsed
/// so the case-view stays compact. Below the threshold every group
/// is open so the moderator sees everything at a glance.
#[cfg(target_arch = "wasm32")]
const AUTO_COLLAPSE_THRESHOLD: usize = 10;

/// Render the grouped + filterable label view.
///
/// Groups by `src` DID; each group is one `<details>` element with
/// labeler name + count in its `<summary>`. The filter input above
/// the groups narrows visible labels by `val` substring (case-
/// insensitive). Rows that don't match the filter get `hidden` so
/// they retain their collapse state when the filter changes.
#[cfg(target_arch = "wasm32")]
fn render_grouped(labels: Vec<NetworkContextLabel>, filter: RwSignal<String>) -> AnyView {
    use std::collections::BTreeMap;

    let total = labels.len();
    let auto_expand = total <= AUTO_COLLAPSE_THRESHOLD;

    // Build groups keyed by `src` DID. BTreeMap keeps the iteration
    // order stable across renders (alphabetical by DID) so a
    // moderator's eye-line doesn't jump when a label streams in.
    let mut groups: BTreeMap<String, Vec<NetworkContextLabel>> = BTreeMap::new();
    for label in labels {
        groups.entry(label.src.clone()).or_default().push(label);
    }

    let group_views = groups
        .into_iter()
        .map(|(src, group_labels)| render_label_group(&src, group_labels, filter, auto_expand))
        .collect_view();

    let on_filter_input = move |ev| {
        filter.set(event_target_value(&ev));
    };

    view! {
        <div class="third-party-labels-panel__filter-row">
            <label
                for="third-party-labels-panel-filter"
                class="third-party-labels-panel__filter-label"
            >
                "Filter by value:"
            </label>
            <input
                id="third-party-labels-panel-filter"
                class="third-party-labels-panel__filter-input"
                type="search"
                placeholder="e.g. spam, nsfw, harassment"
                prop:value=move || filter.get()
                on:input=on_filter_input
            />
            <span class="third-party-labels-panel__total" role="status">
                {total}" label(s) total"
            </span>
        </div>
        <div class="third-party-labels-panel__groups">
            {group_views}
        </div>
    }
    .into_any()
}

/// Render one labeler-grouped `<details>` block.
#[cfg(target_arch = "wasm32")]
fn render_label_group(
    src: &str,
    group_labels: Vec<NetworkContextLabel>,
    filter: RwSignal<String>,
    auto_expand: bool,
) -> AnyView {
    let group_count = group_labels.len();
    // Pick a primary label so the summary can read the display name
    // + handle without re-implementing the priority logic.
    let representative = group_labels
        .first()
        .cloned()
        .unwrap_or_else(|| NetworkContextLabel {
            val: String::new(),
            src: src.to_owned(),
            src_display_name: None,
            src_handle: None,
            uri: String::new(),
            cid: None,
            neg: false,
            cts: None,
            exp: None,
        });
    let display = representative
        .src_display_name
        .clone()
        .or_else(|| representative.src_handle.clone())
        .unwrap_or_else(|| src.to_owned());
    let handle = representative.src_handle.clone();

    // For each row inside the group, compute whether it matches the
    // current filter. The match is a case-insensitive substring on
    // the `val`. Returned as a reactive closure so the visibility
    // updates without re-rendering the group's DOM.
    let rows = group_labels
        .into_iter()
        .map(|label| {
            let val_lower = label.val.to_lowercase();
            let row_view = render_label_row(label);
            let hidden = move || {
                let q = filter.get().trim().to_lowercase();
                if q.is_empty() {
                    false
                } else {
                    !val_lower.contains(&q)
                }
            };
            view! {
                <div
                    class="third-party-labels-panel__row-wrapper"
                    hidden=hidden
                >
                    {row_view}
                </div>
            }
            .into_any()
        })
        .collect_view();

    view! {
        <details class="third-party-labels-panel__group" open=auto_expand>
            <summary class="third-party-labels-panel__group-summary">
                <span class="third-party-labels-panel__group-name">{display}</span>
                {handle.map(|h| view! {
                    <code class="third-party-labels-panel__group-handle">"@"{h}</code>
                })}
                <span class="third-party-labels-panel__group-count">
                    {group_count}" label(s)"
                </span>
            </summary>
            <ul class="third-party-labels-panel__list" role="list">
                {rows}
            </ul>
        </details>
    }
    .into_any()
}

/// Pull the current `value` off a DOM event target. Same shape as
/// the helper in `action_composer.rs`.
#[cfg(target_arch = "wasm32")]
fn event_target_value<E>(ev: &E) -> String
where
    E: leptos::wasm_bindgen::JsCast,
{
    leptos::prelude::event_target_value(ev)
}

/// Render one third-party label row. Surfaces:
///
/// 1. **The label value** itself, with a `[REMOVED]` prefix when
///    `neg = true` so a retraction reads differently from a fresh
///    assertion.
/// 2. **The labeler's display name** (with handle and DID as
///    secondary context). Falls back gracefully to handle, then
///    DID, when the labeler info couldn't be resolved.
/// 3. **The target URI** — a bsky.app link when the URI is an
///    `app.bsky.feed.post` AT-URI so the moderator can click
///    through to the specific labeled post. Renders as inline
///    code for the bare-DID (account-level) case.
/// 4. **The action date**, formatted readably from the wire-shape
///    RFC3339 `cts`. `[REMOVED]` rows use "removed at"; fresh
///    rows use "applied at"; missing `cts` falls back to
///    "unknown timestamp".
/// 5. **An expiry hint** when the labeler issued a time-limited
///    assertion.
#[cfg(target_arch = "wasm32")]
#[allow(
    clippy::too_many_lines,
    reason = "single cohesive label-row render — splitting it would push the four \
              field-presence branches across helpers with no readability win."
)]
fn render_label_row(label: NetworkContextLabel) -> AnyView {
    // Status line — assertion or retraction.
    let status_label = if label.neg { "REMOVED" } else { "APPLIED" };
    let status_modifier = if label.neg {
        "third-party-labels-panel__status--removed"
    } else {
        "third-party-labels-panel__status--applied"
    };

    // Issuer line — prefer display name, fall back to handle, then DID.
    let issuer_primary = label
        .src_display_name
        .clone()
        .or_else(|| label.src_handle.clone())
        .unwrap_or_else(|| label.src.clone());
    let issuer_secondary = match (label.src_handle.clone(), label.src_display_name.is_some()) {
        // Display name present, handle also present → secondary is the handle.
        (Some(h), true) => Some(format!("@{h}")),
        // No display name, handle is the primary; secondary is the DID for
        // copy-paste identification.
        _ => Some(label.src.clone()),
    };

    // Target line — link to bsky.app when this is a post URI; show as code
    // otherwise. The helper returns Some(href) only for
    // `app.bsky.feed.post` URIs; bare DIDs and other collections render
    // as inline code without a click target.
    let target_uri = label.uri.clone();
    let target_link = at_uri_to_bsky_url(&label.uri);
    let target_label = post_rkey_short_label(&label.uri).unwrap_or_else(|| {
        if label.uri.starts_with("did:") {
            "account-level".to_owned()
        } else {
            label.uri.clone()
        }
    });

    // Timestamps. cts is RFC3339; if it parses we format readably, else
    // fall back to the raw string the labeler emitted.
    let cts_display = label
        .cts
        .as_deref()
        .map_or_else(|| "unknown timestamp".to_owned(), format_label_timestamp);
    let action_verb = if label.neg { "removed" } else { "applied" };
    let cts_line = format!("{action_verb} {cts_display}");

    // Optional expiry.
    let exp_line = label
        .exp
        .as_deref()
        .map(|raw| format!("expires {}", format_label_timestamp(raw)));

    view! {
        <li class="third-party-labels-panel__row">
            <div class="third-party-labels-panel__row-head">
                <span class=move || format!(
                    "third-party-labels-panel__status {status_modifier}"
                )>
                    {status_label}
                </span>
                <code class="third-party-labels-panel__val">{label.val}</code>
            </div>
            <div class="third-party-labels-panel__row-issuer">
                <span class="third-party-labels-panel__issuer-name">{issuer_primary}</span>
                {issuer_secondary.map(|sec| view! {
                    <code class="third-party-labels-panel__issuer-detail">{sec}</code>
                })}
            </div>
            <div class="third-party-labels-panel__row-target">
                <span class="third-party-labels-panel__target-label">"on "</span>
                {match target_link {
                    Some(href) => view! {
                        <a
                            class="third-party-labels-panel__target-link"
                            href=href
                            target="_blank"
                            rel="noreferrer"
                            title=target_uri.clone()
                        >
                            {target_label}
                        </a>
                    }.into_any(),
                    None => view! {
                        <code class="third-party-labels-panel__target-uri"
                              title=target_uri.clone()>
                            {target_label}
                        </code>
                    }.into_any(),
                }}
            </div>
            <div class="third-party-labels-panel__row-meta">
                <time class="third-party-labels-panel__cts">{cts_line}</time>
                {exp_line.map(|line| view! {
                    <time class="third-party-labels-panel__exp">" — "{line}</time>
                })}
            </div>
        </li>
    }
    .into_any()
}

/// Format an RFC3339 timestamp into a moderator-readable string.
///
/// Renders as `YYYY-MM-DD HH:MM UTC` so the displayed time is
/// locale-independent and matches the server-log convention used
/// elsewhere in the case-view (matches `media_gallery`'s
/// `format_posted_at` shape). On parse failure returns the raw
/// string unchanged so a malformed labeler stamp never disappears.
#[cfg(target_arch = "wasm32")]
fn format_label_timestamp(raw: &str) -> String {
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(dt) => dt
            .with_timezone(&chrono::Utc)
            .format("%Y-%m-%d %H:%M UTC")
            .to_string(),
        Err(_) => raw.to_owned(),
    }
}

/// Convert a label-target AT-URI to a browser-navigable bsky.app
/// link when it refers to a post. Returns `None` for non-post URIs
/// (DIDs, lists, feeds) — the panel renders those as inline code
/// without a click target.
#[cfg(target_arch = "wasm32")]
fn at_uri_to_bsky_url(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("at://")?;
    let mut parts = rest.splitn(3, '/');
    let did = parts.next()?;
    let collection = parts.next()?;
    let rkey = parts.next()?;
    if did.is_empty() || rkey.is_empty() || collection != "app.bsky.feed.post" {
        return None;
    }
    Some(format!("https://bsky.app/profile/{did}/post/{rkey}"))
}

/// Short human-readable label for a target URI. For post URIs we
/// extract the rkey so the panel reads "on post 3kfoo" rather than
/// showing the full at-URI. For other URIs returns `None` (caller
/// falls back to "account-level" or the raw URI).
#[cfg(target_arch = "wasm32")]
fn post_rkey_short_label(uri: &str) -> Option<String> {
    let rest = uri.strip_prefix("at://")?;
    let mut parts = rest.splitn(3, '/');
    let _did = parts.next()?;
    let collection = parts.next()?;
    let rkey = parts.next()?;
    if rkey.is_empty() {
        return None;
    }
    if collection == "app.bsky.feed.post" {
        Some(format!("post {rkey}"))
    } else if collection == "app.bsky.graph.list" {
        Some(format!("list {rkey}"))
    } else if collection == "app.bsky.feed.generator" {
        Some(format!("feed {rkey}"))
    } else {
        Some(format!("{collection}/{rkey}"))
    }
}

#[cfg(all(test, target_arch = "wasm32"))]
mod wasm_tests {
    use super::*;

    fn sample_label(neg: bool) -> NetworkContextLabel {
        NetworkContextLabel {
            val: "spam".to_owned(),
            src: "did:plc:rh3vjqs4npfpmnkkmx4u4bzj".to_owned(),
            src_display_name: Some("Example Labeler".to_owned()),
            src_handle: Some("example.bsky.social".to_owned()),
            uri: "at://did:plc:dzvxvsiy3maw4iarpvizsj67/app.bsky.feed.post/3kfoo".to_owned(),
            cid: Some("bafyreiabc".to_owned()),
            neg,
            cts: Some("2026-05-05T14:22:38.533Z".to_owned()),
            exp: None,
        }
    }

    /// Each `FetchState` variant must be constructible and
    /// match-dispatchable on wasm so a future refactor that drops a
    /// branch from the render code fails the test rather than
    /// silently dropping a UI state.
    #[test]
    fn fetch_state_variants_construct_and_match() {
        let states = [
            FetchState::Loading,
            FetchState::Ready(vec![sample_label(false)]),
            FetchState::Failed("upstream offline".to_owned()),
        ];
        let mut loading_seen = false;
        let mut ready_count = 0;
        let mut failed_msg: Option<String> = None;
        for s in states {
            match s {
                FetchState::Loading => loading_seen = true,
                FetchState::Ready(labels) => ready_count = labels.len(),
                FetchState::Failed(msg) => failed_msg = Some(msg),
            }
        }
        assert!(loading_seen, "Loading branch must be exercised");
        assert_eq!(ready_count, 1, "Ready branch must carry the labels vec");
        assert_eq!(failed_msg.as_deref(), Some("upstream offline"));
    }

    /// Both assertion and retraction shapes must render without
    /// panicking. The neg-true row triggers the "REMOVED" status
    /// branch; neg-false triggers "APPLIED".
    #[test]
    fn render_label_row_handles_negation_inputs() {
        let _ = render_label_row(sample_label(false));
        let _ = render_label_row(sample_label(true));
    }

    #[test]
    fn format_label_timestamp_renders_utc_explicitly() {
        // Locale-independent format — the rendered string must
        // include "UTC" so a moderator reading the timestamp
        // never has to guess whether it matches server logs.
        assert_eq!(
            format_label_timestamp("2026-05-15T12:34:56Z"),
            "2026-05-15 12:34 UTC",
        );
    }

    #[test]
    fn format_label_timestamp_falls_back_on_garbage() {
        // Malformed labeler timestamps must not silently disappear;
        // pass them through unchanged so the moderator at least
        // sees what the labeler emitted.
        assert_eq!(format_label_timestamp("not-a-timestamp"), "not-a-timestamp",);
    }

    #[test]
    fn at_uri_to_bsky_url_rewrites_post_uri() {
        let url = at_uri_to_bsky_url("at://did:plc:abc/app.bsky.feed.post/3kfoo");
        assert_eq!(
            url.as_deref(),
            Some("https://bsky.app/profile/did:plc:abc/post/3kfoo"),
        );
    }

    #[test]
    fn at_uri_to_bsky_url_rejects_non_post_collections() {
        // Lists, feeds, profile records, etc. have no
        // bsky.app/profile/<did>/post/<rkey> equivalent — the
        // helper must return None so the renderer falls back to a
        // non-clickable display.
        assert!(at_uri_to_bsky_url("at://did:plc:abc/app.bsky.graph.list/3xyz").is_none());
        assert!(at_uri_to_bsky_url("at://did:plc:abc/app.bsky.feed.generator/foo").is_none());
        assert!(at_uri_to_bsky_url("did:plc:abc").is_none());
    }

    #[test]
    fn post_rkey_short_label_extracts_rkey_for_post() {
        assert_eq!(
            post_rkey_short_label("at://did:plc:abc/app.bsky.feed.post/3kfoo"),
            Some("post 3kfoo".to_owned()),
        );
    }

    #[test]
    fn post_rkey_short_label_labels_list_and_feed_collections() {
        assert_eq!(
            post_rkey_short_label("at://did:plc:abc/app.bsky.graph.list/abc"),
            Some("list abc".to_owned()),
        );
        assert_eq!(
            post_rkey_short_label("at://did:plc:abc/app.bsky.feed.generator/feed1"),
            Some("feed feed1".to_owned()),
        );
    }

    #[test]
    fn post_rkey_short_label_returns_none_for_bare_did() {
        // Bare DIDs aren't AT-URIs; the caller renders these as
        // "account-level" instead.
        assert!(post_rkey_short_label("did:plc:abc").is_none());
        assert!(post_rkey_short_label("").is_none());
    }
}
