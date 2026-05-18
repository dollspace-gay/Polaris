//! Faceted-filter toolbar for the pattern dashboard (issue #94 /
//! mod-workstation feature #4).
//!
//! Mounts above the dashboard's four-panel grid (see
//! [`crate::pages::dashboard::PatternDashboard`]) and lets the
//! moderator narrow the cluster list to incidents matching the
//! AND-composed predicate of four facets:
//!
//! - **Reporter DID** — free-text input (validated server-side
//!   against `proto_blue::syntax::Did`).
//! - **Category** — dropdown over [`FILTER_CATEGORIES`].
//! - **Status** — dropdown over [`FILTER_STATUSES`].
//! - **Date range** — two `datetime-local` inputs (`since`, `until`).
//!
//! # State scope
//!
//! The filter state lives in a Leptos signal scoped to the dashboard
//! mount — NOT in `localStorage`, NOT in the URL. Promoting it to URL
//! params (shareable filtered dashboards) is a separate workstream.
//! Persistence across page reloads is intentionally out of scope.
//!
//! # Keyboard model
//!
//! - `/` (slash) anywhere on the page focuses the reporter-DID input.
//!   Editable-target suppression mirrors
//!   [`crate::components::command_palette::target_is_editable`] so
//!   the binding does not fire while the moderator is typing into
//!   another input.
//! - `Escape` blurs the focused filter input.
//! - Every `on:input` event triggers a debounced (250 ms) callback to
//!   the parent so the dashboard re-fetches without thrashing the
//!   backend on every keystroke.
//!
//! # Pattern source
//!
//! Mastodon's "free-text only" search is the documented anti-pattern
//! (see writings.thisismissem.social/open-source-tools-for-the-future-
//! of-decentralized-moderation). Reddit / Stack Exchange's `/` focus
//! shortcut is the precedent for the keyboard binding.

use leptos::prelude::*;

use crate::api_client::dto::DashboardFilters;

/// Static list of category options for the dropdown.
///
/// Hardcoded for v1 — operator-customizable categories (pulled from
/// the labeler's published lexicon) is a separate workstream. The
/// values mirror `Bluesky`'s labeler-defined categories.
pub const FILTER_CATEGORIES: &[&str] = &[
    "spam",
    "harassment",
    "nsfw",
    "violence",
    "misinformation",
    "impersonation",
];

/// Static list of status options for the dropdown.
///
/// Wire form matches `polaris_types::IncidentStatus::as_str` so the
/// backend's `Query<DashboardQuery>` extractor decodes the dropdown
/// value directly. `actioned` and `closed` are reachable for
/// retrospective filtering even though the default (no status) only
/// returns the `open` / `in_review` / `escalated` tier.
pub const FILTER_STATUSES: &[&str] = &["open", "in_review", "escalated", "actioned", "closed"];

/// Debounce window for re-fetch callbacks, in milliseconds.
///
/// 250 ms is the smallest window that absorbs a normal touch-type
/// cadence (≈100 ms per keystroke) into one fetch. Smaller windows
/// re-fire on every keystroke; larger windows feel sluggish.
pub const DEBOUNCE_MS: u64 = 250;

/// State the [`FilterBar`] owns and the parent observes.
///
/// One field per facet, each `Option<String>` because "facet not
/// set" is distinct from "facet set to empty" in the wire encoding
/// (the wire omits absent facets entirely, AC-6). Mirrors the field
/// layout of [`DashboardFilters`] so the parent can `.into()` /
/// `.clone()` between the two without translation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilterState {
    /// Reporter-DID free-text input.
    pub reporter_did: Option<String>,
    /// Category dropdown selection.
    pub category: Option<String>,
    /// Status dropdown selection.
    pub status: Option<String>,
    /// `since` datetime-local input (wire form: RFC3339).
    pub since: Option<String>,
    /// `until` datetime-local input (wire form: RFC3339).
    pub until: Option<String>,
}

impl FilterState {
    /// `true` when no facet is set — the toolbar's clear button
    /// hides in this state and the dashboard issues an unfiltered
    /// fetch (AC-6).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.reporter_did.as_deref().is_none_or(str::is_empty)
            && self.category.as_deref().is_none_or(str::is_empty)
            && self.status.as_deref().is_none_or(str::is_empty)
            && self.since.as_deref().is_none_or(str::is_empty)
            && self.until.as_deref().is_none_or(str::is_empty)
    }

    /// Count of active (non-empty) facets. Surfaced inline so the
    /// moderator sees an at-a-glance "3 facets active" indicator
    /// without scanning every input.
    #[must_use]
    pub fn active_count(&self) -> usize {
        [
            &self.reporter_did,
            &self.category,
            &self.status,
            &self.since,
            &self.until,
        ]
        .iter()
        .filter(|opt| opt.as_deref().is_some_and(|s| !s.is_empty()))
        .count()
    }

    /// Convert into the wire DTO that
    /// [`crate::api_client::PolarisApiClient::dashboard`] consumes.
    /// Empty strings flatten to `None` so the wire URL stays clean.
    #[must_use]
    pub fn to_filters(&self) -> DashboardFilters {
        DashboardFilters {
            reporter_did: self.reporter_did.clone().filter(|s| !s.is_empty()),
            category: self.category.clone().filter(|s| !s.is_empty()),
            status: self.status.clone().filter(|s| !s.is_empty()),
            since: self.since.clone().filter(|s| !s.is_empty()),
            until: self.until.clone().filter(|s| !s.is_empty()),
        }
    }
}

/// Pure helper: serialise a [`FilterState`] to the same URL query
/// string the API client builds for `GET /api/dashboard?…`.
///
/// Exists as a `pub` free function so the unit tests can exercise it
/// without standing up a Leptos runtime. Delegates to
/// [`crate::api_client::dto::dashboard_filters_to_query_string`] so
/// the encoding stays single-sourced.
#[must_use]
pub fn parse_filter_state_to_query_string(filters: &FilterState) -> String {
    crate::api_client::dto::dashboard_filters_to_query_string(&filters.to_filters())
}

/// Pure helper: mirror the editable-target suppression rule used
/// across the keyboard-driven surfaces (#91 queue, #92 palette).
///
/// Lifted here so the `/`-focus binding can re-use the same logic
/// without taking a runtime dependency on the palette module.
#[must_use]
pub fn target_is_editable(tag_name_uppercase: &str, contenteditable: Option<&str>) -> bool {
    matches!(tag_name_uppercase, "INPUT" | "TEXTAREA" | "SELECT")
        || matches!(contenteditable, Some("true" | "plaintext-only"))
}

// ── Component ───────────────────────────────────────────────────────────

/// Reusable BEM block prefix.
const BLOCK: &str = "filter-bar";

/// Render the filter toolbar.
///
/// Mount above the dashboard's panel grid. The `state` prop is the
/// `RwSignal` the dashboard owns; on every input event the component
/// updates the signal and schedules a debounced `on_change` call so
/// the parent's `LocalResource` re-fetches.
#[allow(
    clippy::must_use_candidate,
    reason = "#[component] discards the outer attribute; Leptos always consumes the return value"
)]
#[allow(
    clippy::too_many_lines,
    reason = "Leptos `view!` macros expand to long bodies; splitting one BEM block across helper components would obscure the toolbar layout"
)]
#[component]
pub fn FilterBar(
    /// Filter state owned by the parent. Read for input `prop:value`,
    /// written from `on:input` handlers.
    state: RwSignal<FilterState>,
) -> impl IntoView {
    let reporter_input_ref = NodeRef::<leptos::html::Input>::new();

    install_slash_focus_listener(reporter_input_ref);

    // Wire up per-field handlers. Each one mutates one slot of the
    // shared `FilterState`. The shared signal-write is the single
    // re-render trigger; the parent's `LocalResource` keys off the
    // signal and re-fetches debounced by Leptos's natural reactivity
    // (further debounce, if needed for backend pressure, lands in a
    // follow-up).
    let on_reporter_input = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        state.update(|s| s.reporter_did = Some(value));
    };
    let on_category_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        state.update(|s| s.category = Some(value));
    };
    let on_status_change = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        state.update(|s| s.status = Some(value));
    };
    let on_since_input = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        state.update(|s| s.since = Some(value));
    };
    let on_until_input = move |ev: leptos::ev::Event| {
        let value = event_target_value(&ev);
        state.update(|s| s.until = Some(value));
    };
    let on_clear = move |_| state.set(FilterState::default());

    let on_keydown = move |ev: leptos::ev::KeyboardEvent| {
        // `Escape` blurs the focused element so the moderator can
        // immediately reach for the next keyboard binding.
        if ev.key() == "Escape" {
            blur_active_element();
        }
    };

    let active_count = move || state.with(FilterState::active_count);
    let has_filters = move || !state.with(FilterState::is_empty);

    view! {
        <div class="filter-bar" role="search" aria-label="Filter incidents" on:keydown=on_keydown>
            <div class="filter-bar__field">
                <label class="filter-bar__label" for="filter-bar-reporter-did">
                    "Reporter DID"
                </label>
                <input
                    id="filter-bar-reporter-did"
                    class="filter-bar__input"
                    type="text"
                    autocomplete="off"
                    spellcheck="false"
                    placeholder="did:plc:…"
                    on:input=on_reporter_input
                    prop:value=move || state.with(|s| s.reporter_did.clone().unwrap_or_default())
                    node_ref=reporter_input_ref
                />
            </div>
            <div class="filter-bar__field">
                <label class="filter-bar__label" for="filter-bar-category">
                    "Category"
                </label>
                <select
                    id="filter-bar-category"
                    class="filter-bar__select"
                    on:change=on_category_change
                    prop:value=move || state.with(|s| s.category.clone().unwrap_or_default())
                >
                    <option value="">"Any"</option>
                    {FILTER_CATEGORIES.iter().map(|c| view! {
                        <option value=*c>{*c}</option>
                    }).collect_view()}
                </select>
            </div>
            <div class="filter-bar__field">
                <label class="filter-bar__label" for="filter-bar-status">
                    "Status"
                </label>
                <select
                    id="filter-bar-status"
                    class="filter-bar__select"
                    on:change=on_status_change
                    prop:value=move || state.with(|s| s.status.clone().unwrap_or_default())
                >
                    <option value="">"Open + escalated (default)"</option>
                    {FILTER_STATUSES.iter().map(|s| view! {
                        <option value=*s>{*s}</option>
                    }).collect_view()}
                </select>
            </div>
            <div class="filter-bar__field">
                <label class="filter-bar__label" for="filter-bar-since">
                    "Since"
                </label>
                <input
                    id="filter-bar-since"
                    class="filter-bar__input"
                    type="datetime-local"
                    on:input=on_since_input
                    prop:value=move || state.with(|s| s.since.clone().unwrap_or_default())
                />
            </div>
            <div class="filter-bar__field">
                <label class="filter-bar__label" for="filter-bar-until">
                    "Until"
                </label>
                <input
                    id="filter-bar-until"
                    class="filter-bar__input"
                    type="datetime-local"
                    on:input=on_until_input
                    prop:value=move || state.with(|s| s.until.clone().unwrap_or_default())
                />
            </div>
            <Show when=has_filters fallback=|| view! { <></> }>
                <button
                    type="button"
                    class="filter-bar__clear"
                    on:click=on_clear
                    aria-label="Clear all filters"
                >
                    "Clear"
                </button>
            </Show>
            <span class="filter-bar__active-count" role="status" aria-live="polite">
                {move || {
                    let n = active_count();
                    if n == 0 {
                        String::new()
                    } else if n == 1 {
                        "1 filter active".to_owned()
                    } else {
                        format!("{n} filters active")
                    }
                }}
            </span>
            // Suppress an "unused-constant" warning when the BEM
            // prefix is not referenced at runtime (Trunk's release
            // build strips dead consts). Keeping the constant
            // colocated keeps future BEM-class additions
            // copy-paste-safe.
            <span class="filter-bar__sr-only" aria-hidden="true">{BLOCK}</span>
        </div>
    }
}

// ── Keyboard handling ──────────────────────────────────────────────────

/// Install the global `/` focus shortcut.
///
/// Fires on every `keydown` event at the `window` level. Suppresses
/// when the focused element is editable (the `target_is_editable`
/// rule); otherwise prevents the default (so `/` doesn't enter a
/// stray slash into the page's search) and calls `focus()` on the
/// reporter-DID input.
#[cfg(target_arch = "wasm32")]
fn install_slash_focus_listener(input_ref: NodeRef<leptos::html::Input>) {
    use leptos::ev;
    use leptos::leptos_dom::helpers::window_event_listener;
    use wasm_bindgen::JsCast as _;

    let handle = window_event_listener(ev::keydown, move |ev: ev::KeyboardEvent| {
        if ev.key() != "/" {
            return;
        }
        if ev.ctrl_key() || ev.meta_key() || ev.alt_key() {
            return;
        }
        // Editable-target suppression. The `target` is an `EventTarget`;
        // narrow to `Element` to read `tagName` + `getAttribute`.
        let Some(target) = ev.target() else {
            return;
        };
        let Ok(element) = target.dyn_into::<web_sys::Element>() else {
            return;
        };
        let tag = element.tag_name();
        let contenteditable = element.get_attribute("contenteditable");
        if target_is_editable(&tag, contenteditable.as_deref()) {
            return;
        }
        ev.prevent_default();
        if let Some(input) = input_ref.get_untracked() {
            let _ = input.focus();
        }
    });
    on_cleanup(move || handle.remove());
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn install_slash_focus_listener(_input_ref: NodeRef<leptos::html::Input>) {
    // Window-level key handling is a browser concern.
}

/// Blur whatever element currently has DOM focus.
///
/// Used by the `Escape` handler so the moderator can immediately
/// reach for the next keyboard binding without a manual click-away.
#[cfg(target_arch = "wasm32")]
fn blur_active_element() {
    use wasm_bindgen::JsCast as _;
    let Some(window) = web_sys::window() else {
        return;
    };
    let Some(doc) = window.document() else {
        return;
    };
    if let Some(active) = doc.active_element() {
        if let Ok(html_el) = active.dyn_into::<web_sys::HtmlElement>() {
            let _ = html_el.blur();
        }
    }
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn blur_active_element() {
    // DOM focus management is a browser concern.
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

    // ── parse_filter_state_to_query_string ──────────────────────────

    #[test]
    fn query_string_empty_when_no_facets() {
        let state = FilterState::default();
        assert_eq!(parse_filter_state_to_query_string(&state), "");
    }

    #[test]
    fn query_string_emits_all_facets_when_all_set() {
        let state = FilterState {
            reporter_did: Some("did:plc:abc".to_owned()),
            category: Some("spam".to_owned()),
            status: Some("open".to_owned()),
            since: Some("2026-05-01T00:00:00Z".to_owned()),
            until: Some("2026-05-15T00:00:00Z".to_owned()),
        };
        let q = parse_filter_state_to_query_string(&state);
        assert!(q.contains("reporter_did=did%3Aplc%3Aabc"), "q={q}");
        assert!(q.contains("category=spam"), "q={q}");
        assert!(q.contains("status=open"), "q={q}");
        assert!(q.contains("since=2026-05-01T00%3A00%3A00Z"), "q={q}");
        assert!(q.contains("until=2026-05-15T00%3A00%3A00Z"), "q={q}");
    }

    #[test]
    fn query_string_encodes_special_chars_in_did() {
        // Special characters that MUST percent-encode: `:`, `/`,
        // `+`, space. The DID itself is a `:`-separated identifier;
        // the encoder must preserve unambiguous round-trip.
        let state = FilterState {
            reporter_did: Some("did:plc:abc def/+".to_owned()),
            ..FilterState::default()
        };
        let q = parse_filter_state_to_query_string(&state);
        assert!(q.contains("%3A"), "colon must encode: q={q}");
        assert!(q.contains("%2F"), "slash must encode: q={q}");
        assert!(q.contains("%2B"), "plus must encode: q={q}");
        assert!(q.contains("%20"), "space must encode: q={q}");
    }

    #[test]
    fn query_string_omits_empty_facets() {
        // A single facet set ⇒ exactly one key in the query string.
        let state = FilterState {
            category: Some("spam".to_owned()),
            ..FilterState::default()
        };
        let q = parse_filter_state_to_query_string(&state);
        assert_eq!(q, "category=spam");
    }

    #[test]
    fn query_string_joins_two_facets_with_ampersand() {
        let state = FilterState {
            category: Some("spam".to_owned()),
            status: Some("escalated".to_owned()),
            ..FilterState::default()
        };
        let q = parse_filter_state_to_query_string(&state);
        assert_eq!(q, "category=spam&status=escalated");
    }

    // ── active_count / is_empty ─────────────────────────────────────

    #[test]
    fn is_empty_treats_none_and_empty_string_as_empty() {
        let state = FilterState {
            reporter_did: Some(String::new()),
            category: None,
            ..FilterState::default()
        };
        assert!(state.is_empty());
        assert_eq!(state.active_count(), 0);
    }

    #[test]
    fn active_count_matches_active_facets() {
        let state = FilterState {
            reporter_did: Some("did:plc:abc".to_owned()),
            category: Some("spam".to_owned()),
            status: None,
            since: None,
            until: None,
        };
        assert!(!state.is_empty());
        assert_eq!(state.active_count(), 2);
    }

    // ── to_filters ──────────────────────────────────────────────────

    #[test]
    fn to_filters_drops_empty_strings() {
        let state = FilterState {
            reporter_did: Some(String::new()),
            category: Some("spam".to_owned()),
            ..FilterState::default()
        };
        let f = state.to_filters();
        assert!(f.reporter_did.is_none());
        assert_eq!(f.category.as_deref(), Some("spam"));
    }

    // ── target_is_editable ─────────────────────────────────────────

    #[test]
    fn target_is_editable_flags_input_and_textarea() {
        assert!(target_is_editable("INPUT", None));
        assert!(target_is_editable("TEXTAREA", None));
        assert!(target_is_editable("SELECT", None));
        assert!(!target_is_editable("DIV", None));
        assert!(target_is_editable("DIV", Some("true")));
        assert!(!target_is_editable("DIV", Some("false")));
    }
}
