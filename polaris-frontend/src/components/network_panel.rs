//! `NetworkPanel` — placeholder for M2's network-context surface.
//!
//! Per `design.md` §5.2, the case view includes a network-context panel
//! showing follow graph, reply graph, cohort membership, and shared-image
//! clusters. The pattern engine and graph walks that feed this panel land
//! in M2; M1 ships the case page with the panel reserved so the layout
//! does not jump when M2 turns it on.
//!
//! The panel renders a clearly-worded placeholder rather than a blank
//! gap (no-blank-on-fetch contract from the issue #15 pre-flight). The
//! `network_context` field on the wire is `serde_json::Value::Null` for
//! now — we render the panel unconditionally and let M2 swap in the real
//! data view.

use leptos::prelude::*;

/// Network-context panel placeholder.
///
/// # Accessibility
///
/// The placeholder is a `role="region" aria-label="Network context"`
/// section with a status paragraph that screen readers announce when the
/// case loads. No actionable widgets live in this panel until M2.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn NetworkPanel() -> impl IntoView {
    view! {
        <section class="network-panel" role="region" aria-label="Network context">
            <h2>"Network context"</h2>
            <p class="network-panel__placeholder" role="status">
                "M2 will populate the follow graph, reply graph, cohort membership, "
                "and shared-image clusters here."
            </p>
        </section>
    }
}
