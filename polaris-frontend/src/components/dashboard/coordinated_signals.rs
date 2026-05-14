//! `CoordinatedSignalsPanel` — recent cohort / image-hash / brigade
//! observations.
//!
//! Renders the [`crate::api_client::dto::CoordinatedSignal`] rows from
//! the dashboard snapshot with a kind glyph + label + subject count
//! tuple per row. The glyph carries the discriminator on its own so the
//! panel reads on monochrome displays (`design.md` §7 accessibility
//! contract).

use leptos::prelude::*;

use crate::api_client::dto::CoordinatedSignal;

/// Render the coordinated-signals panel.
///
/// # Props
///
/// - `signals` — pattern-engine observations to surface.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn CoordinatedSignalsPanel(
    /// Coordinated-signal rows from the dashboard snapshot.
    signals: Vec<CoordinatedSignal>,
) -> impl IntoView {
    let count = signals.len();

    if count == 0 {
        return view! {
            <section class="coordinated-signals" aria-label="Coordinated signals">
                <h3>"Coordinated signals"</h3>
                <p class="coordinated-signals__empty" role="status">
                    "No recent coordinated-action observations."
                </p>
            </section>
        }
        .into_any();
    }

    let rows: Vec<_> = signals
        .into_iter()
        .map(|s| {
            let icon = s.kind.icon();
            let kind_label = s.kind.label();
            let when = s.detected_at.to_rfc3339();
            view! {
                <li class="coordinated-signals__row">
                    <span class="coordinated-signals__icon" aria-hidden="true">{icon}</span>
                    <span class="coordinated-signals__kind">{kind_label}</span>
                    <span class="coordinated-signals__label">{s.label}</span>
                    <span class="coordinated-signals__count">
                        {s.subject_count}" subject(s)"
                    </span>
                    <time class="coordinated-signals__when">{when}</time>
                </li>
            }
        })
        .collect();

    view! {
        <section class="coordinated-signals" aria-label="Coordinated signals">
            <h3>"Coordinated signals"</h3>
            <p class="coordinated-signals__count" role="status">
                {count}" recent signal(s)"
            </p>
            <ul class="coordinated-signals__list" role="list">
                {rows}
            </ul>
        </section>
    }
    .into_any()
}
