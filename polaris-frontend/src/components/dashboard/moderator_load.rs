//! `ModeratorLoadPanel` — queue depth per category.
//!
//! Bar-chart-ish per-category view: each row is a category, with the
//! `open` and `in_review` counts rendered as proportionally-sized SVG
//! bars so the moderator sees at a glance which categories are
//! backlogged. Numeric counts accompany the bars so the panel reads
//! on screen readers and without colour.

use leptos::prelude::*;

use crate::api_client::dto::ModeratorLoad;

/// SVG viewport width for the per-row mini-bars (user units).
const BAR_WIDTH: u32 = 200;
/// Per-row bar height.
const BAR_HEIGHT: u32 = 14;

/// Render the moderator-load panel.
///
/// # Props
///
/// - `load` — per-category counts.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn ModeratorLoadPanel(
    /// Per-category queue-depth rows.
    load: Vec<ModeratorLoad>,
) -> impl IntoView {
    if load.is_empty() {
        return view! {
            <section class="moderator-load" aria-label="Moderator load">
                <h3>"Moderator load"</h3>
                <p class="moderator-load__empty" role="status">
                    "No category data available."
                </p>
            </section>
        }
        .into_any();
    }

    // Normalize the bar widths across categories so the longest row fills
    // the available width — proportional, not absolute.
    let max_total = load
        .iter()
        .map(|r| r.open_count + r.in_review_count)
        .max()
        .unwrap_or(0)
        .max(1);

    let rows: Vec<_> = load
        .into_iter()
        .map(|r| {
            let open = r.open_count;
            let in_review = r.in_review_count;
            #[allow(
                clippy::cast_precision_loss,
                reason = "queue depths stay below f64 mantissa for any realistic deployment"
            )]
            let open_w = (open as f64 / max_total as f64 * f64::from(BAR_WIDTH))
                .max(0.0)
                .min(f64::from(BAR_WIDTH));
            #[allow(clippy::cast_precision_loss, reason = "see above")]
            let in_review_w = (in_review as f64 / max_total as f64 * f64::from(BAR_WIDTH))
                .max(0.0)
                .min(f64::from(BAR_WIDTH));
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "open_w / in_review_w are clamped to [0, BAR_WIDTH]"
            )]
            let open_w_u = open_w as u32;
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "see above"
            )]
            let in_review_w_u = in_review_w as u32;
            let category = r.category;
            view! {
                <li class="moderator-load__row">
                    <span class="moderator-load__category">{category}</span>
                    <svg
                        class="moderator-load__bar"
                        width=BAR_WIDTH
                        height=BAR_HEIGHT
                        viewBox=format!("0 0 {BAR_WIDTH} {BAR_HEIGHT}")
                        role="img"
                        aria-label="Queue depth bar"
                    >
                        <rect
                            class="moderator-load__bar-open"
                            x=0
                            y=0
                            width=open_w_u.max(u32::from(open > 0))
                            height=BAR_HEIGHT
                        />
                        <rect
                            class="moderator-load__bar-in-review"
                            x=open_w_u
                            y=0
                            width=in_review_w_u.max(u32::from(in_review > 0))
                            height=BAR_HEIGHT
                        />
                    </svg>
                    <span class="moderator-load__counts">
                        {open}" open / "{in_review}" in review"
                    </span>
                </li>
            }
        })
        .collect();

    view! {
        <section class="moderator-load" aria-label="Moderator load">
            <h3>"Moderator load"</h3>
            <ul class="moderator-load__list" role="list">
                {rows}
            </ul>
        </section>
    }
    .into_any()
}
