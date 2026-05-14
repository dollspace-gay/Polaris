//! `ReportList` — current user reports against the subject.
//!
//! Per `design.md` §5.2, the moderator sees all consolidated reports with
//! reporter context (new account vs. established, prior false-report
//! rate). For M1 the backend ships the bare [`Report`] rows; the reporter
//! context fields (reputation score, prior-rate) land in M2 alongside the
//! pattern engine. Until then, the panel renders the report category,
//! reporter DID, and body verbatim with a placeholder for reporter
//! context so the panel does not look incomplete.

use leptos::prelude::*;
use polaris_types::Report;

/// Render the subject's current reports.
///
/// # Props
///
/// - `reports`: the `reports` vector from the case view response.
///
/// # Accessibility
///
/// The container is `role="region" aria-label="Reports"`; each report is a
/// `<li>` inside a `<ul role="list">` so screen-reader list-navigation
/// shortcuts work as expected.
// See `subject_header::SubjectHeader` for the lint-allow rationale.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn ReportList(
    /// Reports vector from the case-view DTO.
    reports: Vec<Report>,
) -> impl IntoView {
    let count = reports.len();
    let rows = reports
        .into_iter()
        .map(|r| {
            let category = r.category.to_string();
            let reporter = r.reporter_did.to_string();
            let when = r.created_at.to_rfc3339();
            let body = r.body.clone();
            view! {
                <li class="report-list__item">
                    <header class="report-list__header">
                        <span class="report-list__category">{category}</span>
                        <span class="report-list__reporter">"from "<code>{reporter}</code></span>
                        <time class="report-list__when">{when}</time>
                    </header>
                    <p class="report-list__body">{body}</p>
                    <p class="report-list__placeholder" aria-hidden="true">
                        "Reporter reputation: M2 will populate."
                    </p>
                </li>
            }
        })
        .collect::<Vec<_>>();

    view! {
        <section class="report-list" role="region" aria-label="Reports">
            <h2>"Reports"</h2>
            {move || {
                if count == 0 {
                    view! {
                        <p class="report-list__empty" role="status">
                            "No active reports against this subject."
                        </p>
                    }.into_any()
                } else {
                    view! {
                        <p class="report-list__count" role="status">
                            {count}" report(s) consolidated under this case."
                        </p>
                    }.into_any()
                }
            }}
            <ul class="report-list__list" role="list">
                {rows}
            </ul>
        </section>
    }
}
