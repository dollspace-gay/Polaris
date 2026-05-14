//! `ClusterList` — incident clusters ranked by `severity × reach`.
//!
//! Renders the
//! [`crate::api_client::dto::IncidentClusterSummary`] rows from the
//! dashboard snapshot as a scrollable list. Each row is a link to the
//! subject-centric case view (`design.md` §5.2) so a moderator drills
//! straight from the dashboard into the case.
//!
//! # Accessibility
//!
//! - The list is `role="list"` with each row a `<li>` carrying a
//!   semantic `<a>` link (so screen-reader link navigation works).
//! - Severity is rendered as a text tag, not a color swatch — colour is
//!   a secondary signal per `design.md` §7.

use leptos::prelude::*;

use crate::api_client::dto::IncidentClusterSummary;

/// Render the cluster-list panel.
///
/// # Props
///
/// - `clusters` — pre-ranked cluster summaries from the snapshot.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn ClusterList(
    /// Cluster rows from the dashboard snapshot.
    clusters: Vec<IncidentClusterSummary>,
) -> impl IntoView {
    let count = clusters.len();

    if count == 0 {
        return view! {
            <section class="cluster-list" aria-label="Incident clusters">
                <h3>"Active incident clusters"</h3>
                <p class="cluster-list__empty" role="status">
                    "No open or escalated incidents at this time."
                </p>
            </section>
        }
        .into_any();
    }

    let rows: Vec<_> = clusters
        .into_iter()
        .map(|c| {
            let subject_id = c.primary_subject.to_string();
            let incident_id = c.incident_id.to_string();
            let severity = c.severity.as_str();
            let status = c.status.as_str();
            let related = c.related_subject_count;
            let opened = c.opened_at.to_rfc3339();
            let href = format!("/cases/{subject_id}");
            view! {
                <li class="cluster-list__row" data-incident=incident_id>
                    <a class="cluster-list__link" href=href>
                        <span class="cluster-list__severity">{severity}</span>
                        <span class="cluster-list__subject">
                            "subject "<code>{subject_id}</code>
                        </span>
                        <span class="cluster-list__related">
                            {related}" related subject(s)"
                        </span>
                        <span class="cluster-list__status">{status}</span>
                        <time class="cluster-list__when">{opened}</time>
                    </a>
                </li>
            }
        })
        .collect();

    view! {
        <section class="cluster-list" aria-label="Incident clusters">
            <h3>"Active incident clusters"</h3>
            <p class="cluster-list__count" role="status">
                {count}" cluster(s) ranked by severity × reach"
            </p>
            <ul class="cluster-list__list" role="list">
                {rows}
            </ul>
        </section>
    }
    .into_any()
}
