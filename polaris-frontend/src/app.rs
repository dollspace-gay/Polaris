//! Top-level [`App`] component and routing table.
//!
//! Mounted by `main.rs` via [`leptos::mount::mount_to_body`] on wasm.
//! Native builds (tests, IDE rust-analyzer) compile the component but
//! never mount it; their `main` is a no-op stub.
//!
//! # Routes
//!
//! - `/` — [`PatternDashboard`](crate::pages::dashboard::PatternDashboard)
//!   (issue #20, the pattern dashboard from `design.md` §5.1).
//! - `/cases/:subject_id` — [`CaseView`](crate::pages::case_view::CaseView)
//!   (issue #15, the subject-centric case page from `design.md` §5.2).

use leptos::prelude::*;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::pages::case_view::CaseView;
use crate::pages::dashboard::PatternDashboard;

/// Root component.
///
/// Sets up the document-level metadata context, then wires the route
/// table. Route additions land in this function as later milestones
/// introduce them.
// `clippy::must_use_candidate` would have us annotate every `#[component]`
// function with `#[must_use]`, but the `#[component]` proc macro replaces
// the function body and discards outer attributes — the lint cannot be
// satisfied at this site. The generated component is *always* consumed by
// `view!`, so the "dropped return value" hazard the lint guards against
// cannot occur for a Leptos component. Narrow allow with rationale.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title text="Polaris"/>
        <Router>
            <main id="polaris-root">
                <Routes fallback=|| view! { <p>"Not found."</p> }>
                    <Route path=path!("") view=PatternDashboard/>
                    <Route path=path!("/cases/:subject_id") view=CaseView/>
                </Routes>
            </main>
        </Router>
    }
}
