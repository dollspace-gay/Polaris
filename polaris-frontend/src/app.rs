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

use std::sync::Arc;

use leptos::prelude::*;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use proto_blue::lexicon::Lexicons;

use crate::pages::case_view::CaseView;
use crate::pages::dashboard::PatternDashboard;
use crate::validation::build_shared_registry;

/// Leptos context entry: the shared [`Lexicons`] registry, wrapped in
/// `Arc<Lexicons>` so cloning the handle into a component's closures is
/// cheap (`Arc::clone`) and the registry itself is built exactly once
/// at app start. The composer reads this via
/// [`use_context::<LexiconRegistry>()`].
///
/// Wrapping the [`Arc`] in a newtype lets `provide_context` /
/// `use_context` discriminate this entry from any future `Arc<T>`
/// context we might also install. `Lexicons` does not implement
/// `Debug` in `proto-blue` 0.3, so we keep the derive minimal: `Clone`
/// is all the composer needs, and the `Arc` makes the clone shallow.
#[derive(Clone)]
pub struct LexiconRegistry(pub Arc<Lexicons>);

impl std::fmt::Debug for LexiconRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Lexicons` does not impl `Debug`; surface a stable summary so
        // any `tracing` site that captures the value via `?` still
        // renders something useful.
        f.debug_struct("LexiconRegistry")
            .field("doc_count", &self.0.doc_count())
            .finish()
    }
}

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

    // Build the lexicon validation registry exactly once at app start
    // and hand it through Leptos context (REQ-13 / AC-16 — issue #34).
    // On the unreachable path where the embedded JSON fails to parse,
    // render an inline banner instead of mounting the routes: the
    // composer needs the registry to keep its 100ms inline-validation
    // contract, and silently degrading to "no validation" would let a
    // moderator submit malformed records the server will reject.
    let registry_result = build_shared_registry();
    if let Ok(registry) = &registry_result {
        provide_context(LexiconRegistry(Arc::clone(registry)));
    }

    view! {
        <Title text="Polaris"/>
        {match registry_result {
            Err(err) => view! {
                <main id="polaris-root">
                    <p class="app__validation-init-error" role="alert">
                        "Failed to initialise lexicon validation engine: "{err.to_string()}
                    </p>
                </main>
            }.into_any(),
            Ok(_) => view! {
                <Router>
                    <main id="polaris-root">
                        <Routes fallback=|| view! { <p>"Not found."</p> }>
                            <Route path=path!("") view=PatternDashboard/>
                            <Route path=path!("/cases/:subject_id") view=CaseView/>
                        </Routes>
                    </main>
                </Router>
            }.into_any(),
        }}
    }
}
