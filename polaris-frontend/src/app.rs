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
//! - `/login` — [`LoginPage`](crate::pages::login::LoginPage)
//!   (issue #82, the browser login form that posts to
//!   `/auth/atproto/login`).
//! - `/setup` — [`SetupWizard`](crate::pages::setup::SetupWizard)
//!   (issue #84, the first-run setup wizard: generate key + publish
//!   labeler record + publish DID document service entry).
//! - `/admin/moderators` —
//!   [`AdminModeratorsPage`](crate::pages::admin_moderators::AdminModeratorsPage)
//!   (issue #214 / #217, admin-only moderator allow-list
//!   management).
//!
//! # Session-less landing
//!
//! The Polaris session cookie is `HttpOnly` (design.md §6), so the
//! frontend cannot observe its presence from JS. Instead, the
//! authenticated landing pages (dashboard, case view) treat a
//! `401 Unauthorized` from their initial fetch as the signal that the
//! cookie is missing or expired, and hard-navigate to `/login` via
//! [`crate::pages::login::redirect_to_login`]. The login page itself
//! is reachable directly so a deep-link can land there without first
//! tripping a 401.
//!
//! # First-run routing
//!
//! The root route `/` mounts the [`RootRoute`] component instead of
//! [`PatternDashboard`] directly. [`RootRoute`] calls
//! `GET /api/whoami` and inspects the
//! [`first_run`](crate::api_client::dto::WhoamiResponse::first_run)
//! flag:
//!
//! - `true` → hard-navigate to [`SETUP_PATH`](crate::pages::setup::SETUP_PATH).
//! - `false` → render [`PatternDashboard`].
//! - `401` → hard-navigate to [`LOGIN_PATH`](crate::pages::login::LOGIN_PATH).
//!
//! The deep-linked routes (`/cases/:subject_id`, `/login`, `/setup`)
//! are reachable directly — only the root route gates on `first_run`.

use std::sync::Arc;

use leptos::prelude::*;
use leptos_meta::{Title, provide_meta_context};
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;
use proto_blue::lexicon::Lexicons;

use crate::api_client::dto::WhoamiResponse;
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::components::command_palette::CommandPalette;
use crate::components::exposure_counter::ExposureCounter;
use crate::pages::admin_moderators::AdminModeratorsPage;
use crate::pages::case_view::CaseView;
use crate::pages::dashboard::PatternDashboard;
use crate::pages::login::{LoginPage, is_unauthorized, redirect_to_login};
use crate::pages::queue::TriageQueue;
use crate::pages::setup::{SETUP_PATH, SetupWizard};
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
    match &registry_result {
        Ok(_) => web_sys::console::log_1(&"App: registry built OK".into()),
        Err(e) => web_sys::console::log_1(&format!("App: registry build FAILED: {e}").into()),
    }
    if let Ok(registry) = &registry_result {
        provide_context(LexiconRegistry(Arc::clone(registry)));
    }
    web_sys::console::log_1(&"App: building view".into());

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
                    // Issue #92: command palette mounts OUTSIDE the
                    // `<Routes>` block so the Ctrl/Cmd-K overlay is
                    // reachable from every page (dashboard, queue,
                    // case view, …). The component owns its own
                    // visibility signal and renders an empty subtree
                    // when closed, so the always-mounted cost is one
                    // signal allocation + one window-level keydown
                    // listener.
                    <CommandPalette/>
                    // Issue #95: moderator-wellness exposure counter
                    // mounts at the same global level so its toast
                    // nag surfaces on every page (queue, case view,
                    // dashboard). The component owns its own signal
                    // backed by `sessionStorage`; child components
                    // ([`MediaPreview`], [`ActionComposer`]) reach
                    // the signal via Leptos context.
                    <ExposureCounter/>
                    <main id="polaris-root">
                        <Routes fallback=|| view! { <p>"Not found."</p> }>
                            <Route path=path!("") view=RootRoute/>
                            <Route path=path!("/cases/:subject_id") view=CaseView/>
                            <Route path=path!("/login") view=LoginPage/>
                            <Route path=path!("/queue") view=TriageQueue/>
                            <Route path=path!("/setup") view=SetupWizard/>
                            // Issue #214 / #217: admin-only
                            // moderator-management page. The page
                            // itself reads `whoami` and the backend
                            // independently rejects the data fetch
                            // for non-admins — the route is reachable
                            // by anyone, but the contents are gated.
                            <Route path=path!("/admin/moderators") view=AdminModeratorsPage/>
                        </Routes>
                    </main>
                </Router>
            }.into_any(),
        }}
    }
}

/// Root route component (`/`).
///
/// Resolves the right landing surface for the operator by fetching
/// `GET /api/whoami` (issue #83) and inspecting the
/// [`WhoamiResponse::first_run`] flag. The function-level redirect
/// table is documented in the module-level docs under "First-run
/// routing" — keep both call sites in sync.
///
/// Native builds (tests, IDE) skip the fetch and render
/// [`PatternDashboard`] directly: the redirect helpers are no-ops on
/// non-wasm targets, so a fetch that bounced to `/setup` would be a
/// silent no-op that confused diagnostics. The dashboard's own initial
/// fetch already enforces the 401 → `/login` redirect contract for
/// authenticated browsing sessions.
// `clippy::must_use_candidate` is `#[allow]`-ed for the same reason
// as `App`: `#[component]` discards outer attributes, and Leptos
// always consumes the return value via `view!`.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn RootRoute() -> impl IntoView {
    let whoami = LocalResource::new(|| async {
        let client = default_client("").map_err(|e: ApiError| {
            if is_unauthorized(&e) {
                redirect_to_login();
            }
            e.to_string()
        })?;
        client.whoami().await.map_err(|e: ApiError| {
            if is_unauthorized(&e) {
                redirect_to_login();
            }
            e.to_string()
        })
    });

    view! {
        <Suspense fallback=move || view! {
            <p class="root-route__loading" role="status">"Loading…"</p>
        }>
            {move || Suspend::new(async move {
                match whoami.await {
                    Ok(WhoamiResponse { first_run: true, .. }) => {
                        redirect_to_setup();
                        view! {
                            <p class="root-route__redirect" role="status">
                                "Redirecting to first-run setup…"
                            </p>
                        }.into_any()
                    }
                    Ok(WhoamiResponse { first_run: false, .. }) => view! {
                        <PatternDashboard/>
                    }.into_any(),
                    Err(message) => view! {
                        <p class="root-route__error" role="alert">
                            "Failed to load session context: "{message}
                        </p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

/// Hard-navigate to the first-run setup wizard.
///
/// Mirrors the dashboard's [`redirect_to_login`] pattern (issue #82):
/// a full-page navigation rather than a client-side route swap so the
/// wizard mounts with a fresh component tree. No-op on native targets;
/// the function exists in both compilation paths so the call site is
/// target-agnostic.
#[cfg(target_arch = "wasm32")]
fn redirect_to_setup() {
    if let Some(window) = web_sys::window() {
        let _ = window.location().assign(SETUP_PATH);
    }
}

/// Native stub. See the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
fn redirect_to_setup() {
    // Intentionally empty: the navigation side effect only makes
    // sense in a browser context. Native callers exercising the
    // routing contract use the predicate-style tests in
    // `crate::pages::setup::tests` instead.
    let _ = SETUP_PATH;
}
