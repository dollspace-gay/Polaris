//! `CaseView` page — the subject-centric moderation surface.
//!
//! Maps to `design.md` §5.2: a single page that gives the moderator
//! everything the seventh moderator under Ozone would have reconstructed
//! manually — subject metadata, full prior action history, current
//! reports, pattern observations, and an action composer with required
//! reasoning.
//!
//! # Wiring
//!
//! The page reads the `subject_id` path parameter from the router, then
//! delegates the data load to [`CaseViewBody`]. `CaseView` is a thin
//! routing wrapper; the actual `LocalResource` lives inside
//! [`CaseViewBody`] so the same body component can be embedded inside
//! the right-side drawer rendered from the triage queue (issue #93).
//! The action composer is wired to a [`ClientSubmitter`] that closes
//! over a freshly-built [`crate::api_client::default_client`] instance,
//! satisfying the issue #15 contract that the composer not own a
//! [`crate::api_client::PolarisApiClient`] handle directly (so the test
//! harness can stub it).

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use polaris_types::{Action, IncidentId, SubjectId};
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

use crate::api_client::dto::CaseView as CaseViewDto;
use crate::api_client::{ApiError, PolarisApiClient, default_client, dto::SubmitAction};
use crate::components::action_composer::{ActionComposer, ActionSubmitter};
use crate::components::classifier_panel::ClassifierPanel;
use crate::components::history_timeline::HistoryTimeline;
use crate::components::media_gallery::MediaGallery;
use crate::components::network_panel::NetworkPanel;
use crate::components::observations_panel::ObservationsPanel;
use crate::components::related_actions_timeline::RelatedActionsTimeline;
use crate::components::report_list::ReportList;
use crate::components::subject_header::SubjectHeader;
use crate::components::third_party_labels_panel::ThirdPartyLabelsPanel;
use crate::pages::login::{is_unauthorized, redirect_to_login};

/// Render the subject-centric case view.
///
/// # Routing
///
/// Reads `:subject_id` from the URL via [`use_params_map`]. An invalid
/// UUID renders an inline error (no panic — the contract from issue
/// #15's forbidden-pattern checklist forbids `unwrap` / `expect` on user
/// input). On a successful parse, defers to [`CaseViewBody`] so the
/// fetch + Suspense + render path is shared with the drawer call site
/// in `pages::queue` (issue #93).
#[allow(clippy::must_use_candidate)]
#[component]
pub fn CaseView() -> impl IntoView {
    let params = use_params_map();

    // Parse the `:subject_id` parameter into a typed `SubjectId`. The
    // route can only match a non-empty segment but the segment can still
    // be malformed UUID text — handle that case explicitly.
    let parsed_subject = move || -> Result<SubjectId, String> {
        params.with(|p| {
            let raw = p
                .get("subject_id")
                .ok_or_else(|| "missing subject_id in route".to_owned())?;
            let uuid =
                Uuid::parse_str(&raw).map_err(|e| format!("invalid subject id `{raw}`: {e}"))?;
            Ok(SubjectId::from(uuid))
        })
    };

    view! {
        <main class="case-view" id="case-view-root">
            {move || match parsed_subject() {
                Err(msg) => view! {
                    <p class="case-view__route-error" role="alert">
                        "Route error: "{msg}
                    </p>
                }.into_any(),
                Ok(subject_id) => view! {
                    <CaseViewBody subject_id=subject_id/>
                }.into_any(),
            }}
        </main>
    }
}

/// Reusable case-view body.
///
/// Owns the `LocalResource` that hydrates the case payload, the
/// refresh-token signal the action composer bumps on success, and the
/// composition of [`SubjectHeader`], [`HistoryTimeline`], [`ReportList`],
/// [`ActionComposer`], and [`NetworkPanel`]. Both [`CaseView`] (the
/// `/cases/:subject_id` page) and the drawer mounted inside the triage
/// queue (`pages::queue`, issue #93) render this component — the data
/// fetch is therefore defined exactly once.
///
/// # Props
///
/// - `subject_id`: parsed subject identifier. Taken by value (not a
///   signal) so the resource's input is captured once at mount; the
///   drawer wrapper unmounts + remounts this component when the
///   active subject changes (Leptos `Show` semantics), so there is no
///   need for a reactive input here. Embedding it as a signal would
///   risk a re-fetch loop (the resource would re-run on every render).
#[allow(clippy::must_use_candidate)]
#[component]
pub fn CaseViewBody(
    /// Subject identifier the body fetches and renders.
    subject_id: SubjectId,
) -> impl IntoView {
    // Refresher signal: the action composer calls this on a successful
    // submit so the timeline picks up the new row. `LocalResource` does
    // not expose `refetch` directly the way the older `Resource` API did;
    // bumping a version signal that the resource's input depends on is
    // the supported pattern — the closure reads `refresh_token.get()`
    // before kicking off the fetch, so a token bump re-runs the resource.
    let (refresh_token, set_refresh_token) = signal(0_u64);

    let case_resource = LocalResource::new(move || {
        let _token = refresh_token.get();
        async move {
            // 401-redirect contract (#82): an unauthenticated fetch
            // must bounce the operator to `/login` rather than render
            // an inline "HTTP 401" panel. `redirect_to_login` is a
            // no-op on native targets so the same code path compiles
            // for tests / IDE checks. Other errors propagate as their
            // `Display` text into the `<Suspense>` arm.
            let client = default_client("").map_err(|e: ApiError| {
                if is_unauthorized(&e) {
                    redirect_to_login();
                }
                e.to_string()
            })?;
            client.get_case(subject_id).await.map_err(|e: ApiError| {
                if is_unauthorized(&e) {
                    redirect_to_login();
                }
                e.to_string()
            })
        }
    });

    let on_action_success = Callback::new(move |_action: Action| {
        set_refresh_token.update(|v| *v = v.wrapping_add(1));
    });

    view! {
        <Suspense fallback=move || view! {
            <p class="case-view__loading" role="status">"Loading case…"</p>
        }>
            {move || Suspend::new(async move {
                match case_resource.await {
                    Ok(view) => view! {
                        <CaseViewLoaded
                            subject_id=subject_id
                            data=view
                            on_action_success=on_action_success
                        />
                    }.into_any(),
                    Err(message) => view! {
                        <p class="case-view__error" role="alert">
                            "Failed to load case: "{message}
                        </p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

/// Render the loaded case data plus the action composer.
#[component]
fn CaseViewLoaded(
    /// The subject the case view targets.
    subject_id: SubjectId,
    /// Hydrated case-view payload from `GET /api/cases/{subject_id}`.
    data: CaseViewDto,
    /// Refresh-token bump callback wired from [`CaseViewBody`].
    on_action_success: Callback<Action>,
) -> impl IntoView {
    // The action composer needs an `IncidentId`. The case-view DTO carries
    // a flat `history` vector across all incidents on the subject; the
    // most-recent incident is the one a new action attaches to. If there
    // is no prior action, we fall back to a fresh `IncidentId` — M2 will
    // replace this with a proper "create incident or pick existing"
    // selector, but for M1 it lets the composer drive the end-to-end
    // submit path against the backend's relaxed FK rules.
    let incident_id = data
        .history
        .last()
        .map_or_else(IncidentId::new, |a| a.incident_id);

    let CaseViewDto {
        subject,
        history,
        reports,
        reporter_contexts,
        observations,
        // The case-view DTO carries `media_blobs` only as the
        // synchronous cache snapshot from `subject_image_blobs`. The
        // MediaGallery component refreshes via its own
        // `/api/cases/{id}/media` fetch (deeper paginated walker
        // with alt-text capture), so we discard the snapshot here
        // rather than render a partial set and then immediately
        // overwrite it. The wire field stays on the DTO for
        // backwards compatibility.
        media_blobs: _,
        related_actions,
        network_context: _,
    } = data;

    // Clone the observation list so both panels see the same payload.
    // (Cheap — observations are small structs; the case-view DTO is
    // already an owned clone from the LocalResource.)
    let observations_for_classifier = observations.clone();
    // Same dance for the subject: SubjectHeader takes ownership, so
    // hand MediaGallery a clone for the CDN-URL owner-DID lookup.
    let subject_for_media = subject.clone();

    view! {
        <SubjectHeader subject=subject/>
        <div class="case-view__columns">
            <div class="case-view__main">
                <ThirdPartyLabelsPanel subject_id=subject_id/>
                <HistoryTimeline actions=history/>
                <RelatedActionsTimeline actions=related_actions/>
                <ReportList
                    reports=reports
                    reporter_contexts=reporter_contexts
                    subject_id=subject_id
                    incident_id=incident_id
                />

                <MediaGallery subject=subject_for_media subject_id=subject_id/>
                <ObservationsPanel observations=observations/>
                <ClassifierPanel observations=observations_for_classifier/>
                <ActionComposer
                    subject_id=subject_id
                    incident_id=incident_id
                    submitter=ClientSubmitter
                    on_success=on_action_success
                />
            </div>
            <aside class="case-view__sidebar">
                // Issue #97 / M2 network panel: per-subject signal
                // surface (follow graph, reply graph, cohort,
                // shared-image clusters). Fetches its own data on
                // mount from `/api/cases/{subject_id}/network-context`
                // — independent of the main case fetch so a slow
                // upstream getProfile does not block the
                // case-view's primary render.
                <NetworkPanel subject_id=subject_id/>
            </aside>
        </div>
    }
}

/// Production [`ActionSubmitter`] that constructs a fresh
/// [`crate::api_client::default_client`] per call.
///
/// Per-call construction is cheap (`reqwest::Client` would reuse a
/// connection pool internally, but on wasm the client is stateless) and
/// keeps the composer free of any `&self`-captured client lifetime.
#[derive(Debug, Clone, Copy)]
pub struct ClientSubmitter;

impl ActionSubmitter for ClientSubmitter {
    type Fut = Pin<Box<dyn Future<Output = Result<Action, ApiError>>>>;

    fn submit(&self, subject_id: SubjectId, body: SubmitAction) -> Self::Fut {
        Box::pin(async move {
            let client = default_client("")?;
            client.submit_action(subject_id, body).await
        })
    }
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

    /// AC-6 — `CaseViewBody` must compile without a route context.
    ///
    /// `#[component]` rewrites the function body and generates a sibling
    /// `<Name>Props` struct; we form a type-name witness for it so the
    /// compiler proves the symbol is in scope and the prop wiring still
    /// type-checks. The component itself is not invoked — invoking it
    /// would require a Leptos reactive owner. The witness is enough to
    /// guarantee that the drawer call site in `pages::queue` can build
    /// `<CaseViewBody subject_id=… />` without entering a `<Router>` /
    /// `use_params_map` context.
    #[test]
    fn case_view_body_is_renderable_without_route_param() {
        // Materialise both the `SubjectId` argument shape and the
        // generated props struct so a future rename / signature break
        // shows up as a compile error here, not at the queue call site.
        let _id_type = std::any::type_name::<SubjectId>();
        let _props_type = std::any::type_name::<CaseViewBodyProps>();
        let _: SubjectId = SubjectId::from(Uuid::nil());
    }
}
