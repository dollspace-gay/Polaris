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
//! drives a single [`LocalResource`] that calls
//! [`PolarisApiClient::get_case`]. The resource is consumed inside a
//! `<Suspense>` + `<ErrorBoundary>` pair so the moderator never sees a
//! blank panel while the fetch is in flight. The action composer is
//! wired to a [`ClientSubmitter`] that closes over a freshly-built
//! [`crate::api_client::default_client`] instance, satisfying the issue
//! #15 contract that the composer not own a [`crate::api_client::PolarisApiClient`]
//! handle directly (so the test harness can stub it).

use leptos::prelude::*;
use leptos_router::hooks::use_params_map;
use polaris_types::{Action, IncidentId, SubjectId};
use std::future::Future;
use std::pin::Pin;
use uuid::Uuid;

use crate::api_client::dto::CaseView as CaseViewDto;
use crate::api_client::{ApiError, PolarisApiClient, default_client, dto::SubmitAction};
use crate::components::action_composer::{ActionComposer, ActionSubmitter};
use crate::components::history_timeline::HistoryTimeline;
use crate::components::network_panel::NetworkPanel;
use crate::components::report_list::ReportList;
use crate::components::subject_header::SubjectHeader;

/// Render the subject-centric case view.
///
/// # Routing
///
/// Reads `:subject_id` from the URL via [`use_params_map`]. An invalid
/// UUID renders an inline error (no panic — the contract from issue
/// #15's forbidden-pattern checklist forbids `unwrap` / `expect` on user
/// input).
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
                    <CaseViewLoaded subject_id=subject_id/>
                }.into_any(),
            }}
        </main>
    }
}

/// Body of the case view, parameterised on a successfully-parsed
/// [`SubjectId`]. Pulled out of [`CaseView`] so the resource lifecycle is
/// scoped to the route's validity — re-mounts on `:subject_id` change.
#[component]
fn CaseViewLoaded(
    /// Successfully-parsed subject identifier from the URL.
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
            let client = default_client("").map_err(|e: ApiError| e.to_string())?;
            client.get_case(subject_id).await.map_err(|e| e.to_string())
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
                        <CaseViewBody
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
fn CaseViewBody(
    /// The subject the case view targets.
    subject_id: SubjectId,
    /// Hydrated case-view payload from `GET /api/cases/{subject_id}`.
    data: CaseViewDto,
    /// Refresh-token bump callback wired from [`CaseViewLoaded`].
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
        observations: _,
        network_context: _,
    } = data;

    view! {
        <SubjectHeader subject=subject/>
        <div class="case-view__columns">
            <div class="case-view__main">
                <HistoryTimeline actions=history/>
                <ReportList reports=reports/>
                <ActionComposer
                    subject_id=subject_id
                    incident_id=incident_id
                    submitter=ClientSubmitter
                    on_success=on_action_success
                />
            </div>
            <aside class="case-view__sidebar">
                <NetworkPanel/>
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
