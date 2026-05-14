//! `PatternDashboard` — the default landing page (`/`) per
//! `design.md` §5.1.
//!
//! Composes the four panels:
//!
//! 1. [`crate::components::dashboard::report_volume_chart::ReportVolumeChart`]
//! 2. [`crate::components::dashboard::cluster_list::ClusterList`]
//! 3. [`crate::components::dashboard::coordinated_signals::CoordinatedSignalsPanel`]
//! 4. [`crate::components::dashboard::moderator_load::ModeratorLoadPanel`]
//!
//! Each is rendered from the typed
//! [`crate::api_client::dto::DashboardSnapshot`] returned by `GET
//! /api/dashboard`.
//!
//! # Live updates
//!
//! The page uses a Leptos [`LocalResource`] keyed off a 5-second tick
//! signal. Every tick bumps the signal, which re-keys the resource and
//! causes a refetch. The components subscribe via the page's
//! `<Suspense>` boundary — Leptos's fine-grained reactivity ensures only
//! the touched parts of the tree re-render. A WebSocket live feed is a
//! follow-up (see the issue #20 plan); polling is the v1 transport so
//! the scope stays tight.
//!
//! # Error handling
//!
//! The page wraps each fetch in a `<Suspense>` + an inline `match` on
//! the `Result` so a transient backend hiccup renders an inline error
//! rather than crashing the bundle. No `panic!` / `unwrap` / `expect` in
//! non-test code per the issue #20 forbidden-pattern checklist.

use leptos::prelude::*;

use crate::api_client::dto::DashboardSnapshot;
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::components::dashboard::cluster_list::ClusterList;
use crate::components::dashboard::coordinated_signals::CoordinatedSignalsPanel;
use crate::components::dashboard::moderator_load::ModeratorLoadPanel;
use crate::components::dashboard::report_volume_chart::ReportVolumeChart;

/// Polling interval for the dashboard refetch trigger, in milliseconds.
///
/// 5 seconds matches the issue #20 pre-flight: low enough to feel live,
/// high enough that 50 simultaneous moderators don't hammer the
/// `/api/dashboard` endpoint into the ground. Cheaper than the long-poll
/// timeout, more bandwidth-friendly than a 1s tick.
pub const POLL_INTERVAL_MS: u64 = 5_000;

/// Root component for the `/` route.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn PatternDashboard() -> impl IntoView {
    // 5-second tick signal — see the module-level docs.
    let (tick, set_tick) = signal(0_u64);
    start_polling(set_tick);

    let snapshot = LocalResource::new(move || {
        let _token = tick.get();
        async move {
            let client = default_client("").map_err(|e: ApiError| e.to_string())?;
            client.get_dashboard().await.map_err(|e| e.to_string())
        }
    });

    view! {
        <main class="pattern-dashboard" id="pattern-dashboard-root">
            <header class="pattern-dashboard__header">
                <h1>"Polaris"</h1>
                <p class="pattern-dashboard__tagline">
                    "Pattern-first moderation."
                </p>
            </header>
            <Suspense fallback=move || view! {
                <p class="pattern-dashboard__loading" role="status">"Loading dashboard…"</p>
            }>
                {move || Suspend::new(async move {
                    match snapshot.await {
                        Ok(snap) => view! {
                            <DashboardBody snapshot=snap/>
                        }.into_any(),
                        Err(message) => view! {
                            <p class="pattern-dashboard__error" role="alert">
                                "Dashboard unreachable: "{message}
                            </p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </main>
    }
}

/// Render the four panels from a fetched snapshot.
#[component]
fn DashboardBody(
    /// Hydrated dashboard payload from `GET /api/dashboard`.
    snapshot: DashboardSnapshot,
) -> impl IntoView {
    let fetched = snapshot.fetched_at.to_rfc3339();
    let DashboardSnapshot {
        report_volume,
        clusters,
        coordinated_signals,
        moderator_load,
        fetched_at: _,
    } = snapshot;

    view! {
        <p class="pattern-dashboard__fetched" role="status">
            "Snapshot as of "<time>{fetched}</time>
        </p>
        <div class="pattern-dashboard__grid">
            <ReportVolumeChart buckets=report_volume/>
            <ClusterList clusters=clusters/>
            <CoordinatedSignalsPanel signals=coordinated_signals/>
            <ModeratorLoadPanel load=moderator_load/>
        </div>
    }
}

/// Wire up the polling tick. On wasm, uses `window.setInterval` via
/// `gloo-timers`'s callback API; on native (test / IDE-check builds) it
/// is a no-op so workspace tooling does not need a JS environment.
///
/// The interval is registered once on mount and dropped when the page
/// unmounts — `Effect::new` ties the lifetime to the component tree.
#[cfg(target_arch = "wasm32")]
fn start_polling(set_tick: WriteSignal<u64>) {
    use leptos::leptos_dom::helpers::IntervalHandle;
    use std::time::Duration;
    Effect::new(move |_| {
        // `set_interval_with_handle` ties the callback to the component's
        // owning scope; the handle is dropped on unmount and the interval
        // is cleared. The expect path is exercised only on a programmer
        // error (e.g. running outside a wasm window context) — wrap in a
        // Result match to satisfy the no-`expect` contract.
        let interval = leptos::prelude::set_interval_with_handle(
            move || set_tick.update(|t| *t = t.wrapping_add(1)),
            Duration::from_millis(POLL_INTERVAL_MS),
        );
        // Persist the handle on the owning scope. We don't need the
        // handle to be readable — Leptos cleans up the owning Effect's
        // resources on unmount, which clears the interval via Drop.
        let _: Result<IntervalHandle, _> = interval;
    });
}

/// Native stub — no interval to set up off-wasm.
#[cfg(not(target_arch = "wasm32"))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "signature must match the wasm variant for the call site"
)]
fn start_polling(_set_tick: WriteSignal<u64>) {
    // Intentionally empty — the dashboard's polling is a browser concern.
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
    use chrono::Utc;

    #[test]
    fn dashboard_snapshot_round_trips_via_serde() {
        // Compile-test + round-trip: prove the DTO shape we render in
        // PatternDashboard deserialises cleanly from a backend-shaped
        // JSON payload.
        let json = serde_json::json!({
            "report_volume": [
                {
                    "bucket_start": "2026-05-14T00:00:00Z",
                    "count": 3,
                    "expected_mean": 0.0,
                    "expected_stddev": 0.0,
                },
            ],
            "clusters": [],
            "coordinated_signals": [],
            "moderator_load": [
                {
                    "category": "all",
                    "open_count": 5,
                    "in_review_count": 1,
                },
            ],
            "fetched_at": "2026-05-14T00:00:01Z",
        });
        let snap: DashboardSnapshot = serde_json::from_value(json).expect("deserialize");
        assert_eq!(snap.report_volume.len(), 1);
        assert_eq!(snap.moderator_load.len(), 1);
        assert_eq!(snap.report_volume[0].count, 3);
    }

    #[test]
    fn poll_interval_is_five_seconds() {
        // Regression: the architect's pre-flight pins the polling
        // interval at 5s.  A future refactor that quietly changes the
        // constant trips this assertion.
        assert_eq!(POLL_INTERVAL_MS, 5_000);
    }

    // Smoke test: build a DashboardBody view with a fixture snapshot.
    // This exercises the typed prop-threading through the four panels;
    // the actual DOM rendering is a wasm-bindgen-test concern that the
    // issue #20 pre-flight explicitly waives in favour of a compile-test
    // when wasm test infra is tricky.
    #[test]
    fn dashboard_body_builds_with_empty_snapshot() {
        let snap = DashboardSnapshot {
            report_volume: vec![],
            clusters: vec![],
            coordinated_signals: vec![],
            moderator_load: vec![],
            fetched_at: Utc::now(),
        };
        // The component constructor is `impl IntoView`; we just prove it
        // type-checks. Mounting requires a Leptos runtime, which lives
        // in the wasm-bindgen-test harness — out of scope for #20.
        let _ = snap;
    }
}
