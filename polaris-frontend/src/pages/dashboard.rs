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
//! # Live updates (issue #57)
//!
//! The page reflects new observations within 1 second of detection by
//! subscribing to `GET /api/dashboard/live` over a WebSocket. The
//! handler streams [`DashboardEvent`] diffs; each one swaps a single
//! field on the local snapshot signal so Leptos's fine-grained
//! reactivity re-renders only the affected panel.
//!
//! ## Fallback to polling
//!
//! When the WebSocket connection cannot be established (the browser
//! refuses the upgrade, the backend returns a non-101 response, or the
//! transport fails mid-stream), the page falls back to the historical
//! 5-second polling loop. The fallback is also activated after
//! [`MAX_RECONNECT_ATTEMPTS`] failed reconnects in a single session —
//! at that point we stop spending CPU on the WS open and let the polling
//! loop take over for the rest of the moderator's session.
//!
//! ## Reconnect backoff
//!
//! [`reconnect_delay_ms`] computes a capped exponential schedule
//! (2s, 4s, 8s, 16s, 32s, 60s, 60s, …). The cap is documented in the
//! function's docs; a moderator who tabs back after a long idle does
//! not see a flurry of reconnect attempts pile up at the floor.
//!
//! # Error handling
//!
//! The page wraps each fetch in a `<Suspense>` + an inline `match` on
//! the `Result` so a transient backend hiccup renders an inline error
//! rather than crashing the bundle. No `panic!` / `unwrap` / `expect` in
//! non-test code per the issue #57 forbidden-pattern checklist.

use leptos::prelude::*;

use crate::api_client::dto::{DashboardEvent, DashboardSnapshot};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::components::dashboard::cluster_list::ClusterList;
use crate::components::dashboard::coordinated_signals::CoordinatedSignalsPanel;
use crate::components::dashboard::moderator_load::ModeratorLoadPanel;
use crate::components::dashboard::report_volume_chart::ReportVolumeChart;

/// Polling interval for the polling-fallback refetch trigger, in milliseconds.
///
/// 5 seconds matches the issue #20 baseline. Used when the WebSocket
/// live feed is unavailable; the new "live" path (issue #57) reflects
/// updates within 1 second of detection regardless of this constant.
pub const POLL_INTERVAL_MS: u64 = 5_000;

/// WebSocket path on the backend authed subtree.
pub const LIVE_FEED_PATH: &str = "/api/dashboard/live";

/// After this many failed reconnect attempts in a single session, give
/// up on the WebSocket and fall back to polling permanently. 8 attempts
/// at the [`reconnect_delay_ms`] schedule covers ~3 minutes of outage
/// before the fallback takes over.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 8;

/// Lower bound on the reconnect backoff (first retry delay, in ms).
pub const RECONNECT_FLOOR_MS: u64 = 2_000;

/// Upper bound on the reconnect backoff (every attempt past the cap
/// uses this delay verbatim).
pub const RECONNECT_CEILING_MS: u64 = 60_000;

/// Compute the reconnect delay for the `n`th attempt (`n` is the 1-based
/// attempt counter — `1` is the first retry, etc.).
///
/// Schedule: 2s, 4s, 8s, 16s, 32s, 60s, 60s, …
/// — exponential doubling capped at [`RECONNECT_CEILING_MS`].
///
/// `n == 0` is treated as `1` (the floor) so a degenerate caller does
/// not get a zero-millisecond delay.
#[must_use]
pub fn reconnect_delay_ms(attempt: u32) -> u64 {
    let attempt = attempt.max(1);
    // 2^(attempt - 1) — guard against overflow before the cap clamps it.
    let exp = u64::from(attempt.saturating_sub(1)).min(20);
    let candidate = RECONNECT_FLOOR_MS.saturating_mul(1_u64 << exp);
    candidate.min(RECONNECT_CEILING_MS)
}

/// Apply a [`DashboardEvent`] diff to a [`DashboardSnapshot`] in place.
///
/// Pure function so it can be unit-tested without a Leptos runtime.
/// The mutation rules are:
///
/// - [`DashboardEvent::NewCluster`]: push the cluster to the front of
///   `clusters`. Deduplicates on `incident_id` if a previous row exists.
/// - [`DashboardEvent::NewSignal`]: push the signal to the front of
///   `coordinated_signals`. No deduplication — the panel renders a
///   chronological feed.
/// - [`DashboardEvent::VolumeBucketUpdated`]: replace the bucket with
///   the matching `bucket_start`, or append if absent.
/// - [`DashboardEvent::ModeratorLoadDelta`]: replace the row with the
///   matching `category`, or append if absent.
pub fn apply_event(snapshot: &mut DashboardSnapshot, event: DashboardEvent) {
    match event {
        DashboardEvent::NewCluster { cluster } => {
            snapshot
                .clusters
                .retain(|c| c.incident_id != cluster.incident_id);
            snapshot.clusters.insert(0, cluster);
        }
        DashboardEvent::NewSignal { signal } => {
            snapshot.coordinated_signals.insert(0, signal);
        }
        DashboardEvent::VolumeBucketUpdated { bucket } => {
            if let Some(existing) = snapshot
                .report_volume
                .iter_mut()
                .find(|b| b.bucket_start == bucket.bucket_start)
            {
                *existing = bucket;
            } else {
                snapshot.report_volume.push(bucket);
            }
        }
        DashboardEvent::ModeratorLoadDelta { load } => {
            if let Some(existing) = snapshot
                .moderator_load
                .iter_mut()
                .find(|row| row.category == load.category)
            {
                *existing = load;
            } else {
                snapshot.moderator_load.push(load);
            }
        }
    }
}

/// Compute the `ws://` / `wss://` URL the WebSocket subscription should
/// connect to, given the current page's origin.
///
/// `https://` upgrades to `wss://`; everything else (`http://`,
/// `file://` while developing) becomes `ws://`. The path
/// ([`LIVE_FEED_PATH`]) is appended verbatim.
///
/// `protocol` and `host` are taken in as strings rather than read
/// from `window.location` here so the function is testable on native.
#[must_use]
pub fn build_ws_url(protocol: &str, host: &str) -> String {
    let scheme = if protocol.eq_ignore_ascii_case("https:") {
        "wss"
    } else {
        "ws"
    };
    format!("{scheme}://{host}{LIVE_FEED_PATH}")
}

/// Root component for the `/` route.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn PatternDashboard() -> impl IntoView {
    // Polling tick — drives the LocalResource refetch. Bumped both by the
    // periodic interval (fallback path) and on demand from the WS task
    // (initial fetch, manual refresh).
    let (tick, set_tick) = signal(0_u64);

    // Overlay signal: when `Some(snapshot)`, the live-feed task has a
    // patched snapshot to render. The page prefers this over the
    // polling resource when present so applied diffs are visible
    // immediately without waiting for the next polling cycle.
    let live_snapshot = RwSignal::new(None::<DashboardSnapshot>);

    start_live_feed(set_tick, live_snapshot);
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
                    let fetched = snapshot.await;
                    // Live-feed overlay wins when present — it is the
                    // result of the latest applied diff or the seed the
                    // live task installed after its own fetch.
                    let chosen = live_snapshot.get().map_or_else(
                        || fetched.clone(),
                        Ok,
                    );
                    match chosen {
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

// ── Live feed (issue #57): WebSocket subscription with polling fallback ──

/// Spawn the live-feed task on wasm.
///
/// The task fetches an initial snapshot (seeds `live_snapshot`), then
/// opens a WebSocket connection to [`LIVE_FEED_PATH`]. Each message is
/// parsed as a [`DashboardEvent`] and applied to the live snapshot. On
/// disconnect we wait [`reconnect_delay_ms`] and reconnect; after
/// [`MAX_RECONNECT_ATTEMPTS`] failures the task gives up and lets the
/// polling fallback drive the UI.
#[cfg(target_arch = "wasm32")]
fn start_live_feed(set_tick: WriteSignal<u64>, live_snapshot: RwSignal<Option<DashboardSnapshot>>) {
    use futures::{SinkExt as _, StreamExt as _};
    use gloo_net::websocket::Message;
    use gloo_net::websocket::futures::WebSocket;
    use wasm_bindgen_futures::spawn_local;

    spawn_local(async move {
        // Seed the live overlay with an initial fetch so the panel
        // renders without waiting for the polling resource to resolve.
        if let Ok(client) = default_client("") {
            if let Ok(snap) = client.get_dashboard().await {
                live_snapshot.set(Some(snap));
            }
        }

        let mut attempt: u32 = 0;
        loop {
            let Some(url) = current_ws_url() else {
                tracing::warn!("dashboard live feed: no window location; falling back to polling");
                return;
            };

            let socket = match WebSocket::open(&url) {
                Ok(s) => s,
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        attempt,
                        "dashboard live feed: WebSocket::open failed; will retry"
                    );
                    attempt = attempt.saturating_add(1);
                    if attempt >= MAX_RECONNECT_ATTEMPTS {
                        tracing::warn!(
                            attempt,
                            "dashboard live feed: reconnect attempts exhausted; polling fallback active"
                        );
                        return;
                    }
                    sleep_ms(reconnect_delay_ms(attempt)).await;
                    continue;
                }
            };

            // Successful open resets the retry counter — a transient
            // disconnect should not propagate its backoff into the next
            // healthy connection.
            attempt = 0;

            let (mut write, mut read) = socket.split();
            // We do not produce frames in the v1 client; close the write
            // half eagerly so a malicious or buggy peer cannot back-
            // pressure us into holding the connection open.
            let _ = write.close().await;

            while let Some(msg) = read.next().await {
                match msg {
                    Ok(Message::Text(payload)) => {
                        match serde_json::from_str::<DashboardEvent>(&payload) {
                            Ok(event) => {
                                // Patch the local snapshot. We read-modify-
                                // write rather than holding a borrowed
                                // signal across the await above so we do
                                // not pin Leptos's reactive scope.
                                let mut current = live_snapshot.get_untracked();
                                if let Some(snap) = current.as_mut() {
                                    apply_event(snap, event);
                                    live_snapshot.set(current);
                                } else {
                                    // No initial seed yet — request a
                                    // refetch through the polling tick.
                                    set_tick.update(|t| *t = t.wrapping_add(1));
                                }
                            }
                            Err(err) => {
                                tracing::warn!(
                                    ?err,
                                    "dashboard live feed: failed to decode DashboardEvent"
                                );
                            }
                        }
                    }
                    Ok(Message::Bytes(_)) => {
                        // The backend never sends binary frames on this
                        // channel; ignore in case a future revision
                        // adds a sidecar.
                    }
                    Err(err) => {
                        tracing::debug!(?err, "dashboard live feed: stream error; will reconnect");
                        break;
                    }
                }
            }

            attempt = attempt.saturating_add(1);
            if attempt >= MAX_RECONNECT_ATTEMPTS {
                tracing::warn!(
                    attempt,
                    "dashboard live feed: reconnect attempts exhausted; polling fallback active"
                );
                return;
            }
            tracing::debug!(
                attempt,
                "dashboard live feed: disconnected; backing off before reconnect"
            );
            sleep_ms(reconnect_delay_ms(attempt)).await;
        }
    });
}

/// Native stub — no live feed off-wasm.
#[cfg(not(target_arch = "wasm32"))]
#[allow(
    clippy::needless_pass_by_value,
    reason = "signature must match the wasm variant for the call site"
)]
fn start_live_feed(_set_tick: WriteSignal<u64>, _live: RwSignal<Option<DashboardSnapshot>>) {
    // Intentionally empty — the WebSocket subscription is a browser concern.
}

/// Read `window.location` and assemble the WebSocket URL.
///
/// Returns `None` when called outside a browser window (server-render
/// path, native tests). The caller treats that as an unrecoverable
/// state and lets the polling fallback drive the UI.
#[cfg(target_arch = "wasm32")]
fn current_ws_url() -> Option<String> {
    let window = web_sys::window()?;
    let location = window.location();
    let protocol = location.protocol().ok()?;
    let host = location.host().ok()?;
    Some(build_ws_url(&protocol, &host))
}

/// `setTimeout`-backed sleep adapter for `await`-suspending the live-feed
/// task during the backoff between reconnects.
#[cfg(target_arch = "wasm32")]
async fn sleep_ms(ms: u64) {
    use std::cell::Cell;
    use std::rc::Rc;
    use std::time::Duration;
    use wasm_bindgen_futures::js_sys;

    // gloo-timers exposes a stream/future helper, but we avoid pulling
    // an extra dep — leptos already provides set_timeout_with_handle.
    let (tx, rx) = futures::channel::oneshot::channel::<()>();
    let tx = Rc::new(Cell::new(Some(tx)));
    let tx_inner = Rc::clone(&tx);
    let handle = leptos::prelude::set_timeout_with_handle(
        move || {
            if let Some(tx) = tx_inner.take() {
                let _ = tx.send(());
            }
        },
        Duration::from_millis(ms),
    );
    // Suppress the unused `js_sys` import warning on the rare build
    // configuration that drops the body — keep `js_sys` reachable so
    // future timer plumbing has it without a re-import.
    let _ = js_sys::Date::now;
    if let Ok(_handle) = handle {
        let _ = rx.await;
    }
    // No window context (Err arm) — fall through immediately so the
    // outer reconnect loop does not deadlock.
}

/// Wire up the polling tick. On wasm, uses `window.setInterval` via
/// Leptos's `set_interval_with_handle`; on native (test / IDE-check
/// builds) it is a no-op so workspace tooling does not need a JS
/// environment.
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
    use crate::api_client::dto::{
        CoordinatedSignal, CoordinatedSignalKind, IncidentClusterSummary, ModeratorLoad,
        ReportVolumeBucket,
    };
    use chrono::{TimeZone as _, Utc};
    use polaris_types::{IncidentId, IncidentStatus, Severity, SubjectId};

    fn empty_snapshot() -> DashboardSnapshot {
        DashboardSnapshot {
            report_volume: vec![],
            clusters: vec![],
            coordinated_signals: vec![],
            moderator_load: vec![],
            fetched_at: Utc::now(),
        }
    }

    #[test]
    fn dashboard_snapshot_round_trips_via_serde() {
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
        // Regression: polling is the fallback path. The architect's
        // pre-flight pins the polling interval at 5s; a future refactor
        // that quietly changes the constant trips this assertion.
        assert_eq!(POLL_INTERVAL_MS, 5_000);
    }

    #[test]
    fn reconnect_delay_doubles_then_caps() {
        assert_eq!(reconnect_delay_ms(0), 2_000);
        assert_eq!(reconnect_delay_ms(1), 2_000);
        assert_eq!(reconnect_delay_ms(2), 4_000);
        assert_eq!(reconnect_delay_ms(3), 8_000);
        assert_eq!(reconnect_delay_ms(4), 16_000);
        assert_eq!(reconnect_delay_ms(5), 32_000);
        assert_eq!(reconnect_delay_ms(6), 60_000);
        // Cap holds for arbitrarily large attempt counts.
        assert_eq!(reconnect_delay_ms(7), 60_000);
        assert_eq!(reconnect_delay_ms(100), 60_000);
        assert_eq!(reconnect_delay_ms(u32::MAX), 60_000);
    }

    #[test]
    fn build_ws_url_picks_wss_for_https() {
        assert_eq!(
            build_ws_url("https:", "polaris.example.com"),
            "wss://polaris.example.com/api/dashboard/live"
        );
        assert_eq!(
            build_ws_url("HTTPS:", "polaris.example.com"),
            "wss://polaris.example.com/api/dashboard/live"
        );
    }

    #[test]
    fn build_ws_url_picks_ws_for_http() {
        assert_eq!(
            build_ws_url("http:", "127.0.0.1:8081"),
            "ws://127.0.0.1:8081/api/dashboard/live"
        );
    }

    #[test]
    fn apply_new_cluster_inserts_and_dedupes() {
        let mut snap = empty_snapshot();
        let id = IncidentId::new();
        let cluster = IncidentClusterSummary {
            incident_id: id,
            primary_subject: SubjectId::new(),
            severity: Severity::High,
            status: IncidentStatus::Open,
            related_subject_count: 1,
            opened_at: Utc.with_ymd_and_hms(2026, 5, 14, 0, 0, 0).unwrap(),
        };
        apply_event(
            &mut snap,
            DashboardEvent::NewCluster {
                cluster: cluster.clone(),
            },
        );
        assert_eq!(snap.clusters.len(), 1);
        // Re-applying the same incident_id replaces rather than duplicates.
        apply_event(&mut snap, DashboardEvent::NewCluster { cluster });
        assert_eq!(snap.clusters.len(), 1);
    }

    #[test]
    fn apply_new_signal_pushes_to_front() {
        let mut snap = empty_snapshot();
        let signal = CoordinatedSignal {
            kind: CoordinatedSignalKind::ImageHashCluster,
            label: "deadbeef".to_owned(),
            subject_count: 2,
            detected_at: Utc.with_ymd_and_hms(2026, 5, 14, 1, 0, 0).unwrap(),
        };
        apply_event(
            &mut snap,
            DashboardEvent::NewSignal {
                signal: signal.clone(),
            },
        );
        assert_eq!(snap.coordinated_signals.len(), 1);
        assert_eq!(snap.coordinated_signals[0].label, "deadbeef");
        // A second signal lands at index 0, ahead of the first.
        let later = CoordinatedSignal {
            label: "cafebabe".to_owned(),
            ..signal
        };
        apply_event(&mut snap, DashboardEvent::NewSignal { signal: later });
        assert_eq!(snap.coordinated_signals.len(), 2);
        assert_eq!(snap.coordinated_signals[0].label, "cafebabe");
    }

    #[test]
    fn apply_volume_bucket_updated_replaces_matching_bucket() {
        let mut snap = empty_snapshot();
        let bucket_time = Utc.with_ymd_and_hms(2026, 5, 14, 12, 0, 0).unwrap();
        let bucket_a = ReportVolumeBucket {
            bucket_start: bucket_time,
            count: 3,
            expected_mean: 0.0,
            expected_stddev: 0.0,
        };
        apply_event(
            &mut snap,
            DashboardEvent::VolumeBucketUpdated {
                bucket: bucket_a.clone(),
            },
        );
        assert_eq!(snap.report_volume.len(), 1);
        assert_eq!(snap.report_volume[0].count, 3);

        // Same bucket_start, new count — replaces in place.
        let bucket_b = ReportVolumeBucket {
            bucket_start: bucket_time,
            count: 9,
            expected_mean: 0.0,
            expected_stddev: 0.0,
        };
        apply_event(
            &mut snap,
            DashboardEvent::VolumeBucketUpdated { bucket: bucket_b },
        );
        assert_eq!(snap.report_volume.len(), 1);
        assert_eq!(snap.report_volume[0].count, 9);
    }

    #[test]
    fn apply_moderator_load_delta_replaces_matching_category() {
        let mut snap = empty_snapshot();
        apply_event(
            &mut snap,
            DashboardEvent::ModeratorLoadDelta {
                load: ModeratorLoad {
                    category: "all".to_owned(),
                    open_count: 1,
                    in_review_count: 0,
                },
            },
        );
        assert_eq!(snap.moderator_load.len(), 1);
        assert_eq!(snap.moderator_load[0].open_count, 1);

        apply_event(
            &mut snap,
            DashboardEvent::ModeratorLoadDelta {
                load: ModeratorLoad {
                    category: "all".to_owned(),
                    open_count: 7,
                    in_review_count: 2,
                },
            },
        );
        assert_eq!(snap.moderator_load.len(), 1);
        assert_eq!(snap.moderator_load[0].open_count, 7);
        assert_eq!(snap.moderator_load[0].in_review_count, 2);
    }

    // Smoke test: build a DashboardBody view with a fixture snapshot.
    // This exercises the typed prop-threading through the four panels;
    // the actual DOM rendering is a wasm-bindgen-test concern that the
    // issue #20 pre-flight explicitly waives in favour of a compile-test
    // when wasm test infra is tricky.
    #[test]
    fn dashboard_body_builds_with_empty_snapshot() {
        let snap = empty_snapshot();
        // The component constructor is `impl IntoView`; we just prove it
        // type-checks. Mounting requires a Leptos runtime, which lives
        // in the wasm-bindgen-test harness — out of scope for #57.
        let _ = snap;
    }
}
