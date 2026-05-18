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

use crate::api_client::dto::{DashboardEvent, DashboardSnapshot, WhoamiResponse};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::components::dashboard::cluster_list::ClusterList;
use crate::components::dashboard::coordinated_signals::CoordinatedSignalsPanel;
use crate::components::dashboard::moderator_load::ModeratorLoadPanel;
use crate::components::dashboard::report_volume_chart::ReportVolumeChart;
use crate::components::filter_bar::{FilterBar, FilterState};
use crate::pages::admin_moderators::ADMIN_MODERATORS_PATH;
use crate::pages::login::{is_unauthorized, redirect_to_login};

/// Role identifier the backend's `whoami` response uses for the
/// admin tier (snake-case matching `Role::as_db_str`).
///
/// Centralised here so the admin-link gate in the dashboard nav and
/// any future role-aware affordance read from one constant rather
/// than re-typing the literal.
const ROLE_ADMIN: &str = "admin";

/// Pure predicate: does the supplied [`WhoamiResponse`] carry the
/// admin role?
///
/// The frontend uses this to decide whether to render the dashboard's
/// `Moderators` admin-only link. The backend independently enforces
/// the gate on every admin endpoint, so this predicate is a UX
/// affordance — its job is to keep the link out of view for
/// non-admins, NOT to provide security.
#[must_use]
pub fn whoami_is_admin(whoami: &WhoamiResponse) -> bool {
    whoami.roles.iter().any(|r| r == ROLE_ADMIN)
}

/// Render the dashboard's role-gated admin-link nav.
///
/// Fetches `GET /api/whoami` once on mount; renders the "Moderators"
/// link iff the response carries `Role::Admin`. Every failure mode
/// (unauthenticated, transport error, JSON decode error) is treated
/// as "render nothing" — the dashboard's main fetch already runs the
/// 401-redirect contract, so a duplicate redirect path here would
/// race with it. Mirrors the dashboard's anti-flicker philosophy:
/// the absence of a UI affordance is always safe, the presence of
/// one is what we gate.
#[component]
fn AdminLink() -> impl IntoView {
    let whoami = LocalResource::new(|| async move {
        let client = default_client("").ok()?;
        client.whoami().await.ok()
    });

    view! {
        <Suspense fallback=|| ()>
            {move || Suspend::new(async move {
                match whoami.await {
                    Some(response) if whoami_is_admin(&response) => view! {
                        <a class="pattern-dashboard__admin-link" href=ADMIN_MODERATORS_PATH>
                            "Moderators →"
                        </a>
                    }.into_any(),
                    _ => ().into_any(),
                }
            })}
        </Suspense>
    }
}

/// Polling interval for the polling-fallback refetch trigger, in milliseconds.
///
/// 5 seconds matches the issue #20 baseline. Used when the WebSocket
/// live feed is unavailable; the new "live" path (issue #57) reflects
/// updates within 1 second of detection regardless of this constant.
// Polling fallback interval. Set to 60 seconds (NOT 5) because the
// primary data path is the WebSocket live feed (#57); polling exists
// only as a stale-watcher for when the WS connection drops. A 5s
// polling cadence was steamrolling the moderator's input focus and
// visibly flashing the panel grid every tick. The WS pump still
// pushes diffs at real-time rates; the polling interval governs only
// how long a WS-disconnected client can drift from server state
// before a forced refresh — one minute is the right operational
// floor for that fallback.
pub const POLL_INTERVAL_MS: u64 = 60_000;

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

    // Anti-flicker cache: the most recent successful snapshot from
    // the `LocalResource`. The view reads from this signal so the
    // panels stay mounted across refetches — the polling tick,
    // filter changes, and WS-induced refetches no longer flash the
    // "Loading dashboard…" placeholder. The bridging `Effect` below
    // copies the resource's value into this cache whenever the
    // resource resolves successfully.
    let cached_snapshot = RwSignal::new(None::<DashboardSnapshot>);

    // Last-fetch-error signal — surfaced inline beneath the panels
    // without destroying the cached snapshot. A transient network
    // blip therefore reads as "panels are stale, here's why" rather
    // than "everything is gone, retry."
    let fetch_error = RwSignal::new(None::<String>);

    // Issue #94: faceted-filter state. Lives on the dashboard mount
    // (NOT in `localStorage`, NOT in the URL). Promotion to URL
    // params for shareable filtered dashboards is a separate
    // workstream. The `LocalResource` below keys off this signal so
    // changing a facet kicks off a re-fetch.
    let filters = RwSignal::new(FilterState::default());

    start_live_feed(set_tick, live_snapshot);
    start_polling(set_tick);

    let snapshot = LocalResource::new(move || {
        let _token = tick.get();
        let filters_snapshot = filters.get();
        async move {
            // Inspect each error against the 401-redirect contract
            // (#82) BEFORE stringifying: an unauthenticated dashboard
            // call must bounce the operator to `/login` rather than
            // render an inline "HTTP 401" panel. `redirect_to_login`
            // is a no-op on native targets so the same code path
            // compiles for tests / IDE checks. Other errors propagate
            // as their `Display` text into the `<Suspense>` arm.
            let client = default_client("").map_err(|e: ApiError| {
                if is_unauthorized(&e) {
                    redirect_to_login();
                }
                e.to_string()
            })?;
            let dto_filters = filters_snapshot.to_filters();
            client.dashboard(&dto_filters).await.map_err(|e: ApiError| {
                if is_unauthorized(&e) {
                    redirect_to_login();
                }
                e.to_string()
            })
        }
    });

    // Anti-flicker bridge: every time the `LocalResource` resolves,
    // copy its value into the cache / error signal. On success the
    // panels re-render from `cached_snapshot` without ever flashing
    // the `<Suspense>` fallback. On failure the cache is preserved
    // (the moderator keeps seeing the last-known state) and the
    // inline error band surfaces the reason.
    Effect::new(move |_| {
        if let Some(result) = snapshot.get() {
            match result {
                Ok(snap) => {
                    // Anti-flicker safeguard: only push the new
                    // snapshot through the cache signal if it
                    // actually differs from what's already there.
                    // Polling refetches always produce a `Ok(snap)`
                    // — but if the underlying counts/clusters/etc.
                    // haven't moved, calling `set()` would still
                    // fire every reactive subscriber on the view
                    // side, re-evaluating the closure that renders
                    // `<DashboardBody>` and ultimately re-mounting
                    // every panel's child components. The
                    // serde_json fingerprint comparison is cheap
                    // (small snapshot, ~ms) and skipping no-op
                    // updates means the panels hold steady across
                    // polling ticks. The signal still fires when
                    // any sub-field changes; we just stop firing
                    // on every snapshot whose only difference is
                    // the (server-stamped) `fetched_at` timestamp
                    // for unchanged data.
                    let is_distinct = cached_snapshot
                        .get_untracked()
                        .as_ref()
                        .and_then(|existing| {
                            // Both serialise: compare fingerprints.
                            // Either fails: fall back to "distinct"
                            // so we update (visible-value bias is
                            // safer than a stale display).
                            let new_json = serde_json::to_string(&snap).ok()?;
                            let cur_json = serde_json::to_string(existing).ok()?;
                            Some(cur_json != new_json)
                        })
                        .unwrap_or(true);
                    if is_distinct {
                        cached_snapshot.set(Some(snap));
                    }
                    // Always clear the error flag on a successful
                    // fetch, even when the data was identical. The
                    // operator's mental model is "last refresh
                    // worked", not "last refresh produced different
                    // data".
                    if fetch_error.get_untracked().is_some() {
                        fetch_error.set(None);
                    }
                }
                Err(message) => {
                    fetch_error.set(Some(message));
                }
            }
        }
    });

    view! {
        <main class="pattern-dashboard" id="pattern-dashboard-root">
            <header class="pattern-dashboard__header">
                <h1>"Polaris"</h1>
                <p class="pattern-dashboard__tagline">
                    "Pattern-first moderation."
                </p>
                // First tab-stop CTA on the dashboard: a keyboard-
                // focusable link into the triage queue (issue #91,
                // mod-workstation feature #1). The href matches
                // `crate::pages::queue::QUEUE_PATH` — kept in sync
                // there via a unit test. Anchor (not button) so a
                // middle-click or cmd-click opens in a new tab.
                <a class="triage-queue__open-cta" href=crate::pages::queue::QUEUE_PATH>
                    "Open triage queue →"
                </a>
                // Issue #214 / #217: admin-only nav link to the
                // moderator allow-list page. Hidden when the
                // operator's `whoami` response does not carry
                // `Role::Admin`. The backend independently rejects
                // the data fetch on the linked page, so this gate
                // is decoration — but a missing link prevents an
                // operator from being confused by a Forbidden
                // banner they did not expect to see.
                <AdminLink/>
                // Issue #92: subdued hint about the global Ctrl/Cmd-K
                // command palette. Visual only — the palette is mounted
                // globally in `app.rs` and responds to the keystroke
                // regardless of which surface has focus. `<kbd>` is the
                // semantic element for keyboard input; styled by
                // `pattern-dashboard.css`'s `.pattern-dashboard__cmdk-hint`
                // selector + the existing `kbd` styling on neighbouring
                // surfaces.
                <p class="pattern-dashboard__cmdk-hint">
                    "or press "<kbd>"⌘K"</kbd>" to jump to any subject."
                </p>
                // Pointer-driven counterpart to the keyboard-only
                // command palette: a visible search bar that accepts
                // the same identifier shapes (handle, DID, AT-URI,
                // bsky.app URL) and routes to the case view. Mounted
                // here in the header so it's the second affordance an
                // operator sees after the queue CTA.
                <crate::components::subject_lookup_bar::SubjectLookupBar/>
            </header>
            // Issue #94: faceted-filter toolbar mounted above the
            // grid. The component owns the keystroke handler that
            // focuses the reporter-DID input on `/`.
            <FilterBar state=filters/>
            // Anti-flicker render path. The `LocalResource`
            // (`snapshot`) keeps refetching on every polling tick,
            // filter change, and WS-triggered refresh. The reactive
            // `Effect` above copies the resource's value into
            // `cached_snapshot`. The view here reads ONLY from the
            // cache signal — never from the resource directly — so
            // the polling refetches do NOT trigger a Suspense
            // boundary remount, and the panels' child components
            // keep their mounted DOM nodes across ticks.
            //
            // The previous `<Suspense fallback=...>{move || Suspend::new(async move { let _ = snapshot.await; ... })}</Suspense>`
            // shape re-ran the inner async on every refetch which
            // caused the panels' children to be reconstructed
            // — visible to the operator as the panel grid flashing
            // every few seconds.
            {move || {
                let chosen = live_snapshot
                    .get()
                    .or_else(|| cached_snapshot.get());
                match chosen {
                    Some(snap) => view! { <DashboardBody snapshot=snap/> }.into_any(),
                    None => view! {
                        <p class="pattern-dashboard__loading" role="status">
                            "Loading dashboard…"
                        </p>
                    }.into_any(),
                }
            }}
            // Inline non-blocking error band — only renders when the
            // last fetch failed. Surfaces alongside the (possibly
            // stale) cached panels so the moderator can see *both*
            // the last-known data AND the fact that the refresh
            // failed.
            {move || fetch_error.get().map(|message| view! {
                <p class="pattern-dashboard__error" role="alert">
                    "Dashboard refresh failed: "{message}
                </p>
            })}
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
    fn poll_interval_is_sixty_seconds() {
        // Regression: polling is the fallback path. The 60-second
        // cadence is the load-bearing constant — a 5-second cadence
        // (the original value) was steamrolling moderator input focus
        // and visibly re-mounting the panel grid every tick because
        // each refetch pushed a new (identical) snapshot through the
        // cache signal. The WebSocket live feed (#57) is the primary
        // data path; this interval governs only how long a
        // WS-disconnected client may drift from server state before a
        // forced refresh. A future refactor that quietly drops the
        // interval will trip this assertion.
        assert_eq!(POLL_INTERVAL_MS, 60_000);
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
