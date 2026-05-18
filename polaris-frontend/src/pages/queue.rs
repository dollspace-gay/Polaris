//! `TriageQueue` — the keyboard-driven incident triage surface
//! (issue #91, mod-workstation feature #1).
//!
//! Renders the same incident-cluster rows the dashboard ships, but in a
//! shape optimised for sweeping: a single column of focusable rows that
//! a moderator drives with the keyboard. Modelled on Reddit's modqueue
//! ([CHI 2026 study](https://arxiv.org/html/2509.07314v2)) and Bluesky
//! Ozone's queue view.
//!
//! # Data
//!
//! The queue consumes the same `GET /api/dashboard` payload the pattern
//! dashboard already polls. No new backend endpoint is required for #1
//! — the cluster summaries carry every field the queue surface needs
//! (subject id, severity, status, related-subject count, opened-at).
//! Future PRs (#94 faceted search) may need a dedicated `/api/queue`
//! endpoint; that decision is deliberately deferred so the queue ships
//! as a pure client surface here.
//!
//! # Keyboard model
//!
//! Captured at `window` so a moderator never has to click into the list
//! before keys work. Event listeners are torn down on unmount via
//! [`on_cleanup`]; the suppression rules below short-circuit when the
//! event target is editable so the keys do not fire while the moderator
//! is typing reasoning into a future drawer (#93).
//!
//! | Key | Action |
//! |-----|--------|
//! | `j` / `ArrowDown` | Focus next row |
//! | `k` / `ArrowUp` | Focus previous row |
//! | `Enter` / `o` | Open the focused incident's case page |
//! | `r` | Flag the focused row "reviewed" (client-only; the persisted form ships with #93's drawer) |
//! | `g g` | Jump to top (two presses) |
//! | `G` | Jump to bottom |
//! | `?` | Toggle keymap overlay |
//!
//! # Path
//!
//! Mounted at `/queue` by [`crate::app::App`].
//!
//! [`on_cleanup`]: leptos::prelude::on_cleanup

use std::collections::HashSet;

use chrono::{Duration, Utc};
use leptos::prelude::*;
use leptos::task::spawn_local;
use polaris_types::{ActionKind, IncidentId, PolicyId, SubjectId};

use crate::api_client::dto::{
    BulkActionOutcome, BulkSubmitAction, DashboardSnapshot, IncidentClusterSummary, SubmitAction,
};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::pages::login::{is_unauthorized, redirect_to_login};

/// Path the triage queue is mounted at.
///
/// Centralising the constant keeps the route declaration in
/// [`crate::app`] and the dashboard's "Open triage queue" CTA in sync
/// — a future move (e.g. `/triage`) lands at one site.
pub const QUEUE_PATH: &str = "/queue";

/// Compute the next-focus index for a `j` / `ArrowDown` press.
///
/// Wraps from the last row back to index 0; returns 0 when `len == 0`
/// so callers do not have to special-case the empty list at the call
/// site. The wrap matches Reddit modqueue / Ozone behaviour: a
/// moderator who has swept the bottom row should not have to scroll
/// back up to start over.
#[must_use]
pub const fn next_focus(current: usize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    let next = current.saturating_add(1);
    if next >= len { 0 } else { next }
}

/// Compute the previous-focus index for a `k` / `ArrowUp` press.
///
/// Wraps from index 0 to the last row (`len - 1`); returns 0 when
/// `len == 0`. Symmetric with [`next_focus`].
#[must_use]
pub const fn prev_focus(current: usize, len: usize) -> usize {
    if len == 0 {
        return 0;
    }
    if current == 0 {
        // Wrap to the bottom. `len` is >= 1 in this arm so the
        // subtraction is sound; `saturating_sub` makes the intent
        // explicit and keeps the function `const`-eligible.
        len.saturating_sub(1)
    } else {
        current.saturating_sub(1)
    }
}

/// Render the triage queue page.
///
/// On mount, fetches `GET /api/dashboard` and renders the cluster rows
/// inside a focusable list. The keyboard handler is wired at the
/// window level on the wasm target and torn down on unmount.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn TriageQueue() -> impl IntoView {
    let snapshot = LocalResource::new(|| async move {
        // 401-redirect contract (#82): an unauthenticated dashboard
        // call must bounce the operator to `/login` rather than
        // render an inline error. `redirect_to_login` is a no-op on
        // native targets so the same code path compiles for tests /
        // IDE checks. Other errors propagate as their `Display` text
        // into the `<Suspense>` arm. Mirrors the pattern in
        // `crate::pages::dashboard::PatternDashboard`.
        let client = default_client("").map_err(|e: ApiError| {
            if is_unauthorized(&e) {
                redirect_to_login();
            }
            e.to_string()
        })?;
        client.get_dashboard().await.map_err(|e: ApiError| {
            if is_unauthorized(&e) {
                redirect_to_login();
            }
            e.to_string()
        })
    });

    view! {
        <main class="triage-queue" id="triage-queue-root">
            <header class="triage-queue__header">
                <h1>"Triage queue"</h1>
                <p class="triage-queue__keymap-hint">
                    <kbd>"j"</kbd>"/"<kbd>"k"</kbd>" move · "
                    <kbd>"Enter"</kbd>" open · "
                    <kbd>"r"</kbd>" reviewed · "
                    <kbd>"?"</kbd>" keymap"
                </p>
            </header>
            <Suspense fallback=move || view! {
                <p class="triage-queue__loading" role="status">"Loading queue…"</p>
            }>
                {move || Suspend::new(async move {
                    match snapshot.await {
                        Ok(snap) => view! {
                            <TriageQueueBody snapshot=snap/>
                        }.into_any(),
                        Err(message) => view! {
                            <p class="triage-queue__error" role="alert">
                                "Queue unreachable: "{message}
                            </p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </main>
    }
}

/// Render the queue body given a fetched snapshot.
///
/// Owns the focus index, reviewed-set, and keymap-overlay-visible
/// signals. Pulled out of [`TriageQueue`] so the resource lifecycle is
/// scoped to a successful fetch — a transient 5xx renders the inline
/// error path without paying for the keyboard wiring.
#[component]
fn TriageQueueBody(
    /// Hydrated dashboard payload (we consume the `clusters` field).
    snapshot: DashboardSnapshot,
) -> impl IntoView {
    let DashboardSnapshot { clusters, .. } = snapshot;
    let count = clusters.len();

    if count == 0 {
        return view! {
            <p class="triage-queue__empty" role="status">
                "No open or escalated incidents at this time."
            </p>
        }
        .into_any();
    }

    let (focus_idx, set_focus_idx) = signal(0_usize);
    let (reviewed, set_reviewed) = signal(std::collections::BTreeSet::<usize>::new());
    let (overlay_open, set_overlay_open) = signal(false);
    // Issue #195: multi-select for the bulk-action toolbar. We track
    // (SubjectId, IncidentId) pairs so the toolbar can group by
    // incident and issue one POST per incident — the bulk-actions
    // endpoint shares one incident_id across its batch.
    let selected = RwSignal::new(HashSet::<(SubjectId, IncidentId)>::new());
    let bulk_status = RwSignal::new(BulkBarStatus::Idle);
    // Drawer subject signal — issue #93 / mod-workstation #3. When
    // `Some(subject_id)`, `<CaseDrawer/>` slides in from the right and
    // the queue's `j/k/r/?/Enter/o/g/G` keys are suppressed (see
    // `install_keyboard_handler` below). The drawer installs its own
    // window-level Escape listener so dismissing the drawer doesn't
    // require the queue handler.
    let (drawer_subject, set_drawer_subject) = signal(None::<String>);

    // Snapshot a vector of (subject_id_string, incident_id_string) the
    // window-level keyboard handler can navigate / inspect without
    // re-borrowing the cluster vec on every event.
    let subjects: Vec<String> = clusters
        .iter()
        .map(|c| c.primary_subject.to_string())
        .collect();

    install_keyboard_handler(
        count,
        subjects,
        focus_idx,
        set_focus_idx,
        set_reviewed,
        set_overlay_open,
        drawer_subject,
        set_drawer_subject,
    );

    let rows = render_rows(clusters, focus_idx, reviewed, set_focus_idx, selected);
    let drawer_signal: leptos::prelude::Signal<Option<String>> = drawer_subject.into();
    let drawer_on_close: leptos::prelude::Callback<()> =
        leptos::prelude::Callback::new(move |()| set_drawer_subject.set(None));

    view! {
        <p class="triage-queue__count" role="status">
            {count}" open incident(s) — sweep with "<kbd>"j"</kbd>"/"<kbd>"k"</kbd>
        </p>
        {render_bulk_toolbar(selected, bulk_status)}
        <ul class="triage-queue__list" role="listbox" aria-label="Open incidents">
            {rows}
        </ul>
        {move || overlay_open.get().then(|| view! {
            <KeymapOverlay on_close=move || set_overlay_open.set(false)/>
        })}
        <crate::components::case_drawer::CaseDrawer
            subject_id=drawer_signal
            on_close=drawer_on_close
        />
    }
    .into_any()
}

/// State of the bulk-action toolbar's submit button.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BulkBarStatus {
    /// No action in flight; toolbar accepts clicks.
    Idle,
    /// A bulk POST is mid-flight; buttons disable.
    Pending,
    /// Last action result: succeeded count + failed count.
    Done { succeeded: usize, failed: usize },
    /// Last action errored before completing (network / client error).
    Error(String),
}

/// Render the bulk-action toolbar. Hidden when no rows are selected;
/// shows count + per-verb buttons when 1+ are selected.
fn render_bulk_toolbar(
    selected: RwSignal<HashSet<(SubjectId, IncidentId)>>,
    status: RwSignal<BulkBarStatus>,
) -> AnyView {
    let on_acknowledge = move |_| {
        spawn_bulk(selected, status, ActionKind::NoAction);
    };
    let on_escalate = move |_| {
        spawn_bulk(selected, status, ActionKind::Escalate);
    };
    let on_clear = move |_| {
        selected.set(HashSet::new());
        status.set(BulkBarStatus::Idle);
    };

    view! {
        <div
            class="triage-queue__bulkbar"
            role="region"
            aria-label="Bulk action toolbar"
            hidden=move || selected.with(HashSet::is_empty)
        >
            <span class="triage-queue__bulkbar-count" role="status">
                {move || format!("{} subject(s) selected", selected.with(HashSet::len))}
            </span>
            <button
                type="button"
                class="triage-queue__bulkbar-btn triage-queue__bulkbar-btn--ack"
                disabled=move || matches!(status.get(), BulkBarStatus::Pending)
                on:click=on_acknowledge
            >
                "Acknowledge all"
            </button>
            <button
                type="button"
                class="triage-queue__bulkbar-btn triage-queue__bulkbar-btn--escalate"
                disabled=move || matches!(status.get(), BulkBarStatus::Pending)
                on:click=on_escalate
            >
                "Escalate all"
            </button>
            <button
                type="button"
                class="triage-queue__bulkbar-btn triage-queue__bulkbar-btn--clear"
                on:click=on_clear
            >
                "Clear selection"
            </button>
            {move || render_bulk_status(&status.get())}
        </div>
    }
    .into_any()
}

/// Render the inline status line below the toolbar buttons.
fn render_bulk_status(status: &BulkBarStatus) -> AnyView {
    match status {
        BulkBarStatus::Idle => ().into_any(),
        BulkBarStatus::Pending => view! {
            <span class="triage-queue__bulkbar-status" role="status">
                "Applying…"
            </span>
        }
        .into_any(),
        BulkBarStatus::Done { succeeded, failed } => {
            let msg = if *failed == 0 {
                format!("Done: {succeeded} succeeded")
            } else {
                format!("Done: {succeeded} succeeded, {failed} failed")
            };
            view! {
                <span class="triage-queue__bulkbar-status triage-queue__bulkbar-status--done"
                      role="status">
                    {msg}
                </span>
            }
            .into_any()
        }
        BulkBarStatus::Error(msg) => view! {
            <span class="triage-queue__bulkbar-status triage-queue__bulkbar-status--error"
                  role="status">
                "Failed: "{msg.clone()}
            </span>
        }
        .into_any(),
    }
}

/// Fire bulk-action POSTs across the unique incidents in the
/// selection. The bulk-actions endpoint takes one `incident_id` per
/// batch, so the frontend groups subjects by incident and issues one
/// POST per group. The combined succeeded/failed counts are summed
/// into the toolbar's status signal.
fn spawn_bulk(
    selected: RwSignal<HashSet<(SubjectId, IncidentId)>>,
    status: RwSignal<BulkBarStatus>,
    kind: ActionKind,
) {
    if matches!(status.get_untracked(), BulkBarStatus::Pending) {
        return;
    }
    let snapshot: Vec<(SubjectId, IncidentId)> = selected.get_untracked().into_iter().collect();
    if snapshot.is_empty() {
        return;
    }
    status.set(BulkBarStatus::Pending);

    // Group by incident_id so we can issue one POST per incident.
    let mut by_incident: std::collections::HashMap<IncidentId, Vec<SubjectId>> =
        std::collections::HashMap::new();
    for (sub, inc) in snapshot {
        by_incident.entry(inc).or_default().push(sub);
    }

    let reasoning = match kind {
        ActionKind::NoAction => "Bulk acknowledgement from triage queue".to_owned(),
        ActionKind::Escalate => "Bulk escalation from triage queue for senior review".to_owned(),
        other => format!("Bulk {} from triage queue", other.as_str()),
    };

    spawn_local(async move {
        let client = match default_client("") {
            Ok(c) => c,
            Err(e) => {
                status.set(BulkBarStatus::Error(describe_error(&e)));
                return;
            }
        };
        let mut total_succeeded = 0_usize;
        let mut total_failed = 0_usize;
        for (incident_id, subject_ids) in by_incident {
            let body = BulkSubmitAction {
                subject_ids: subject_ids.clone(),
                body: SubmitAction {
                    incident_id,
                    kind,
                    label: None,
                    reasoning: reasoning.clone(),
                    policy_refs: vec![PolicyId::new("polaris.spam")],
                    reversible_until: Utc::now() + Duration::hours(24),
                    reverses_action_id: None,
                    // Bulk subject-level apply — not a per-report
                    // decision, so the idempotency key stays `None`.
                    report_id: None,
                },
            };
            match client.bulk_action(body).await {
                Ok(BulkActionOutcome { succeeded, failed }) => {
                    total_succeeded = total_succeeded.saturating_add(succeeded.len());
                    total_failed = total_failed.saturating_add(failed.len());
                }
                Err(e) => {
                    total_failed = total_failed.saturating_add(subject_ids.len());
                    tracing::warn!("bulk-action POST failed: {}", describe_error(&e));
                }
            }
        }
        // Clear the selection once the bulk operation completes — the
        // moderator's eye moves to the toolbar's "Done" line; carrying
        // stale checkmarks on next interaction would invite a
        // double-apply.
        selected.set(HashSet::new());
        status.set(BulkBarStatus::Done {
            succeeded: total_succeeded,
            failed: total_failed,
        });
    });
}

fn describe_error(err: &ApiError) -> String {
    match err {
        ApiError::Transport(msg) => format!("transport: {msg}"),
        ApiError::Http { status, message } => format!("HTTP {status}: {message}"),
    }
}

/// Build the row elements for the queue body.
///
/// Each row is rendered as an `<li>` (rather than the
/// `cluster-list__row` `<a>` shape) so the focus model is uniform
/// across keyboard-driven and click-driven entry — clicking a row
/// shifts focus to it, and the global `Enter` handler then navigates.
/// Click navigation still works via the global handler too.
fn render_rows(
    clusters: Vec<IncidentClusterSummary>,
    focus_idx: ReadSignal<usize>,
    reviewed: ReadSignal<std::collections::BTreeSet<usize>>,
    set_focus_idx: WriteSignal<usize>,
    selected: RwSignal<HashSet<(SubjectId, IncidentId)>>,
) -> Vec<impl IntoView> {
    clusters
        .into_iter()
        .enumerate()
        .map(|(idx, c)| {
            let subject_id_typed = c.primary_subject;
            let incident_id_typed = c.incident_id;
            let pair = (subject_id_typed, incident_id_typed);
            let subject_id = c.primary_subject.to_string();
            let incident_id = c.incident_id.to_string();
            let severity = c.severity.as_str();
            let status = c.status.as_str();
            let related = c.related_subject_count;
            let opened = c.opened_at.to_rfc3339();

            // Reactive class string so Leptos rebuilds it on each focus
            // / reviewed change. We assemble static class names so the
            // `styles_coverage` test sees every selector as a literal.
            let class = move || {
                let focused = focus_idx.get() == idx;
                let is_reviewed = reviewed.with(|set| set.contains(&idx));
                match (focused, is_reviewed) {
                    (true, true) => {
                        "triage-queue__row triage-queue__row--focused triage-queue__row--reviewed"
                    }
                    (true, false) => "triage-queue__row triage-queue__row--focused",
                    (false, true) => "triage-queue__row triage-queue__row--reviewed",
                    (false, false) => "triage-queue__row",
                }
            };
            let aria_selected = move || (focus_idx.get() == idx).to_string();
            let on_click = move |_| set_focus_idx.set(idx);

            // Per-row selection checkbox for the bulk-action
            // toolbar (#195). `is_checked` reads the selection set;
            // `on_check` toggles membership. Click handler on the
            // checkbox stops propagation so checking a row doesn't
            // also shift keyboard focus to it.
            let pair_for_check = pair;
            let is_checked = move || selected.with(|s| s.contains(&pair_for_check));
            let pair_for_toggle = pair;
            let on_check_change = move |_| {
                selected.update(|s| {
                    if !s.insert(pair_for_toggle) {
                        s.remove(&pair_for_toggle);
                    }
                });
            };
            let on_check_click = |ev: leptos::ev::MouseEvent| {
                ev.stop_propagation();
            };

            view! {
                <li
                    class=class
                    role="option"
                    aria-selected=aria_selected
                    data-incident=incident_id
                    on:click=on_click
                >
                    <input
                        type="checkbox"
                        class="triage-queue__checkbox"
                        aria-label="Select for bulk action"
                        prop:checked=is_checked
                        on:change=on_check_change
                        on:click=on_check_click
                    />
                    <span class="triage-queue__severity">{severity}</span>
                    <span class="triage-queue__subject">{subject_id}</span>
                    <span class="triage-queue__related">{related}" related"</span>
                    <span class="triage-queue__status">{status}</span>
                    <time class="triage-queue__when">{opened}</time>
                </li>
            }
        })
        .collect()
}

/// Render the keymap overlay (`?`-toggled).
///
/// A small modal listing the keymap so a moderator can self-orient
/// without leaving the page. Closing returns focus to the row that
/// had focus before opening.
#[component]
fn KeymapOverlay(
    /// Callback to dismiss the overlay (bound to the `Close` button
    /// and the backdrop click).
    on_close: impl Fn() + Copy + 'static,
) -> impl IntoView {
    let on_close_click = move |_| on_close();
    view! {
        <div
            class="triage-queue__keymap-overlay"
            role="dialog"
            aria-modal="true"
            aria-label="Keyboard shortcuts"
            on:click=on_close_click
        >
            <div class="triage-queue__keymap-overlay-panel">
                <h2>"Keyboard shortcuts"</h2>
                <dl>
                    <dt><kbd>"j"</kbd>" / "<kbd>"↓"</kbd></dt>
                    <dd>"Focus next row"</dd>
                    <dt><kbd>"k"</kbd>" / "<kbd>"↑"</kbd></dt>
                    <dd>"Focus previous row"</dd>
                    <dt><kbd>"Enter"</kbd>" / "<kbd>"o"</kbd></dt>
                    <dd>"Open the focused incident"</dd>
                    <dt><kbd>"r"</kbd></dt>
                    <dd>"Flag the focused row reviewed"</dd>
                    <dt><kbd>"g g"</kbd></dt>
                    <dd>"Jump to top (press g twice)"</dd>
                    <dt><kbd>"G"</kbd></dt>
                    <dd>"Jump to bottom"</dd>
                    <dt><kbd>"?"</kbd></dt>
                    <dd>"Toggle this overlay"</dd>
                </dl>
                <button
                    type="button"
                    class="triage-queue__keymap-overlay-close"
                    on:click=on_close_click
                >
                    "Close"
                </button>
            </div>
        </div>
    }
}

// ── Keyboard wiring ─────────────────────────────────────────────────────

/// Pure decision: should this keyboard event be ignored because the
/// user is typing into an editable element?
///
/// Returns `true` for `<input>`, `<textarea>`, `<select>`, and any
/// element whose `contenteditable` attribute is `"true"` /
/// `"plaintext-only"`. The wasm-bound caller passes in the
/// tag-name + contenteditable value pre-resolved so the function is
/// fully testable without a DOM.
#[must_use]
pub fn target_is_editable(tag_name_uppercase: &str, contenteditable: Option<&str>) -> bool {
    matches!(tag_name_uppercase, "INPUT" | "TEXTAREA" | "SELECT")
        || matches!(contenteditable, Some("true" | "plaintext-only"))
}

/// Pure predicate: should the queue's global key handler fire on this
/// event? Returns `true` only when (a) the moderator is not typing
/// into an editable element and (b) the case drawer is closed.
///
/// Issue #93 / mod-workstation #3 — the drawer captures its own
/// keyboard focus when open, so the queue's `j/k/r/?/Enter/o/g/G`
/// must be suppressed for the drawer's lifetime. The drawer's own
/// window-level Escape listener fires independently (it runs even
/// when the focused element is editable, by design), so this
/// suppression is symmetrical: the queue stays quiet, the drawer
/// handles its own dismissal.
#[must_use]
pub fn should_queue_handler_fire(drawer_open: bool, editable_target: bool) -> bool {
    !drawer_open && !editable_target
}

#[cfg(target_arch = "wasm32")]
#[allow(
    clippy::too_many_arguments,
    reason = "queue keyboard handler legitimately threads focus, reviewed-set, overlay, and drawer signals — each is independent state with no obvious coalescing"
)]
fn install_keyboard_handler(
    len: usize,
    subjects: Vec<String>,
    focus_idx: ReadSignal<usize>,
    set_focus_idx: WriteSignal<usize>,
    set_reviewed: WriteSignal<std::collections::BTreeSet<usize>>,
    set_overlay_open: WriteSignal<bool>,
    drawer_subject: ReadSignal<Option<String>>,
    set_drawer_subject: WriteSignal<Option<String>>,
) {
    use leptos::ev;
    use leptos::leptos_dom::helpers::window_event_listener;
    use std::cell::Cell;
    use std::rc::Rc;
    use wasm_bindgen::JsCast as _;

    // Pending-`g` state for the `g g` chord. Kept in an `Rc<Cell<_>>`
    // so the closure can mutate it across invocations without
    // capturing a `&mut` reference (the closure has to be `Fn`).
    let pending_g: Rc<Cell<bool>> = Rc::new(Cell::new(false));

    let handle = window_event_listener(ev::keydown, move |ev: ev::KeyboardEvent| {
        // Suppression rules: never fire while the moderator is typing
        // into an editable element, and never fire while the case
        // drawer (issue #93 / mod-workstation #3) is open — the
        // drawer manages its own keyboard focus and its own Escape
        // handler. We read tag name + contenteditable off the event
        // target if present, then ask the pure helper
        // `should_queue_handler_fire`.
        let editable = ev
            .target()
            .and_then(|t| t.dyn_into::<web_sys::Element>().ok())
            .is_some_and(|el| {
                let tag = el.tag_name();
                let ce = el
                    .get_attribute("contenteditable")
                    .or_else(|| Some(String::new()))
                    .filter(|s| !s.is_empty());
                target_is_editable(tag.as_str(), ce.as_deref())
            });
        let drawer_open = drawer_subject.get_untracked().is_some();
        if !should_queue_handler_fire(drawer_open, editable) {
            return;
        }

        let key = ev.key();
        // Track whether we've consumed the previous `g` for the chord;
        // any non-`g` key clears the pending state so a moderator who
        // mashes keys does not strand the chord across many events.
        let had_pending_g = pending_g.replace(false);

        match key.as_str() {
            "j" | "ArrowDown" => {
                ev.prevent_default();
                let next = next_focus(focus_idx.get_untracked(), len);
                set_focus_idx.set(next);
            }
            "k" | "ArrowUp" => {
                ev.prevent_default();
                let prev = prev_focus(focus_idx.get_untracked(), len);
                set_focus_idx.set(prev);
            }
            "Enter" => {
                // Issue #93 / mod-workstation #3: Enter opens the
                // case in the right-side drawer rather than
                // full-page-navigating away. The moderator stays in
                // the queue's keyboard context; `j`/`k` continues to
                // work after dismissing the drawer.
                ev.prevent_default();
                let idx = focus_idx.get_untracked();
                if let Some(subject) = subjects.get(idx) {
                    set_drawer_subject.set(Some(subject.clone()));
                }
            }
            "o" => {
                // `o` keeps the original behavior: full-page navigation
                // for a moderator who wants the case in its own tab.
                // Documented in the keymap overlay.
                ev.prevent_default();
                let idx = focus_idx.get_untracked();
                if let Some(subject) = subjects.get(idx) {
                    navigate_to_case(subject);
                }
            }
            "r" => {
                ev.prevent_default();
                let idx = focus_idx.get_untracked();
                set_reviewed.update(|set| {
                    if !set.insert(idx) {
                        set.remove(&idx);
                    }
                });
            }
            "?" => {
                ev.prevent_default();
                set_overlay_open.update(|v| *v = !*v);
            }
            "Escape" => {
                set_overlay_open.set(false);
            }
            "g" => {
                ev.prevent_default();
                if had_pending_g {
                    set_focus_idx.set(0);
                    pending_g.set(false);
                } else {
                    pending_g.set(true);
                }
            }
            "G" => {
                ev.prevent_default();
                if len > 0 {
                    set_focus_idx.set(len.saturating_sub(1));
                }
            }
            _ => {}
        }
    });

    on_cleanup(move || handle.remove());
}

/// Native stub — the keyboard handler is a browser concern.
///
/// The signature matches the wasm variant so the call site is
/// target-agnostic; native test builds compile against this no-op.
#[cfg(not(target_arch = "wasm32"))]
#[allow(
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    reason = "signature must match the wasm variant for the call site"
)]
fn install_keyboard_handler(
    _len: usize,
    _subjects: Vec<String>,
    _focus_idx: ReadSignal<usize>,
    _set_focus_idx: WriteSignal<usize>,
    _set_reviewed: WriteSignal<std::collections::BTreeSet<usize>>,
    _set_overlay_open: WriteSignal<bool>,
    _drawer_subject: ReadSignal<Option<String>>,
    _set_drawer_subject: WriteSignal<Option<String>>,
) {
    // Intentionally empty — window-level event handling only makes
    // sense in a browser context. Pure helpers `next_focus` /
    // `prev_focus` / `target_is_editable` cover the testable surface.
}

/// Navigate to the case page for the given subject via the Leptos
/// client-side router.
///
/// Falls back to `window.location.assign` if the router context is
/// unavailable (e.g. mid-teardown). The fallback keeps the contract
/// honest: `Enter` always lands the moderator on the case page.
#[cfg(target_arch = "wasm32")]
fn navigate_to_case(subject_id: &str) {
    use leptos_router::NavigateOptions;
    use leptos_router::hooks::use_navigate;

    let href = format!("/cases/{subject_id}");
    // `use_navigate` panics if called outside a `<Router>`; we are
    // inside one (the queue is a `<Route>`) but defer to a hard
    // navigation if some future refactor breaks that assumption.
    let navigated = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let nav = use_navigate();
        nav(&href, NavigateOptions::default());
    }))
    .is_ok();
    if !navigated {
        if let Some(window) = web_sys::window() {
            let _ = window.location().assign(&href);
        }
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

    #[test]
    fn queue_path_is_slash_queue() {
        // Regression: the route declaration in `crate::app` and the
        // dashboard's "Open triage queue" CTA both key off this
        // constant.
        assert_eq!(QUEUE_PATH, "/queue");
    }

    #[test]
    fn next_focus_wraps_from_bottom_to_top() {
        // Last row → row 0. The wrap matches Reddit modqueue /
        // Ozone behaviour: sweeping past the bottom returns to the
        // top so the moderator never has to scroll back manually.
        assert_eq!(next_focus(4, 5), 0);
        assert_eq!(next_focus(0, 1), 0); // single-row list wraps onto itself
    }

    #[test]
    fn next_focus_advances_in_mid_list() {
        assert_eq!(next_focus(0, 5), 1);
        assert_eq!(next_focus(2, 5), 3);
        assert_eq!(next_focus(3, 5), 4);
    }

    #[test]
    fn next_focus_returns_zero_for_empty_list() {
        // Defensive: an empty list should not produce an out-of-bounds
        // index. The body short-circuits the empty case before wiring
        // the handler, so this case is only reachable on a race; we
        // return 0 anyway so a future caller is not surprised.
        assert_eq!(next_focus(0, 0), 0);
        assert_eq!(next_focus(7, 0), 0);
    }

    #[test]
    fn prev_focus_wraps_from_top_to_bottom() {
        // Row 0 → last row. Symmetric with `next_focus` so the keymap
        // is reversible without a special "first row" case.
        assert_eq!(prev_focus(0, 5), 4);
        assert_eq!(prev_focus(0, 1), 0); // single-row wraps onto itself
    }

    #[test]
    fn prev_focus_decrements_in_mid_list() {
        assert_eq!(prev_focus(4, 5), 3);
        assert_eq!(prev_focus(2, 5), 1);
        assert_eq!(prev_focus(1, 5), 0);
    }

    #[test]
    fn prev_focus_returns_zero_for_empty_list() {
        assert_eq!(prev_focus(0, 0), 0);
        assert_eq!(prev_focus(7, 0), 0);
    }

    #[test]
    fn target_is_editable_catches_form_controls() {
        // Standard form controls always trip the suppression rule so
        // single-letter keys (`r`, `o`, `j`) do not fire while a
        // moderator is filling out reasoning in a future drawer.
        assert!(target_is_editable("INPUT", None));
        assert!(target_is_editable("TEXTAREA", None));
        assert!(target_is_editable("SELECT", None));
    }

    #[test]
    fn target_is_editable_catches_contenteditable() {
        // Rich-text editors render their content in a div with
        // `contenteditable="true"`; suppress keys against those too.
        assert!(target_is_editable("DIV", Some("true")));
        assert!(target_is_editable("SPAN", Some("plaintext-only")));
    }

    #[test]
    fn target_is_editable_passes_through_non_editable() {
        // Body / button / list-item targets are the queue's normal
        // event source and must NOT be suppressed.
        assert!(!target_is_editable("BODY", None));
        assert!(!target_is_editable("BUTTON", None));
        assert!(!target_is_editable("LI", None));
        assert!(!target_is_editable("DIV", None));
        assert!(!target_is_editable("DIV", Some("false")));
        assert!(!target_is_editable("DIV", Some("")));
    }
}
