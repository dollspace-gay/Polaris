//! `HistoryTimeline` — chronological prior-action list with `j`/`k` keyboard
//! navigation.
//!
//! Per `design.md` §5.2, the moderator opening a case for the first time
//! sees the same audit context the seventh moderator would have
//! reconstructed manually under Ozone. The timeline is that surface.
//!
//! # Keyboard model
//!
//! - `j` moves the selection one step forward (newer action).
//! - `k` moves the selection one step backward (older action).
//! - The selection cursor is announced via `aria-activedescendant` on the
//!   timeline `<ul>` so screen readers track focus without the keyboard
//!   handler having to call `.focus()` on each item.
//!
//! Selection indexing matches the order of the `actions` vector
//! (chronological — older first). An empty timeline disables the
//! keyboard handler outright.

use chrono::{DateTime, Utc};
use leptos::ev;
use leptos::prelude::*;
use polaris_types::{Action, ActionId, ActionKind, ModeratorId};
use wasm_bindgen::JsCast as _;

use crate::api_client::dto::ReverseBody;
use crate::api_client::{ApiError, PolarisApiClient, default_client};

/// Minimum reasoning length for a reversal. Mirrors
/// `polaris_backend::api::reversal::MIN_REASONING_LEN`. The backend is
/// the source of truth; the affordance refuses to submit until the
/// reasoning is long enough so the user gets immediate feedback rather
/// than a 400 round-trip.
pub const MIN_REASONING_LEN: usize = 10;

/// Identity hint about the moderator viewing the page.
///
/// The timeline uses this to render the "Reverse" button only when the
/// requester is eligible — mirroring backend `can_reverse` so the
/// affordance does not invite a request the server will reject. The
/// backend remains the source of truth; this is purely an affordance
/// hint.
///
/// Wired by the page-level component from whatever identity surface is
/// available (today: not yet — a `/api/me` lands in #34). Until then,
/// callers pass `None` and the Reverse button is hidden. Once the
/// identity endpoint lands the hint can be threaded through without
/// touching this component again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Viewer {
    /// Stable moderator identifier — matches `Action.moderator_id` on
    /// authored actions.
    pub moderator_id: ModeratorId,
    /// `true` when the viewer holds the `Admin` or `SeniorModerator`
    /// role. Senior moderators bypass the 24h window per `design.md`
    /// §5.5.
    pub is_senior: bool,
}

/// Client-side mirror of `polaris_backend::api::reversal::can_reverse`.
///
/// Returns `true` when the viewer is eligible to reverse `original`
/// given a `now` timestamp and a flag indicating whether the action has
/// already been reversed. The backend remains the source of truth — this
/// is purely an affordance gate.
#[must_use]
pub fn can_reverse(
    viewer: &Viewer,
    original: &Action,
    already_reversed: bool,
    now: DateTime<Utc>,
) -> bool {
    if already_reversed {
        return false;
    }
    // Reversal-of-reversal is not offered through this affordance.
    if original.kind == ActionKind::Reverse {
        return false;
    }
    if viewer.is_senior {
        return true;
    }
    let is_author = viewer.moderator_id == original.moderator_id;
    is_author && now < original.reversible_until
}

/// Chronological timeline of prior actions against a subject.
///
/// # Props
///
/// - `actions`: the `history` vector from the [`crate::api_client::dto::CaseView`]
///   response. Already chronologically ordered by the backend.
///
/// # Accessibility
///
/// The list is `role="listbox"` (rather than the default `role="list"`)
/// because the moderator selects an item with `j`/`k`. Each row is a
/// `role="option"` with a stable `id` attribute so the listbox's
/// `aria-activedescendant` can name it. The selection class also flips a
/// visual marker so sighted users see the same cursor.
// See `subject_header::SubjectHeader` for the rationale on each lint
// allow: `must_use_candidate` is unsatisfiable on `#[component]`,
// `missing_docs` covers the macro-generated Props struct fields, and
// `too_many_lines` reflects the natural shape of a keyboard-aware list
// view (signals + handlers + listbox body) which is more readable inline
// than fragmented across helper components.
#[allow(
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    reason = "Leptos #[component] requires the prop signature to be owned; \
              `viewer` is moved into the per-row closures rather than borrowed"
)]
#[component]
pub fn HistoryTimeline(
    /// Chronological history vector from the case-view DTO.
    actions: Vec<Action>,
    /// Identity hint about the requesting moderator. `None` hides the
    /// Reverse affordance — used today because the identity endpoint
    /// (#34) hasn't landed.
    #[prop(optional)]
    viewer: Option<Viewer>,
    /// Optional callback invoked after a successful reversal so the
    /// page can refetch the case view. Wired in `case_view.rs` to the
    /// same refresh-token bump signal the action composer uses.
    #[prop(into, optional)]
    on_reverse_success: Option<Callback<Action>>,
) -> impl IntoView {
    let actions_len = actions.len();
    let (selected, set_selected) = signal(0_usize);

    // Build the lookup set of already-reversed action ids in one pass so
    // each row's eligibility check is O(1) rather than O(actions).
    let already_reversed_ids: std::collections::HashSet<ActionId> = actions
        .iter()
        .filter_map(|a| {
            if a.kind == ActionKind::Reverse {
                a.reverses_action_id
            } else {
                None
            }
        })
        .collect();

    // Element id of the timeline container (so the keydown handler can
    // scope itself — see `on_keydown` below).
    let list_id = "history-timeline-list";

    // Stable per-row id used by `aria-activedescendant`. Built once at
    // render time because `actions` is owned by this component.
    let row_ids: Vec<String> = (0..actions_len)
        .map(|i| format!("history-timeline-row-{i}"))
        .collect();
    let row_ids_for_aria = row_ids.clone();

    // Move the selection cursor on `j`/`k`. The handler is attached to the
    // `<ul>` so it only fires when the timeline has focus; the element's
    // `tabindex="0"` makes it focusable.
    let on_keydown = move |ev: ev::KeyboardEvent| {
        if actions_len == 0 {
            return;
        }
        let key = ev.key();
        match key.as_str() {
            "j" => {
                ev.prevent_default();
                set_selected.update(|i| {
                    if *i + 1 < actions_len {
                        *i += 1;
                    }
                });
            }
            "k" => {
                ev.prevent_default();
                set_selected.update(|i| {
                    if *i > 0 {
                        *i -= 1;
                    }
                });
            }
            _ => {}
        }
    };

    // `aria-activedescendant` follows the selection signal. Reactive
    // string so the attribute updates when `selected` changes.
    let aria_active = move || {
        row_ids_for_aria
            .get(selected.get())
            .cloned()
            .unwrap_or_default()
    };

    let row_views = actions
        .into_iter()
        .enumerate()
        .map(|(idx, action)| {
            let id = row_ids
                .get(idx)
                .cloned()
                .unwrap_or_else(|| format!("history-timeline-row-{idx}"));
            let kind = action.kind.as_str();
            let when = action.created_at.to_rfc3339();
            let reasoning = action.reasoning.clone();
            let moderator = action.moderator_id.to_string();
            // Reactive class so the selected row gets a marker.
            let is_selected = move || selected.get() == idx;
            let row_class = move || {
                if is_selected() {
                    "history-timeline__row history-timeline__row--selected"
                } else {
                    "history-timeline__row"
                }
            };
            // Clicking the row should also move the cursor — gives mouse
            // users the same selection model as keyboard users.
            let on_click = move |_| set_selected.set(idx);

            // Affordance: render a Reverse button only when the viewer is
            // eligible per `can_reverse`. The check is evaluated once at
            // render time — `now` is sampled when the row is built, which
            // is fine for an affordance gate (the backend rechecks on
            // submit).
            let already_reversed = already_reversed_ids.contains(&action.id);
            let render_reverse = match &viewer {
                Some(v) => can_reverse(v, &action, already_reversed, Utc::now()),
                None => false,
            };
            let action_id = action.id;
            let reverse_callback = on_reverse_success;

            view! {
                <li
                    id=id
                    role="option"
                    class=row_class
                    aria-selected=move || if is_selected() { "true" } else { "false" }
                    on:click=on_click
                >
                    <span class="history-timeline__kind">{kind}</span>
                    <time class="history-timeline__when">{when}</time>
                    <span class="history-timeline__moderator">"by "{moderator}</span>
                    <p class="history-timeline__reasoning">{reasoning}</p>
                    {if render_reverse {
                        view! {
                            <ReverseAffordance
                                action_id=action_id
                                on_reverse_success=reverse_callback
                            />
                        }.into_any()
                    } else {
                        view! { <span></span> }.into_any()
                    }}
                </li>
            }
        })
        .collect::<Vec<_>>();

    view! {
        <section class="history-timeline" aria-label="Moderation history">
            <h2>"History"</h2>
            {move || {
                if actions_len == 0 {
                    view! {
                        <p class="history-timeline__empty" role="status">
                            "No prior actions against this subject."
                        </p>
                    }.into_any()
                } else {
                    view! {
                        <p class="history-timeline__help">
                            "Press " <kbd>"j"</kbd> " / " <kbd>"k"</kbd>
                            " to navigate the timeline."
                        </p>
                    }.into_any()
                }
            }}
            <ul
                id=list_id
                class="history-timeline__list"
                role="listbox"
                tabindex="0"
                aria-label="Prior actions, chronological"
                aria-activedescendant=aria_active
                on:keydown=on_keydown
                node_ref=focus_on_mount()
            >
                {row_views}
            </ul>
        </section>
    }
}

/// Submit lifecycle for the reversal affordance.
#[derive(Debug, Clone)]
enum ReverseStatus {
    /// User has not opened the modal.
    Idle,
    /// Modal is open; reasoning is being entered.
    Composing,
    /// Submit in flight.
    Submitting,
    /// Submit failed — message announced via `aria-live`.
    Error(String),
}

/// Inline "Reverse" affordance rendered next to a timeline row.
///
/// Shows a button that opens a small inline composer for the reasoning,
/// then calls `PolarisApiClient::reverse_action`. On success the
/// optional `on_reverse_success` callback fires so the page can refresh
/// the case view. The affordance is purely an affordance — the backend
/// authorizes via `can_reverse` on submit and remains the source of
/// truth.
#[allow(
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    reason = "Leptos #[component] requires the prop signature to be owned"
)]
#[component]
fn ReverseAffordance(
    /// The action being reversed.
    action_id: ActionId,
    /// Refresh callback wired from [`HistoryTimeline::on_reverse_success`].
    on_reverse_success: Option<Callback<Action>>,
) -> impl IntoView {
    let (reasoning, set_reasoning) = signal(String::new());
    let (status, set_status) = signal(ReverseStatus::Idle);

    let reasoning_len = move || reasoning.with(String::len);
    let is_valid = move || reasoning_len() >= MIN_REASONING_LEN;

    let on_open = move |_| set_status.set(ReverseStatus::Composing);
    let on_cancel = move |_| {
        set_reasoning.set(String::new());
        set_status.set(ReverseStatus::Idle);
    };
    let on_reasoning_input = move |ev: ev::Event| {
        set_reasoning.set(event_target_value(&ev));
    };

    let on_submit = move |_| {
        if !is_valid() {
            set_status.set(ReverseStatus::Error(
                "Reasoning must be at least 10 characters.".to_owned(),
            ));
            return;
        }
        let body = ReverseBody {
            reasoning: reasoning.get(),
        };
        set_status.set(ReverseStatus::Submitting);
        let cb = on_reverse_success;
        leptos::task::spawn_local(async move {
            match submit_reversal(action_id, body).await {
                Ok(action) => {
                    if let Some(cb) = cb {
                        cb.run(action);
                    }
                    set_reasoning.set(String::new());
                    set_status.set(ReverseStatus::Idle);
                }
                Err(err) => {
                    set_status.set(ReverseStatus::Error(err.to_string()));
                }
            }
        });
    };

    view! {
        <div class="history-timeline__reverse">
            {move || match status.get() {
                ReverseStatus::Idle => view! {
                    <button
                        type="button"
                        class="history-timeline__reverse-btn"
                        aria-label="Reverse this action"
                        on:click=on_open
                    >
                        "Reverse"
                    </button>
                }.into_any(),
                ReverseStatus::Composing | ReverseStatus::Submitting | ReverseStatus::Error(_) => {
                    let is_submitting = matches!(status.get(), ReverseStatus::Submitting);
                    let error_msg = match status.get() {
                        ReverseStatus::Error(msg) => Some(msg),
                        _ => None,
                    };
                    view! {
                        <div
                            class="history-timeline__reverse-modal"
                            role="dialog"
                            aria-label="Confirm reversal"
                        >
                            <label for="reverse-reasoning">
                                "Reason for reversal (≥ 10 chars):"
                            </label>
                            <textarea
                                id="reverse-reasoning"
                                aria-required="true"
                                on:input=on_reasoning_input
                                prop:value=move || reasoning.get()
                            />
                            <p class="history-timeline__reverse-counter">
                                {move || format!("{} / {} chars", reasoning_len(), MIN_REASONING_LEN)}
                            </p>
                            <div class="history-timeline__reverse-actions">
                                <button
                                    type="button"
                                    class="history-timeline__reverse-cancel"
                                    on:click=on_cancel
                                    disabled=is_submitting
                                >
                                    "Cancel"
                                </button>
                                <button
                                    type="button"
                                    class="history-timeline__reverse-confirm"
                                    on:click=on_submit
                                    disabled=move || !is_valid() || matches!(status.get(), ReverseStatus::Submitting)
                                >
                                    {if is_submitting { "Submitting…" } else { "Confirm reversal" }}
                                </button>
                            </div>
                            <div class="history-timeline__reverse-status" role="status" aria-live="polite">
                                {error_msg.map(|m| view! {
                                    <span class="history-timeline__reverse-error" role="alert">
                                        "Reversal failed: "{m}
                                    </span>
                                })}
                            </div>
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

/// Submit the reversal call. Pulled out as a free async fn so the
/// component's `on_submit` closure stays under the readability ceiling.
async fn submit_reversal(action_id: ActionId, body: ReverseBody) -> Result<Action, ApiError> {
    let client = default_client("")?;
    client.reverse_action(action_id, body).await
}

/// Pull the current `value` off a DOM event target. Mirrors the helper
/// used by `action_composer` — kept module-local so the composer's
/// implementation stays its own concern.
fn event_target_value<E>(ev: &E) -> String
where
    E: leptos::wasm_bindgen::JsCast,
{
    leptos::prelude::event_target_value(ev)
}

/// Auto-focus the timeline `<ul>` when the component mounts.
///
/// Keyboard-first per `design.md` §7: opening a case puts the cursor on
/// the timeline so `j` / `k` work without an upfront click. The function
/// returns a [`NodeRef`] the caller wires to `node_ref=` on the element
/// to focus.
fn focus_on_mount() -> NodeRef<leptos::html::Ul> {
    let node = NodeRef::<leptos::html::Ul>::new();
    Effect::new(move |_| {
        if let Some(el) = node.get() {
            // `HtmlUListElement` doesn't expose `.focus()` directly in
            // web-sys without the `HtmlElement` cast. The cast is
            // infallible for an actual `<ul>` rendered into the DOM, but
            // we still fall back gracefully on `None` rather than
            // unwrapping.
            let _: Option<()> = el.dyn_ref::<web_sys::HtmlElement>().map(|h| {
                let _ = h.focus();
            });
        }
    });
    node
}
