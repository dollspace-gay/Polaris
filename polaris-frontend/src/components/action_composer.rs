//! `ActionComposer` — the kind/reasoning/policy form that submits an action.
//!
//! Maps to `design.md` §5.2 (action composer) plus §5.5 (every action
//! requires a free-text `reasoning`, the category dropdown is a tag —
//! not the reason). The backend enforces `reasoning.len() >= 10`; the
//! composer mirrors that rule client-side so a moderator never submits a
//! payload the server is about to reject.
//!
//! # Validation
//!
//! - The submit button is disabled until `reasoning` is `>= MIN_REASONING_LEN`
//!   characters long.
//! - A live counter shows the current length against the threshold and
//!   flips a `valid` / `invalid` class plus a ✓ / ✗ icon for screen-reader
//!   accessibility (color is not the only signal — `design.md` §7).
//! - On `submit-attempt` with a short `reasoning`, an inline error renders
//!   with `aria-live="polite"` so screen readers announce it.
//!
//! # Plumbing
//!
//! The composer is generic over the [`ActionSubmitter`] trait. The
//! production wiring is the page-level [`crate::api_client::PolarisApiClient`];
//! the [`wasm-bindgen-test`] suite swaps in a [`StubSubmitter`] (defined
//! in this module) so the validation contract is testable without a live
//! backend.

use leptos::ev;
use leptos::prelude::*;
use polaris_types::{Action, ActionKind, IncidentId, LabelValue, PolicyId, SubjectId};
use std::future::Future;

use crate::api_client::ApiError;
use crate::api_client::dto::SubmitAction;

/// Minimum length of the reasoning field. Mirrors
/// [`polaris_backend::api::cases::validate_submit_action`]'s `>= 10` check.
pub const MIN_REASONING_LEN: usize = 10;

/// Default policy ref hardcoded for the M1 composer.
///
/// The richer policy picker (multi-select against the operator's policy
/// registry) lands in M2 alongside the policy admin UI. For now we ship a
/// single placeholder ref so the composer can drive the end-to-end
/// submit path without a separate policy fetch.
const DEFAULT_POLICY_REF: &str = "polaris.spam";

/// Minimal abstraction over "submit an action".
///
/// Used so tests can stub the network call without standing up a real
/// HTTP client. The production impl is implemented for any closure
/// matching the signature (the page wires the
/// [`crate::api_client::PolarisApiClient::submit_action`] call into the
/// closure).
pub trait ActionSubmitter: Clone + 'static {
    /// Future returned by [`Self::submit`].
    type Fut: Future<Output = Result<Action, ApiError>>;

    /// Submit `body` against `subject_id`. Returns the persisted [`Action`]
    /// on success.
    fn submit(&self, subject_id: SubjectId, body: SubmitAction) -> Self::Fut;
}

/// Test-only stub submitter.
///
/// Always succeeds and returns a fabricated [`Action`] reflecting the
/// submitted fields. Lives in non-test code so the
/// [`composer_validation`](../../tests/composer_validation.rs) integration
/// test can drive the composer without a live backend; the unwrap-free
/// construction means it satisfies the same lint gate as the rest of
/// `polaris-frontend/src/`.
#[derive(Debug, Clone)]
pub struct StubSubmitter;

impl ActionSubmitter for StubSubmitter {
    type Fut = std::future::Ready<Result<Action, ApiError>>;

    fn submit(&self, subject_id: SubjectId, body: SubmitAction) -> Self::Fut {
        let action = Action {
            id: polaris_types::ActionId::new(),
            incident_id: body.incident_id,
            subject_id,
            moderator_id: polaris_types::ModeratorId::new(),
            kind: body.kind,
            label: body.label,
            reasoning: body.reasoning,
            policy_refs: body.policy_refs,
            reversible_until: body.reversible_until,
            reverses_action_id: body.reverses_action_id,
            created_at: chrono::Utc::now(),
            emitted_to_atproto: None,
        };
        std::future::ready(Ok(action))
    }
}

/// Compose-and-submit form for a new moderation [`Action`].
///
/// # Props
///
/// - `subject_id`: identifier of the subject the action targets.
/// - `incident_id`: identifier of the incident the action belongs to.
/// - `submitter`: an [`ActionSubmitter`] (production = HTTP client, tests
///   = stub).
/// - `on_success`: callback invoked with the persisted [`Action`] on a
///   successful submit. The page uses this to refresh the timeline.
///
/// # Accessibility
///
/// - The kind selector is a `<select>` with an explicit `<label for="">`.
/// - The reasoning field is a `<textarea>` with an explicit `<label>` and
///   a live counter announced via `aria-describedby`.
/// - Validation errors render into an `aria-live="polite"` region so
///   screen readers announce them as they appear.
// `needless_pass_by_value` fires on `submitter` (the closure captures
// it via clone), but Leptos components take props by value as the API
// convention — see `subject_header::SubjectHeader` for the full
// rationale. `too_many_lines` reflects the natural shape of a form with
// per-field handlers + a status banner; splitting would harm readability.
#[allow(
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
#[component]
pub fn ActionComposer<S>(
    /// Subject the action targets. Path component on submit.
    subject_id: SubjectId,
    /// Incident the action attaches to. Carried in the request body.
    incident_id: IncidentId,
    /// Strategy for executing the HTTP submit. Production wires
    /// [`crate::pages::case_view::ClientSubmitter`]; tests pass
    /// [`StubSubmitter`].
    submitter: S,
    /// Optional callback fired with the persisted [`Action`] on success.
    /// The page wires this to a refresh-token signal so the timeline
    /// picks up the new row.
    #[prop(into, optional)]
    on_success: Option<Callback<Action>>,
) -> impl IntoView
where
    S: ActionSubmitter,
{
    let (kind, set_kind) = signal(ActionKind::Label);
    let (label, set_label) = signal(String::new());
    let (reasoning, set_reasoning) = signal(String::new());
    let (status, set_status) = signal(ComposerStatus::Idle);

    let reasoning_len = move || reasoning.with(String::len);
    let is_valid = move || reasoning_len() >= MIN_REASONING_LEN;

    // Counter label: "X / 10 chars ✓" / "X / 10 chars ✗".
    let counter_text = move || {
        let n = reasoning_len();
        let ok = if n >= MIN_REASONING_LEN { "✓" } else { "✗" };
        format!("{n} / {MIN_REASONING_LEN} chars {ok}")
    };
    let counter_class = move || {
        if is_valid() {
            "composer__counter composer__counter--valid"
        } else {
            "composer__counter composer__counter--invalid"
        }
    };

    let on_kind_input = move |ev: ev::Event| {
        let value = event_target_value(&ev);
        if let Some(parsed) = ActionKind::from_wire(&value) {
            set_kind.set(parsed);
        }
    };

    let on_reasoning_input = move |ev: ev::Event| {
        set_reasoning.set(event_target_value(&ev));
    };

    let on_label_input = move |ev: ev::Event| {
        set_label.set(event_target_value(&ev));
    };

    // Submit handler — pulled out of the form's `on:submit` so the
    // composer page can also trigger it from a `Cmd-Enter` keydown.
    let submitter_for_submit = submitter.clone();
    let do_submit = move || {
        if !is_valid() {
            set_status.set(ComposerStatus::Error(
                "Reasoning must be at least 10 characters.".to_owned(),
            ));
            return;
        }
        let body = SubmitAction {
            incident_id,
            kind: kind.get(),
            label: label.with(|l| {
                if l.is_empty() {
                    None
                } else {
                    Some(LabelValue::new(l.clone()))
                }
            }),
            reasoning: reasoning.get(),
            policy_refs: vec![PolicyId::new(DEFAULT_POLICY_REF)],
            // 24h reversibility window — `design.md` §5.5.
            reversible_until: chrono::Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
        };
        set_status.set(ComposerStatus::Submitting);
        let s = submitter_for_submit.clone();
        let on_success = on_success;
        // `spawn_local` — Leptos's wasm-bindgen-futures executor on wasm,
        // a no-op shim on native. Either way, no tokio.
        leptos::task::spawn_local(async move {
            match s.submit(subject_id, body).await {
                Ok(action) => {
                    set_reasoning.set(String::new());
                    set_label.set(String::new());
                    set_status.set(ComposerStatus::Success);
                    if let Some(cb) = on_success {
                        cb.run(action);
                    }
                }
                Err(err) => {
                    set_status.set(ComposerStatus::Error(err.to_string()));
                }
            }
        });
    };

    // Two consumers (`on:submit` on the form, `on:keydown` on the
    // textarea) each need their own `Fn`. Clone the submit closure once
    // per consumer rather than moving — `do_submit` is small (a few
    // signal handles) and clippy's `redundant_clone` is OK with this
    // pattern because both bindings are reactively required.
    let do_submit_for_form = do_submit.clone();
    let on_form_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        do_submit_for_form();
    };

    // `Cmd-Enter` / `Ctrl-Enter` shortcut on the reasoning textarea.
    // `design.md` §7 plus the issue #15 pre-flight: submit-from-composer
    // is keyboard-accessible without a mouse trip to the button.
    let on_reasoning_keydown = move |ev: ev::KeyboardEvent| {
        if ev.key() == "Enter" && (ev.meta_key() || ev.ctrl_key()) {
            ev.prevent_default();
            do_submit();
        }
    };

    let kinds = ALL_KINDS;

    view! {
        <form
            class="composer"
            aria-label="Submit moderation action"
            on:submit=on_form_submit
        >
            <h2>"Action"</h2>

            <div class="composer__row">
                <label for="composer-kind">"Kind"</label>
                <select
                    id="composer-kind"
                    class="composer__kind"
                    on:change=on_kind_input
                    prop:value=move || kind.get().as_str().to_owned()
                >
                    {kinds.iter().copied().map(|k| {
                        view! {
                            <option value=k.as_str()>{k.as_str()}</option>
                        }
                    }).collect::<Vec<_>>()}
                </select>
            </div>

            <div class="composer__row">
                <label for="composer-label">"Label value (when kind=label)"</label>
                <input
                    id="composer-label"
                    class="composer__label-input"
                    type="text"
                    on:input=on_label_input
                    prop:value=move || label.get()
                />
            </div>

            <div class="composer__row">
                <label for="composer-reasoning">"Reasoning"</label>
                <textarea
                    id="composer-reasoning"
                    class="composer__reasoning"
                    aria-describedby="composer-counter"
                    aria-required="true"
                    on:input=on_reasoning_input
                    on:keydown=on_reasoning_keydown
                    prop:value=move || reasoning.get()
                />
                <p id="composer-counter" class=counter_class>{counter_text}</p>
            </div>

            <div class="composer__row composer__row--policy">
                <p class="composer__policy-note">
                    "Policy ref: " <code>{DEFAULT_POLICY_REF}</code>
                    " (multi-select picker lands in M2)."
                </p>
            </div>

            <div class="composer__row composer__row--actions">
                <button
                    type="submit"
                    class="composer__submit"
                    disabled=move || !is_valid() || matches!(status.get(), ComposerStatus::Submitting)
                >
                    {move || match status.get() {
                        ComposerStatus::Submitting => "Submitting…",
                        _ => "Submit action",
                    }}
                </button>
            </div>

            <div
                class="composer__status"
                role="status"
                aria-live="polite"
            >
                {move || match status.get() {
                    ComposerStatus::Idle | ComposerStatus::Submitting => {
                        view! { <span></span> }.into_any()
                    }
                    ComposerStatus::Success => view! {
                        <span class="composer__status--success">
                            "Action recorded. Timeline refreshed."
                        </span>
                    }.into_any(),
                    ComposerStatus::Error(msg) => view! {
                        <span class="composer__status--error" role="alert">
                            "Submit failed: "{msg}
                        </span>
                    }.into_any(),
                }}
            </div>
        </form>
    }
}

/// State machine for the composer's submit lifecycle.
///
/// Distinct from the wire-level [`ApiError`] so that a single signal can
/// drive the success banner, the error banner, and the
/// "submitting…"-state of the button.
#[derive(Debug, Clone)]
pub enum ComposerStatus {
    /// No submit attempted yet.
    Idle,
    /// Submit in flight — button is disabled, label shows "Submitting…".
    Submitting,
    /// Submit succeeded — banner announced via `aria-live="polite"`.
    Success,
    /// Submit failed — message announced via `aria-live="polite"` and the
    /// inner banner role is `"alert"` for stronger SR cueing.
    Error(String),
}

/// The set of `ActionKind` values the composer offers.
///
/// Mirrors the backend's `ActionKind` enum in declaration order, minus
/// `Reverse` — reversal is a separate UI flow (#36).
const ALL_KINDS: &[ActionKind] = &[
    ActionKind::Label,
    ActionKind::Takedown,
    ActionKind::Mute,
    ActionKind::Warn,
    ActionKind::Escalate,
    ActionKind::NoAction,
];

/// Pull the current `value` off a DOM event target.
///
/// Wrap `event_target_value` so we can keep the cast bounded to the
/// `HtmlInputElement` / `HtmlTextAreaElement` / `HtmlSelectElement`
/// surface the composer actually uses. Leptos provides
/// `leptos::prelude::event_target_value`; we re-export it via a thin
/// alias so the composer's call sites stay in the local module surface.
fn event_target_value<E>(ev: &E) -> String
where
    E: leptos::wasm_bindgen::JsCast,
{
    leptos::prelude::event_target_value(ev)
}
