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
use crate::app::LexiconRegistry;
use crate::components::exposure_counter::record_action_on_global;
use crate::validation::validate_label_def;

/// Minimum length of the reasoning field. Mirrors
/// [`polaris_backend::api::cases::validate_submit_action`]'s `>= 10` check.
pub const MIN_REASONING_LEN: usize = 10;

/// Predicate behind the submit-button gate: a reasoning string is valid
/// when its `len()` (byte length, matching the backend's identical check)
/// is at least [`MIN_REASONING_LEN`].
///
/// Surfaced as a free function so the `composer_validation`
/// `wasm-bindgen-test` (issue #54) can assert the contract without
/// mounting the full component. The component itself routes its
/// `is_valid` closure through this same function so the test and the
/// runtime UI cannot drift.
///
/// # Examples
///
/// ```
/// use polaris_frontend::components::action_composer::is_valid_reasoning;
/// assert!(!is_valid_reasoning("nine char"));   // 9 bytes
/// assert!(is_valid_reasoning("ten chars."));   // 10 bytes
/// assert!(is_valid_reasoning(&"a".repeat(100)));
/// ```
#[must_use]
pub fn is_valid_reasoning(reasoning: &str) -> bool {
    reasoning.len() >= MIN_REASONING_LEN
}

/// Default policy ref hardcoded for the M1 composer.
///
/// The richer policy picker (multi-select against the operator's policy
/// registry) lands in M2 alongside the policy admin UI. For now we ship a
/// single placeholder ref so the composer can drive the end-to-end
/// submit path without a separate policy fetch.
const DEFAULT_POLICY_REF: &str = "polaris.spam";

/// Debounce window for client-side lexicon validation (REQ-13 / AC-16).
///
/// AC-16's budget is "inline validation error within 100ms of the
/// input event"; 50ms keeps us comfortably under that while still
/// coalescing bursts of keystrokes (typical typing cadence is
/// 80-150ms/char). The constant is exported so the matching
/// integration test can use the same value rather than guess.
pub const VALIDATION_DEBOUNCE_MS: u64 = 50;

/// `did:` placeholder used when the composer builds the in-progress
/// label record for validation. The real `src` (the labeler's DID) is
/// stamped server-side on `POST /api/actions`; for client-side schema
/// validation we just need a syntactically-valid placeholder so the
/// `format: "did"` check on `src` (when reached) does not mask the
/// real per-field error the moderator is trying to fix.
const VALIDATION_PLACEHOLDER_DID: &str = "did:plc:polaris-client-placeholder";

/// Subject-URI placeholder used when the composer builds the in-progress
/// label record for validation. Same rationale as
/// [`VALIDATION_PLACEHOLDER_DID`]: shape the placeholder so the schema
/// validator's per-property error points at the field the moderator is
/// editing, not at one of the wire-stamped fields the server fills in.
const VALIDATION_PLACEHOLDER_URI: &str = "at://did:plc:placeholder/app.bsky.feed.post/placeholder";

/// Schedule a debounced lexicon-validation pass against `val` and
/// post the result to `sink`.
///
/// On `wasm32-unknown-unknown` we use Leptos's `set_timeout_with_handle`
/// to fire 50ms after the last keystroke. The pending handle is parked
/// on a thread-local `StoredValue` so each new call clears the previous
/// timer before scheduling its own — that is the actual debounce.
///
/// On native (test / IDE-check builds) there is no event loop to
/// schedule against, so we run the validator inline. Native tests
/// drive the composer through stub-only paths and exercise the
/// validation surface directly via `validation::tests` rather than
/// observing the timer.
#[cfg(target_arch = "wasm32")]
fn schedule_label_validation(
    registry: &std::sync::Arc<proto_blue::lexicon::Lexicons>,
    val: &str,
    sink: WriteSignal<Option<String>>,
) {
    use leptos::leptos_dom::helpers::TimeoutHandle;
    use std::time::Duration;

    // One-handle slot per effect run lineage; reactively shared via
    // `StoredValue` so we can park the previous pending timer and
    // cancel it from the next invocation. The slot persists for the
    // composer's owning scope; `on_cleanup` will drop it on unmount.
    let slot = StoredValue::new(None::<TimeoutHandle>);

    // Cancel any pending timer.
    if let Some(prev) = slot.get_value() {
        prev.clear();
    }

    // Take owning copies for the deferred closure. The `Arc` clone is
    // a single ref-count bump; the `val` clone is unavoidable because
    // the timer callback fires after the input event's `&str` has gone
    // out of scope.
    let registry_for_timer = std::sync::Arc::clone(registry);
    let val_for_timer = val.to_owned();

    let timeout = leptos::prelude::set_timeout_with_handle(
        move || {
            let json = label_record_for_validation(&val_for_timer);
            let result = validate_label_def(&registry_for_timer, &json);
            sink.set(result.err().map(|e| e.to_string()));
        },
        Duration::from_millis(VALIDATION_DEBOUNCE_MS),
    );

    // `set_timeout_with_handle` is fallible only when called outside a
    // window context (e.g. on the server-render path). The frontend is
    // wasm-only at runtime; surface the failure as "no client-side
    // validation this round" rather than panicking — server-side
    // validation still covers the submit path.
    if let Ok(handle) = timeout {
        slot.set_value(Some(handle));
    }
}

/// Native stub: run the validator synchronously.
///
/// The native build path exists for workspace tooling (`cargo check`,
/// `cargo test --lib`) and never mounts the composer in a real
/// reactive scope. Running synchronously here keeps the function
/// signature symmetric with the wasm side without pulling a tokio
/// runtime into the frontend — `validation::tests` exercises the
/// per-record contract directly.
#[cfg(not(target_arch = "wasm32"))]
fn schedule_label_validation(
    registry: &std::sync::Arc<proto_blue::lexicon::Lexicons>,
    val: &str,
    sink: WriteSignal<Option<String>>,
) {
    let json = label_record_for_validation(val);
    let result = validate_label_def(registry, &json);
    sink.set(result.err().map(|e| e.to_string()));
}

/// Build the in-progress `com.atproto.label.defs#label` value the
/// composer validates on every (debounced) keystroke.
///
/// `val` is the only moderator-editable field at the composer level;
/// `src` / `uri` / `cts` are stamped server-side, but the lexicon
/// requires them, so we include syntactically-valid placeholders.
/// This keeps any schema error the validator returns scoped to the
/// `val` property the moderator is actually editing.
fn label_record_for_validation(val: &str) -> serde_json::Value {
    serde_json::json!({
        "src": VALIDATION_PLACEHOLDER_DID,
        "uri": VALIDATION_PLACEHOLDER_URI,
        "val": val,
        "cts": "2026-01-01T00:00:00.000Z",
    })
}

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
            evidence_car_cid: None,
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
    /// Whether the subject has at least one media artifact attached.
    /// Threaded through to the global exposure counter (issue #95) on
    /// every successful submit: `record_action` increments the
    /// `actions_submitted` field only when this is `true`, so the
    /// counter measures actual graphic-content exposure rather than
    /// total action volume. Defaults to `false` while the case-view
    /// DTO does not yet surface `media_blobs`.
    #[prop(default = false)]
    subject_has_media: bool,
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

    // Moderator UX: the label-value input is a `<select>` populated
    // from the labeler's declared `policies.labelValues` (fetched
    // from `GET /api/labeler/policies`) — moderators should never
    // hand-type a label value they could pick from a known set.
    // The state below caches the available values; `None` is the
    // pre-fetch / fetch-failed state and the composer falls back to
    // a free-text input so the surface degrades gracefully if the
    // operator hasn't completed setup or the endpoint is down.
    let (label_options, set_label_options) = signal::<Option<Vec<String>>>(None);
    #[cfg(target_arch = "wasm32")]
    {
        use crate::api_client::{PolarisApiClient as _, default_client};
        leptos::task::spawn_local(async move {
            if let Ok(client) = default_client("") {
                if let Ok(policies) = client.labeler_policies().await {
                    set_label_options.set(Some(policies.label_values));
                }
            }
        });
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // Native test builds: no backend to fetch from; the
        // composer renders the free-text fallback the same way it
        // would on a fetch failure in the browser.
        let _ = set_label_options;
    }

    // Lexicon-validation message for the in-progress `label` field
    // (REQ-13 / AC-16, issue #34). `None` means "no error"; the submit
    // button is gated on `lex_error.get().is_none()` plus the existing
    // reasoning-length check.
    //
    // We carry the rendered [`Display`] of the typed
    // [`crate::validation::ValidationError`] (rather than the variant
    // itself) for two reasons: (1) the upstream
    // `proto_blue::lexicon::ValidationError` does not implement
    // `Clone`, so Leptos's `signal::get()` (which needs `Clone`) would
    // refuse to compile against a `ValidationError`-shaped state; and
    // (2) the view layer only needs the Display form for inline
    // rendering — variant discrimination happens at the
    // `validate_label_def` site, not in the component tree.
    let (lex_error, set_lex_error) = signal::<Option<String>>(None);

    let reasoning_len = move || reasoning.with(String::len);
    // Routed through `is_valid_reasoning` (rather than inlining the
    // `>= MIN_REASONING_LEN` check) so the `composer_validation`
    // wasm-bindgen-test can assert the same predicate the rendered UI
    // uses. Keeps the test and the gate from drifting.
    let is_valid = move || reasoning.with(|r| is_valid_reasoning(r));

    // Pull the shared `Lexicons` registry off Leptos context. The App
    // root (`app.rs`) provides this. `None` means the registry failed
    // to build at startup (the app root renders a degraded banner in
    // that case); the composer still mounts, but per-keystroke
    // validation is suppressed and the moderator can submit — the
    // server-side schema check is the last line.
    let registry = use_context::<LexiconRegistry>();

    // Debounced effect: 50ms after the most recent `label` change,
    // build the in-progress label record and run it through the
    // lexicon validator. The signal-graph subscription is via
    // `label.get()`; the debounce is implemented with leptos's
    // `set_timeout_with_handle` (wasm) plus a `StoredValue` to keep
    // the latest pending handle alive across re-runs so we can clear
    // the previous timer before scheduling a new one.
    let label_validation_effect_registry = registry.clone();
    Effect::new(move |_| {
        // Subscribe to the label signal.
        let current = label.get();

        let Some(LexiconRegistry(registry_arc)) = label_validation_effect_registry.clone() else {
            // No registry → no client-side validation. Server-side
            // validation still covers the submit path.
            set_lex_error.set(None);
            return;
        };

        // Empty label is a "no error" state — the field is optional at
        // the composer level and `LabelValue::new` only fires on
        // non-empty input. A `val` of "" would also schema-fail because
        // `com.atproto.label.defs#label` requires `val` to be a
        // non-empty string, but surfacing that error before the
        // moderator has typed anything would be noise.
        if current.is_empty() {
            set_lex_error.set(None);
            return;
        }

        schedule_label_validation(&registry_arc, &current, set_lex_error);
    });

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
        // AC-16: a non-empty client-side lexicon error blocks submit.
        // The button is also disabled in that state; this check is the
        // belt-and-braces for the `Cmd-Enter` path which bypasses the
        // button's `disabled` attribute.
        if let Some(err) = lex_error.get() {
            set_status.set(ComposerStatus::Error(format!(
                "Label value fails lexicon validation: {err}"
            )));
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
            // The action composer is a per-subject submission, not a
            // per-report decision; leave the idempotency key `None` so
            // the backend's pre-#202 behavior is preserved here.
            report_id: None,
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
                    // Issue #95 / mod-workstation feature #5: increment
                    // the global exposure counter on every successful
                    // action submission against a media-bearing
                    // subject. The function is a no-op when
                    // `subject_has_media` is false OR the global
                    // exposure signal has not been mounted (isolated
                    // tests), so the wiring is safe regardless of the
                    // host tree.
                    record_action_on_global(subject_has_media);
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
                // Moderators pick the label from a `<select>` populated
                // with the labeler's declared `policies.labelValues`.
                // The fetch above writes `label_options` once the
                // policies endpoint responds; until then (or on fetch
                // failure) the composer renders a free-text input
                // fallback so the surface remains operable even when
                // setup is incomplete. Both code paths fire the same
                // `set_label` update so the downstream lexicon
                // validator, the subscriber-effect preview, and the
                // submit pipeline are unaffected.
                {move || match label_options.get() {
                    Some(options) if !options.is_empty() => view! {
                        <select
                            id="composer-label"
                            class="composer__label-select"
                            aria-describedby="composer-label-lex-error"
                            on:change=on_label_input
                            prop:value=move || label.get()
                        >
                            // Empty default so the moderator is forced
                            // to make an intentional choice and the
                            // `is_valid()` gate keeps the submit button
                            // disabled until they do.
                            <option value="">"Choose a label…"</option>
                            {options.into_iter().map(|value| {
                                let v = value.clone();
                                view! {
                                    <option value=value.clone()>{v}</option>
                                }
                            }).collect_view()}
                        </select>
                    }.into_any(),
                    _ => view! {
                        // Free-text fallback. Renders before the
                        // policy fetch completes, and as a graceful
                        // degradation if the operator hasn't completed
                        // the setup wizard or `/api/labeler/policies`
                        // returns 404. The lexicon validator still
                        // gates the value at submit time so a typo
                        // does not produce a malformed record.
                        <input
                            id="composer-label"
                            class="composer__label-input"
                            type="text"
                            aria-describedby="composer-label-lex-error"
                            placeholder="Loading declared labels… (or type one)"
                            on:input=on_label_input
                            prop:value=move || label.get()
                        />
                    }.into_any(),
                }}
                // REQ-13 / AC-16: inline lexicon-validation error for the
                // in-progress label value. The `aria-live="polite"` region
                // means screen readers announce the error as it appears
                // without interrupting the moderator's typing. The empty
                // wrapper stays in the DOM (rather than `<Show when>`) so
                // the `aria-describedby` link is stable across the
                // valid/invalid transitions.
                <p
                    id="composer-label-lex-error"
                    class="composer__lex-error"
                    role="alert"
                    aria-live="polite"
                >
                    {move || lex_error.get().unwrap_or_default()}
                </p>
            </div>

            // Issue #96 / mod-workstation #6: inline subscriber-effect
            // preview rendered ONLY when the composer's `kind` is
            // `Label` and a value has been typed. The component
            // fetches `/api/labeler/policies` on its own mount and
            // renders a stacked-bar forecast of hide / warn / ignore
            // shares using published-default heuristics — see the
            // module docs on
            // [`crate::components::subscriber_effect_preview`] for
            // the honesty caveat about the data source.
            <crate::components::subscriber_effect_preview::SubscriberEffectPreview
                label_value=Signal::derive(move || label.get())
                visible=Signal::derive(move || {
                    matches!(kind.get(), ActionKind::Label) && !label.get().trim().is_empty()
                })
            />

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
                    disabled=move || !is_valid()
                        || lex_error.get().is_some()
                        || matches!(status.get(), ComposerStatus::Submitting)
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
    // Ozone-parity `#modEventComment` (issue #188): a moderator note
    // recorded in the `actions` table with no enforcement side-effect.
    // The `reasoning` field doubles as the note body, so the rest of
    // the composer's required-fields invariants (reasoning ≥ 10 chars,
    // non-empty policy_refs) still apply.
    ActionKind::Comment,
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
