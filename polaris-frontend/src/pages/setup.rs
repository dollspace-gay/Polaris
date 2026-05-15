//! First-run setup wizard (issue #84).
//!
//! Three-step flow the first admin walks through after onboarding:
//!
//! 1. **Generate signing key** — `POST /api/setup/generate-key` returns
//!    a freshly-minted `did:key:z…` for the labeler service. The wizard
//!    displays the public key and pins it for the next step.
//! 2. **Publish labeler service record** — the operator supplies the
//!    labeler's public HTTPS URL plus the set of label values it emits.
//!    `POST /api/setup/publish-labeler-record` writes the
//!    `app.bsky.labeler.service` record on the operator's PDS.
//! 3. **Publish DID document service entry** — `POST /api/setup/
//!    request-plc-signature` asks the PDS to email the operator a PLC
//!    operation token; the operator copy-pastes it back and `POST
//!    /api/setup/submit-plc-operation` adds the `#atproto_labeler`
//!    service entry to the operator's DID document.
//!
//! After step 3 the operator sees a "Done" panel pointing back at `/`,
//! which now routes to the pattern dashboard because the
//! [`crate::api_client::dto::WhoamiResponse`] `first_run` flag has
//! flipped — the first emitted label moves the deployment out of the
//! first-run state permanently.
//!
//! # Step state machine
//!
//! The wizard's position is a [`SetupStep`] held in an [`RwSignal`].
//! [`advance`] is the only legal transition function — it maps each
//! step to its successor. On an error from any `/api/setup/*` call the
//! wizard stays on the current step and surfaces the [`ApiError`] in
//! an inline `role="alert"` paragraph; the operator can retry without
//! re-walking the prior steps.
//!
//! # Error UI
//!
//! Every step renders its error region with `role="alert"` so screen
//! readers announce failures. The error text is the `Display` form of
//! the [`ApiError`] (transport message or HTTP status + body) so the
//! operator sees the actual diagnostic. A 401 bounces the operator to
//! `/login` via [`crate::pages::login::redirect_to_login`] per the #82
//! contract.
//!
//! # `service_url` default
//!
//! Step 2's `service_url` input is pre-filled with the current page's
//! origin via [`default_service_url`]. The intent: the simplest
//! deployment co-locates the labeler service with the Polaris frontend,
//! so the operator just confirms the value. On native (tests, IDE) the
//! default is empty — `web_sys::window` is browser-only.
//!
//! # Forbidden patterns observed (issue #84 checklist)
//!
//! - No `polaris-backend` imports; every fetch routes through
//!   [`crate::api_client::PolarisApiClient`].
//! - No `unwrap()` / `expect()` in non-test code.
//! - No `HttpOnly` cookie reads; 401 → [`redirect_to_login`] per #82.
//! - No `set_inner_html`; every dynamic string lands in the DOM via
//!   Leptos's text-node interpolation.

use leptos::ev;
use leptos::prelude::*;

use crate::api_client::dto::{
    GenerateKeyResponse, PublishLabelerRecordRequest, PublishLabelerRecordResponse,
    RequestPlcSignatureResponse, SubmitPlcOperationRequest, SubmitPlcOperationResponse,
};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::pages::login::{is_unauthorized, redirect_to_login};

/// Path the setup wizard is mounted at.
///
/// Centralising the constant keeps the route declaration in
/// [`crate::app`] and any future deep-link hop to the wizard in sync.
pub const SETUP_PATH: &str = "/setup";

/// Position within the three-step first-run wizard.
///
/// Transitions are linear and one-way; [`advance`] is the only legal
/// successor function. The wizard never reverses — by the time the
/// operator lands on a later step, the side effects of the earlier
/// ones (key minted, record published) are already durable on the
/// backend and re-running them would emit duplicate audit-trail rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
    /// Step 1: mint a fresh signing key.
    GenerateKey,
    /// Step 2: publish the `app.bsky.labeler.service` record.
    PublishLabelerRecord,
    /// Step 3: publish the `#atproto_labeler` DID document service
    /// entry via a PLC operation.
    PublishDidDocument,
    /// Wizard complete; operator can navigate back to `/`.
    Done,
}

/// Successor of `step` in the wizard's state machine.
///
/// Pure function so the transition table is unit-testable without a
/// Leptos runtime. [`SetupStep::Done`] is a fixpoint — calling
/// `advance(Done)` returns `Done` so a stray double-advance is a no-op
/// rather than a panic / wrap-around.
#[must_use]
pub const fn advance(step: SetupStep) -> SetupStep {
    match step {
        SetupStep::GenerateKey => SetupStep::PublishLabelerRecord,
        SetupStep::PublishLabelerRecord => SetupStep::PublishDidDocument,
        SetupStep::PublishDidDocument | SetupStep::Done => SetupStep::Done,
    }
}

/// Numeric label rendered in the wizard's step list (`1`, `2`, `3`).
///
/// [`SetupStep::Done`] returns `3` because the third step's "completed"
/// indicator is what marks the wizard as finished — there is no
/// fourth step.
#[must_use]
pub const fn step_number(step: SetupStep) -> u8 {
    match step {
        SetupStep::GenerateKey => 1,
        SetupStep::PublishLabelerRecord => 2,
        SetupStep::PublishDidDocument | SetupStep::Done => 3,
    }
}

/// Human-readable title for the step.
#[must_use]
pub const fn step_title(step: SetupStep) -> &'static str {
    match step {
        SetupStep::GenerateKey => "Generate signing key",
        SetupStep::PublishLabelerRecord => "Publish labeler service record",
        SetupStep::PublishDidDocument => "Publish DID document service entry",
        SetupStep::Done => "Setup complete",
    }
}

/// Parse the operator-supplied label-values input (a comma-separated
/// list) into the wire shape [`PublishLabelerRecordRequest::label_values`]
/// expects.
///
/// Splits on commas, trims surrounding whitespace, and drops empty
/// segments. `"spam, porn,"` → `["spam", "porn"]`. The backend
/// (`polaris-publish-labeler-record::build_labeler_service_record`)
/// rejects an empty list with [`crate::api_client::ApiError::Http`];
/// surfacing that as a server-side error is preferable to a duplicated
/// client-side check that could drift.
#[must_use]
pub fn parse_label_values(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Resolve the default `service_url` from the browser's
/// `window.location.origin`.
///
/// On native (tests, IDE rust-analyzer) this returns an empty string
/// because there is no `window`. The wizard's form treats `""` as
/// "no default" and renders the input empty.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn default_service_url() -> String {
    web_sys::window()
        .and_then(|w| w.location().origin().ok())
        .unwrap_or_default()
}

/// Native stub — see the wasm variant for the contract.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn default_service_url() -> String {
    String::new()
}

/// Map an [`ApiError`] to either a 401-redirect side effect (returning
/// `None` to indicate the wizard step should not surface an inline
/// error — the redirect is already underway) or the `Display` text of
/// the error for inline rendering.
///
/// Pulled out as a free function so every step handler maps errors
/// identically; mirrors the dashboard / case-view's per-fetch pattern.
/// Takes `err` by reference because the function consumes only the
/// `Display` form — the caller retains ownership.
fn handle_api_error(err: &ApiError) -> Option<String> {
    if is_unauthorized(err) {
        redirect_to_login();
        None
    } else {
        Some(err.to_string())
    }
}

/// Top-level wizard component mounted at `/setup`.
///
/// Owns the [`SetupStep`] signal plus the cross-step `did_key` and
/// `service_url` values the later steps need to surface to the
/// operator. Each step is a child component that drives its own
/// fetch state.
// `clippy::must_use_candidate` cannot be honored at a `#[component]`
// site — see the rationale on `LoginPage`.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn SetupWizard() -> impl IntoView {
    let step = RwSignal::new(SetupStep::GenerateKey);

    // The minted `did:key:z…` from step 1, surfaced in the step list
    // so the operator sees it persist as they walk through the wizard.
    let did_key: RwSignal<Option<String>> = RwSignal::new(None);

    // The `service_url` used by step 2 + step 3. Pre-filled to the
    // current origin (browser) or empty (native test).
    let service_url = RwSignal::new(default_service_url());

    // The PLC operation message returned by step 3a, surfaced to the
    // operator so they know which inbox to check.
    let plc_message: RwSignal<Option<String>> = RwSignal::new(None);

    // The DID returned by step 3b, surfaced in the Done panel.
    let final_did: RwSignal<Option<String>> = RwSignal::new(None);

    let on_key_done = Callback::new(move |key: String| {
        did_key.set(Some(key));
        step.update(|s| *s = advance(*s));
    });
    let on_record_done = Callback::new(move |_resp: PublishLabelerRecordResponse| {
        step.update(|s| *s = advance(*s));
    });
    let on_plc_signature = Callback::new(move |message: String| {
        plc_message.set(Some(message));
    });
    let on_plc_done = Callback::new(move |did: String| {
        final_did.set(Some(did));
        step.update(|s| *s = advance(*s));
    });

    view! {
        <main class="setup-wizard" id="setup-wizard-root">
            <header class="setup-wizard__header">
                <h1>"Polaris first-run setup"</h1>
                <p class="setup-wizard__tagline">
                    "Walk through these three steps to bring the labeler online."
                </p>
            </header>
            <ol class="setup-wizard__steps">
                <StepListItem step_index=SetupStep::GenerateKey current=step>
                    {move || match step.get() {
                        SetupStep::GenerateKey => view! {
                            <GenerateKeyStep on_done=on_key_done/>
                        }.into_any(),
                        _ => view! {
                            <ResultLine
                                label="did:key"
                                value=Signal::derive(move || did_key.get().unwrap_or_default())
                            />
                        }.into_any(),
                    }}
                </StepListItem>
                <StepListItem step_index=SetupStep::PublishLabelerRecord current=step>
                    {move || match step.get() {
                        SetupStep::GenerateKey => view! {
                            <p class="setup-wizard__pending">
                                "Complete the previous step to continue."
                            </p>
                        }.into_any(),
                        SetupStep::PublishLabelerRecord => view! {
                            <PublishLabelerRecordStep
                                service_url=service_url
                                on_done=on_record_done
                            />
                        }.into_any(),
                        _ => view! {
                            <p class="setup-wizard__pending">"Done."</p>
                        }.into_any(),
                    }}
                </StepListItem>
                <StepListItem step_index=SetupStep::PublishDidDocument current=step>
                    {move || match step.get() {
                        SetupStep::GenerateKey | SetupStep::PublishLabelerRecord => view! {
                            <p class="setup-wizard__pending">
                                "Complete the previous steps to continue."
                            </p>
                        }.into_any(),
                        SetupStep::PublishDidDocument => view! {
                            <PublishDidDocumentStep
                                service_url=service_url
                                plc_message=plc_message
                                on_signature=on_plc_signature
                                on_done=on_plc_done
                            />
                        }.into_any(),
                        SetupStep::Done => view! {
                            <ResultLine
                                label="did"
                                value=Signal::derive(move || final_did.get().unwrap_or_default())
                            />
                        }.into_any(),
                    }}
                </StepListItem>
            </ol>
            {move || (step.get() == SetupStep::Done).then(|| view! {
                <DoneStep/>
            })}
        </main>
    }
}

/// One row of the wizard's step list. Renders the step number, the
/// title, and the body (the `children` prop). Past steps render with
/// a check-mark glyph; future steps render greyed; the current step
/// renders expanded.
#[component]
fn StepListItem(
    /// Identifier of this step (where in the wizard it lives).
    step_index: SetupStep,
    /// The wizard's current step. The component reads this reactively
    /// to flip its `--past` / `--current` / `--future` class.
    current: RwSignal<SetupStep>,
    /// The step's rendered body.
    children: ChildrenFn,
) -> impl IntoView {
    // Order rank for past / current / future comparison. `Done` is
    // strictly greater than `PublishDidDocument`; everything else
    // matches its [`step_number`].
    const fn rank(s: SetupStep) -> u8 {
        match s {
            SetupStep::GenerateKey => 1,
            SetupStep::PublishLabelerRecord => 2,
            SetupStep::PublishDidDocument => 3,
            SetupStep::Done => 4,
        }
    }

    let item_class = move || {
        let here = rank(step_index);
        let now = rank(current.get());
        match here.cmp(&now) {
            std::cmp::Ordering::Less => "setup-wizard__step setup-wizard__step--past",
            std::cmp::Ordering::Equal => "setup-wizard__step setup-wizard__step--current",
            std::cmp::Ordering::Greater => "setup-wizard__step setup-wizard__step--future",
        }
    };

    let marker = move || {
        let here = rank(step_index);
        let now = rank(current.get());
        if here < now { "✓" } else { "•" }
    };

    let number = step_number(step_index);
    let title = step_title(step_index);

    view! {
        <li class=item_class>
            <header class="setup-wizard__step-header">
                <span class="setup-wizard__step-marker" aria-hidden="true">{marker}</span>
                <span class="setup-wizard__step-number">"Step "{number}</span>
                <h2 class="setup-wizard__step-title">{title}</h2>
            </header>
            <div class="setup-wizard__step-body">
                {children()}
            </div>
        </li>
    }
}

/// Render a labelled key/value confirmation row (`label: value`).
///
/// Used in the past-step summary to surface the minted `did:key` / the
/// committed DID so the operator can see them persist as they advance.
#[component]
fn ResultLine(
    /// Field name to render before the value.
    label: &'static str,
    /// Field value, read reactively so the row updates when the
    /// parent stores the result.
    value: Signal<String>,
) -> impl IntoView {
    view! {
        <p class="setup-wizard__result">
            <span class="setup-wizard__result-label">{label}":"</span>
            " "
            <code class="setup-wizard__result-value">{move || value.get()}</code>
        </p>
    }
}

/// Step 1: mint a fresh signing key via `POST /api/setup/generate-key`.
#[component]
fn GenerateKeyStep(
    /// Fires with the minted `did:key:z…` on success.
    on_done: Callback<String>,
) -> impl IntoView {
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);
    let minted_key: RwSignal<Option<String>> = RwSignal::new(None);

    let on_click = move |_ev: ev::MouseEvent| {
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let on_done = on_done;
        leptos::task::spawn_local(async move {
            let result = async {
                let client = default_client("")?;
                client.setup_generate_key().await
            }
            .await;
            busy.set(false);
            match result {
                Ok(GenerateKeyResponse { did_key }) => {
                    minted_key.set(Some(did_key.clone()));
                    on_done.run(did_key);
                }
                Err(err) => {
                    if let Some(message) = handle_api_error(&err) {
                        error.set(Some(message));
                    }
                }
            }
        });
    };

    view! {
        <div class="setup-wizard__step-content">
            <p>
                "Polaris will generate a K-256 signing key and store the private \
                half in the moderator keystore. The public half is published to \
                downstream consumers via the labeler service record (step 2) and \
                the DID document (step 3)."
            </p>
            <button
                type="button"
                class="setup-wizard__primary-button"
                disabled=move || busy.get()
                on:click=on_click
            >
                {move || if busy.get() { "Generating…" } else { "Generate signing key" }}
            </button>
            {move || minted_key.get().map(|key| view! {
                <p class="setup-wizard__result" role="status">
                    <span class="setup-wizard__result-label">"did:key:"</span>
                    " "
                    <code class="setup-wizard__result-value">{key}</code>
                </p>
            })}
            {move || error.get().map(|msg| view! {
                <p class="setup-wizard__error" role="alert">
                    "Failed to generate key: "{msg}
                </p>
            })}
        </div>
    }
}

/// Step 2: publish the `app.bsky.labeler.service` record.
#[component]
fn PublishLabelerRecordStep(
    /// Shared `service_url` signal. The component reads its initial
    /// value to seed the input and writes back on each change so the
    /// next step picks up the same URL.
    service_url: RwSignal<String>,
    /// Fires with the publish response on success.
    on_done: Callback<PublishLabelerRecordResponse>,
) -> impl IntoView {
    let label_values_input = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error: RwSignal<Option<String>> = RwSignal::new(None);

    let on_service_url_input = move |ev: ev::Event| {
        service_url.set(event_target_value(&ev));
    };
    let on_label_values_input = move |ev: ev::Event| {
        label_values_input.set(event_target_value(&ev));
    };

    let on_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get() {
            return;
        }
        busy.set(true);
        error.set(None);
        let req = PublishLabelerRecordRequest {
            service_url: service_url.get(),
            label_values: parse_label_values(&label_values_input.get()),
        };
        let on_done = on_done;
        leptos::task::spawn_local(async move {
            let result = async {
                let client = default_client("")?;
                client.setup_publish_labeler_record(req).await
            }
            .await;
            busy.set(false);
            match result {
                Ok(resp) => {
                    on_done.run(resp);
                }
                Err(err) => {
                    if let Some(message) = handle_api_error(&err) {
                        error.set(Some(message));
                    }
                }
            }
        });
    };

    view! {
        <form class="setup-wizard__form" on:submit=on_submit>
            <p>
                "Publish the labeler service record on your PDS. The service URL is \
                where consumers will connect to your label firehose; the label values \
                are the verdicts your labeler will emit."
            </p>
            <label for="setup-service-url">"Service URL"</label>
            <input
                id="setup-service-url"
                name="service_url"
                type="url"
                required
                placeholder="https://labeler.example.com"
                prop:value=move || service_url.get()
                on:input=on_service_url_input
            />
            <label for="setup-label-values">"Label values (comma-separated)"</label>
            <input
                id="setup-label-values"
                name="label_values"
                type="text"
                required
                placeholder="spam, porn, hate"
                prop:value=move || label_values_input.get()
                on:input=on_label_values_input
            />
            <button
                type="submit"
                class="setup-wizard__primary-button"
                disabled=move || busy.get()
            >
                {move || if busy.get() { "Publishing…" } else { "Publish labeler record" }}
            </button>
            {move || error.get().map(|msg| view! {
                <p class="setup-wizard__error" role="alert">
                    "Failed to publish record: "{msg}
                </p>
            })}
        </form>
    }
}

/// Step 3: request a PLC operation token by email, then submit the
/// signed operation with the token the operator copy-pastes back in.
#[component]
fn PublishDidDocumentStep(
    /// The `service_url` written into the DID document's
    /// `#atproto_labeler` entry. Read-only at this step — the value
    /// was pinned in step 2.
    service_url: RwSignal<String>,
    /// Surface for the PLC-signature confirmation message returned by
    /// the first sub-call. `Some(_)` means the email was requested
    /// and the wizard should now render the token-input form.
    plc_message: RwSignal<Option<String>>,
    /// Fires when the PLC signature email has been requested
    /// successfully — the parent stores the message for display.
    on_signature: Callback<String>,
    /// Fires with the updated DID on a successful submit.
    on_done: Callback<String>,
) -> impl IntoView {
    let busy = RwSignal::new(false);
    let token_input = RwSignal::new(String::new());
    let signature_error: RwSignal<Option<String>> = RwSignal::new(None);
    let submit_error: RwSignal<Option<String>> = RwSignal::new(None);

    let on_request_signature = move |_ev: ev::MouseEvent| {
        if busy.get() {
            return;
        }
        busy.set(true);
        signature_error.set(None);
        let on_signature = on_signature;
        leptos::task::spawn_local(async move {
            let result = async {
                let client = default_client("")?;
                client.setup_request_plc_signature().await
            }
            .await;
            busy.set(false);
            match result {
                Ok(RequestPlcSignatureResponse { message }) => {
                    on_signature.run(message);
                }
                Err(err) => {
                    if let Some(msg) = handle_api_error(&err) {
                        signature_error.set(Some(msg));
                    }
                }
            }
        });
    };

    let on_token_input = move |ev: ev::Event| {
        token_input.set(event_target_value(&ev));
    };

    let on_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get() {
            return;
        }
        busy.set(true);
        submit_error.set(None);
        let req = SubmitPlcOperationRequest {
            token: token_input.get(),
            service_url: service_url.get(),
        };
        let on_done = on_done;
        leptos::task::spawn_local(async move {
            let result = async {
                let client = default_client("")?;
                client.setup_submit_plc_operation(req).await
            }
            .await;
            busy.set(false);
            match result {
                Ok(SubmitPlcOperationResponse { did }) => {
                    on_done.run(did);
                }
                Err(err) => {
                    if let Some(msg) = handle_api_error(&err) {
                        submit_error.set(Some(msg));
                    }
                }
            }
        });
    };

    view! {
        <div class="setup-wizard__step-content">
            <p>
                "Add the `#atproto_labeler` service entry to your DID document. The PDS \
                will email you a one-time PLC operation token; paste it below to sign \
                and submit the update."
            </p>
            <button
                type="button"
                class="setup-wizard__secondary-button"
                disabled=move || busy.get()
                on:click=on_request_signature
            >
                "Request PLC signature email"
            </button>
            {move || signature_error.get().map(|msg| view! {
                <p class="setup-wizard__error" role="alert">
                    "Failed to request PLC signature: "{msg}
                </p>
            })}
            {move || plc_message.get().map(|message| view! {
                <p class="setup-wizard__result" role="status">{message}</p>
            })}
            <form class="setup-wizard__form" on:submit=on_submit>
                <label for="setup-plc-token">"PLC operation token"</label>
                <input
                    id="setup-plc-token"
                    name="token"
                    type="text"
                    required
                    autocomplete="off"
                    placeholder="Paste the token from the email"
                    prop:value=move || token_input.get()
                    on:input=on_token_input
                />
                <button
                    type="submit"
                    class="setup-wizard__primary-button"
                    disabled=move || busy.get() || token_input.with(String::is_empty)
                >
                    {move || if busy.get() { "Submitting…" } else { "Submit PLC operation" }}
                </button>
                {move || submit_error.get().map(|msg| view! {
                    <p class="setup-wizard__error" role="alert">
                        "Failed to submit PLC operation: "{msg}
                    </p>
                })}
            </form>
        </div>
    }
}

/// The "Setup complete" panel rendered when [`SetupStep::Done`].
#[component]
fn DoneStep() -> impl IntoView {
    view! {
        <section class="setup-wizard__done" id="setup-wizard-done" role="status">
            <h2>"Setup complete."</h2>
            <p>
                "Your labeler is now reachable and your DID document declares the \
                service entry. You can return to the dashboard to start moderating."
            </p>
            <a class="setup-wizard__primary-link" href="/">"Go to dashboard"</a>
        </section>
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
    fn setup_path_is_slash_setup() {
        // Regression: the route declaration in `crate::app` and the
        // root-route routing component both key off this constant.
        assert_eq!(SETUP_PATH, "/setup");
    }

    #[test]
    fn advance_walks_through_each_step_in_order() {
        assert_eq!(
            advance(SetupStep::GenerateKey),
            SetupStep::PublishLabelerRecord
        );
        assert_eq!(
            advance(SetupStep::PublishLabelerRecord),
            SetupStep::PublishDidDocument
        );
        assert_eq!(advance(SetupStep::PublishDidDocument), SetupStep::Done);
    }

    #[test]
    fn advance_is_idempotent_at_done() {
        // A stray double-advance from the Done state is a fixpoint, not
        // a wrap-around. The wizard never re-runs the first step.
        assert_eq!(advance(SetupStep::Done), SetupStep::Done);
    }

    #[test]
    fn step_number_is_one_through_three() {
        assert_eq!(step_number(SetupStep::GenerateKey), 1);
        assert_eq!(step_number(SetupStep::PublishLabelerRecord), 2);
        assert_eq!(step_number(SetupStep::PublishDidDocument), 3);
        // Done lives under step 3's heading — there is no fourth step.
        assert_eq!(step_number(SetupStep::Done), 3);
    }

    #[test]
    fn step_title_is_stable() {
        // The titles are surfaced verbatim in the wizard's step list;
        // a silent rename would break the accessibility text.
        assert_eq!(step_title(SetupStep::GenerateKey), "Generate signing key");
        assert_eq!(
            step_title(SetupStep::PublishLabelerRecord),
            "Publish labeler service record"
        );
        assert_eq!(
            step_title(SetupStep::PublishDidDocument),
            "Publish DID document service entry"
        );
        assert_eq!(step_title(SetupStep::Done), "Setup complete");
    }

    #[test]
    fn parse_label_values_splits_on_comma_and_trims() {
        assert_eq!(
            parse_label_values("spam, porn,hate"),
            vec!["spam".to_owned(), "porn".to_owned(), "hate".to_owned()],
        );
    }

    #[test]
    fn parse_label_values_drops_empty_segments() {
        // Trailing commas / repeated commas must not produce empty
        // strings — the backend rejects an empty value with a 400, and
        // surfacing that error for what is really an input formatting
        // wart would be annoying.
        assert_eq!(
            parse_label_values(",spam,,porn,"),
            vec!["spam".to_owned(), "porn".to_owned()],
        );
    }

    #[test]
    fn parse_label_values_returns_empty_for_blank_input() {
        assert!(parse_label_values("").is_empty());
        assert!(parse_label_values("   ").is_empty());
        assert!(parse_label_values(",,").is_empty());
    }

    #[test]
    fn handle_api_error_returns_message_for_non_401() {
        let err = ApiError::Http {
            status: 500,
            message: "server explosion".to_owned(),
        };
        // The function returns `Some(_)` for inline rendering. The
        // exact text is the `Display` form of `ApiError` — assert that
        // the body is reachable rather than pinning the prefix.
        let msg = handle_api_error(&err).expect("non-401 must yield an inline message");
        assert!(
            msg.contains("server explosion"),
            "expected the underlying message, got `{msg}`",
        );
    }

    #[test]
    fn handle_api_error_swallows_401_for_redirect() {
        let err = ApiError::Http {
            status: 401,
            message: "unauthenticated".to_owned(),
        };
        // 401 returns `None` because the redirect side effect is
        // already underway. The inline error region must stay empty.
        assert!(handle_api_error(&err).is_none());
    }

    #[test]
    fn handle_api_error_surfaces_transport_errors_inline() {
        let err = ApiError::Transport("net down".to_owned());
        let msg = handle_api_error(&err).expect("transport errors must yield an inline message");
        assert!(msg.contains("net down"), "got `{msg}`");
    }

    /// Smoke test: the `#[component]` constructor type-checks.
    ///
    /// Mounting requires a Leptos runtime, which lives in the
    /// wasm-bindgen-test harness — `tests/setup_page.rs` exercises
    /// that.
    #[test]
    fn setup_wizard_builds() {
        let _ = SetupWizard;
    }

    #[test]
    fn default_service_url_on_native_is_empty() {
        // On non-wasm targets there is no `window`. The wizard's form
        // treats `""` as "no default" and renders the input empty.
        assert_eq!(default_service_url(), String::new());
    }
}
