//! `/admin/policies` — admin-only policy workbook page (REQ-D1..D3,
//! issue #226).
//!
//! Two-pane layout: scrollable list on the left, detail+edit form on
//! the right. Mirrors `/admin/moderators` in structure. The edit form
//! groups fields into three sections — header (identifier / name /
//! description), body (scope / severity / `decision_criteria` /
//! examples / suggested actions), autonomy (mode / kinds / thresholds
//! / pause). Below the form: a version-history panel listing prior
//! versions with their `change_summary`.
//!
//! # Surface
//!
//! - `GET /api/policies` — list (admin sees the same projection as
//!   moderators; the admin-only writes live under `/api/admin/policies`).
//! - `GET /api/policies/:identifier` — current version (full payload).
//! - `GET /api/admin/policies/:identifier/history` — version history.
//! - `PATCH /api/admin/policies/:identifier` — amend. Required
//!   `change_summary`. Server bumps the version.
//! - `POST /api/admin/policies/:identifier/pause` — set
//!   `autonomous_paused_until`.
//! - `DELETE /api/admin/policies/:identifier/pause` — clear it.
//!
//! # RBAC
//!
//! The page itself is reachable by anyone — the backend independently
//! rejects every fetch for non-admins with `403`. A 403 on the initial
//! list renders the inline Forbidden banner so a non-admin who follows
//! a deep link sees an explanation rather than an empty pane.

use leptos::ev;
use leptos::prelude::*;

use crate::api_client::dto::{
    ModPolicyDto, ModPolicyEditDto, ModPolicyHistoryEntryDto, ModPolicySummaryDto, PausePolicyDto,
    PolicyListFilters,
};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::pages::admin_moderators::{FetchOutcome, is_forbidden};
use crate::pages::login::{is_unauthorized, redirect_to_login};
use crate::pages::policies::{PoliciesBody, autonomy_chip_class};

/// Path the admin policies page is mounted at.
pub const ADMIN_POLICIES_PATH: &str = "/admin/policies";

/// Render the admin policies page.
///
/// On mount: fire `GET /api/policies` (the moderator-readable index;
/// admins see the same projection). The list resolves either to the
/// admin two-pane body, the Forbidden banner (403 on a non-admin), or
/// an inline error band.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn AdminPoliciesPage() -> impl IntoView {
    // Refresh token: bump after a successful mutation to re-fire the
    // list + detail fetches.
    let refresh_tick = RwSignal::new(0_u64);

    let policies = LocalResource::new(move || {
        let _token = refresh_tick.get();
        async move {
            let client = default_client("").map_err(|e| FetchOutcome::from_error(&e))?;
            client
                .list_policies(&PolicyListFilters::default())
                .await
                .map_err(|e| FetchOutcome::from_error(&e))
        }
    });

    view! {
        <main class="admin-policies" id="admin-policies-root">
            <header class="admin-policies__header">
                <h1>"Moderation policy workbook"</h1>
                <p class="admin-policies__tagline">
                    "Edit the structured policies moderators cite on actions. \
                    Every amendment bumps the policy's version and is audit-logged \
                    with the operator's change-summary note."
                </p>
                <a class="admin-policies__back-link" href="/">
                    "← Back to dashboard"
                </a>
            </header>
            <Suspense fallback=move || view! {
                <p class="admin-policies__loading" role="status">"Loading…"</p>
            }>
                {move || Suspend::new(async move {
                    match policies.await {
                        Ok(rows) => view! {
                            <AdminPoliciesBody
                                rows=rows
                                refresh_tick=refresh_tick
                            />
                        }.into_any(),
                        Err(FetchOutcome::Unauthorized) => {
                            redirect_to_login();
                            view! {
                                <p class="admin-policies__redirect" role="status">
                                    "Redirecting to login…"
                                </p>
                            }.into_any()
                        }
                        Err(FetchOutcome::Forbidden) => view! {
                            <Forbidden/>
                        }.into_any(),
                        Err(FetchOutcome::Other(message)) => view! {
                            <p class="admin-policies__error" role="alert">
                                "Failed to load policies: "{message}
                            </p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </main>
    }
}

/// Forbidden state — rendered when the backend returns 403 on the
/// initial fetch.
#[component]
fn Forbidden() -> impl IntoView {
    view! {
        <section class="admin-policies__forbidden" role="alert">
            <h2>"Forbidden"</h2>
            <p>
                "This page is restricted to operators with the "
                <strong>"admin"</strong>" role. Non-admin moderators can browse \
                the policy workbook read-only at "<a href="/policies">"/policies"</a>"."
            </p>
            <a class="admin-policies__back-link" href="/">
                "← Back to dashboard"
            </a>
        </section>
    }
}

/// Render the admin two-pane body once the index has resolved.
#[component]
fn AdminPoliciesBody(
    /// Hydrated list of policy summaries.
    rows: Vec<ModPolicySummaryDto>,
    /// Refresh-token signal bumped after every successful amend.
    refresh_tick: RwSignal<u64>,
) -> impl IntoView {
    if rows.is_empty() {
        return view! {
            <p class="admin-policies__hint" role="status">
                "No policies yet — seed the workbook from "
                <code>"deploy/seeds/mod-policies.yml"</code>" or use \
                "<code>"polaris-setup seed-policies"</code>"."
            </p>
        }
        .into_any();
    }

    // Reuse the read-only list rendering from the browse view but
    // override the right pane with the admin edit form.
    let initial = rows.first().map(|r| r.identifier.clone());
    let selected: RwSignal<Option<String>> = RwSignal::new(initial);

    // Render the left pane via the shared body component but with
    // `readonly = true` for the rows (rows themselves don't carry
    // edit affordances; the right pane does). We bypass `PoliciesBody`
    // here because it owns its own `selected` signal — we need ours to
    // also drive the admin edit form.
    let _ = PoliciesBody; // referenced to keep the symbol live in docs

    let row_views = rows
        .iter()
        .map(|row| {
            let identifier = row.identifier.clone();
            let identifier_for_click = identifier.clone();
            let identifier_for_class = identifier.clone();
            let name = row.name.clone();
            let scope = row.scope.clone();
            let severity = row.severity.clone();
            let autonomy_mode = row.autonomy_mode.clone();
            let is_retired = row.is_retired;
            let chip_class = autonomy_chip_class(&autonomy_mode);
            view! {
                <li>
                    <button
                        type="button"
                        class=move || {
                            let active = selected
                                .get()
                                .as_deref()
                                .is_some_and(|s| s == identifier_for_class.as_str());
                            if active {
                                "admin-policies__list-row admin-policies__list-row--active"
                            } else {
                                "admin-policies__list-row"
                            }
                        }
                        on:click=move |_| selected.set(Some(identifier_for_click.clone()))
                    >
                        <code class="admin-policies__cell--identifier">{identifier}</code>
                        <span class="admin-policies__cell--name">{name}</span>
                        <span class=chip_class title=autonomy_mode.clone()>
                            {autonomy_mode.clone()}
                        </span>
                        {is_retired.then(|| view! {
                            <span class="admin-policies__chip--retired" title="Retired">
                                "retired"
                            </span>
                        })}
                        <span class="admin-policies__cell--scope" title="scope">
                            {scope}
                        </span>
                        <span class="admin-policies__cell--severity" title="severity">
                            {severity}
                        </span>
                    </button>
                </li>
            }
        })
        .collect::<Vec<_>>();

    view! {
        <section class="admin-policies__layout">
            <aside class="admin-policies__list" aria-label="Policy list">
                <ul class="admin-policies__list-items">
                    {row_views}
                </ul>
            </aside>
            <article class="admin-policies__detail" aria-live="polite">
                <AdminPolicyEditor selected=selected refresh_tick=refresh_tick/>
            </article>
        </section>
    }
    .into_any()
}

/// Render the admin edit form for the selected policy.
///
/// Re-fires on every `selected`/`refresh_tick` change. Owns the form
/// signals locally so a row swap resets the staged edits cleanly.
#[component]
fn AdminPolicyEditor(
    /// Selected identifier (drives the fetch).
    selected: RwSignal<Option<String>>,
    /// Page-level refresh token. Bumped on every successful mutation.
    refresh_tick: RwSignal<u64>,
) -> impl IntoView {
    let policy = LocalResource::new(move || {
        let id = selected.get();
        let _tick = refresh_tick.get();
        async move {
            match id {
                None => Ok(None),
                Some(identifier) => {
                    let client = default_client("").map_err(|e: ApiError| e.to_string())?;
                    client
                        .get_policy(&identifier)
                        .await
                        .map(Some)
                        .map_err(|e: ApiError| e.to_string())
                }
            }
        }
    });

    view! {
        <Suspense fallback=move || view! {
            <p class="admin-policies__loading" role="status">"Loading policy…"</p>
        }>
            {move || Suspend::new(async move {
                match policy.await {
                    Ok(None) => view! {
                        <p class="admin-policies__hint" role="status">
                            "Select a policy from the list to edit it."
                        </p>
                    }.into_any(),
                    Ok(Some(policy)) => view! {
                        <AdminPolicyForm policy=policy refresh_tick=refresh_tick/>
                    }.into_any(),
                    Err(message) => view! {
                        <p class="admin-policies__error" role="alert">
                            "Failed to load policy: "{message}
                        </p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

/// Active tab inside the decision-criteria editor.
///
/// Two states: `Edit` shows the textarea; `Preview` shows the saved
/// Markdown rendered as a `<pre>` block (per the brief's minimal
/// fallback — no Markdown crate is in the frontend bundle yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecisionTab {
    Edit,
    Preview,
}

/// Active tab on the right pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetailTab {
    Body,
    Autonomy,
    History,
}

/// Render the full admin edit form for a single policy.
///
/// Owns the per-field staged-edit signals plus the `change_summary`
/// textarea. The Save button PATCHes the backend with only the fields
/// that actually changed.
#[component]
fn AdminPolicyForm(
    /// The policy currently being edited.
    policy: ModPolicyDto,
    /// Page-level refresh token.
    refresh_tick: RwSignal<u64>,
) -> impl IntoView {
    // Staged edits. Each signal seeds from the loaded policy.
    let name = RwSignal::new(policy.name.clone());
    let description = RwSignal::new(policy.description.clone());
    let scope = RwSignal::new(policy.scope.clone());
    let severity = RwSignal::new(policy.severity.clone());
    let decision_criteria = RwSignal::new(policy.decision_criteria.clone());
    let suggested_action_kinds = RwSignal::new(policy.suggested_action_kinds.join(","));
    let exceptions = RwSignal::new(policy.exceptions.clone().unwrap_or_default());
    let linked_label_value = RwSignal::new(policy.linked_label_value.clone().unwrap_or_default());
    let human_required_always = RwSignal::new(policy.human_required_always);
    let autonomy_mode = RwSignal::new(policy.autonomy_mode.clone());
    let autonomous_action_kinds = RwSignal::new(policy.autonomous_action_kinds.join(","));
    let autonomous_threshold = RwSignal::new(policy.autonomous_confidence_threshold);
    let assisted_threshold = RwSignal::new(policy.assisted_confidence_threshold);
    let change_summary = RwSignal::new(String::new());

    let decision_tab = RwSignal::new(DecisionTab::Edit);
    let detail_tab = RwSignal::new(DetailTab::Body);
    let busy = RwSignal::new(false);
    let error_msg: RwSignal<Option<String>> = RwSignal::new(None);
    let confirm_retire = RwSignal::new(false);
    let confirm_pause = RwSignal::new(false);

    let identifier = policy.identifier.clone();
    let version = policy.version;
    let is_retired = policy.is_retired;
    let already_paused = policy.autonomous_paused_until.is_some();
    let identifier_for_save = identifier.clone();
    let identifier_for_retire = identifier.clone();
    let identifier_for_pause = identifier.clone();

    // Capture starting values for the diff at save time.
    let baseline = policy.clone();

    let on_save = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if busy.get_untracked() {
            return;
        }
        let summary = change_summary.get_untracked().trim().to_owned();
        if summary.is_empty() {
            error_msg.set(Some(
                "A non-empty change-summary is required to amend a policy.".to_owned(),
            ));
            return;
        }
        let body = stage_edit(
            &baseline,
            &name.get_untracked(),
            &description.get_untracked(),
            &scope.get_untracked(),
            &severity.get_untracked(),
            &decision_criteria.get_untracked(),
            &suggested_action_kinds.get_untracked(),
            &exceptions.get_untracked(),
            &linked_label_value.get_untracked(),
            human_required_always.get_untracked(),
            &autonomy_mode.get_untracked(),
            &autonomous_action_kinds.get_untracked(),
            autonomous_threshold.get_untracked(),
            assisted_threshold.get_untracked(),
            summary,
        );
        busy.set(true);
        error_msg.set(None);
        let identifier = identifier_for_save.clone();
        leptos::task::spawn_local(async move {
            let outcome = async move {
                let client = default_client("")?;
                client.amend_policy(&identifier, body).await
            }
            .await;
            busy.set(false);
            match outcome {
                Ok(_updated) => {
                    change_summary.set(String::new());
                    refresh_tick.update(|t| *t = t.wrapping_add(1));
                }
                Err(err) => {
                    handle_mutation_error(&err, error_msg);
                }
            }
        });
    };

    let on_retire = move |_ev: ev::MouseEvent| {
        if busy.get_untracked() || is_retired {
            return;
        }
        if !confirm_retire.get_untracked() {
            confirm_retire.set(true);
            return;
        }
        let summary = change_summary.get_untracked().trim().to_owned();
        if summary.is_empty() {
            error_msg.set(Some(
                "Retiring a policy still writes a tombstone version — a \
                 non-empty change-summary is required."
                    .to_owned(),
            ));
            return;
        }
        busy.set(true);
        error_msg.set(None);
        let body = ModPolicyEditDto {
            is_retired: Some(true),
            change_summary: summary,
            ..ModPolicyEditDto::default()
        };
        let identifier = identifier_for_retire.clone();
        leptos::task::spawn_local(async move {
            let outcome = async move {
                let client = default_client("")?;
                client.amend_policy(&identifier, body).await
            }
            .await;
            busy.set(false);
            confirm_retire.set(false);
            match outcome {
                Ok(_updated) => {
                    refresh_tick.update(|t| *t = t.wrapping_add(1));
                }
                Err(err) => {
                    handle_mutation_error(&err, error_msg);
                }
            }
        });
    };

    let on_pause_resume = move |_ev: ev::MouseEvent| {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        error_msg.set(None);
        let identifier = identifier_for_pause.clone();
        let resume = already_paused;
        if !resume && !confirm_pause.get_untracked() {
            confirm_pause.set(true);
            busy.set(false);
            return;
        }
        leptos::task::spawn_local(async move {
            let outcome = async move {
                let client = default_client("")?;
                if resume {
                    client.resume_policy(&identifier).await
                } else {
                    // Pause forever — empty body triggers the backend's
                    // "forever" path per the design.
                    client
                        .pause_policy(&identifier, PausePolicyDto::default())
                        .await
                }
            }
            .await;
            busy.set(false);
            confirm_pause.set(false);
            match outcome {
                Ok(_updated) => {
                    refresh_tick.update(|t| *t = t.wrapping_add(1));
                }
                Err(err) => {
                    handle_mutation_error(&err, error_msg);
                }
            }
        });
    };

    let header_chip = autonomy_chip_class(&policy.autonomy_mode);
    let identifier_header = identifier.clone();
    let identifier_for_history = identifier.clone();
    let autonomy_label = policy.autonomy_mode.clone();
    let autonomy_label_for_chip = autonomy_label.clone();

    view! {
        <form class="admin-policies__form" on:submit=on_save>
            <header class="admin-policies__detail-header">
                <h2>
                    <code class="admin-policies__cell--identifier">{identifier_header}</code>
                    " v"{version}
                </h2>
                <div class="admin-policies__detail-chips">
                    <span class=header_chip>{autonomy_label_for_chip}</span>
                    {move || human_required_always.get().then(|| view! {
                        <span class="admin-policies__chip--human-required"
                              title="This policy can never run autonomously (REQ-G3)">
                            "human-required"
                        </span>
                    })}
                    {is_retired.then(|| view! {
                        <span class="admin-policies__chip--retired" title="Retired">
                            "retired"
                        </span>
                    })}
                </div>
            </header>

            <nav class="admin-policies__tabs" aria-label="Policy detail tabs">
                <button type="button"
                    class=move || tab_class(detail_tab.get() == DetailTab::Body)
                    on:click=move |_| detail_tab.set(DetailTab::Body)
                >"Body"</button>
                <button type="button"
                    class=move || tab_class(detail_tab.get() == DetailTab::Autonomy)
                    on:click=move |_| detail_tab.set(DetailTab::Autonomy)
                >"Autonomy"</button>
                <button type="button"
                    class=move || tab_class(detail_tab.get() == DetailTab::History)
                    on:click=move |_| detail_tab.set(DetailTab::History)
                >"History"</button>
            </nav>

            <div
                class="admin-policies__tab-panel"
                style:display=move || if detail_tab.get() == DetailTab::Body { "block" } else { "none" }
            >
                <label class="admin-policies__field-label" for="admin-policies-name">"Name"</label>
                <input
                    id="admin-policies-name"
                    class="admin-policies__input"
                    type="text"
                    prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev))
                />
                <label class="admin-policies__field-label" for="admin-policies-description">
                    "Description"
                </label>
                <textarea
                    id="admin-policies-description"
                    class="admin-policies__textarea"
                    rows="3"
                    prop:value=move || description.get()
                    on:input=move |ev| description.set(event_target_value(&ev))
                />
                <label class="admin-policies__field-label" for="admin-policies-scope">"Scope"</label>
                <select
                    id="admin-policies-scope"
                    class="admin-policies__input"
                    on:change=move |ev| scope.set(event_target_value(&ev))
                >
                    {scope_options(&scope.get_untracked())}
                </select>
                <label class="admin-policies__field-label" for="admin-policies-severity">
                    "Severity"
                </label>
                <select
                    id="admin-policies-severity"
                    class="admin-policies__input"
                    on:change=move |ev| severity.set(event_target_value(&ev))
                >
                    {severity_options(&severity.get_untracked())}
                </select>

                <div class="admin-policies__decision-tabs">
                    <button type="button"
                        class=move || tab_class(decision_tab.get() == DecisionTab::Edit)
                        on:click=move |_| decision_tab.set(DecisionTab::Edit)
                    >"Edit"</button>
                    <button type="button"
                        class=move || tab_class(decision_tab.get() == DecisionTab::Preview)
                        on:click=move |_| decision_tab.set(DecisionTab::Preview)
                    >"Preview"</button>
                </div>
                <label class="admin-policies__field-label" for="admin-policies-decision">
                    "Decision criteria (Markdown)"
                </label>
                <textarea
                    id="admin-policies-decision"
                    class="admin-policies__textarea admin-policies__textarea--mono"
                    rows="10"
                    style:display=move || {
                        if decision_tab.get() == DecisionTab::Edit { "block" } else { "none" }
                    }
                    prop:value=move || decision_criteria.get()
                    on:input=move |ev| decision_criteria.set(event_target_value(&ev))
                />
                <pre
                    class="admin-policies__decision-pre"
                    style:display=move || {
                        if decision_tab.get() == DecisionTab::Preview { "block" } else { "none" }
                    }
                >{move || decision_criteria.get()}</pre>

                <label class="admin-policies__field-label" for="admin-policies-suggested">
                    "Suggested action kinds (comma-separated)"
                </label>
                <input
                    id="admin-policies-suggested"
                    class="admin-policies__input"
                    type="text"
                    placeholder="label, warn, takedown"
                    prop:value=move || suggested_action_kinds.get()
                    on:input=move |ev| suggested_action_kinds.set(event_target_value(&ev))
                />
                <label class="admin-policies__field-label" for="admin-policies-linked-label">
                    "Linked label value"
                </label>
                <input
                    id="admin-policies-linked-label"
                    class="admin-policies__input"
                    type="text"
                    prop:value=move || linked_label_value.get()
                    on:input=move |ev| linked_label_value.set(event_target_value(&ev))
                />
                <label class="admin-policies__field-label" for="admin-policies-exceptions">
                    "Exceptions"
                </label>
                <textarea
                    id="admin-policies-exceptions"
                    class="admin-policies__textarea"
                    rows="3"
                    prop:value=move || exceptions.get()
                    on:input=move |ev| exceptions.set(event_target_value(&ev))
                />
            </div>

            <div
                class="admin-policies__tab-panel"
                style:display=move || {
                    if detail_tab.get() == DetailTab::Autonomy { "block" } else { "none" }
                }
            >
                {move || if human_required_always.get() {
                    view! {
                        <p class="admin-policies__autonomy-locked" role="status">
                            "This policy is marked "<code>"human_required_always"</code>" \
                            (REQ-G3). It can never run in "<code>"autonomous"</code>" mode. \
                            Clear the human-required floor below before changing autonomy mode."
                        </p>
                    }.into_any()
                } else {
                    ().into_any()
                }}
                <label class="admin-policies__field-label" for="admin-policies-autonomy-mode">
                    "Autonomy mode"
                </label>
                <select
                    id="admin-policies-autonomy-mode"
                    class="admin-policies__input"
                    disabled=move || human_required_always.get()
                    on:change=move |ev| autonomy_mode.set(event_target_value(&ev))
                >
                    {autonomy_options(&autonomy_mode.get_untracked())}
                </select>
                <label class="admin-policies__field-label" for="admin-policies-autonomy-kinds">
                    "Autonomous action kinds (comma-separated; subset of label,warn,takedown)"
                </label>
                <input
                    id="admin-policies-autonomy-kinds"
                    class="admin-policies__input"
                    type="text"
                    placeholder="label, warn"
                    prop:value=move || autonomous_action_kinds.get()
                    on:input=move |ev| autonomous_action_kinds.set(event_target_value(&ev))
                />
                <label class="admin-policies__field-label" for="admin-policies-autonomous-th">
                    "Autonomous confidence threshold"
                </label>
                <input
                    id="admin-policies-autonomous-th"
                    class="admin-policies__slider"
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    prop:value=move || autonomous_threshold.get().to_string()
                    on:input=move |ev| {
                        if let Ok(v) = event_target_value(&ev).parse::<f32>() {
                            autonomous_threshold.set(v);
                        }
                    }
                />
                <output class="admin-policies__slider-value">
                    {move || format!("{:.2}", autonomous_threshold.get())}
                </output>
                <label class="admin-policies__field-label" for="admin-policies-assisted-th">
                    "Assisted confidence threshold"
                </label>
                <input
                    id="admin-policies-assisted-th"
                    class="admin-policies__slider"
                    type="range"
                    min="0"
                    max="1"
                    step="0.01"
                    prop:value=move || assisted_threshold.get().to_string()
                    on:input=move |ev| {
                        if let Ok(v) = event_target_value(&ev).parse::<f32>() {
                            assisted_threshold.set(v);
                        }
                    }
                />
                <output class="admin-policies__slider-value">
                    {move || format!("{:.2}", assisted_threshold.get())}
                </output>
                <label class="admin-policies__chip-toggle">
                    <input
                        type="checkbox"
                        prop:checked=move || human_required_always.get()
                        on:change=move |ev| {
                            human_required_always.set(event_target_checked(&ev));
                        }
                    />
                    " "<span>"Human required always (REQ-G3 floor)"</span>
                </label>
                <button
                    type="button"
                    class="admin-policies__pause-btn"
                    disabled=move || busy.get()
                    on:click=on_pause_resume
                >
                    {move || {
                        if already_paused {
                            "Resume autonomy".to_owned()
                        } else if confirm_pause.get() {
                            "Click again to pause forever".to_owned()
                        } else {
                            "Pause autonomy".to_owned()
                        }
                    }}
                </button>
            </div>

            <div
                class="admin-policies__tab-panel"
                style:display=move || {
                    if detail_tab.get() == DetailTab::History { "block" } else { "none" }
                }
            >
                <PolicyHistoryPanel identifier=identifier_for_history.clone()
                                    refresh_tick=refresh_tick/>
            </div>

            <label class="admin-policies__field-label" for="admin-policies-change-summary">
                "Change summary (required for any amendment)"
            </label>
            <textarea
                id="admin-policies-change-summary"
                class="admin-policies__textarea"
                rows="2"
                placeholder="Why this version was written…"
                prop:value=move || change_summary.get()
                on:input=move |ev| change_summary.set(event_target_value(&ev))
            />

            {move || error_msg.get().map(|msg| view! {
                <p class="admin-policies__error" role="alert">{msg}</p>
            })}

            <div class="admin-policies__form-actions">
                <button
                    type="submit"
                    class="admin-policies__save-btn"
                    disabled=move || busy.get() || is_retired
                >
                    {move || if busy.get() { "Saving…" } else { "Save amendment" }}
                </button>
                <button
                    type="button"
                    class="admin-policies__retire-btn"
                    disabled=move || busy.get() || is_retired
                    on:click=on_retire
                >
                    {move || {
                        if is_retired {
                            "Retired".to_owned()
                        } else if confirm_retire.get() {
                            "Click again to retire".to_owned()
                        } else {
                            "Retire policy".to_owned()
                        }
                    }}
                </button>
            </div>
        </form>
    }
}

/// Build a `ModPolicyEditDto` from the staged signals, including only
/// fields that actually differ from the baseline.
///
/// Pure helper so the diff is unit-testable without a Leptos owner.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn stage_edit(
    baseline: &ModPolicyDto,
    name: &str,
    description: &str,
    scope: &str,
    severity: &str,
    decision_criteria: &str,
    suggested_action_kinds_csv: &str,
    exceptions: &str,
    linked_label_value: &str,
    human_required_always: bool,
    autonomy_mode: &str,
    autonomous_action_kinds_csv: &str,
    autonomous_threshold: f32,
    assisted_threshold: f32,
    change_summary: String,
) -> ModPolicyEditDto {
    let mut body = ModPolicyEditDto {
        change_summary,
        ..ModPolicyEditDto::default()
    };
    if name != baseline.name {
        body.name = Some(name.to_owned());
    }
    if description != baseline.description {
        body.description = Some(description.to_owned());
    }
    if scope != baseline.scope {
        body.scope = Some(scope.to_owned());
    }
    if severity != baseline.severity {
        body.severity = Some(severity.to_owned());
    }
    if decision_criteria != baseline.decision_criteria {
        body.decision_criteria = Some(decision_criteria.to_owned());
    }
    let suggested: Vec<String> = parse_csv(suggested_action_kinds_csv);
    if suggested != baseline.suggested_action_kinds {
        body.suggested_action_kinds = Some(suggested);
    }
    let exceptions_owned = if exceptions.is_empty() {
        None
    } else {
        Some(exceptions.to_owned())
    };
    if exceptions_owned != baseline.exceptions {
        // The PATCH endpoint's wire shape uses a plain `Option<String>`
        // on the frontend (the backend distinguishes missing-key from
        // null-key via `Option<Option<T>>` server-side; the frontend
        // currently only sends the "replace" path).
        if let Some(value) = exceptions_owned {
            body.exceptions = Some(value);
        }
    }
    let linked_owned = if linked_label_value.is_empty() {
        None
    } else {
        Some(linked_label_value.to_owned())
    };
    if linked_owned != baseline.linked_label_value {
        if let Some(value) = linked_owned {
            body.linked_label_value = Some(value);
        }
    }
    if human_required_always != baseline.human_required_always {
        body.human_required_always = Some(human_required_always);
    }
    if autonomy_mode != baseline.autonomy_mode {
        body.autonomy_mode = Some(autonomy_mode.to_owned());
    }
    let autonomy_kinds: Vec<String> = parse_csv(autonomous_action_kinds_csv);
    if autonomy_kinds != baseline.autonomous_action_kinds {
        body.autonomous_action_kinds = Some(autonomy_kinds);
    }
    if (autonomous_threshold - baseline.autonomous_confidence_threshold).abs() > f32::EPSILON {
        body.autonomous_confidence_threshold = Some(autonomous_threshold);
    }
    if (assisted_threshold - baseline.assisted_confidence_threshold).abs() > f32::EPSILON {
        body.assisted_confidence_threshold = Some(assisted_threshold);
    }
    body
}

/// Parse a comma-separated value list into a trimmed-and-filtered Vec.
///
/// Whitespace-only entries are dropped; non-empty entries keep their
/// inner trim. Pure helper for the action-kinds inputs.
fn parse_csv(input: &str) -> Vec<String> {
    input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Render the version-history panel for a policy.
#[component]
fn PolicyHistoryPanel(
    /// Policy identifier whose history to fetch.
    identifier: String,
    /// Refresh-token signal — bumped on every amend, which re-fires the
    /// history fetch so a freshly-written version is visible immediately.
    refresh_tick: RwSignal<u64>,
) -> impl IntoView {
    let identifier_for_fetch = identifier.clone();
    let history = LocalResource::new(move || {
        let _tick = refresh_tick.get();
        let id = identifier_for_fetch.clone();
        async move {
            let client = default_client("").map_err(|e: ApiError| e.to_string())?;
            client
                .get_policy_history(&id)
                .await
                .map_err(|e: ApiError| e.to_string())
        }
    });

    view! {
        <Suspense fallback=move || view! {
            <p class="admin-policies__loading" role="status">"Loading history…"</p>
        }>
            {move || Suspend::new(async move {
                match history.await {
                    Ok(entries) => view! {
                        <ul class="admin-policies__history-list">
                            {entries.iter().map(history_row).collect::<Vec<_>>()}
                        </ul>
                    }.into_any(),
                    Err(message) => view! {
                        <p class="admin-policies__error" role="alert">
                            "Failed to load history: "{message}
                        </p>
                    }.into_any(),
                }
            })}
        </Suspense>
    }
}

/// Render one history-row card. Pure (no signals).
fn history_row(entry: &ModPolicyHistoryEntryDto) -> impl IntoView {
    let version = entry.version;
    let summary = entry
        .change_summary
        .clone()
        .unwrap_or_else(|| "(no change summary)".to_owned());
    let created_at = entry.created_at.to_rfc3339();
    let diff_link = entry.diff_url.clone();
    let is_retired = entry.is_retired;
    view! {
        <li class="admin-policies__history-row">
            <span class="admin-policies__history-version">"v"{version}</span>
            <span class="admin-policies__history-summary">{summary}</span>
            <time class="admin-policies__history-time">{created_at}</time>
            {is_retired.then(|| view! {
                <span class="admin-policies__chip--retired" title="Retired">"retired"</span>
            })}
            {diff_link.map(|href| view! {
                <a class="admin-policies__history-diff" href=href>"diff"</a>
            })}
        </li>
    }
}

/// Return the `<option>` block for the scope select with the current
/// value pre-selected.
fn scope_options(current: &str) -> Vec<impl IntoView + use<>> {
    [("account", "Account"), ("post", "Post"), ("both", "Both")]
        .iter()
        .map(|(value, label)| {
            let selected = *value == current;
            view! { <option value=*value selected=selected>{*label}</option> }
        })
        .collect()
}

/// `<option>` block for the severity select.
fn severity_options(current: &str) -> Vec<impl IntoView + use<>> {
    [
        ("inform", "Inform"),
        ("alert", "Alert"),
        ("hide", "Hide"),
        ("remove", "Remove"),
    ]
    .iter()
    .map(|(value, label)| {
        let selected = *value == current;
        view! { <option value=*value selected=selected>{*label}</option> }
    })
    .collect()
}

/// `<option>` block for the autonomy-mode select.
fn autonomy_options(current: &str) -> Vec<impl IntoView + use<>> {
    [
        ("manual", "Manual"),
        ("assisted", "Assisted"),
        ("autonomous", "Autonomous"),
    ]
    .iter()
    .map(|(value, label)| {
        let selected = *value == current;
        view! { <option value=*value selected=selected>{*label}</option> }
    })
    .collect()
}

/// BEM class for a tab button, applying `--active` when the tab is
/// selected.
fn tab_class(active: bool) -> &'static str {
    if active {
        "admin-policies__tab admin-policies__tab--active"
    } else {
        "admin-policies__tab"
    }
}

/// Map a mutation error onto the inline-error band.
fn handle_mutation_error(err: &ApiError, last_error: RwSignal<Option<String>>) {
    if is_unauthorized(err) || is_forbidden(err) {
        redirect_to_login();
        return;
    }
    last_error.set(Some(err.to_string()));
}

/// Pure helper: read the current value out of an event target.
#[cfg(target_arch = "wasm32")]
fn event_target_value(ev: &ev::Event) -> String {
    use wasm_bindgen::JsCast as _;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|el| el.value())
        .or_else(|| {
            ev.target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
                .map(|el| el.value())
        })
        .or_else(|| {
            ev.target()
                .and_then(|t| t.dyn_into::<web_sys::HtmlTextAreaElement>().ok())
                .map(|el| el.value())
        })
        .unwrap_or_default()
}

/// Native stub.
#[cfg(not(target_arch = "wasm32"))]
const fn event_target_value(_ev: &ev::Event) -> String {
    String::new()
}

#[cfg(target_arch = "wasm32")]
fn event_target_checked(ev: &ev::Event) -> bool {
    use wasm_bindgen::JsCast as _;
    ev.target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .is_some_and(|el| el.checked())
}

#[cfg(not(target_arch = "wasm32"))]
const fn event_target_checked(_ev: &ev::Event) -> bool {
    false
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
    use uuid::Uuid;

    fn fixture() -> ModPolicyDto {
        ModPolicyDto {
            id: Uuid::nil(),
            identifier: "polaris.spam".to_owned(),
            version: 2,
            name: "Spam".to_owned(),
            description: "Unsolicited promotional content.".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "When the post is recurring promotional content from a low-effort throwaway account.".to_owned(),
            examples_positive: serde_json::Value::Array(Vec::new()),
            examples_negative: serde_json::Value::Array(Vec::new()),
            suggested_action_kinds: vec!["label".to_owned(), "warn".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "manual".to_owned(),
            autonomous_action_kinds: Vec::new(),
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            autonomous_paused_until: None,
            is_retired: false,
            created_at: Utc::now(),
            created_by_moderator_id: Uuid::nil(),
            effective_from: Utc::now(),
            effective_until: None,
            supersedes_id: None,
            change_summary: None,
        }
    }

    #[test]
    fn admin_policies_path_is_stable() {
        assert_eq!(ADMIN_POLICIES_PATH, "/admin/policies");
    }

    #[test]
    fn stage_edit_no_change_yields_empty_patch() {
        let p = fixture();
        let body = stage_edit(
            &p,
            &p.name,
            &p.description,
            &p.scope,
            &p.severity,
            &p.decision_criteria,
            "label,warn",
            "",
            "",
            p.human_required_always,
            &p.autonomy_mode,
            "",
            p.autonomous_confidence_threshold,
            p.assisted_confidence_threshold,
            "noop".to_owned(),
        );
        assert!(body.name.is_none());
        assert!(body.description.is_none());
        assert!(body.scope.is_none());
        assert!(body.severity.is_none());
        assert!(body.decision_criteria.is_none());
        assert!(body.suggested_action_kinds.is_none());
        assert!(body.human_required_always.is_none());
        assert_eq!(body.change_summary, "noop");
    }

    #[test]
    fn stage_edit_picks_up_modified_fields() {
        let p = fixture();
        let body = stage_edit(
            &p,
            "Spam — updated",
            &p.description,
            &p.scope,
            "hide",
            &p.decision_criteria,
            "label,warn,takedown",
            "",
            "",
            p.human_required_always,
            "assisted",
            "label",
            0.92,
            0.65,
            "tighten thresholds".to_owned(),
        );
        assert_eq!(body.name, Some("Spam — updated".to_owned()));
        assert_eq!(body.severity, Some("hide".to_owned()));
        assert_eq!(
            body.suggested_action_kinds,
            Some(vec![
                "label".to_owned(),
                "warn".to_owned(),
                "takedown".to_owned(),
            ]),
        );
        assert_eq!(body.autonomy_mode, Some("assisted".to_owned()));
        assert_eq!(body.autonomous_action_kinds, Some(vec!["label".to_owned()]));
        let auton = body.autonomous_confidence_threshold.unwrap();
        assert!((auton - 0.92).abs() < f32::EPSILON);
    }

    #[test]
    fn parse_csv_trims_and_filters_empty() {
        assert_eq!(parse_csv(""), Vec::<String>::new());
        assert_eq!(parse_csv("  "), Vec::<String>::new());
        assert_eq!(
            parse_csv("label, warn,  , takedown,"),
            vec!["label".to_owned(), "warn".to_owned(), "takedown".to_owned(),],
        );
    }

    #[test]
    fn is_forbidden_predicate_reused() {
        // Regression: the admin-policies error path reuses the
        // `is_forbidden` predicate from the admin-moderators page so the
        // mid-flow 403 → redirect-to-login behaviour matches the
        // sibling admin surface.
        let err = ApiError::Http {
            status: 403,
            message: String::new(),
        };
        assert!(is_forbidden(&err));
    }

    #[test]
    fn admin_policies_page_builds() {
        let _ = AdminPoliciesPage;
    }
}
