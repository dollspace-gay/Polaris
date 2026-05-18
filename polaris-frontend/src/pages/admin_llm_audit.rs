//! `/admin/llm/audit` — operator's "what is the autonomous agent doing?"
//! page (issue #238 / LLM-9 / `.design/llm-moderation-assist.md`
//! REQ-J2).
//!
//! Admin-only. The backend's `Role::Admin` check on `GET
//! /api/admin/llm/audit` is the source of truth — a non-admin who
//! navigates directly to this URL sees a Forbidden banner instead of
//! the table.
//!
//! # Surface
//!
//! Filter bar (model / policy / reversed / date range) → table of
//! autonomous actions → click-row expand to reveal the full LLM
//! response payload (read out of `observations.evidence` via the
//! row's `llm_observation_id`), input_hash, and full reasoning.
//! Pagination is keyset; the "Load more" affordance posts the
//! server-returned `next_cursor` to fetch the next page.
//!
//! Mirrors the admin-moderators page's RBAC handling pattern: the
//! initial fetch's outcome routes the render between three branches
//! (success / forbidden banner / login redirect / inline error).

use leptos::ev;
use leptos::prelude::*;

use crate::api_client::dto::{LlmAuditEntryDto, LlmAuditFilters};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::pages::admin_moderators::FetchOutcome;
use crate::pages::login::redirect_to_login;

/// Path the admin LLM audit page is mounted at.
///
/// Centralised here so the route declaration in [`crate::app`] and the
/// dashboard's admin-link href can reference the same constant.
pub const ADMIN_LLM_AUDIT_PATH: &str = "/admin/llm/audit";

/// Render the admin LLM audit page.
///
/// On mount: fire `GET /api/admin/llm/audit`. The outcome routes the
/// render between the four standard branches (success, 401 → /login,
/// 403 → Forbidden, other → inline error band).
#[allow(clippy::must_use_candidate)]
#[component]
pub fn AdminLlmAuditPage() -> impl IntoView {
    // Filter signals — bound to the inputs in the filter bar.
    let model_filter = RwSignal::new(String::new());
    let policy_filter = RwSignal::new(String::new());
    let reversed_filter: RwSignal<Option<bool>> = RwSignal::new(None);

    // Accumulating page state. `pages` holds the rows already loaded;
    // `next_cursor` is the keyset cursor for the next page (None when
    // we've reached the end).
    let rows: RwSignal<Vec<LlmAuditEntryDto>> = RwSignal::new(Vec::new());
    let next_cursor: RwSignal<Option<String>> = RwSignal::new(None);
    let loading = RwSignal::new(false);
    let load_error: RwSignal<Option<String>> = RwSignal::new(None);

    // Initial load on mount.
    let initial = LocalResource::new(move || async move {
        let client = default_client("").map_err(|e| FetchOutcome::from_error(&e))?;
        client
            .list_llm_audit(&LlmAuditFilters::default())
            .await
            .map_err(|e| FetchOutcome::from_error(&e))
    });

    view! {
        <main class="admin-llm-audit" id="admin-llm-audit-root">
            <header class="admin-llm-audit__header">
                <h1>"LLM audit"</h1>
                <p class="admin-llm-audit__tagline">
                    "Every autonomous action the dispatcher emitted, with the LLM \
                     audit envelope (model + version + prompt + confidence + input hash), \
                     the cited policies at action-create time, and the reversal state."
                </p>
                <a class="admin-llm-audit__back-link" href="/">
                    "← Back to dashboard"
                </a>
            </header>
            <Suspense fallback=move || view! {
                <p class="admin-llm-audit__loading" role="status">"Loading…"</p>
            }>
                {move || Suspend::new(async move {
                    match initial.await {
                        Ok(page) => {
                            rows.set(page.items);
                            next_cursor.set(page.next_cursor);
                            view! {
                                <AdminLlmAuditBody
                                    rows=rows
                                    next_cursor=next_cursor
                                    loading=loading
                                    load_error=load_error
                                    model_filter=model_filter
                                    policy_filter=policy_filter
                                    reversed_filter=reversed_filter
                                />
                            }.into_any()
                        }
                        Err(FetchOutcome::Unauthorized) => {
                            redirect_to_login();
                            view! {
                                <p class="admin-llm-audit__redirect" role="status">
                                    "Redirecting to login…"
                                </p>
                            }.into_any()
                        }
                        Err(FetchOutcome::Forbidden) => view! {
                            <Forbidden/>
                        }.into_any(),
                        Err(FetchOutcome::Other(message)) => view! {
                            <p class="admin-llm-audit__error" role="alert">
                                "Failed to load audit list: "{message}
                            </p>
                        }.into_any(),
                    }
                })}
            </Suspense>
        </main>
    }
}

/// Forbidden state — rendered when the backend returns 403 on the
/// initial list fetch.
#[component]
fn Forbidden() -> impl IntoView {
    view! {
        <section class="admin-llm-audit__forbidden" role="alert">
            <h2>"Forbidden"</h2>
            <p>
                "This page is restricted to operators with the "
                <strong>"admin"</strong>" role. Ask the operator who set up \
                 this install to grant you the role."
            </p>
            <a class="admin-llm-audit__back-link" href="/">
                "← Back to dashboard"
            </a>
        </section>
    }
}

/// Render the filter bar + table once the initial fetch resolves.
///
/// The body owns its own apply-filters / load-more callbacks instead
/// of receiving them as `impl Fn` props, because Leptos signals copy
/// the closures into multiple reactive scopes (the filter form's
/// `on:submit`, the load-more button's `on:click`, plus the implicit
/// re-renders driven by the signal reads inside them) and `impl Fn` is
/// not `Copy`. Closing over the signals directly keeps every
/// invocation site cheap (signals ARE `Copy`).
#[component]
#[allow(
    clippy::too_many_arguments,
    reason = "single-purpose page body; arguments are bound to the page's reactive state, not domain entities"
)]
fn AdminLlmAuditBody(
    rows: RwSignal<Vec<LlmAuditEntryDto>>,
    next_cursor: RwSignal<Option<String>>,
    loading: RwSignal<bool>,
    load_error: RwSignal<Option<String>>,
    model_filter: RwSignal<String>,
    policy_filter: RwSignal<String>,
    reversed_filter: RwSignal<Option<bool>>,
) -> impl IntoView {
    // ── Apply-filters handler ────────────────────────────────────────
    let on_apply_filters = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if loading.get_untracked() {
            return;
        }
        loading.set(true);
        load_error.set(None);
        let model = model_filter.get_untracked();
        let policy = policy_filter.get_untracked();
        let reversed = reversed_filter.get_untracked();
        leptos::task::spawn_local(async move {
            let outcome = async move {
                let client = default_client("")?;
                let filters = LlmAuditFilters {
                    model: Some(model).filter(|s| !s.is_empty()),
                    policy: Some(policy).filter(|s| !s.is_empty()),
                    reversed,
                    ..Default::default()
                };
                client.list_llm_audit(&filters).await
            }
            .await;
            loading.set(false);
            match outcome {
                Ok(page) => {
                    rows.set(page.items);
                    next_cursor.set(page.next_cursor);
                }
                Err(err) => handle_mutation_error(&err, load_error),
            }
        });
    };

    // ── Load-more handler ────────────────────────────────────────────
    let on_load_more = move |_ev: ev::MouseEvent| {
        if loading.get_untracked() {
            return;
        }
        let Some(cursor) = next_cursor.get_untracked() else {
            return;
        };
        loading.set(true);
        load_error.set(None);
        let model = model_filter.get_untracked();
        let policy = policy_filter.get_untracked();
        let reversed = reversed_filter.get_untracked();
        leptos::task::spawn_local(async move {
            let outcome = async move {
                let client = default_client("")?;
                let filters = LlmAuditFilters {
                    model: Some(model).filter(|s| !s.is_empty()),
                    policy: Some(policy).filter(|s| !s.is_empty()),
                    reversed,
                    cursor: Some(cursor),
                    ..Default::default()
                };
                client.list_llm_audit(&filters).await
            }
            .await;
            loading.set(false);
            match outcome {
                Ok(page) => {
                    rows.update(|r| r.extend(page.items));
                    next_cursor.set(page.next_cursor);
                }
                Err(err) => handle_mutation_error(&err, load_error),
            }
        });
    };
    view! {
        <form class="admin-llm-audit__filters" on:submit=on_apply_filters>
            <label for="admin-llm-audit-model" class="admin-llm-audit__filter-label">
                "Model"
            </label>
            <input
                id="admin-llm-audit-model"
                class="admin-llm-audit__filter-input"
                type="text"
                placeholder="e.g. qwen2.5-32b-instruct-q3_k_m"
                autocomplete="off"
                prop:value=move || model_filter.get()
                on:input=move |ev| model_filter.set(event_target_value(&ev))
            />
            <label for="admin-llm-audit-policy" class="admin-llm-audit__filter-label">
                "Policy"
            </label>
            <input
                id="admin-llm-audit-policy"
                class="admin-llm-audit__filter-input"
                type="text"
                placeholder="e.g. polaris.spam"
                autocomplete="off"
                prop:value=move || policy_filter.get()
                on:input=move |ev| policy_filter.set(event_target_value(&ev))
            />
            <label for="admin-llm-audit-reversed" class="admin-llm-audit__filter-label">
                "Reversed"
            </label>
            <select
                id="admin-llm-audit-reversed"
                class="admin-llm-audit__filter-select"
                on:change=move |ev| {
                    let raw = event_target_value(&ev);
                    reversed_filter.set(match raw.as_str() {
                        "true" => Some(true),
                        "false" => Some(false),
                        _ => None,
                    });
                }
            >
                <option value="">"Any"</option>
                <option value="true">"Reversed only"</option>
                <option value="false">"Not reversed"</option>
            </select>
            <button
                type="submit"
                class="admin-llm-audit__filter-submit"
                disabled=move || loading.get()
            >
                {move || if loading.get() { "Loading…" } else { "Apply" }}
            </button>
        </form>
        {move || load_error.get().map(|msg| view! {
            <p class="admin-llm-audit__error" role="alert">{msg}</p>
        })}
        <table class="admin-llm-audit__table">
            <thead>
                <tr>
                    <th scope="col" class="admin-llm-audit__th admin-llm-audit__th--kind">
                        "Action"
                    </th>
                    <th scope="col" class="admin-llm-audit__th admin-llm-audit__th--subject">
                        "Subject"
                    </th>
                    <th scope="col" class="admin-llm-audit__th admin-llm-audit__th--confidence">
                        "Confidence"
                    </th>
                    <th scope="col" class="admin-llm-audit__th admin-llm-audit__th--model">
                        "Model"
                    </th>
                    <th scope="col" class="admin-llm-audit__th admin-llm-audit__th--policies">
                        "Policies"
                    </th>
                    <th scope="col" class="admin-llm-audit__th admin-llm-audit__th--reversal">
                        "Reversal"
                    </th>
                    <th scope="col" class="admin-llm-audit__th admin-llm-audit__th--created">
                        "Created"
                    </th>
                </tr>
            </thead>
            <tbody>
                {move || rows.get().into_iter().map(|row| view! {
                    <AuditRow row=row/>
                }).collect::<Vec<_>>()}
            </tbody>
        </table>
        {move || rows.get().is_empty().then(|| view! {
            <p class="admin-llm-audit__empty" role="status">
                "No autonomous actions match these filters yet."
            </p>
        })}
        {move || next_cursor.get().map(|_| view! {
            <button
                type="button"
                class="admin-llm-audit__load-more"
                disabled=move || loading.get()
                on:click=on_load_more
            >
                {move || if loading.get() { "Loading…" } else { "Load more" }}
            </button>
        })}
    }
}

/// Render one audit table row. Click expands to reveal the full
/// reasoning + input hash + LLM observation pointer.
#[component]
fn AuditRow(row: LlmAuditEntryDto) -> impl IntoView {
    let expanded = RwSignal::new(false);
    let confidence_pct = (row.recommendation_confidence.clamp(0.0, 1.0) * 100.0).round() as u32;
    let confidence_label = format!("{confidence_pct}%");
    let action_chip = format!(
        "admin-llm-audit__action-chip admin-llm-audit__action-chip--{}",
        sanitize_modifier(&row.action_kind),
    );
    let reversal_chip_class = if row.reversal.is_some() {
        "admin-llm-audit__reversal-chip admin-llm-audit__reversal-chip--reversed"
    } else {
        "admin-llm-audit__reversal-chip admin-llm-audit__reversal-chip--standing"
    };
    let reversal_label = if row.reversal.is_some() {
        "Reversed"
    } else {
        "Standing"
    };

    let subject_label = row
        .subject_did
        .clone()
        .or_else(|| row.subject_uri.clone())
        .unwrap_or_else(|| "—".to_owned());
    let subject_kind_label = row.subject_kind.clone();
    let policies_label = if row.cited_policies.is_empty() {
        "—".to_owned()
    } else {
        row.cited_policies
            .iter()
            .map(|p| format!("{}@{}", p.identifier, p.version))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let created_label = row.created_at.to_rfc3339();
    let action_kind_label = row.action_kind.clone();
    let label_value_suffix = row
        .label_value
        .as_deref()
        .map(|v| format!(": {v}"))
        .unwrap_or_default();
    let action_text = format!("{action_kind_label}{label_value_suffix}");
    let model_label = row.model.clone();
    let model_version_label = row.model_version.clone();

    let reasoning = row.reasoning.clone();
    let input_hash = row.input_hash.clone();
    let prompt_template_id = row.prompt_template_id.clone();
    let llm_observation_id = row.llm_observation_id.to_string();
    let action_id_label = row.action_id.to_string();
    let reversible_until = row.reversible_until.to_rfc3339();

    let on_toggle = move |_ev: ev::MouseEvent| {
        expanded.update(|v| *v = !*v);
    };

    view! {
        <tr class="admin-llm-audit__row" data-action-id=action_id_label.clone()>
            <td class="admin-llm-audit__cell admin-llm-audit__cell--kind">
                <button
                    type="button"
                    class="admin-llm-audit__row-expander"
                    on:click=on_toggle
                    aria-expanded=move || expanded.get().to_string()
                >
                    <span class=action_chip>{action_text}</span>
                </button>
            </td>
            <td class="admin-llm-audit__cell admin-llm-audit__cell--subject">
                <span class="admin-llm-audit__subject-kind">{subject_kind_label}</span>
                <code class="admin-llm-audit__subject-id">{subject_label}</code>
            </td>
            <td class="admin-llm-audit__cell admin-llm-audit__cell--confidence">
                <span class="admin-llm-audit__confidence-bar"
                      role="meter"
                      aria-valuenow=confidence_pct.to_string()
                      aria-valuemin="0"
                      aria-valuemax="100">
                    <span class="admin-llm-audit__confidence-fill"
                          style=format!("width: {confidence_pct}%;")>
                    </span>
                </span>
                <span class="admin-llm-audit__confidence-label">{confidence_label}</span>
            </td>
            <td class="admin-llm-audit__cell admin-llm-audit__cell--model">
                <code class="admin-llm-audit__model">{model_label}</code>
                <span class="admin-llm-audit__model-version">{model_version_label}</span>
            </td>
            <td class="admin-llm-audit__cell admin-llm-audit__cell--policies">
                {policies_label}
            </td>
            <td class="admin-llm-audit__cell admin-llm-audit__cell--reversal">
                <span class=reversal_chip_class>{reversal_label}</span>
            </td>
            <td class="admin-llm-audit__cell admin-llm-audit__cell--created">
                <time class="admin-llm-audit__created">{created_label}</time>
            </td>
        </tr>
        {move || expanded.get().then(|| view! {
            <tr class="admin-llm-audit__expand-row">
                <td colspan="7" class="admin-llm-audit__expand-cell">
                    <dl class="admin-llm-audit__expand">
                        <dt class="admin-llm-audit__expand-label">"Action id"</dt>
                        <dd class="admin-llm-audit__expand-value">
                            <code>{action_id_label.clone()}</code>
                        </dd>
                        <dt class="admin-llm-audit__expand-label">"LLM observation"</dt>
                        <dd class="admin-llm-audit__expand-value">
                            <code>{llm_observation_id.clone()}</code>
                        </dd>
                        <dt class="admin-llm-audit__expand-label">"Prompt template"</dt>
                        <dd class="admin-llm-audit__expand-value">
                            <code>{prompt_template_id.clone()}</code>
                        </dd>
                        <dt class="admin-llm-audit__expand-label">"Input hash"</dt>
                        <dd class="admin-llm-audit__expand-value">
                            <code>{input_hash.clone()}</code>
                        </dd>
                        <dt class="admin-llm-audit__expand-label">"Reversible until"</dt>
                        <dd class="admin-llm-audit__expand-value">
                            <time>{reversible_until.clone()}</time>
                        </dd>
                        <dt class="admin-llm-audit__expand-label">"Reasoning"</dt>
                        <dd class="admin-llm-audit__expand-value admin-llm-audit__reasoning">
                            {reasoning.clone()}
                        </dd>
                    </dl>
                </td>
            </tr>
        })}
    }
}

/// Sanitise an action-kind string into a BEM-modifier-safe token.
///
/// The backend's `actions.kind` enum is already lower-snake_case
/// (`label`, `warn`, `takedown`, …) but we strip anything non-`[a-z0-9-]`
/// defensively so a hypothetical future kind with weirder characters
/// cannot leak into the class string.
fn sanitize_modifier(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            out.push(ch.to_ascii_lowercase());
        } else if ch == '_' {
            out.push('-');
        }
    }
    if out.is_empty() {
        "unknown".to_owned()
    } else {
        out
    }
}

/// Map a mutation error onto the inline-error band. Mirrors the
/// admin-moderators page's handler so a 401 / 403 mid-flow forces a
/// re-auth round-trip.
fn handle_mutation_error(err: &ApiError, last_error: RwSignal<Option<String>>) {
    match FetchOutcome::from_error(err) {
        FetchOutcome::Unauthorized | FetchOutcome::Forbidden => {
            redirect_to_login();
        }
        FetchOutcome::Other(message) => {
            last_error.set(Some(message));
        }
    }
}

/// Wasm event-target value extractor (matches the helper in
/// `admin_moderators`).
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
        .unwrap_or_default()
}

/// Native stub — the form is exercised through unit tests against the
/// pure helpers, not the DOM.
#[cfg(not(target_arch = "wasm32"))]
const fn event_target_value(_ev: &ev::Event) -> String {
    String::new()
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
    fn admin_llm_audit_path_is_stable() {
        assert_eq!(ADMIN_LLM_AUDIT_PATH, "/admin/llm/audit");
    }

    #[test]
    fn sanitize_modifier_passes_snake_case_kinds() {
        assert_eq!(sanitize_modifier("label"), "label");
        assert_eq!(sanitize_modifier("warn"), "warn");
        assert_eq!(sanitize_modifier("takedown"), "takedown");
    }

    #[test]
    fn sanitize_modifier_replaces_underscore_with_dash() {
        // `actions.kind` includes `no_action` — the BEM modifier must
        // not contain an underscore (the class-tokenising styles_*
        // tests reject anything outside `[a-z0-9-]`).
        assert_eq!(sanitize_modifier("no_action"), "no-action");
    }

    #[test]
    fn sanitize_modifier_falls_back_to_unknown_on_empty() {
        assert_eq!(sanitize_modifier(""), "unknown");
        assert_eq!(sanitize_modifier("!!!"), "unknown");
    }

    #[test]
    fn sanitize_modifier_lowercases_input() {
        assert_eq!(sanitize_modifier("LABEL"), "label");
    }

    #[test]
    fn admin_llm_audit_page_builds() {
        // Smoke test: the #[component] constructor type-checks.
        let _ = AdminLlmAuditPage;
    }
}
