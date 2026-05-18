//! `/policies` — read-only policy browse view (REQ-D4, issue #226).
//!
//! Moderators look policies up here while triaging a case. Same two-pane
//! layout as the admin page but the right pane shows only the current
//! version, no edit affordances, no autonomy tab, no version history.
//!
//! # Surface
//!
//! - `GET /api/policies` — initial list render. 401 → `/login` redirect,
//!   any other failure → inline error band.
//! - `GET /api/policies/:identifier` — full detail when the moderator
//!   selects a row from the left pane.
//!
//! # RBAC
//!
//! Backend gates these endpoints on `Role::Moderator` or higher. A
//! non-authenticated browser sees `401` → redirect-to-login; an
//! authenticated user without moderator role sees `403` → inline error.
//! The frontend does not pre-check; the backend is the source of truth.

use leptos::prelude::*;

use crate::api_client::dto::{ModPolicyDto, ModPolicySummaryDto, PolicyListFilters};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::pages::login::{is_unauthorized, redirect_to_login};

/// Path the read-only browse page is mounted at.
pub const POLICIES_PATH: &str = "/policies";

/// Render the read-only browse page.
///
/// Mounts the two-pane scaffold and lets [`PoliciesBody`] own the
/// per-row selection state once the initial list has resolved.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn PoliciesPage() -> impl IntoView {
    let policies = LocalResource::new(|| async {
        let client = default_client("").map_err(|e: ApiError| {
            if is_unauthorized(&e) {
                redirect_to_login();
            }
            e.to_string()
        })?;
        client
            .list_policies(&PolicyListFilters::default())
            .await
            .map_err(|e: ApiError| {
                if is_unauthorized(&e) {
                    redirect_to_login();
                }
                e.to_string()
            })
    });

    view! {
        <main class="admin-policies admin-policies--readonly" id="policies-root">
            <header class="admin-policies__header">
                <h1>"Moderation policies"</h1>
                <p class="admin-policies__tagline">
                    "Reference for the structured policies a moderator may cite \
                    on an action. Read-only — only operators with the admin role \
                    can amend or retire a policy."
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
                            <PoliciesBody rows=rows readonly=true/>
                        }.into_any(),
                        Err(message) => view! {
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

/// Render the two-pane body once the index list has resolved.
///
/// `readonly` is `true` for `/policies` and `false` for the admin page
/// when it shares this scaffold. The component is structured so a future
/// edit-affordance addition can live in the admin page's own body
/// component without rebuilding the list rendering twice.
// Narrow allow: `#[component]` discards outer attributes — the lint
// cannot be satisfied at this site. Same rationale as every other
// `#[component]` in this crate.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn PoliciesBody(
    /// Initial list of policy summaries.
    rows: Vec<ModPolicySummaryDto>,
    /// `true` to suppress every edit affordance.
    readonly: bool,
) -> impl IntoView {
    // Selected identifier — drives the right-pane resource. `None` means
    // no row selected yet; on first load we auto-select the first row
    // (most-common moderator gesture is "show me the first one").
    let initial = rows.first().map(|r| r.identifier.clone());
    let selected: RwSignal<Option<String>> = RwSignal::new(initial);

    let row_views = rows
        .into_iter()
        .map(|row| {
            let identifier = row.identifier;
            let identifier_for_click = identifier.clone();
            let identifier_for_class = identifier.clone();
            let name = row.name;
            let scope = row.scope;
            let severity = row.severity;
            let autonomy_mode = row.autonomy_mode;
            let is_retired = row.is_retired;
            let chip_class = autonomy_chip_class(&autonomy_mode);
            view! {
                <li>
                    <button
                        type="button"
                        class=move || {
                            let active = selected.get()
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
                <PolicyDetail selected=selected readonly=readonly/>
            </article>
        </section>
    }
}

/// Compute the BEM class for an autonomy-mode chip.
///
/// Pure helper so the cell class string lives outside the view closure;
/// the `styles_coverage` test extracts BEM literals from anywhere the
/// regex finds them.
#[must_use]
pub fn autonomy_chip_class(mode: &str) -> &'static str {
    match mode {
        "autonomous" => "admin-policies__chip--autonomy-autonomous",
        "assisted" => "admin-policies__chip--autonomy-assisted",
        _ => "admin-policies__chip--autonomy-manual",
    }
}

/// Render the right pane: full policy detail for the selected
/// identifier.
///
/// Fires `GET /api/policies/:identifier` whenever `selected` changes.
/// The form fields are read-only when `readonly = true`.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn PolicyDetail(
    /// Currently-selected policy identifier (drives the fetch).
    selected: RwSignal<Option<String>>,
    /// Suppress edit affordances.
    readonly: bool,
) -> impl IntoView {
    let resource = LocalResource::new(move || {
        let id = selected.get();
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
                match resource.await {
                    Ok(None) => view! {
                        <p class="admin-policies__hint" role="status">
                            "Select a policy from the list to view its details."
                        </p>
                    }.into_any(),
                    Ok(Some(policy)) => view! {
                        <PolicyDetailFields policy=policy readonly=readonly/>
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

/// Render the read-only field block. Shared between the admin and the
/// browse views — the admin page wraps this in an edit form, the
/// browse view shows it as plain text.
#[component]
fn PolicyDetailFields(
    /// The policy to render.
    policy: ModPolicyDto,
    /// Suppress edit affordances (no-op here — the read-only fields
    /// are the same in both views; the admin page renders its own
    /// editable form separately).
    #[allow(unused_variables)]
    readonly: bool,
) -> impl IntoView {
    let header_chip = autonomy_chip_class(&policy.autonomy_mode);
    let identifier_text = policy.identifier.clone();
    let version_text = policy.version;
    let name_text = policy.name.clone();
    let description_text = policy.description.clone();
    let scope_text = policy.scope.clone();
    let severity_text = policy.severity.clone();
    let decision_text = policy.decision_criteria.clone();
    let suggested = policy.suggested_action_kinds.join(", ");
    let exceptions = policy.exceptions.clone().unwrap_or_default();
    let linked_label = policy.linked_label_value.clone().unwrap_or_default();
    let autonomy_mode = policy.autonomy_mode.clone();
    let human_required = policy.human_required_always;
    let is_retired = policy.is_retired;

    view! {
        <section class="admin-policies__fields">
            <header class="admin-policies__detail-header">
                <h2>
                    <code class="admin-policies__cell--identifier">{identifier_text}</code>
                    " v"{version_text}
                </h2>
                <div class="admin-policies__detail-chips">
                    <span class=header_chip>{autonomy_mode}</span>
                    {human_required.then(|| view! {
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
            <dl class="admin-policies__dl">
                <dt>"Name"</dt>
                <dd>{name_text}</dd>
                <dt>"Description"</dt>
                <dd>{description_text}</dd>
                <dt>"Scope"</dt>
                <dd>{scope_text}</dd>
                <dt>"Severity"</dt>
                <dd>{severity_text}</dd>
                <dt>"Suggested action kinds"</dt>
                <dd>{suggested}</dd>
                <dt>"Linked label value"</dt>
                <dd>{linked_label}</dd>
                <dt>"Exceptions"</dt>
                <dd>{exceptions}</dd>
                <dt>"Decision criteria"</dt>
                <dd>
                    <pre class="admin-policies__decision-pre">{decision_text}</pre>
                </dd>
            </dl>
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
    fn policies_path_is_stable() {
        assert_eq!(POLICIES_PATH, "/policies");
    }

    #[test]
    fn autonomy_chip_class_routes_known_modes() {
        assert_eq!(
            autonomy_chip_class("autonomous"),
            "admin-policies__chip--autonomy-autonomous",
        );
        assert_eq!(
            autonomy_chip_class("assisted"),
            "admin-policies__chip--autonomy-assisted",
        );
        assert_eq!(
            autonomy_chip_class("manual"),
            "admin-policies__chip--autonomy-manual",
        );
        // Unknown modes fall back to manual (grey) — never panics.
        assert_eq!(
            autonomy_chip_class(""),
            "admin-policies__chip--autonomy-manual",
        );
    }

    #[test]
    fn policies_page_builds() {
        let _ = PoliciesPage;
    }
}
