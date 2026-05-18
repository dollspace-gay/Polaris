//! `/admin/moderators` — admin-only moderator-management page
//! (issue #214 / #217).
//!
//! Operators manage the Polaris login allow-list here: who may complete
//! the OAuth dance, and with what role. The page is gated by the
//! backend's `Role::Admin` check on every API call — a non-admin who
//! navigates directly to this URL sees a Forbidden banner instead of
//! the table, and the dashboard navigation hides the entry point
//! entirely for non-admins. The hide is decoration; the backend gate
//! is the source of truth.
//!
//! # Surface
//!
//! - `GET /api/admin/moderators` — initial table render. 403 → Forbidden banner.
//! - `POST /api/admin/moderators` — add a new (handle | DID, role) pair.
//! - `PATCH /api/admin/moderators/{did}/roles` — toggle one of the four
//!   admin-facing roles on a row.
//! - `DELETE /api/admin/moderators/{did}` — remove a moderator (unless pinned).
//!
//! # Roles
//!
//! The wire vocabulary is the four operator-relevant tiers the backend
//! [`parse_role`](polaris_backend::api::admin_moderators) function
//! accepts: `admin`, `senior_moderator`, `moderator`, `triage`. The
//! `read_only` role still exists in the DB but is intentionally NOT
//! selectable from the wire surface, so the frontend mirrors that
//! omission.
//!
//! # Pinned-admin guard
//!
//! The bootstrap admin row (`pinned_admin = true`) is hard-protected
//! by the backend: any attempt to revoke its `admin` role returns
//! `409 Conflict`, and `DELETE` against a pinned row returns the same.
//! The frontend mirrors the rule in two places:
//!
//! 1. The pinned admin's `admin` role checkbox is `disabled` (the
//!    grant is locked in).
//! 2. The pinned admin's "Remove" button is `disabled` with a
//!    `title=` tooltip explaining the SQL-only escape hatch.
//!
//! Both safeguards are pure UX — the backend gate is the source of
//! truth — but they save the operator a confused round-trip.

use leptos::ev;
use leptos::prelude::*;

use crate::api_client::dto::{AddModeratorRequest, AdminModerator, PatchModeratorRoleRequest};
use crate::api_client::{ApiError, PolarisApiClient, default_client};
use crate::pages::login::{is_unauthorized, redirect_to_login};

/// Path the admin moderators page is mounted at.
///
/// Centralising the constant keeps the route declaration in
/// [`crate::app`] and the dashboard's admin-link href in sync.
pub const ADMIN_MODERATORS_PATH: &str = "/admin/moderators";

/// HTTP status code that triggers the inline Forbidden banner.
///
/// The backend returns `403 Forbidden` for any moderator-management
/// request that arrives without `Role::Admin`; the frontend renders
/// the `Forbidden` sub-component when it sees this status on the
/// initial list fetch.
pub const FORBIDDEN_STATUS: u16 = 403;

/// The four admin-facing role tiers in display order.
///
/// Matches the backend's
/// [`parse_role`](polaris_backend::api::admin_moderators) vocabulary
/// — `read_only` is intentionally omitted.
pub const ROLE_TIERS: &[(&str, &str)] = &[
    ("admin", "Admin"),
    ("senior_moderator", "Senior moderator"),
    ("moderator", "Moderator"),
    ("triage", "Triage"),
];

/// Pure helper: does the supplied [`ApiError`] represent a 403
/// Forbidden response from the Polaris backend?
///
/// Mirrors the shape of
/// [`crate::pages::login::is_unauthorized`] for the moderator-
/// management surface: a Forbidden hit on the initial list fetch
/// triggers the inline banner; a Forbidden hit on a mutation
/// triggers an inline error band on the row.
#[must_use]
pub fn is_forbidden(err: &ApiError) -> bool {
    matches!(
        err,
        ApiError::Http {
            status: FORBIDDEN_STATUS,
            ..
        }
    )
}

/// Categorise a [`PolarisApiClient`] error so the page can decide
/// between "bounce to /login" (401), "render the Forbidden banner"
/// (403), and "surface inline" (every other failure).
///
/// Returning a tri-state (rather than a `Result<bool, String>`) lets
/// the caller distinguish the redirect path from the inline-banner
/// path without overloading the `String` semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// `401 Unauthorized` — caller should redirect to `/login`.
    Unauthorized,
    /// `403 Forbidden` — caller should render the Forbidden banner.
    Forbidden,
    /// Any other failure; carries the `Display` text for inline
    /// rendering.
    Other(String),
}

impl FetchOutcome {
    /// Build a [`FetchOutcome`] from an [`ApiError`].
    ///
    /// Pure function so the categorisation is unit-testable without
    /// a browser runtime.
    #[must_use]
    pub fn from_error(err: &ApiError) -> Self {
        if is_unauthorized(err) {
            Self::Unauthorized
        } else if is_forbidden(err) {
            Self::Forbidden
        } else {
            Self::Other(err.to_string())
        }
    }
}

/// Render the admin-moderators page.
///
/// On mount: fire `GET /api/admin/moderators`. The outcome routes
/// the render between three branches:
///
/// - `Ok(rows)` → render the add form + the moderator table.
/// - `Err(Unauthorized)` → hard-navigate to `/login` (no-op on native).
/// - `Err(Forbidden)` → render the [`Forbidden`] sub-component.
/// - `Err(Other(msg))` → render an inline error band.
// `clippy::must_use_candidate` cannot be honored at a `#[component]`
// site — the proc macro discards outer attributes and the return
// value is always consumed by `view!`. Mirror the narrow allow used
// at every other `#[component]` site in this crate.
#[allow(clippy::must_use_candidate)]
#[component]
pub fn AdminModeratorsPage() -> impl IntoView {
    // Refetch token: bump after every successful add / patch /
    // delete to re-fire the `LocalResource` and pick up the
    // server-side state. The table reads strictly from the resource
    // — there is no client-side patch-in-place — so the source of
    // truth stays on the server.
    let refresh_tick = RwSignal::new(0_u64);
    // Last-mutation error band: surfaced beneath the form when a
    // POST / PATCH / DELETE fails (handle didn't resolve, 409
    // conflict from the last-admin guard, etc.).
    let last_error: RwSignal<Option<String>> = RwSignal::new(None);

    let moderators = LocalResource::new(move || {
        let _token = refresh_tick.get();
        async move {
            let client = default_client("").map_err(|e| FetchOutcome::from_error(&e))?;
            client
                .list_admin_moderators()
                .await
                .map_err(|e| FetchOutcome::from_error(&e))
        }
    });

    view! {
        <main class="admin-moderators" id="admin-moderators-root">
            <header class="admin-moderators__header">
                <h1>"Moderator allow-list"</h1>
                <p class="admin-moderators__tagline">
                    "Manage which Bluesky accounts may sign in to this Polaris install \
                    and what role they hold. Removing a moderator immediately revokes \
                    their session at the next request."
                </p>
                <a class="admin-moderators__back-link" href="/">
                    "← Back to dashboard"
                </a>
            </header>
            <Suspense fallback=move || view! {
                <p class="admin-moderators__loading" role="status">"Loading…"</p>
            }>
                {move || Suspend::new(async move {
                    match moderators.await {
                        Ok(rows) => view! {
                            <AdminModeratorsBody
                                rows=rows
                                refresh_tick=refresh_tick
                                last_error=last_error
                            />
                        }.into_any(),
                        Err(FetchOutcome::Unauthorized) => {
                            // Hard-navigate; render a status line while
                            // the navigation lands so the page is not
                            // blank during the redirect.
                            redirect_to_login();
                            view! {
                                <p class="admin-moderators__redirect" role="status">
                                    "Redirecting to login…"
                                </p>
                            }.into_any()
                        }
                        Err(FetchOutcome::Forbidden) => view! {
                            <Forbidden/>
                        }.into_any(),
                        Err(FetchOutcome::Other(message)) => view! {
                            <p class="admin-moderators__error" role="alert">
                                "Failed to load moderators: "{message}
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
///
/// Pulled into its own component so the audit story is clear: a
/// 403 from any admin endpoint flows through exactly one render
/// path. The copy explains the gate without leaking the role
/// vocabulary in user-facing text.
#[component]
fn Forbidden() -> impl IntoView {
    view! {
        <section class="admin-moderators__forbidden" role="alert">
            <h2>"Forbidden"</h2>
            <p>
                "This page is restricted to operators with the "
                <strong>"admin"</strong>" role. Ask the operator who "
                "set up this install to grant you the role, or open "
                "the dashboard for the surfaces you already have access to."
            </p>
            <a class="admin-moderators__back-link" href="/">
                "← Back to dashboard"
            </a>
        </section>
    }
}

/// Render the form + table once the initial fetch has resolved
/// successfully.
///
/// Splitting the success path into its own component keeps the
/// resource lifecycle scoped to a successful fetch — a transient
/// 5xx renders the inline error path without paying for the
/// form-state signals.
#[component]
fn AdminModeratorsBody(
    /// Hydrated list of moderators returned by the backend.
    rows: Vec<AdminModerator>,
    /// Bumped after every successful mutation to re-fire the list
    /// fetch.
    refresh_tick: RwSignal<u64>,
    /// Inline-error band for the last failed mutation.
    last_error: RwSignal<Option<String>>,
) -> impl IntoView {
    let add_handle = RwSignal::new(String::new());
    let add_role = RwSignal::new("moderator".to_owned());
    let add_busy = RwSignal::new(false);

    let on_add_submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        if add_busy.get_untracked() {
            return;
        }
        let handle = add_handle.get_untracked().trim().to_owned();
        if handle.is_empty() {
            last_error.set(Some("Enter a handle or DID before submitting.".to_owned()));
            return;
        }
        add_busy.set(true);
        last_error.set(None);
        let role = add_role.get_untracked();
        let body = AddModeratorRequest { handle, role };
        leptos::task::spawn_local(async move {
            let outcome = async move {
                let client = default_client("")?;
                client.add_admin_moderator(body).await
            }
            .await;
            add_busy.set(false);
            match outcome {
                Ok(_row) => {
                    add_handle.set(String::new());
                    refresh_tick.update(|t| *t = t.wrapping_add(1));
                }
                Err(err) => {
                    handle_mutation_error(&err, last_error);
                }
            }
        });
    };

    let table_rows: Vec<_> = rows
        .into_iter()
        .map(|row| {
            view! {
                <ModeratorRow
                    row=row
                    refresh_tick=refresh_tick
                    last_error=last_error
                />
            }
        })
        .collect();

    view! {
        <form class="admin-moderators__add-form" on:submit=on_add_submit>
            <label for="admin-moderators-handle">"Handle or DID"</label>
            <input
                id="admin-moderators-handle"
                class="admin-moderators__add-handle"
                type="text"
                placeholder="alice.bsky.social or did:plc:…"
                required
                autocomplete="off"
                prop:value=move || add_handle.get()
                on:input=move |ev| add_handle.set(event_target_value(&ev))
            />
            <label for="admin-moderators-role">"Role"</label>
            <select
                id="admin-moderators-role"
                class="admin-moderators__add-role"
                on:change=move |ev| add_role.set(event_target_value(&ev))
            >
                {ROLE_TIERS.iter().map(|(value, label)| {
                    let selected = *value == "moderator";
                    view! {
                        <option value=*value selected=selected>{*label}</option>
                    }
                }).collect::<Vec<_>>()}
            </select>
            <button
                type="submit"
                class="admin-moderators__add-submit"
                disabled=move || add_busy.get()
            >
                {move || if add_busy.get() { "Adding…" } else { "Add moderator" }}
            </button>
        </form>
        {move || last_error.get().map(|msg| view! {
            <p class="admin-moderators__error" role="alert">
                {msg}
            </p>
        })}
        <table class="admin-moderators__table">
            <thead>
                <tr>
                    <th scope="col" class="admin-moderators__th admin-moderators__th--handle">
                        "Handle / display"
                    </th>
                    <th scope="col" class="admin-moderators__th admin-moderators__th--did">"DID"</th>
                    <th scope="col" class="admin-moderators__th admin-moderators__th--roles">
                        "Roles"
                    </th>
                    <th scope="col" class="admin-moderators__th admin-moderators__th--pinned">
                        "Pinned"
                    </th>
                    <th scope="col" class="admin-moderators__th admin-moderators__th--last-login">
                        "Last login"
                    </th>
                    <th scope="col" class="admin-moderators__th admin-moderators__th--actions">
                        "Actions"
                    </th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    }
}

/// Render one moderator row.
///
/// Lifted into its own component so the per-row signals
/// (`busy`, `confirm_delete`) live on the row, not the page, and
/// a click on row N never blocks row M.
#[component]
fn ModeratorRow(
    /// The moderator row to render.
    row: AdminModerator,
    /// Page-level refetch token — bumped after every successful
    /// mutation so the table re-reads from the server.
    refresh_tick: RwSignal<u64>,
    /// Page-level last-error signal — surfaced above the table
    /// when a mutation fails.
    last_error: RwSignal<Option<String>>,
) -> impl IntoView {
    let row_busy = RwSignal::new(false);
    let confirm_delete = RwSignal::new(false);
    let pinned = row.pinned_admin;
    let did_for_actions = row.did.clone();

    // Pre-compute the row class so a pinned row picks up the
    // `--pinned` modifier without recomputing on every render.
    let row_class = if pinned {
        "admin-moderators__row admin-moderators__row--pinned"
    } else {
        "admin-moderators__row"
    };

    let pinned_badge = pinned.then(|| {
        view! {
            <span class="admin-moderators__pinned-badge"
                  title="Hard-pinned bootstrap admin — cannot be removed via this page">
                "Pinned"
            </span>
        }
    });

    let role_chips = ROLE_TIERS
        .iter()
        .map(|(role_id, role_label)| {
            let role_id = *role_id;
            let role_label = *role_label;
            let granted = row.roles.iter().any(|r| r == role_id);
            // Disable the pinned admin's `admin` checkbox so the
            // operator cannot stage a click that the backend would
            // reject — the row is the single bootstrap admin.
            let disabled = row_busy.get_untracked() || (pinned && role_id == "admin" && granted);
            let did_for_toggle = did_for_actions.clone();
            let on_change = move |_ev: ev::Event| {
                if row_busy.get_untracked() {
                    return;
                }
                row_busy.set(true);
                last_error.set(None);
                let did = did_for_toggle.clone();
                let role = role_id.to_owned();
                let grant = !granted;
                leptos::task::spawn_local(async move {
                    let outcome = async move {
                        let client = default_client("")?;
                        client
                            .patch_admin_moderator_role(
                                &did,
                                PatchModeratorRoleRequest { role, grant },
                            )
                            .await
                    }
                    .await;
                    row_busy.set(false);
                    match outcome {
                        Ok(_row) => {
                            refresh_tick.update(|t| *t = t.wrapping_add(1));
                        }
                        Err(err) => {
                            handle_mutation_error(&err, last_error);
                        }
                    }
                });
            };
            view! {
                <label class="admin-moderators__role-chip">
                    <input
                        type="checkbox"
                        class="admin-moderators__role-checkbox"
                        prop:checked=granted
                        disabled=disabled
                        on:change=on_change
                    />
                    <span class="admin-moderators__role-label">{role_label}</span>
                </label>
            }
        })
        .collect::<Vec<_>>();

    let did_attr = did_for_actions.clone();
    let did_title = did_for_actions.clone();
    let did_display = did_for_actions.clone();
    let display_name = row.display_name.clone().unwrap_or_else(|| "—".to_owned());
    let last_login = row
        .last_login_at
        .map_or_else(|| "—".to_owned(), |t| t.to_rfc3339());

    // ── Delete button ────────────────────────────────────────────
    let did_for_delete = did_for_actions.clone();
    let on_remove_click = move |_ev: ev::MouseEvent| {
        if row_busy.get_untracked() || pinned {
            return;
        }
        if !confirm_delete.get_untracked() {
            // First click arms; second click commits. Avoids the
            // browser `confirm()` modal so the page stays in a
            // single keyboard focus context.
            confirm_delete.set(true);
            return;
        }
        row_busy.set(true);
        last_error.set(None);
        let did = did_for_delete.clone();
        leptos::task::spawn_local(async move {
            let outcome = async move {
                let client = default_client("")?;
                client.delete_admin_moderator(&did).await
            }
            .await;
            row_busy.set(false);
            confirm_delete.set(false);
            match outcome {
                Ok(()) => {
                    refresh_tick.update(|t| *t = t.wrapping_add(1));
                }
                Err(err) => {
                    handle_mutation_error(&err, last_error);
                }
            }
        });
    };

    let remove_label = move || {
        if pinned {
            "Remove".to_owned()
        } else if confirm_delete.get() {
            "Click again to confirm".to_owned()
        } else {
            "Remove".to_owned()
        }
    };
    let remove_title = if pinned {
        "Pinned bootstrap admin — removable only via direct SQL"
    } else {
        "Remove this moderator. Click again to confirm."
    };

    view! {
        <tr class=row_class data-did=did_attr>
            <td class="admin-moderators__cell admin-moderators__cell--handle">
                {display_name}
            </td>
            <td class="admin-moderators__cell admin-moderators__cell--did">
                <code class="admin-moderators__did" title=did_title>
                    {did_display}
                </code>
            </td>
            <td class="admin-moderators__cell admin-moderators__cell--roles">
                <div class="admin-moderators__role-chips">
                    {role_chips}
                </div>
            </td>
            <td class="admin-moderators__cell admin-moderators__cell--pinned">
                {pinned_badge}
            </td>
            <td class="admin-moderators__cell admin-moderators__cell--last-login">
                <time class="admin-moderators__last-login">{last_login}</time>
            </td>
            <td class="admin-moderators__cell admin-moderators__cell--actions">
                <button
                    type="button"
                    class="admin-moderators__remove-btn"
                    disabled=move || pinned || row_busy.get()
                    title=remove_title
                    on:click=on_remove_click
                >
                    {remove_label}
                </button>
            </td>
        </tr>
    }
}

/// Map a mutation error onto the inline-error band.
///
/// Mirrors the dashboard's per-fetch handler: a 401 triggers the
/// hard redirect, every other error surfaces inline. Distinct from
/// the initial-list path (which has the Forbidden banner) because
/// a mid-flow 403 means the operator's role changed under them —
/// that's a redirect-worthy event, NOT an inline banner. We treat
/// it the same as 401 so the operator re-authenticates and the
/// page re-evaluates on the next paint.
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

/// Pure helper: read the current value out of an event target.
///
/// Mirrors the `event_target_value` helper used by the setup
/// wizard / login page; pulled local to the admin-moderators
/// module so the page does not reach across a sibling module for
/// a one-line utility.
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

/// Native stub — the form is exercised through unit tests against
/// the pure helpers, not the DOM.
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
    fn admin_moderators_path_is_stable() {
        // Regression: the route declaration in `crate::app` and the
        // dashboard's admin-link href both key off this constant.
        assert_eq!(ADMIN_MODERATORS_PATH, "/admin/moderators");
    }

    #[test]
    fn role_tiers_match_backend_vocabulary() {
        // The backend's `parse_role` accepts exactly these four
        // tiers; the wire surface intentionally omits `read_only`.
        // A future expansion lands here AND on the backend
        // simultaneously.
        let ids: Vec<&str> = ROLE_TIERS.iter().map(|(id, _)| *id).collect();
        assert_eq!(
            ids,
            vec!["admin", "senior_moderator", "moderator", "triage"],
        );
    }

    #[test]
    fn is_forbidden_matches_403() {
        let err = ApiError::Http {
            status: 403,
            message: "forbidden".to_owned(),
        };
        assert!(is_forbidden(&err));
    }

    #[test]
    fn is_forbidden_rejects_other_statuses() {
        for status in [200_u16, 400, 401, 404, 409, 500] {
            let err = ApiError::Http {
                status,
                message: String::new(),
            };
            assert!(
                !is_forbidden(&err),
                "is_forbidden must reject status {status}",
            );
        }
    }

    #[test]
    fn is_forbidden_rejects_transport_errors() {
        let err = ApiError::Transport("net down".to_owned());
        assert!(!is_forbidden(&err));
    }

    #[test]
    fn fetch_outcome_routes_401_to_unauthorized() {
        let err = ApiError::Http {
            status: 401,
            message: "auth required".to_owned(),
        };
        assert_eq!(FetchOutcome::from_error(&err), FetchOutcome::Unauthorized);
    }

    #[test]
    fn fetch_outcome_routes_403_to_forbidden() {
        let err = ApiError::Http {
            status: 403,
            message: "admin only".to_owned(),
        };
        assert_eq!(FetchOutcome::from_error(&err), FetchOutcome::Forbidden);
    }

    #[test]
    fn fetch_outcome_carries_message_for_other_failures() {
        let err = ApiError::Http {
            status: 409,
            message: "cannot remove the last admin".to_owned(),
        };
        match FetchOutcome::from_error(&err) {
            FetchOutcome::Other(msg) => {
                assert!(
                    msg.contains("cannot remove the last admin"),
                    "expected 409 body in `Other` payload, got: {msg}",
                );
                assert!(
                    msg.contains("409"),
                    "expected status code in `Other` payload, got: {msg}",
                );
            }
            other => panic!("expected FetchOutcome::Other, got {other:?}"),
        }
    }

    #[test]
    fn fetch_outcome_carries_transport_message() {
        let err = ApiError::Transport("dns failed".to_owned());
        match FetchOutcome::from_error(&err) {
            FetchOutcome::Other(msg) => assert!(msg.contains("dns failed")),
            other => panic!("expected FetchOutcome::Other, got {other:?}"),
        }
    }

    /// Smoke test: the `#[component]` constructor type-checks.
    #[test]
    fn admin_moderators_page_builds() {
        let _ = AdminModeratorsPage;
    }
}
