//! HTTP API surface.
//!
//! # Router shape
//!
//! [`router`] composes two subtrees:
//!
//! 1. **Public** — `/healthz`. No auth middleware. `polaris_backend::db::Db`
//!    is used as state because the handler only needs a DB ping.
//! 2. **Authed** — every other route under `/api/`. The auth middleware
//!    from issue #9 validates the Polaris session cookie and attaches an
//!    `Extension<ModeratorAuthCtx>` to the request; handlers extract it.
//!
//! [`router`] returns a `Router` with no remaining state — both subtrees
//! attach their state before merging so the caller does not need to know
//! how the substates compose.
//!
//! # AC-7 alignment
//!
//! AC-7 from `.design/polaris-proto-blue-integration.md` requires every
//! mutating endpoint under `/api/*` to reject requests without a valid
//! Polaris session cookie. The auth middleware short-circuits with `401
//! Unauthorized` on any failure (missing cookie, malformed cookie, expired
//! session, DB error). The middleware also exempts `/healthz` and the OIDC
//! routes — see [`crate::middleware::auth::auth_middleware`].

pub mod admin_moderators;
pub mod admin_policies;
pub mod appeals;
pub mod auth_atproto;
pub mod cases;
pub mod dashboard;
pub mod dashboard_ws;
pub mod dto;
pub mod error;
pub mod healthz;
pub mod labeler_policies;
pub mod llm;
pub mod media;
pub mod metrics;
pub mod moderation;
pub mod moderator_controls;
pub mod moderator_email;
pub mod network_context;
pub mod oauth_metadata;
pub mod pattern_actions;
pub mod policies;
pub mod policy;
pub mod policy_cache;
pub mod readyz;
pub mod reversal;
pub mod scheduled_takedowns;
pub mod second_opinion;
pub mod setup;
pub mod state;
pub mod subjects;
pub mod webauthn;
pub mod wellness;
pub mod whoami;

use axum::Router;
use axum::middleware;
use axum::routing::{get, post};

pub use crate::api::state::ApiState;
use crate::auth::session::SessionStore;
use crate::config::PatternActionsConfig;
use crate::db::Db;
use crate::labeler;
use crate::middleware::auth::auth_middleware;

/// Build the top-level Axum router.
///
/// Returns a state-erased `Router` (i.e. `Router<()>`) ready to be passed
/// to `axum::serve`. The healthz subtree carries `Db` as its state; the
/// `/api/*` subtree carries [`ApiState`] (which includes the
/// [`SessionStore`] the auth middleware needs).
///
/// The pattern-action senior-cosign threshold is read from
/// [`PatternActionsConfig`] and threaded onto the [`ApiState`] so the
/// propose handler can consult it without re-parsing env at every call.
pub fn router(db: Db, sessions: SessionStore, pattern_actions: PatternActionsConfig) -> Router {
    let api_state = ApiState::with_config(db.pool().clone(), sessions, pattern_actions);
    router_with_state(db, api_state)
}

/// Assemble the top-level router around a pre-built [`ApiState`].
///
/// Used by the binary entrypoint (`main.rs`) to install the
/// startup-constructed [`crate::labeler::emitter::LabelEmitter`] onto the
/// state before the router takes ownership; tests reach the same shape
/// through [`router`] when emit isn't part of what's exercised.
pub fn router_with_state(db: Db, api_state: ApiState) -> Router {
    let healthz = healthz_router(db);
    // Issue #87: serve the operator-built polaris-frontend static
    // bundle. Production wiring picks the directory off
    // `POLARIS_FRONTEND_DIST`; tests install it directly on
    // `ApiState::frontend_dist` (the env-mutation route would require
    // an `unsafe { set_var }` block the workspace's `unsafe_code = "deny"`
    // lint refuses). REQ-A5's boot-from-zero test is the first user of
    // the state-borne path. SPA routing: `index.html` is served as the
    // fallback so deep links like `/login` and `/setup` load the
    // wasm runtime which then takes over routing client-side.
    //
    // Resolved before the router subtrees consume the state so the
    // single owned `ApiState` can move into the last subtree without
    // a final `.clone()` (clippy::needless_pass_by_value).
    let dist_from_state = api_state.frontend_dist.clone();
    let dist_from_env = std::env::var("POLARIS_FRONTEND_DIST")
        .ok()
        .filter(|d| !d.is_empty())
        .map(std::path::PathBuf::from);
    let dist_path = dist_from_state.or(dist_from_env);

    // `labeler_router` exposes the labeler XRPC endpoints on the PUBLIC
    // subtree — downstream AppViews subscribe without Polaris credentials
    // (REQ-1 / AC-1). It is therefore NOT layered with the auth middleware.
    let labeler = labeler::server::router(api_state.clone());
    // Workstream D / REQ-D1 + REQ-D2: `/readyz` + `/metrics` mount on
    // the public subtree (no auth) so Kubernetes readiness probes and
    // Prometheus scrape jobs work without a moderator session. Both
    // handlers take the full `ApiState` (readyz reads the signer and
    // DB; metrics reads the recorder handle off the state).
    let observability = observability_router(api_state.clone());
    let public_api = public_api_router(api_state.clone());
    let authed = authed_router(api_state);
    let merged = healthz
        .merge(labeler)
        .merge(observability)
        .merge(public_api)
        .merge(authed);

    if let Some(dist_path) = dist_path {
        use tower_http::services::{ServeDir, ServeFile};
        let index_html = dist_path.join("index.html");
        // `.fallback(...)` preserves the fallback's 200 status; the
        // `.not_found_service(...)` variant wraps in SetStatus(404)
        // which breaks SPA client routing.
        let serve_dir = ServeDir::new(dist_path).fallback(ServeFile::new(index_html));
        merged.fallback_service(serve_dir)
    } else {
        merged
    }
}

/// Build the public subtree (`/healthz` today; possibly `/readyz` later).
fn healthz_router(db: Db) -> Router {
    Router::new()
        .route("/healthz", get(healthz::handler))
        .with_state(db)
}

/// Build the observability subtree (`/readyz` + `/metrics`).
///
/// Both routes mount on the public subtree so Kubernetes readiness
/// probes and Prometheus scrape jobs work without a moderator session.
/// They share `ApiState` because:
///
/// - `/readyz` reads `active_signer` + `pool` + `polaris_setup_state`.
/// - `/metrics` reads `metrics_handle` (the Prometheus recorder
///   installed in `main.rs`).
fn observability_router(state: ApiState) -> Router {
    Router::new()
        .route("/readyz", get(readyz::handler))
        .route("/metrics", get(metrics::handler))
        .with_state(state)
}

/// Build the public-but-stateful `/api/*` subtree.
///
/// `POST /api/appeals` is the single un-authenticated `/api/*` endpoint:
/// appellants are not Polaris moderators and have no session cookie.
/// The auth middleware is therefore not applied here. IP rate-limiting
/// is the per-route mitigation, applied inside
/// [`appeals::submit_appeal`].
///
/// The two `/auth/atproto/{login,callback}` routes (issue #67) also live
/// here: they operate in the pre-session-cookie window and would
/// short-circuit on the missing cookie if they were mounted under the
/// authed subtree. They are also listed in
/// [`crate::middleware::auth::is_exempt`] so a future router
/// reorganisation that pulls them back under a uniform layer remains
/// safe.
fn public_api_router(state: ApiState) -> Router {
    // The four `/api/auth/webauthn/*` endpoints (#40) live on the public
    // subtree: they operate in the post-OIDC / post-ATProto, pre-session-
    // cookie window so the auth middleware cannot extract a `ModeratorAuthCtx`.
    // The moderator id arrives in the request body (echoed from the
    // hardware-key gate response); the verifier authenticates each ceremony
    // against the persisted `webauthn_register_states` / `webauthn_assert_states`
    // row.
    Router::new()
        .route("/api/appeals", post(appeals::submit_appeal))
        .route(
            "/api/auth/webauthn/register/start",
            post(webauthn::register_start),
        )
        .route(
            "/api/auth/webauthn/register/finish",
            post(webauthn::register_finish),
        )
        .route(
            "/api/auth/webauthn/assert/start",
            post(webauthn::assert_start),
        )
        .route(
            "/api/auth/webauthn/assert/finish",
            post(webauthn::assert_finish),
        )
        // Issue #67: ATProto OAuth login + callback. POST starts the
        // dance and returns a 303 to the AS; GET completes the
        // exchange, mints a Polaris session cookie, and 303s the
        // browser back to `/`.
        .route("/auth/atproto/login", post(auth_atproto::login))
        .route("/auth/atproto/callback", get(auth_atproto::callback))
        // Issue #81: serve the operator's OAuth client_metadata.json so
        // Polaris itself can be the URL declared as `client_id` in
        // atproto OAuth flows. Returns 404 when the operator did not
        // install a payload (e.g., labeler-profile builds with OIDC
        // auth that have no atproto client metadata).
        .route("/oauth/client-metadata.json", get(oauth_metadata::serve))
        .with_state(state)
}

/// Build the authed subtree — every `/api/*` route + the auth middleware
/// layer.
///
/// `route_layer` rather than `layer` so the middleware runs only for the
/// routes added to *this* router. The middleware is wired with
/// `from_fn_with_state` against the [`SessionStore`] that
/// `FromRef<ApiState>` extracts.
#[allow(
    clippy::too_many_lines,
    reason = "single-purpose router builder; the route declarations are linear and \
              read top-to-bottom. Splitting them across helpers would add indirection \
              without adding readability — the natural unit of comprehension here is \
              'the full /api surface', not arbitrary 100-line chunks."
)]
fn authed_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/cases", get(cases::list_cases))
        .route("/api/cases/{subject_id}", get(cases::get_case))
        // Issue #97 / M2 case-view network panel: profile signals,
        // follow graph, reply graph, cohort, shared-image clusters.
        // Routed under /api/cases/* so the moderator's role gate
        // (any authed moderator role) applies uniformly with the
        // rest of the case-view surface.
        .route(
            "/api/cases/{subject_id}/network-context",
            get(network_context::handler),
        )
        // Issue #95 / case-view media gallery: on-demand deep walk
        // of the subject's authored images. Mounted alongside the
        // network-context endpoint so the case-view's MediaGallery
        // component can refresh independently of the main DTO
        // (which only carries the synchronous cache snapshot).
        .route("/api/cases/{subject_id}/media", get(media::handler))
        .route(
            "/api/cases/{subject_id}/actions",
            post(cases::submit_action),
        )
        // Issue #193: multi-subject bulk apply. Same SubmitAction shape
        // as the single-subject endpoint, applied to each subject in the
        // request's subject_ids array.
        .route("/api/bulk-actions", post(cases::submit_bulk_action))
        // L1: Scheduled takedowns. Deferred-execution takedown intents
        // that fire when their `execute_at` deadline passes (worker
        // in `crate::workers::scheduled_takedown_worker`).
        .route(
            "/api/scheduled-takedowns",
            get(scheduled_takedowns::list_scheduled).post(scheduled_takedowns::schedule),
        )
        .route(
            "/api/scheduled-takedowns/{id}",
            axum::routing::delete(scheduled_takedowns::cancel),
        )
        // Issue #189: subject tags. Multi-valued categorical
        // labels attached to a subject for queue routing + search.
        .route(
            "/api/cases/{subject_id}/tags",
            get(moderator_controls::list_tags).post(moderator_controls::add_tag),
        )
        .route(
            "/api/cases/{subject_id}/tags/{tag}",
            axum::routing::delete(moderator_controls::delete_tag),
        )
        // Issue #194: subject divert — route a subject to an
        // alternate queue. POST applies (idempotent on subject),
        // DELETE clears.
        .route(
            "/api/cases/{subject_id}/divert",
            post(moderator_controls::divert_subject).delete(moderator_controls::clear_divert),
        )
        .route(
            "/api/diverted-subjects",
            get(moderator_controls::list_diverted),
        )
        // Issue #190: moderator EMAIL verb. Sends an email via lettre
        // when SMTP is configured; persists the intent regardless so
        // the audit trail is intact.
        .route(
            "/api/cases/{subject_id}/email",
            post(moderator_email::send_email),
        )
        .route(
            "/api/cases/{subject_id}/emails",
            get(moderator_email::list_emails),
        )
        // Issue #191: per-report priority score.
        .route(
            "/api/reports/{report_id}/priority",
            axum::routing::patch(moderator_controls::set_report_priority),
        )
        // Issue #192: muted reporters (anti-abuse for spammy DIDs).
        .route(
            "/api/moderation/muted-reporters",
            get(moderator_controls::list_muted_reporters).post(moderator_controls::mute_reporter),
        )
        .route(
            "/api/moderation/muted-reporters/{reporter_did}",
            axum::routing::delete(moderator_controls::unmute_reporter),
        )
        .route(
            "/api/cases/{incident_id}/escalate",
            post(cases::escalate_incident),
        )
        // Issue #242 / LLM-5: moderator-initiated LLM recommendation
        // (`.design/llm-moderation-assist.md` REQ-C2 "Pull" trigger).
        // Drives the recommend dispatcher with `DispatchTrigger::Pull`;
        // returns a `DispatchOutcomeDto` carrying the resulting
        // observation + (optional) draft / action ids.
        .route(
            "/api/cases/{incident_id}/llm-recommendation",
            post(llm::case_endpoint::request_recommendation),
        )
        // Issue #241 / LLM-12: global LLM kill switch (REQ-S7). POST
        // sets `polaris_setup_state.global_autonomous_pause_until`,
        // DELETE clears it. Both admin-only (handler-enforced) and
        // audit-logged inside the same transaction as the toggle.
        .route(
            "/api/admin/llm/pause",
            post(llm::admin_pause::pause_llm).delete(llm::admin_pause::resume_llm),
        )
        .route(
            "/api/actions/{action_id}/reverse",
            post(reversal::reverse_action),
        )
        .route("/api/appeals/{id}", get(appeals::get_appeal))
        .route("/api/appeals/{id}/decide", post(appeals::decide_appeal))
        .route("/api/pattern-actions", post(pattern_actions::propose))
        .route(
            "/api/pattern-actions/{id}/cosign",
            post(pattern_actions::cosign),
        )
        .route(
            "/api/incidents/{incident_id}/second-opinion",
            post(second_opinion::open_thread),
        )
        .route(
            "/api/threads/{thread_id}/messages",
            post(second_opinion::append_message),
        )
        .route("/api/threads/search", get(second_opinion::search_threads))
        .route("/api/threads/{thread_id}", get(second_opinion::get_thread))
        .route("/api/dashboard", get(dashboard::handler))
        .route("/api/dashboard/live", get(dashboard_ws::live_handler))
        // Issue #83b: authenticated moderator-context endpoint plus
        // first-run signal for the future setup wizard (#84).
        .route("/api/whoami", get(whoami::whoami))
        // Issue #85: setup-wizard endpoints. All admin-gated (the
        // handlers verify `Role::Admin` themselves; the auth
        // middleware runs first so an unauthenticated request never
        // reaches them). The order matches the wizard's natural
        // sequence: generate-key → publish-labeler-record →
        // request-plc-signature → submit-plc-operation.
        .route("/api/setup/generate-key", post(setup::generate_key))
        .route(
            "/api/setup/publish-labeler-record",
            post(setup::publish_labeler_record),
        )
        .route(
            "/api/setup/request-plc-signature",
            post(setup::request_plc_signature),
        )
        .route(
            "/api/setup/submit-plc-operation",
            post(setup::submit_plc_operation),
        )
        // Issue #92: command-palette subject lookup. Admin / moderator
        // /senior-moderator only — triage and read-only roles get
        // 403. POST shape with a JSON body because the response
        // varies by request body, but the semantics are GET-shaped
        // (idempotent read-or-insert) per the spec.
        .route("/api/subjects/lookup", post(subjects::lookup))
        // Issue #96 / mod-workstation feature #6: subscriber-effect
        // preview reads the labeler's declared `labelValueDefinitions`
        // off `polaris_setup_state`. No admin gate — the data is
        // operator-public (published in the labeler service record
        // on the operator's PDS), so any authenticated moderator can
        // read it via the moderator-context `ActionComposer`.
        .route("/api/labeler/policies", get(labeler_policies::policies))
        // Issue #214: Ozone-style moderator allow-list management.
        // All endpoints admin-only (gated server-side via
        // `admin_moderators::require_admin`).
        .route(
            "/api/admin/moderators",
            get(admin_moderators::list_moderators).post(admin_moderators::add_moderator),
        )
        .route(
            "/api/admin/moderators/{did}/roles",
            axum::routing::patch(admin_moderators::patch_moderator_roles),
        )
        .route(
            "/api/admin/moderators/{did}",
            axum::routing::delete(admin_moderators::delete_moderator),
        )
        // Issue #225 (WB-3): mod-policies admin REST surface — admin
        // CRUD + version history + pause/resume.
        //
        // Route-ordering is load-bearing: the literal-path routes
        // (`/history`, `/diff`, `/pause`) MUST be registered before
        // the generic `:identifier/:version` route so axum's
        // matcher doesn't consume `"history"` / `"diff"` / `"pause"`
        // as a version path parameter.
        .route(
            "/api/admin/policies",
            get(admin_policies::list_admin_policies).post(admin_policies::create_admin_policy),
        )
        .route(
            "/api/admin/policies/{identifier}/history",
            get(admin_policies::get_admin_policy_history),
        )
        .route(
            "/api/admin/policies/{identifier}/diff",
            get(admin_policies::get_admin_policy_diff),
        )
        .route(
            "/api/admin/policies/{identifier}/pause",
            post(admin_policies::pause_admin_policy).delete(admin_policies::resume_admin_policy),
        )
        .route(
            "/api/admin/policies/{identifier}",
            get(admin_policies::get_admin_policy).patch(admin_policies::patch_admin_policy),
        )
        // Catch-all version path — registered LAST so the literal
        // routes above win the matcher's longest-prefix race.
        .route(
            "/api/admin/policies/{identifier}/{version}",
            get(admin_policies::get_admin_policy_at_version),
        )
        // Moderator-facing read-only browse (REQ-D4). Same DTO shape
        // the admin surface returns; RBAC is `Role::Moderator` or
        // higher (handler-enforced).
        .route("/api/policies", get(policies::list_policies))
        .route("/api/policies/{identifier}", get(policies::get_policy))
        .route("/api/wellness/exposure/me", get(wellness::get_my_exposure))
        .route(
            "/api/wellness/exposure/me/cap",
            axum::routing::put(wellness::set_my_cap),
        )
        .route(
            "/api/wellness/exposure/me/share-with-manager",
            axum::routing::put(wellness::set_my_share_with_manager),
        )
        .route_layer(middleware::from_fn_with_state(
            state.sessions.clone(),
            auth_middleware,
        ))
        .with_state(state)
}
