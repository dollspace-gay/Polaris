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

pub mod appeals;
pub mod auth_atproto;
pub mod cases;
pub mod dashboard;
pub mod dashboard_ws;
pub mod dto;
pub mod error;
pub mod healthz;
pub mod pattern_actions;
pub mod policy;
pub mod reversal;
pub mod second_opinion;
pub mod state;
pub mod webauthn;
pub mod wellness;

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
    // `labeler_router` exposes the labeler XRPC endpoints on the PUBLIC
    // subtree — downstream AppViews subscribe without Polaris credentials
    // (REQ-1 / AC-1). It is therefore NOT layered with the auth middleware.
    let labeler = labeler::server::router(api_state.clone());
    let public_api = public_api_router(api_state.clone());
    let authed = authed_router(api_state);
    healthz.merge(labeler).merge(public_api).merge(authed)
}

/// Build the public subtree (`/healthz` today; possibly `/readyz` later).
fn healthz_router(db: Db) -> Router {
    Router::new()
        .route("/healthz", get(healthz::handler))
        .with_state(db)
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
        .with_state(state)
}

/// Build the authed subtree — every `/api/*` route + the auth middleware
/// layer.
///
/// `route_layer` rather than `layer` so the middleware runs only for the
/// routes added to *this* router. The middleware is wired with
/// `from_fn_with_state` against the [`SessionStore`] that
/// `FromRef<ApiState>` extracts.
fn authed_router(state: ApiState) -> Router {
    Router::new()
        .route("/api/cases", get(cases::list_cases))
        .route("/api/cases/{subject_id}", get(cases::get_case))
        .route(
            "/api/cases/{subject_id}/actions",
            post(cases::submit_action),
        )
        .route(
            "/api/cases/{incident_id}/escalate",
            post(cases::escalate_incident),
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
