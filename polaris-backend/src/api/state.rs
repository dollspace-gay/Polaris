//! [`ApiState`] — the cloneable container of repo handles passed to handlers.
//!
//! Per the architect's pre-flight, #14 uses the *concrete* state shape: each
//! field is an `Arc<Pg*Repo>`. The trade-offs are documented in the issue's
//! completion report.
//!
//! - **Concrete, not generic.** The repo traits are AFIT (async fn in
//!   trait); without `#[trait_variant]` or the `async-trait` macro they are
//!   not `dyn`-compatible. A *generic-on-five-traits* `ApiState<S, I, A, O,
//!   R>` is technically possible but propagates five type parameters
//!   through every router-construction site for a single-implementation
//!   workspace today. Concrete is the right balance.
//! - **`Arc<PgFooRepo>`, not `Arc<PgPool>`.** The architect's pre-flight
//!   forbids `Arc<PgPool>` (the pool is internally `Arc`-shared already).
//!   `Arc<PgFooRepo>` is a different shape: it wraps a *thin* per-repo
//!   handle so `ApiState::clone()` is cheap (`axum` clones the state for
//!   every request).
//! - **Test fakes follow up.** Swapping in test fakes today would require
//!   introducing `Box<dyn FooRepo>`-style trait objects, which forces the
//!   `async-trait` macro back into the trait definition or a
//!   `#[trait_variant]` shim. We defer that refactor — the integration
//!   tests in `tests/case_api.rs` use the live `Pg*Repo` against a
//!   testcontainers Postgres.

use std::sync::Arc;

use crate::api::appeals::AppealsRateLimiter;
use crate::auth::session::SessionStore;
use crate::auth::webauthn::WebauthnVerifier;
use crate::config::PatternActionsConfig;
use crate::labeler::emitter::LabelEmitter;
use crate::labeler::server::{LabelBroadcaster, PgLabelRepo};
use crate::labeler::signer::ActiveSignerReceiver;
use crate::repo::{
    PgActionRepo, PgAppealRepo, PgCalibrationEventRepo, PgIncidentRepo, PgObservationRepo,
    PgPatternActionRepo, PgReportRepo, PgSecondOpinionRepo, PgSubjectRepo,
};

/// Application state shared with every API handler under `/api/`.
///
/// Cloning is cheap: every field is an `Arc<_>` and the underlying
/// `sqlx::PgPool` is internally `Arc`-shared. Axum clones state per request
/// so this matters.
#[derive(Clone, Debug)]
pub struct ApiState {
    /// Subject repository handle.
    pub subjects: Arc<PgSubjectRepo>,
    /// Incident repository handle.
    pub incidents: Arc<PgIncidentRepo>,
    /// Action repository handle (append-only).
    pub actions: Arc<PgActionRepo>,
    /// Observation repository handle.
    pub observations: Arc<PgObservationRepo>,
    /// Report repository handle.
    pub reports: Arc<PgReportRepo>,
    /// Pattern-action repository handle (issue #21).
    pub pattern_actions: Arc<PgPatternActionRepo>,
    /// Appeal repository handle (issue #24).
    pub appeals: Arc<PgAppealRepo>,
    /// Calibration-event repository handle (issue #24).
    pub calibration_events: Arc<PgCalibrationEventRepo>,
    /// Second-opinion thread repository handle (issue #25).
    pub second_opinion: Arc<PgSecondOpinionRepo>,
    /// Label repository handle (issue #26). Backs both the `queryLabels`
    /// HTTP endpoint and the `subscribeLabels` WebSocket backfill phase.
    pub labels: Arc<PgLabelRepo>,
    /// Live label broadcaster (issue #26). The signer (#28) calls
    /// `publish` on each insert; every connected subscription holds its
    /// own receiver via `subscribe`. Cloning is cheap (`broadcast::Sender`
    /// is internally `Arc`-backed).
    pub label_broadcaster: LabelBroadcaster,
    /// Signed-label emitter (issue #28). Holds the `Arc<dyn SigningKey>`
    /// plus a pool clone and a broadcaster clone. The action-submission
    /// path calls `label_emitter.emit(action, …)` after a successful
    /// insert when the action's kind is `Label | Takedown`. `Option<_>`
    /// because the emitter is constructed at startup from the operator's
    /// configured custody mode — integration tests that don't exercise
    /// the labeler pipeline skip the construction and leave it `None`.
    pub label_emitter: Option<Arc<LabelEmitter>>,
    /// Receiver side of the live-process active-signer slot (issue #30).
    ///
    /// `None` when the labeler subsystem is not configured (tests, the
    /// `--no-labeler` deploy variant in #65). When `Some`, the live
    /// server's rotation-discovery task polls `signing_key_history` on
    /// a `tokio::time::interval` and calls `signer_tx.send(new_signer)`
    /// when it detects a new active key. Consumers (the emitter, the
    /// verifier) `borrow().clone()` to read the current signer for a
    /// single op.
    ///
    /// `ApiState::clone` is cheap: `watch::Receiver` is itself
    /// internally `Arc`-shared, matching the existing `Arc<Pg*Repo>`
    /// shape of every other field.
    pub active_signer: Option<ActiveSignerReceiver>,
    /// IP rate-limiter for the public `POST /api/appeals` endpoint
    /// (issue #24). Cloning is cheap — the inner `HashMap` is wrapped in
    /// an `Arc<Mutex<_>>`.
    pub appeals_rate_limiter: AppealsRateLimiter,
    /// Direct pool handle for handlers that issue aggregate / cross-entity
    /// queries (the dashboard handler in #20 is the first user). The repos
    /// remain the source of truth for single-entity CRUD; carrying the pool
    /// here keeps composite-read handlers from inventing a leaky `pool()`
    /// accessor on every repo. The pool is already `Arc`-shared internally,
    /// so this is not a second allocation.
    pub pool: sqlx::PgPool,
    /// Session store — used by the auth middleware to validate cookies.
    /// Carried on `ApiState` so the router can hand it to
    /// `middleware::from_fn_with_state` from a single place.
    pub sessions: SessionStore,
    /// Pattern-action settings — currently just the senior-co-sign
    /// threshold. Carried on `ApiState` so the propose handler can read
    /// it without re-parsing env at every call.
    pub pattern_actions_cfg: PatternActionsConfig,
    /// Hardware-key (WebAuthn / FIDO2) verifier (issue #40, design.md
    /// §6 + §9.1). `None` when the operator did not configure the
    /// hardware-key gate at startup (e.g. labeler-profile builds that
    /// did not opt into the gate). When `None`, the four
    /// `/api/auth/webauthn/*` endpoints are not mounted.
    pub webauthn: Option<WebauthnVerifier>,
}

impl ApiState {
    /// Build an [`ApiState`] from a `sqlx::PgPool` and a [`SessionStore`].
    /// Each `Pg*Repo` is constructed against the same pool (the pool is
    /// already `Arc`-shared internally).
    #[must_use]
    pub fn new(pool: sqlx::PgPool, sessions: SessionStore) -> Self {
        Self::with_config(pool, sessions, PatternActionsConfig::default())
    }

    /// Build an [`ApiState`] with an explicit [`PatternActionsConfig`].
    ///
    /// Integration tests use this entry point to lower the co-sign
    /// threshold below the production default of 100 so the
    /// requires-cosign branch is reachable without seeding hundreds of
    /// subjects.
    #[must_use]
    pub fn with_config(
        pool: sqlx::PgPool,
        sessions: SessionStore,
        pattern_actions_cfg: PatternActionsConfig,
    ) -> Self {
        Self {
            subjects: Arc::new(PgSubjectRepo::new(pool.clone())),
            incidents: Arc::new(PgIncidentRepo::new(pool.clone())),
            actions: Arc::new(PgActionRepo::new(pool.clone())),
            observations: Arc::new(PgObservationRepo::new(pool.clone())),
            reports: Arc::new(PgReportRepo::new(pool.clone())),
            pattern_actions: Arc::new(PgPatternActionRepo::new(pool.clone())),
            appeals: Arc::new(PgAppealRepo::new(pool.clone())),
            calibration_events: Arc::new(PgCalibrationEventRepo::new(pool.clone())),
            second_opinion: Arc::new(PgSecondOpinionRepo::new(pool.clone())),
            labels: Arc::new(PgLabelRepo::new(pool.clone())),
            label_broadcaster: LabelBroadcaster::with_default_capacity(),
            // The signer is constructed at startup; tests that don't
            // need label emission leave the emitter `None` and the
            // submit-action path silently skips emit when so configured.
            label_emitter: None,
            // The active-signer slot is installed by the binary entrypoint
            // after `build_signing_key` succeeds. Tests that don't
            // exercise rotation leave it `None`.
            active_signer: None,
            appeals_rate_limiter: AppealsRateLimiter::new(),
            pool,
            sessions,
            pattern_actions_cfg,
            webauthn: None,
        }
    }

    /// Install a [`WebauthnVerifier`] onto the state.
    ///
    /// Issue #40: the binary entrypoint builds the verifier from the
    /// `[auth] rp_id` + `[auth] rp_origin` configuration when
    /// `require_hardware_key` resolves to `true`. Tests that exercise
    /// the hardware-key gate (in particular the `webauthn_roundtrip`
    /// integration test) install the verifier the same way.
    #[must_use]
    pub fn with_webauthn(mut self, verifier: WebauthnVerifier) -> Self {
        self.webauthn = Some(verifier);
        self
    }

    /// Build an [`ApiState`] with an explicit [`AppealsRateLimiter`].
    ///
    /// Integration tests use this entry point to lower the per-IP quota
    /// and shrink the window so the rate-limited branch is reachable
    /// without sleeping for an hour. Production wiring goes through
    /// [`Self::with_config`] which calls [`AppealsRateLimiter::new`]
    /// with the production policy.
    #[must_use]
    pub fn with_appeals_rate_limiter(mut self, limiter: AppealsRateLimiter) -> Self {
        self.appeals_rate_limiter = limiter;
        self
    }

    /// Plug a live-process active-signer slot onto the state.
    ///
    /// Issue #30: the binary entrypoint constructs a
    /// `tokio::sync::watch::channel(initial_signer)`, hands the
    /// `Sender` to the rotation-discovery task, and installs the
    /// `Receiver` on `ApiState` here. Tests that exercise AC-15
    /// hold the `Sender` directly so they can simulate the
    /// live-server-detected swap by calling `signer_tx.send(...)`.
    #[must_use]
    pub fn with_active_signer(mut self, rx: ActiveSignerReceiver) -> Self {
        self.active_signer = Some(rx);
        self
    }

    /// Plug a constructed [`LabelEmitter`] onto the state.
    ///
    /// The binary entrypoint (`main.rs`) calls
    /// [`crate::labeler::signer::build_signing_key`] at startup, wraps
    /// the resulting `Arc<dyn SigningKey>` in a [`LabelEmitter`], and
    /// installs it via this method before the router takes ownership of
    /// the state. Tests that exercise label emission build their own
    /// emitter (with a `FilePlainSigner` over a fresh keypair) and
    /// install it the same way.
    #[must_use]
    pub fn with_label_emitter(mut self, emitter: Arc<LabelEmitter>) -> Self {
        self.label_emitter = Some(emitter);
        self
    }
}

// `axum::extract::FromRef<ApiState> for SessionStore` lets the auth
// middleware (which is wired with `State<SessionStore>`) extract its
// dependency from the composite `ApiState`. The trait is derivable in
// axum 0.8 via `#[derive(FromRef)]`, but we hand-implement it to keep the
// derive macro off the dependency list.
impl axum::extract::FromRef<ApiState> for SessionStore {
    fn from_ref(state: &ApiState) -> Self {
        state.sessions.clone()
    }
}
