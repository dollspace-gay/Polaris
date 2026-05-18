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
use crate::api::dto::DashboardEvent;
use crate::auth::AnyModeratorAuth;
use crate::auth::session::SessionStore;
use crate::auth::webauthn::WebauthnVerifier;
use crate::bus::EventBus;
use crate::bus::memory::MemoryBus;
use crate::config::{
    LabelerSigningKeyConfig, ModeratorAnomalyEnvConfig, PatternActionsConfig, ReputationConfig,
};
use crate::labeler::emitter::LabelEmitter;
use crate::labeler::server::{LabelBroadcaster, PgLabelRepo};
use crate::labeler::signer::{ActiveSigner, ActiveSignerReceiver};
use crate::pattern::moderator_anomaly::ModeratorAnomalyConfig;
use crate::repo::{
    PgActionRepo, PgAppealRepo, PgCalibrationEventRepo, PgIncidentRepo, PgObservationRepo,
    PgPatternActionRepo, PgReportRepo, PgSecondOpinionRepo, PgSubjectRepo,
};
use crate::reputation::{PgReputationProvider, ReputationParams};

/// Application state shared with every API handler under `/api/`.
///
/// Cloning is cheap: every field is an `Arc<_>` and the underlying
/// `sqlx::PgPool` is internally `Arc`-shared. Axum clones state per request
/// so this matters.
#[derive(Clone)]
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
    /// Upstream-labeler signing-key cache, shared with the live
    /// subscriber + the on-demand `queryLabels` backfill driver (issue
    /// #51). The case-view handler uses it to verify-then-persist
    /// historic labels pulled from each labeler's own XRPC endpoint
    /// when a moderator opens a subject for the first time. `None`
    /// when the labeler subsystem is not configured (tests).
    pub upstream_key_cache: Option<Arc<crate::ingest::upstream_labels::UpstreamKeyCache>>,
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
    /// Sender side of the live-process active-signer slot (REQ-A4).
    ///
    /// `None` when the labeler subsystem is not configured (tests, the
    /// `--no-labeler` deploy variant). When `Some`, the setup wizard's
    /// `POST /api/setup/generate-key` handler uses it to hot-swap the
    /// freshly-loaded `FilePlainSigner` into the slot the emitter
    /// reads from, atomically and without a process restart.
    ///
    /// The receiver side is held by every cloned `ApiState`; the
    /// sender side is the single point of update. Production wiring
    /// in `main.rs` installs it via [`Self::with_active_signer_tx`]
    /// alongside the receiver, so the rotation-discovery task (#65)
    /// and the setup wizard share one channel.
    ///
    /// `Arc<ActiveSigner>` rather than the bare `tokio::sync::watch::Sender`
    /// so `ApiState::clone` stays cheap — `watch::Sender` itself is
    /// `Send + Sync` but holding it through an `Arc` matches the
    /// "every field is Arc-shared" convention the rest of the state
    /// follows.
    pub active_signer_tx: Option<Arc<ActiveSigner>>,
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
    /// Reporter-reputation provider (issue #37, design.md §9.3).
    /// Threaded onto the state so handlers (the case-view DTO build path
    /// and the pattern-engine integration in `dashboard::build_report_volume`)
    /// can fetch scores without re-deriving the pool wiring. Always
    /// present — the constructor builds it from the configured params
    /// at startup; tests that don't exercise reputation simply ignore
    /// the field. Cloning is cheap (`Arc::clone`).
    pub reputation: Arc<PgReputationProvider>,
    /// Live dashboard event bus (issue #57). Producers (the pattern
    /// engine, the incident-state transition path, the report-insert
    /// path) publish [`DashboardEvent`] diffs here; the
    /// `GET /api/dashboard/live` WebSocket handler subscribes per
    /// connection and forwards each envelope as a JSON text frame.
    ///
    /// Default is an in-process [`MemoryBus`] — production deployments
    /// keep this seam in place because the dashboard feed is process-
    /// local (one Polaris instance serves the moderator UI). If a future
    /// deployment fans out across multiple backend processes, swap a
    /// kafka- or nats-backed implementation in via [`Self::with_dashboard_bus`].
    ///
    /// `Arc<dyn EventBus<_>>` rather than a concrete `MemoryBus` so the
    /// test fixtures and the production wiring share one field shape and
    /// the bus implementation is interchangeable.
    pub dashboard_bus: Arc<dyn EventBus<DashboardEvent>>,
    /// Moderator-authentication verifier (issue #67).
    ///
    /// The `/auth/atproto/{login,callback}` handlers reach the atproto
    /// verifier through [`AnyModeratorAuth::as_atproto`]; a future OIDC
    /// handler will reach the OIDC verifier through a sibling
    /// accessor. The enum lives behind an `Arc` so cloning the state
    /// per request is cheap — every concrete verifier owns a `PgPool`,
    /// a `Crypto`, and (for atproto) an `Arc<dyn FetchHandler>`, and
    /// none of those want to be cloned per Axum request.
    ///
    /// `None` when the binary entrypoint did not construct a verifier
    /// (the integration-test path that does not exercise the
    /// `/auth/*` routes). Production wiring always installs the
    /// verifier via [`Self::with_moderator_auth`].
    pub moderator_auth: Option<Arc<AnyModeratorAuth>>,
    /// OAuth client-metadata payload served at
    /// `/oauth/client-metadata.json` (issue #81). `None` (the default)
    /// makes the route return 404; production deployments install it
    /// via [`Self::with_oauth_client_metadata`] when the operator
    /// configures the atproto backend.
    pub oauth_client_metadata: crate::api::oauth_metadata::ClientMetadataState,
    /// Optional override for the polaris-frontend static-bundle
    /// directory. Production wiring (`main.rs`) leaves this `None`,
    /// in which case [`api::router_with_state`] consults
    /// `POLARIS_FRONTEND_DIST` from the process environment. Tests
    /// install a directory directly via
    /// [`Self::with_frontend_dist`] to avoid the `unsafe` env-mutation
    /// the workspace-level `unsafe_code = "deny"` lint refuses.
    pub frontend_dist: Option<std::path::PathBuf>,

    /// Labeler signing-key custody configuration (issue #85).
    ///
    /// The `/api/setup/generate-key` handler reads this to decide
    /// whether the wizard's in-process key mint is the right
    /// configured path (only `file-plain` is supported from the
    /// HTTP-driven wizard; other modes route through the
    /// `labeler-key-rotate` CLI). Threaded onto the state so the
    /// handler does not have to re-parse env on every call.
    pub labeler_signing_key_cfg: LabelerSigningKeyConfig,

    /// Prometheus recorder handle (Workstream D / REQ-D2).
    ///
    /// `None` when the binary did not install the recorder (slim
    /// integration tests that do not exercise `/metrics`). Production
    /// wiring in `main.rs` installs it once via
    /// `metrics_exporter_prometheus::PrometheusBuilder::new()
    /// .install_recorder()` BEFORE the router is built, so the
    /// `axum-prometheus` tower layer sees the same recorder when it
    /// auto-instruments HTTP-level series, and the
    /// [`crate::api::metrics::handler`] renders the same handle on
    /// `/metrics`.
    ///
    /// `Arc<PrometheusHandle>` keeps cloning the state cheap — the
    /// underlying recorder state is shared and the handle itself is
    /// already a thin wrapper around an `Arc`.
    pub metrics_handle: Option<std::sync::Arc<metrics_exporter_prometheus::PrometheusHandle>>,
}

impl ApiState {
    /// Build an [`ApiState`] from a `sqlx::PgPool` and a [`SessionStore`].
    /// Each `Pg*Repo` is constructed against the same pool (the pool is
    /// already `Arc`-shared internally).
    ///
    /// Reputation defaults to [`ReputationConfig::default`] — see
    /// [`Self::with_full_config`] for the test entry-point that
    /// overrides both.
    ///
    /// # Panics
    ///
    /// Panics if the default reputation params fail validation; the
    /// validation rejects non-positive priors / half-lives, which the
    /// default `1.0 / 1.0 / 90.0` satisfies.
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
    ///
    /// # Panics
    ///
    /// Panics if the default reputation params fail validation; see
    /// [`Self::new`] for the rationale.
    #[must_use]
    pub fn with_config(
        pool: sqlx::PgPool,
        sessions: SessionStore,
        pattern_actions_cfg: PatternActionsConfig,
    ) -> Self {
        Self::with_full_config(
            pool,
            sessions,
            pattern_actions_cfg,
            ReputationConfig::default(),
            ModeratorAnomalyEnvConfig::default(),
        )
    }

    /// Build an [`ApiState`] with an explicit [`PatternActionsConfig`]
    /// and [`ReputationConfig`] (issue #37 entry point).
    ///
    /// # Panics
    ///
    /// Panics if `reputation_cfg`'s params (priors, half-life) are
    /// non-positive — the constructor on [`PgReputationProvider`]
    /// validates them and this is the binary-startup configuration
    /// path. Tests that pass invalid params expect the panic; the
    /// production path reads from validated env so the validation
    /// already passed at `AppConfig::from_env`.
    ///
    /// Panics if `moderator_anomaly_cfg` carries a zero `threshold` or
    /// `window_secs` — the constructor on
    /// [`ModeratorAnomalyConfig::new`] rejects degenerate values, and
    /// the default (50, 3600) trivially satisfies them. The
    /// `AppConfig::from_env` validation rejects any operator override
    /// outside `u32` range, so the only path to a panic here is a
    /// test passing zero deliberately.
    #[must_use]
    pub fn with_full_config(
        pool: sqlx::PgPool,
        sessions: SessionStore,
        pattern_actions_cfg: PatternActionsConfig,
        reputation_cfg: ReputationConfig,
        moderator_anomaly_cfg: ModeratorAnomalyEnvConfig,
    ) -> Self {
        let reputation_params = ReputationParams {
            prior_actioned: reputation_cfg.prior_actioned,
            prior_dismissed: reputation_cfg.prior_dismissed,
            half_life_days: reputation_cfg.half_life_days,
        };
        #[allow(
            clippy::expect_used,
            reason = "Constructor-time validation of operator-supplied \
                      params. Defaults always pass; env-derived params \
                      are already validated upstream in \
                      ReputationConfig::from_env, so this expect is a \
                      defence-in-depth for a degenerate caller."
        )]
        let reputation = Arc::new(
            PgReputationProvider::new(pool.clone(), reputation_params)
                .expect("ReputationConfig::default / env-validated params are positive"),
        );
        Self {
            subjects: Arc::new(PgSubjectRepo::new(pool.clone())),
            incidents: Arc::new(PgIncidentRepo::new(pool.clone())),
            // Issue #37: the action insert path needs to bump
            // reporter_stats per-reporter on Label/Takedown/NoAction.
            // Inject the provider so the same tx commits the action
            // and the stats update atomically.
            actions: {
                // Issue #73, T1 mitigation: install the moderator-
                // behavior-anomaly hook on the action-insert path. The
                // ModeratorAnomalyEnvConfig fields are already u32-
                // validated by env parsing; only a deliberate test
                // override of zero would reach the panic branch.
                #[allow(
                    clippy::expect_used,
                    reason = "Constructor-time validation of operator-supplied \
                              params. Defaults (50, 3600) trivially pass; env-\
                              derived params are validated upstream in \
                              ModeratorAnomalyEnvConfig::from_env, so this \
                              expect guards a degenerate caller only."
                )]
                let anomaly_cfg = ModeratorAnomalyConfig::new(
                    moderator_anomaly_cfg.threshold,
                    moderator_anomaly_cfg.window_secs,
                )
                .expect("ModeratorAnomalyEnvConfig defaults / env-validated params are non-zero");
                Arc::new(
                    PgActionRepo::new(pool.clone())
                        .with_reputation(Arc::clone(&reputation))
                        .with_moderator_anomaly(anomaly_cfg),
                )
            },
            observations: Arc::new(PgObservationRepo::new(pool.clone())),
            // Issue #37: same wiring for the report-insert path
            // (bumps reports_filed + last_active).
            reports: Arc::new(
                PgReportRepo::new(pool.clone()).with_reputation(Arc::clone(&reputation)),
            ),
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
            // The key cache is installed by `main.rs` after
            // `spawn_labeler_discovery_and_supervisor`. Tests that
            // don't exercise the on-demand backfill leave it `None`
            // and `should_backfill` short-circuits.
            upstream_key_cache: None,
            // The active-signer slot is installed by the binary entrypoint
            // after `build_signing_key` succeeds. Tests that don't
            // exercise rotation leave it `None`.
            active_signer: None,
            // The sender half of the active-signer channel is installed
            // alongside the receiver by the binary entrypoint
            // (REQ-A4). Tests that exercise the hot-swap path
            // construct their own channel and install both halves via
            // [`Self::with_active_signer`] + [`Self::with_active_signer_tx`].
            active_signer_tx: None,
            appeals_rate_limiter: AppealsRateLimiter::new(),
            pool,
            sessions,
            pattern_actions_cfg,
            webauthn: None,
            reputation,
            // Process-local in-memory bus is the default backend. Tests
            // that drive the WebSocket directly construct their own bus
            // and install it via `with_dashboard_bus`; production wiring
            // can swap in a kafka/nats backend the same way once the
            // multi-process deploy lands.
            dashboard_bus: Arc::new(MemoryBus::<DashboardEvent>::new_default()),
            // Issue #67: the moderator-auth verifier is installed by the
            // binary entrypoint via `with_moderator_auth` after
            // `build_moderator_auth` succeeds. Integration tests that
            // exercise the `/auth/*` routes construct their own
            // verifier and install it the same way; tests that don't
            // touch those routes leave the slot `None`.
            moderator_auth: None,
            // Issue #81: empty cache by default; the binary installs it
            // via with_oauth_client_metadata after loading the
            // operator-supplied client_metadata.json.
            oauth_client_metadata: crate::api::oauth_metadata::ClientMetadataState::empty(),
            // Issue #85: default signing-key custody is the
            // labeler-profile default (file-plain at the sentinel
            // path). The binary entrypoint overrides it via
            // [`Self::with_labeler_signing_key_cfg`] after env parse;
            // tests that don't exercise the setup endpoints leave the
            // default in place.
            labeler_signing_key_cfg: LabelerSigningKeyConfig::default(),
            // Production wiring reads `POLARIS_FRONTEND_DIST` from
            // env at router-construction time; tests install a path
            // directly via [`Self::with_frontend_dist`].
            frontend_dist: None,
            // Workstream D / REQ-D2: the binary entrypoint installs
            // the Prometheus recorder handle via
            // [`Self::with_metrics_handle`] after
            // `metrics_exporter_prometheus::PrometheusBuilder::new()
            // .install_recorder()` succeeds. Slim integration tests
            // that do not exercise `/metrics` leave it `None`; the
            // metrics handler then returns 503 (the empty-body
            // sentinel posture).
            metrics_handle: None,
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

    /// Plug the **sender** side of the active-signer channel onto the
    /// state (REQ-A4).
    ///
    /// The binary entrypoint constructs the channel once via
    /// `tokio::sync::watch::channel(initial_signer)`, installs the
    /// receiver via [`Self::with_active_signer`], and installs the
    /// sender here so the setup wizard's
    /// `POST /api/setup/generate-key` handler can hot-swap the
    /// freshly-loaded `FilePlainSigner` into the slot. Tests that
    /// exercise the AC-A4 hot-swap path own both halves and install
    /// them the same way.
    #[must_use]
    pub fn with_active_signer_tx(mut self, tx: Arc<ActiveSigner>) -> Self {
        self.active_signer_tx = Some(tx);
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

    /// Install the shared [`UpstreamKeyCache`] for the on-demand
    /// `queryLabels` backfill driver. The cache is constructed at
    /// startup by [`spawn_labeler_discovery_and_supervisor`] and
    /// shared with the live subscriber so a backfill verify-step
    /// hits the same warm cache the live consumer uses.
    ///
    /// [`UpstreamKeyCache`]: crate::ingest::upstream_labels::UpstreamKeyCache
    #[must_use]
    pub fn with_upstream_key_cache(
        mut self,
        cache: Arc<crate::ingest::upstream_labels::UpstreamKeyCache>,
    ) -> Self {
        self.upstream_key_cache = Some(cache);
        self
    }

    /// Install an explicit [`EventBus`] backend for the live-dashboard
    /// feed (issue #57).
    ///
    /// Production wiring leaves the default in-process [`MemoryBus`] in
    /// place. Tests that need to observe the WebSocket fan-out construct
    /// a `MemoryBus<DashboardEvent>`, install it here, and publish
    /// directly while a client is connected. A future multi-process
    /// deploy can swap a kafka- or nats-backed implementation in via
    /// this builder without touching the handler.
    #[must_use]
    pub fn with_dashboard_bus(mut self, bus: Arc<dyn EventBus<DashboardEvent>>) -> Self {
        self.dashboard_bus = bus;
        self
    }

    /// Install the moderator-authentication verifier onto the state
    /// Install the OAuth client-metadata payload (issue #81). Production
    /// wiring calls this after [`polaris_types::oauth_config::load_client_metadata`]
    /// succeeds; the metadata is then served from
    /// `/oauth/client-metadata.json` for the AS to fetch when verifying
    /// the `client_id` URL.
    #[must_use]
    pub fn with_oauth_client_metadata(
        mut self,
        metadata: crate::api::oauth_metadata::ClientMetadataState,
    ) -> Self {
        self.oauth_client_metadata = metadata;
        self
    }

    /// Install a polaris-frontend static-bundle directory override.
    ///
    /// Production wiring leaves this unset (the router falls back to
    /// `POLARIS_FRONTEND_DIST`). Tests use this builder to point the
    /// SPA fallback at a fixture directory without mutating process
    /// env (the workspace's `unsafe_code = "deny"` lint refuses the
    /// `unsafe { std::env::set_var(...) }` pattern required by the
    /// newer Rust env API).
    #[must_use]
    pub fn with_frontend_dist(mut self, dist: std::path::PathBuf) -> Self {
        self.frontend_dist = Some(dist);
        self
    }

    /// Install the labeler signing-key custody configuration onto the
    /// state (issue #85).
    ///
    /// The binary entrypoint calls this after `LabelerConfig::from_env`
    /// succeeds so the `/api/setup/generate-key` handler can pick the
    /// configured path off the state without re-parsing env. Tests
    /// that exercise the setup endpoints install their own config the
    /// same way.
    #[must_use]
    pub fn with_labeler_signing_key_cfg(mut self, cfg: LabelerSigningKeyConfig) -> Self {
        self.labeler_signing_key_cfg = cfg;
        self
    }

    /// Install the Prometheus recorder handle onto the state
    /// (Workstream D / REQ-D2).
    ///
    /// The binary entrypoint calls this after
    /// `metrics_exporter_prometheus::PrometheusBuilder::new()
    /// .install_recorder()` succeeds (which globally registers the
    /// recorder so all subsequent `metrics::counter!` / `metrics::gauge!`
    /// emissions route to it). The `axum-prometheus` middleware
    /// layered on the merged router in `main.rs` shares the same
    /// recorder; the `/metrics` handler renders the handle's text
    /// output. Tests that exercise `/metrics` install the handle the
    /// same way.
    #[must_use]
    pub fn with_metrics_handle(
        mut self,
        handle: std::sync::Arc<metrics_exporter_prometheus::PrometheusHandle>,
    ) -> Self {
        self.metrics_handle = Some(handle);
        self
    }

    /// Install the moderator-authentication verifier (issue #67).
    ///
    /// The binary entrypoint builds the verifier via
    /// [`crate::auth::build_moderator_auth`] from the configured backend
    /// (`oidc` / `atproto`) and installs the resulting
    /// `Arc<AnyModeratorAuth>` here before the router takes ownership of
    /// the state. The atproto HTTP handlers
    /// (`/auth/atproto/{login,callback}`) reach the verifier through
    /// [`AnyModeratorAuth::as_atproto`]; an OIDC counterpart will reach
    /// it through a sibling accessor when that handler lands.
    #[must_use]
    pub fn with_moderator_auth(mut self, auth: Arc<AnyModeratorAuth>) -> Self {
        self.moderator_auth = Some(auth);
        self
    }
}

// Manual `Debug` impl so the `Arc<dyn EventBus<DashboardEvent>>` field
// (which the trait does not require to be `Debug`) does not block the
// auto-derive on `ApiState`. The bus is opaque in logs — its address is
// not useful and the topic surface is fixed by [`crate::api::dashboard_ws`].
impl std::fmt::Debug for ApiState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiState")
            .field("subjects", &self.subjects)
            .field("incidents", &self.incidents)
            .field("actions", &self.actions)
            .field("observations", &self.observations)
            .field("reports", &self.reports)
            .field("pattern_actions", &self.pattern_actions)
            .field("appeals", &self.appeals)
            .field("calibration_events", &self.calibration_events)
            .field("second_opinion", &self.second_opinion)
            .field("labels", &self.labels)
            .field("label_broadcaster", &self.label_broadcaster)
            .field("label_emitter", &self.label_emitter)
            .field(
                "upstream_key_cache",
                &self
                    .upstream_key_cache
                    .as_ref()
                    .map(|_| "<UpstreamKeyCache>"),
            )
            .field(
                "active_signer",
                &self.active_signer.as_ref().map(|_| "<receiver>"),
            )
            .field(
                "active_signer_tx",
                &self.active_signer_tx.as_ref().map(|_| "<sender>"),
            )
            .field("appeals_rate_limiter", &self.appeals_rate_limiter)
            .field("pool", &self.pool)
            .field("sessions", &self.sessions)
            .field("pattern_actions_cfg", &self.pattern_actions_cfg)
            .field("webauthn", &self.webauthn.as_ref().map(|_| "<verifier>"))
            .field("reputation", &self.reputation)
            .field("dashboard_bus", &"<dyn EventBus<DashboardEvent>>")
            .field(
                "moderator_auth",
                &self.moderator_auth.as_ref().map(|_| "<verifier>"),
            )
            .field(
                "oauth_client_metadata",
                &self
                    .oauth_client_metadata
                    .payload()
                    .map(|_| "<client-metadata>"),
            )
            .field("labeler_signing_key_cfg", &self.labeler_signing_key_cfg)
            .field("frontend_dist", &self.frontend_dist)
            .field(
                "metrics_handle",
                &self.metrics_handle.as_ref().map(|_| "<prometheus-handle>"),
            )
            .finish()
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

impl axum::extract::FromRef<ApiState> for crate::api::oauth_metadata::ClientMetadataState {
    fn from_ref(state: &ApiState) -> Self {
        state.oauth_client_metadata.clone()
    }
}
