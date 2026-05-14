//! Polaris backend binary entrypoint.
//!
//! Responsibilities, in order:
//!
//! 1. Initialise tracing (stdout for dev; M4 wires JSON + OpenTelemetry).
//! 2. Load [`polaris_backend::config::AppConfig`] from env, fail closed on
//!    error.
//! 3. Open the Postgres pool and run migrations via
//!    [`polaris_backend::db::connect`].
//! 4. Build the [`polaris_backend::api`] router with the `Db` injected as
//!    state and serve on `cfg.http.bind`.
//!
//! `anyhow::Result` is used here — and only here — because the binary glue is
//! the one place where ad-hoc error chaining is more useful than a typed
//! error enum. Library code returns typed `Result<_, DbError>` /
//! `Result<_, ConfigError>` so callers can match on variants.

use std::sync::Arc;

use anyhow::Context as _;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::labeler::emitter::LabelEmitter;
use polaris_backend::labeler::rotation::{CustodyMode, bootstrap_active_key};
use polaris_backend::labeler::signer::{SigningKey, build_signing_key};
use polaris_backend::{api, config::AppConfig, db};
use tokio::sync::watch;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Polaris backend starting"
    );

    let cfg = AppConfig::from_env().context("loading AppConfig from environment")?;
    info!(bind = %cfg.http.bind, "configuration loaded");

    let db = db::connect(&cfg.db)
        .await
        .context("connecting to Postgres and running migrations")?;
    info!("database ready");

    // Construct the session store the auth middleware will consult. The
    // crypto handle is built from the configured cookie key; the
    // `SecurityConfig::from_env` path already rejects a zero key in
    // production so this is safe to forward verbatim here.
    let crypto = Crypto::new(cfg.security.cookie_key);
    let sessions = SessionStore::new(db.pool().clone(), crypto);

    // Build the labeler signing key from the operator's configured
    // custody mode. AC-14's profile-vs-mode refusal fires inside
    // `build_signing_key`; an error here aborts boot before any HTTP
    // traffic begins. The Arc<dyn SigningKey> shape composes with the
    // four backend impls without monomorphisation.
    let signer = build_signing_key(&cfg.labeler.signing_key, cfg.profile)
        .context("building labeler signing key")?;
    info!(
        signing_did = signer.public_key_did(),
        "labeler signing key ready",
    );

    // Bootstrap signing_key_history with the active key. Idempotent: a
    // re-run inserts ON CONFLICT DO NOTHING. This is the "issuance-time
    // key" record consumed by the historical-label verifier (#30 /
    // REQ-12). The bootstrap must happen before the emitter goes live
    // so any label emitted under this signer can be later verified by
    // looking up signed_at against signing_key_history.
    let custody_mode = CustodyMode::from(&cfg.labeler.signing_key);
    bootstrap_active_key(db.pool(), signer.public_key_did(), custody_mode)
        .await
        .context("bootstrapping signing_key_history with the active key")?;

    // Build the active-signer slot. The Sender stays here in main(); a
    // future #65 issue lands the polling-discovery task that watches
    // `signing_key_history` on a `tokio::time::interval` and pushes
    // freshly-loaded `Arc<dyn SigningKey>` instances through this
    // sender. The Receiver is handed to ApiState for read access.
    let (signer_tx, signer_rx) = watch::channel::<Arc<dyn SigningKey>>(signer.clone());
    // Hold the sender for the process lifetime so the channel does not
    // close. The variable is intentionally underscored — the active
    // rotation-discovery task (filed as #65) will own it.
    let _signer_tx = signer_tx;

    // Assemble ApiState with the emitter installed. `api::router`'s
    // public signature takes `(Db, SessionStore, PatternActionsConfig)`
    // and constructs its own ApiState internally; we build state here
    // so the emitter can be wired in, then call the state-taking
    // router constructor.
    let api_state = ApiState::with_config(db.pool().clone(), sessions, cfg.pattern_actions);
    let emitter = Arc::new(LabelEmitter::new(
        signer,
        db.pool().clone(),
        api_state.label_broadcaster.clone(),
    ));
    let api_state = api_state
        .with_label_emitter(emitter)
        .with_active_signer(signer_rx);

    let app = api::router_with_state(db, api_state);

    let listener = tokio::net::TcpListener::bind(&cfg.http.bind)
        .await
        .with_context(|| format!("binding HTTP listener to {}", cfg.http.bind))?;
    info!(bind = %cfg.http.bind, "HTTP server listening");

    axum::serve(listener, app)
        .await
        .context("axum::serve terminated with an error")?;

    Ok(())
}
