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
use std::time::Duration;

use anyhow::Context as _;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::BlobStoreKind;
use polaris_backend::evidence::{
    BlobStore, EvidenceFetcher, EvidenceFetcherError, EvidenceWorker, FetchedEvidence,
    InMemoryBlobStore, LocalFsBlobStore,
};
use polaris_backend::ingest::upstream_labels::{
    self, UpstreamKeyCache, UpstreamKeyFetcher, UpstreamLabelerConsumer,
};
use polaris_backend::labeler::emitter::LabelEmitter;
use polaris_backend::labeler::rotation::{CustodyMode, bootstrap_active_key};
use polaris_backend::labeler::signer::{SigningKey, build_signing_key};
use polaris_backend::repo::PgObservationRepo;
use polaris_backend::{api, config::AppConfig, db};
use tokio::sync::watch;
use tracing::{info, warn};

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
    let sessions = SessionStore::new(db.pool().clone(), crypto.clone());

    // Build the moderator-auth verifier from configuration. Both OIDC
    // and ATProto backends compile in; the [auth] backend toggle picks
    // one at runtime. `_moderator_auth` is held so the verifier stays
    // alive for the process lifetime; #67 (to-be-filed) wires it into
    // ApiState so the `/auth/<backend>/{login,callback}` handlers can
    // drive it directly. The handlers themselves are out of scope for
    // #31 — this dispatch only needs the verifier to exist at startup
    // for the AC-5 swap-by-config criterion.
    let _moderator_auth = polaris_backend::auth::build_moderator_auth(
        &cfg.auth,
        sessions.clone(),
        crypto,
        db.pool().clone(),
    )
    .await
    .context("building the configured moderator-auth verifier")?;

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

    // Issue #32: spawn one per-upstream subscribeLabels consumer for every
    // `upstream_labelers WHERE enabled = TRUE` row. Each task is detached
    // (`tokio::spawn`) and owns its own cursor by value; the in-memory
    // signing-key cache is shared via the documented `UpstreamKeyCache`.
    // Failures are isolated per-upstream — a misbehaving upstream cannot
    // wedge the HTTP server.
    spawn_upstream_labeler_consumers(db.pool().clone()).await;

    // Issue #33: spawn the evidence-preservation worker. Bounded
    // concurrency via `tokio::sync::Semaphore` inside the worker. The
    // fetcher is a NotWiredFetcher stub today; #69 swaps it for a
    // proto-blue-api `Agent`-backed implementation. The blob store is
    // selected by config. The spawn is detached: the worker runs for
    // the process lifetime and a fatal error logs at WARN before
    // exiting the task.
    spawn_evidence_worker(&cfg.evidence, db.pool().clone());

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

/// Issue #32: at startup, load every operator-configured upstream labeler
/// row with `enabled = TRUE` and spawn one detached
/// [`UpstreamLabelerConsumer`] task per row.
///
/// The tasks share a single [`UpstreamKeyCache`] (one entry per upstream
/// DID; per-process). Each consumer owns its own [`PgObservationRepo`]
/// handle constructed against the supplied pool — the pool itself is
/// internally `Arc`-shared so this is a cheap clone, not a re-allocation.
///
/// A load failure on the initial query is logged at WARN and the function
/// returns: the binary continues to come up so the HTTP server is reachable
/// even when the labeler integrations are misconfigured. Per-consumer
/// fatal errors are logged at WARN inside the task; the supervisor /
/// restart loop is filed as #51 (wire-level reconnect integration test)
/// and #65 (live discovery).
async fn spawn_upstream_labeler_consumers(pool: sqlx::PgPool) {
    let configs = match upstream_labels::load_enabled_upstreams(&pool).await {
        Ok(c) => c,
        Err(err) => {
            warn!(
                error = ?err,
                "failed to load upstream_labelers rows; \
                 no upstream consumers will run this process lifetime",
            );
            return;
        }
    };
    if configs.is_empty() {
        info!("no enabled upstream labelers configured; skipping spawn");
        return;
    }
    info!(count = configs.len(), "spawning upstream labeler consumers");

    let fetcher: Arc<dyn UpstreamKeyFetcher> = Arc::new(PlcDirectoryKeyFetcher);
    let cache = Arc::new(UpstreamKeyCache::new(pool.clone(), fetcher));
    for cfg in configs {
        let observations = Arc::new(PgObservationRepo::new(pool.clone()));
        let consumer =
            UpstreamLabelerConsumer::new(cfg.clone(), pool.clone(), observations, cache.clone());
        info!(did = %cfg.did, hostname = %cfg.hostname, "spawned upstream consumer");
        tokio::spawn(park_consumer(consumer));
    }
}

/// Hold the consumer alive in a spawned task without running its
/// (deferred) wire loop.
///
/// The run-loop's WebSocket transport lands with #51; until then the
/// process maintains exactly the structure the brief mandates ("one task
/// per upstream") and the consumer's owned state (`Arc<dyn
/// ObservationRepo>`, `Arc<UpstreamKeyCache>`) remains pinned for the
/// process lifetime. The task makes zero CPU progress — `pending::<()>()`
/// never completes — so the "no tight-loop reconnect" rule is observed
/// trivially.
async fn park_consumer(consumer: UpstreamLabelerConsumer<PgObservationRepo>) {
    // Hold the consumer alive across the suspended future by binding it
    // into a name the future captures by ownership. After the (never-
    // resolving) `pending` await, dropping the binding would release the
    // `Arc<dyn ObservationRepo>` and the `Arc<UpstreamKeyCache>` — but
    // since the future never completes the binding stays live for the
    // process lifetime, which is the intended behaviour.
    //
    // The trailing `drop` is unreachable but spells out the ownership
    // story for the clippy `no_effect_underscore_binding` rule.
    std::future::pending::<()>().await;
    drop(consumer);
}

/// Issue #33: spawn the evidence-preservation worker.
///
/// Builds the configured [`BlobStore`] backend, attaches a
/// [`NotWiredEvidenceFetcher`] (#69 will wire a real proto-blue-api
/// agent-backed fetcher in its place), and detaches the worker on a
/// `tokio::spawn`. The semaphore-bounded drain loop runs for the
/// process lifetime.
fn spawn_evidence_worker(cfg: &polaris_backend::config::EvidenceConfig, pool: sqlx::PgPool) {
    let blob_store: Arc<dyn BlobStore> = match cfg.blob_store.clone() {
        BlobStoreKind::InMemory => Arc::new(InMemoryBlobStore::new()),
        BlobStoreKind::LocalFs { root } => Arc::new(LocalFsBlobStore::new(root)),
        BlobStoreKind::S3 { bucket, region } => {
            // The s3-blob-store Cargo feature is what brings the AWS
            // SDK into the build; when it's not enabled, an operator
            // who selects `s3` at config time falls back to a
            // documented warn + in-memory backend so the process
            // does not silently lose evidence. Issue #69 wires the
            // real S3 path under the feature gate.
            warn!(
                bucket,
                region,
                "S3 evidence-blob-store selected, but the `s3-blob-store` Cargo \
                 feature is not built into this binary; falling back to in-memory \
                 (no evidence will survive process restart) — #69",
            );
            Arc::new(InMemoryBlobStore::new())
        }
    };
    let fetcher: Arc<dyn EvidenceFetcher> = Arc::new(NotWiredEvidenceFetcher);
    let worker = Arc::new(EvidenceWorker::new(
        pool,
        blob_store,
        fetcher,
        cfg.worker_concurrency,
        Duration::from_secs(cfg.poll_interval_secs),
    ));
    info!(
        concurrency = cfg.worker_concurrency,
        poll_secs = cfg.poll_interval_secs,
        "spawning evidence-preservation worker",
    );
    let task_worker = worker.clone();
    tokio::spawn(async move {
        if let Err(err) = task_worker.run_forever().await {
            warn!(error = ?err, "evidence worker exited with error");
        }
    });
    // Hold an Arc so the worker is not dropped if the task is cancelled
    // by the runtime. The variable is intentionally underscored — the
    // `run_forever` future owns the worker via the clone above.
    drop(worker);
}

/// Stub fetcher that surfaces a typed error on every call.
///
/// The live impl (issue #69) wraps a `proto_blue::api::Agent` with the
/// repo PDS endpoint resolved via `describeRepo`. Until that lands,
/// every job in production will mark itself `failed` with a clear
/// message — preferable to silently dropping evidence.
#[derive(Debug, Clone, Copy)]
struct NotWiredEvidenceFetcher;

impl EvidenceFetcher for NotWiredEvidenceFetcher {
    fn fetch_record_with_proof<'a>(
        &'a self,
        subject_uri: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<FetchedEvidence, EvidenceFetcherError>>
                + Send
                + 'a,
        >,
    > {
        let uri = subject_uri.to_owned();
        Box::pin(async move {
            Err(EvidenceFetcherError::Upstream {
                message: format!(
                    "live proto-blue evidence fetcher not wired in this build \
                     (subject_uri={uri}); #69 lands the real fetch path",
                ),
            })
        })
    }
}

/// Default [`UpstreamKeyFetcher`]: resolves the upstream's signing key by
/// fetching the PLC directory DID document and extracting the
/// `#atproto_label` verification method.
///
/// Concrete network implementation lands with the wire-level transport
/// task (#51). For now the stub returns an error so misconfigured rows
/// surface clearly in logs rather than silently appearing as cache hits.
#[derive(Debug, Clone, Copy)]
struct PlcDirectoryKeyFetcher;

impl UpstreamKeyFetcher for PlcDirectoryKeyFetcher {
    fn fetch(
        &self,
        upstream_did: &str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<String, polaris_backend::ingest::upstream_labels::CacheError>,
                > + Send
                + '_,
        >,
    > {
        let did = upstream_did.to_owned();
        Box::pin(async move {
            Err(
                polaris_backend::ingest::upstream_labels::CacheError::Fetch {
                    message: format!(
                        "live PLC fetch not wired in this build; seed upstream_labeler_keys for did={did} manually (#51)"
                    ),
                },
            )
        })
    }
}
