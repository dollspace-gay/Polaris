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
use axum_prometheus::PrometheusMetricLayer;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::BlobStoreKind;
use polaris_backend::evidence::{
    BlobStore, EvidenceFetcher, EvidenceWorker, InMemoryBlobStore, LiveEvidenceFetcher,
    LocalFsBlobStore,
};
use polaris_backend::federation;
use polaris_backend::ingest::aggregator::{AggregatorConfig, ReportAggregator};
use polaris_backend::ingest::upstream_labels::{
    self, UpstreamKeyCache, UpstreamKeyFetcher, UpstreamLabelerConsumer,
};
use polaris_backend::labeler::emitter::LabelEmitter;
use polaris_backend::labeler::rotation::{CustodyMode, bootstrap_active_key};
use polaris_backend::labeler::signer::{SigningKey, build_signing_key};
use polaris_backend::repo::PgObservationRepo;
use polaris_backend::{api, config::AppConfig, db};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Polaris backend starting"
    );

    // Workstream D / REQ-D2: install the Prometheus recorder ONCE,
    // BEFORE the router is built, so the `axum-prometheus` middleware
    // and the in-handler `metrics::counter!` / `metrics::gauge!`
    // emissions both route to the same recorder. `install_recorder`
    // sets the global recorder and returns the handle the `/metrics`
    // endpoint renders; `install` (no underscore) would also spawn an
    // HTTP server we don't want.
    let (prometheus_layer, prometheus_handle) = PrometheusMetricLayer::pair();
    let prometheus_handle = Arc::new(prometheus_handle);
    info!("Prometheus recorder installed; /metrics will serve text exposition");

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
    // one at runtime. Installed onto `ApiState` below so the
    // `/auth/atproto/{login,callback}` handlers (issue #67) can drive
    // the verifier through `ApiState::moderator_auth`. The OIDC
    // counterpart shares the same accessor surface
    // ([`AnyModeratorAuth::as_atproto`] / a future `as_oidc`) so the
    // handler shape stays uniform across backends.
    let moderator_auth = polaris_backend::auth::build_moderator_auth(
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

    // Build the active-signer slot. The Sender is promoted onto
    // `ApiState` (REQ-A4) so the setup wizard's
    // `POST /api/setup/generate-key` handler can hot-swap the
    // freshly-loaded signer through the same channel the rotation-
    // discovery task uses. The Receiver is handed to ApiState for
    // read access.
    let (signer_tx, signer_rx) = watch::channel::<Arc<dyn SigningKey>>(signer.clone());
    let signer_tx = Arc::new(signer_tx);

    // Assemble ApiState with the emitter installed. `api::router`'s
    // public signature takes `(Db, SessionStore, PatternActionsConfig)`
    // and constructs its own ApiState internally; we build state here
    // so the emitter can be wired in, then call the state-taking
    // router constructor.
    let api_state = ApiState::with_config(db.pool().clone(), sessions, cfg.pattern_actions);
    // REQ-A4 / Workstream A carry-over: build the emitter around the
    // **receiver** half of the active-signer channel so every emit
    // reads through to the live signer. The receiver and the matching
    // sender (held below via `with_active_signer_tx`) share one
    // channel; the wizard's `generate_key` handler pushes a real
    // `FilePlainSigner` through the sender and the next emit sees it
    // without a process restart. `signer` (the initial value) is
    // already inside the channel.
    let _ = signer; // initial value lives inside the watch channel
    let emitter = Arc::new(LabelEmitter::with_active_signer(
        signer_rx.clone(),
        db.pool().clone(),
        api_state.label_broadcaster.clone(),
    ));
    // Issue #81: serve the operator's OAuth client_metadata.json at
    // `/oauth/client-metadata.json` so the same Polaris process can be
    // the URL declared as `client_id` in the atproto OAuth flow. The
    // payload is loaded once at startup from the operator-configured
    // path; if the operator did not configure the atproto backend
    // (e.g. OIDC-only deploy), `client_metadata` is the empty cache
    // and the route returns 404.
    let oauth_client_metadata = {
        let path = &cfg.auth.atproto.client_metadata_path;
        if path.as_os_str().is_empty() {
            polaris_backend::api::oauth_metadata::ClientMetadataState::empty()
        } else {
            match polaris_types::oauth_config::load_client_metadata(path) {
                Ok(md) => {
                    polaris_backend::api::oauth_metadata::ClientMetadataState::from_metadata(&md)
                }
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        path = ?path,
                        "could not load OAuth client metadata at startup; /oauth/client-metadata.json will return 404"
                    );
                    polaris_backend::api::oauth_metadata::ClientMetadataState::empty()
                }
            }
        }
    };

    // Hold one extra reference so the channel cannot close even if a
    // future refactor drops the `ApiState`-borne handle. The
    // rotation-discovery task (#65) will eventually own this binding;
    // until then it lives for the process lifetime.
    let _signer_tx_keepalive = Arc::clone(&signer_tx);
    let api_state = api_state
        .with_label_emitter(emitter)
        .with_active_signer(signer_rx)
        .with_active_signer_tx(signer_tx)
        .with_moderator_auth(moderator_auth)
        .with_oauth_client_metadata(oauth_client_metadata)
        // Issue #85: the setup wizard's generate-key handler picks its
        // output path from `state.labeler_signing_key_cfg`. Without
        // this wire-through the handler falls back to the
        // `LabelerSigningKeyConfig::default()` sentinel
        // (`/etc/polaris/labeler.key`) and a non-root operator hits
        // `Permission denied` on `create_dir_all`. Thread the
        // env-parsed config through so the wizard writes the key to
        // the same path the labeler subsystem already loaded at boot.
        .with_labeler_signing_key_cfg(cfg.labeler.signing_key.clone())
        // Workstream D / REQ-D2: thread the Prometheus handle onto
        // the state so the `/metrics` handler can render it. The
        // recorder itself was set globally above via
        // `PrometheusMetricLayer::pair()`; the handle is the read
        // side of the recorder and is `Arc`-cloneable.
        .with_metrics_handle(Arc::clone(&prometheus_handle));

    // Issue #32: spawn one per-upstream subscribeLabels consumer for every
    // `upstream_labelers WHERE enabled = TRUE` row. Each task is detached
    // (`tokio::spawn`) and owns its own cursor by value; the in-memory
    // signing-key cache is shared via the documented `UpstreamKeyCache`.
    // Failures are isolated per-upstream — a misbehaving upstream cannot
    // wedge the HTTP server.
    spawn_upstream_labeler_consumers(db.pool().clone()).await;

    // Issue #33 + #70: spawn the evidence-preservation worker.
    // Bounded concurrency via `tokio::sync::Semaphore` inside the
    // worker. The fetcher is a [`LiveEvidenceFetcher`] backed by
    // proto-blue's typed `com.atproto.sync.getRecord` binding (#70);
    // PDS endpoints are resolved on demand through the
    // [`proto_blue::identity::IdResolver`]. The blob store is selected
    // by config. The spawn is detached: the worker runs for the
    // process lifetime and a fatal error logs at WARN before exiting
    // the task.
    spawn_evidence_worker(&cfg.evidence, db.pool().clone()).await;

    // Issue #75: spawn the report-aggregation worker. The detached
    // task walks reports with `incident_id IS NULL`, groups them by
    // `subject_id`, and binds each batch to a fresh or existing
    // incident under SKIP LOCKED — so multiple replicas can drain in
    // parallel without stepping on each other. A failure inside the
    // tick is logged and the loop continues; the only way the worker
    // exits is task abort. See design.md §9 #4 (T4 mitigation).
    spawn_report_aggregator(&cfg.aggregator, db.pool().clone());

    // Issue #107 / M5 PR 1: spawn the federation worker if enabled. The
    // supervisor manages one per-peer Firehose task and drains the JoinSet
    // until cancellation. The CancellationToken is created here and held
    // for the process lifetime so SIGINT propagates gracefully.
    let _fed_cancel = spawn_federation_worker_if_enabled(&cfg.federation, db.pool().clone());

    // Layer the auto-instrumenting `axum-prometheus` middleware on
    // the merged router so every request fires
    // `axum_http_requests_total{method,endpoint,status}` +
    // the duration histogram. The recorder set globally above
    // captures both these series and the hand-emitted
    // `polaris_*_total` counters.
    let app = api::router_with_state(db, api_state).layer(prometheus_layer);

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

/// Issue #33 + #70: spawn the evidence-preservation worker.
///
/// Builds the configured [`BlobStore`] backend, attaches a live
/// [`LiveEvidenceFetcher`] (#70 — typed `proto_blue::api::com::atproto::
/// sync::get_record` over a shared `reqwest` transport, PDS endpoints
/// resolved on demand via `proto_blue::identity::IdResolver`), and
/// detaches the worker on a `tokio::spawn`. The semaphore-bounded
/// drain loop runs for the process lifetime.
///
/// The function is `async` because the `BlobStoreKind::S3` arm
/// constructs an `aws_sdk_s3::Client` through
/// `aws_config::defaults(...).load().await`, which resolves
/// credentials via the SDK's default chain (env vars → shared config
/// → IMDS → SSO) and may make an asynchronous IMDS lookup on
/// EC2-hosted deployments. The other arms (`InMemory`, `LocalFs`) are
/// trivially sync; the function never suspends in those branches.
async fn spawn_evidence_worker(cfg: &polaris_backend::config::EvidenceConfig, pool: sqlx::PgPool) {
    let blob_store: Arc<dyn BlobStore> = match cfg.blob_store.clone() {
        BlobStoreKind::InMemory => Arc::new(InMemoryBlobStore::new()),
        BlobStoreKind::LocalFs { root } => Arc::new(LocalFsBlobStore::new(root)),
        BlobStoreKind::S3 { bucket, region } => build_s3_blob_store(bucket, region).await,
    };
    let fetcher: Arc<dyn EvidenceFetcher> = Arc::new(LiveEvidenceFetcher::with_default_transport());
    let worker = Arc::new(EvidenceWorker::with_retry_policy(
        pool,
        blob_store,
        fetcher,
        cfg.worker_concurrency,
        Duration::from_secs(cfg.poll_interval_secs),
        cfg.max_attempts,
        cfg.retry_base_secs,
    ));
    info!(
        concurrency = cfg.worker_concurrency,
        poll_secs = cfg.poll_interval_secs,
        max_attempts = cfg.max_attempts,
        retry_base_secs = cfg.retry_base_secs,
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

/// Issue #75: spawn the report-aggregation worker.
///
/// Translates [`polaris_backend::config::AggregatorEnvConfig`] into a
/// runtime [`AggregatorConfig`] (which clamps pathological values to
/// safe minima inside the constructor) and detaches the worker on a
/// `tokio::spawn`. The worker holds the pool by value; `PgPool` is
/// internally `Arc`-shared so the clone is cheap.
///
/// The function is synchronous because the worker constructor never
/// awaits — only the spawned future does. The spawn is intentionally
/// fire-and-forget: the `run` loop is `! `-returning and folds every
/// fallible step into a WARN log so a transient DB failure cannot
/// terminate the task.
fn spawn_report_aggregator(cfg: &polaris_backend::config::AggregatorEnvConfig, pool: sqlx::PgPool) {
    let aggregator_cfg = AggregatorConfig {
        batch_size: cfg.batch_size,
        poll_interval: Duration::from_secs(cfg.poll_interval_secs),
        window_secs: cfg.window_secs,
    };
    info!(
        batch_size = cfg.batch_size,
        poll_interval_secs = cfg.poll_interval_secs,
        window_secs = cfg.window_secs,
        "spawning report aggregator",
    );
    let aggregator = ReportAggregator::new(pool, aggregator_cfg);
    tokio::spawn(aggregator.run());
}

/// Issue #107 / M5 PR 1: conditionally spawn the federation supervisor.
///
/// When `config.federation.enabled = true` this creates a shared
/// [`CancellationToken`] and spawns the federation supervisor via
/// [`federation::spawn_federation_worker`]. The token is returned so the
/// caller can hold it for the process lifetime and cancel it on SIGINT.
///
/// When federation is disabled the function is a no-op that returns a dummy
/// token (never cancelled).
fn spawn_federation_worker_if_enabled(
    cfg: &polaris_backend::config::FederationConfig,
    pool: sqlx::PgPool,
) -> CancellationToken {
    let cancel = CancellationToken::new();

    if !cfg.enabled {
        info!("federation disabled (POLARIS_FEDERATION_ENABLED not set); skipping");
        return cancel;
    }

    info!(
        peer_count = cfg.peers.len(),
        key_cache_ttl_secs = cfg.public_key_cache_ttl_secs,
        "federation enabled; spawning supervisor",
    );

    let _handle = federation::spawn_federation_worker(cfg.clone(), pool, cancel.clone());
    // The handle is intentionally dropped: the supervisor runs for the
    // process lifetime and we rely on the CancellationToken (returned to
    // the caller) for co-operative shutdown. The handle is held by the
    // tokio runtime until SIGINT fires and the token is cancelled by the
    // operator's process manager (e.g. `docker stop`, `systemctl stop`).
    cancel
}

/// Construct the [`S3BlobStore`] backend from configuration (#68).
///
/// Resolves credentials through the AWS SDK's **default credential
/// chain**: env vars (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
/// `AWS_SESSION_TOKEN`) → shared config (`~/.aws/credentials`,
/// `AWS_PROFILE`) → container-/EC2-IMDS → SSO. Plaintext credentials
/// **never** appear in argv or in this code path; the SDK reads them
/// from the process environment / instance metadata.
///
/// The function consumes the configured bucket + region pair and
/// returns an `Arc<dyn BlobStore>` ready to hand to
/// [`crate::evidence::EvidenceWorker`]. Endpoint URL is left
/// AWS-default; operators pointing at a non-AWS S3-compatible store
/// (minio, R2, …) drive that via the AWS SDK's `AWS_ENDPOINT_URL_S3`
/// env var, which `aws_config::defaults(...).load()` honours.
#[cfg(feature = "s3-blob-store")]
async fn build_s3_blob_store(bucket: String, region: String) -> Arc<dyn BlobStore> {
    info!(
        bucket = %bucket,
        region = %region,
        "constructing S3 evidence-blob-store via AWS SDK default credential chain",
    );
    let region_owned = aws_sdk_s3::config::Region::new(region);
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(region_owned)
        .load()
        .await;
    let client = aws_sdk_s3::Client::new(&sdk_config);
    Arc::new(polaris_backend::evidence::S3BlobStore::new(client, bucket))
}

/// Fallback for builds without the `s3-blob-store` feature flag.
///
/// When the operator selects `BlobStoreKind::S3` at config time but
/// the binary was built without `--features s3-blob-store`, we log a
/// WARN and fall back to an in-memory store. This is intentionally
/// fail-loud: the evidence will not survive process restart, but the
/// process boots so the rest of the labeler stays available. An
/// operator who genuinely wants S3 must rebuild with the feature.
///
/// The `async` qualifier on the signature is load-bearing — it
/// matches the feature-enabled arm so the caller's `.await` compiles
/// regardless of feature selection. clippy's
/// `unused_async` would fire on this body alone; the allow is
/// justified because the qualifier is part of the cross-cfg API
/// contract, not a developer mistake.
#[cfg(not(feature = "s3-blob-store"))]
#[allow(
    clippy::unused_async,
    reason = "signature matches the s3-blob-store-enabled arm for cross-cfg dispatch"
)]
async fn build_s3_blob_store(bucket: String, region: String) -> Arc<dyn BlobStore> {
    warn!(
        bucket = %bucket,
        region = %region,
        "S3 evidence-blob-store selected, but the `s3-blob-store` Cargo \
         feature is not built into this binary; falling back to in-memory \
         (no evidence will survive process restart)",
    );
    Arc::new(InMemoryBlobStore::new())
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
