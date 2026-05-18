//! AC-D1: `/readyz` reports `ready`, `signing_key_provisioned`,
//! `last_emit_at`, `db_reachable`, `setup_complete` and transitions
//! correctly across boot → key provisioned → wizard complete.
//!
//! # Why this test exists
//!
//! Workstream D's REQ-D1 introduces a new readiness probe distinct
//! from `/healthz`: the orchestrator should be able to gate traffic
//! to the pod until the signing key is provisioned, while still
//! routing operator clicks through to the setup wizard. The status
//! code shape (200 vs. 503) is what Kubernetes / Compose health
//! checks read; the JSON body is what Prometheus / Grafana scrape.
//!
//! Three sub-tests pin three boundary points along the lifecycle:
//!
//! 1. Stub signer (boot from zero) — `ready=false`, 503.
//! 2. Real signer pushed through the watch channel — `ready=true`, 200.
//!    `setup_complete` is still false (the wizard's PLC step hasn't
//!    run); the orchestrator routes traffic anyway so the operator
//!    can finish the wizard.
//! 3. `polaris_setup_state.did_document_updated_at = now()` —
//!    `ready=true`, `setup_complete=true`, 200.
//!
//! # Carry-over check
//!
//! Implicit in (2): the watch-channel push is observed by the
//! `/readyz` handler. This is the same mechanism Workstream A's
//! `generate_key` uses to push the freshly-loaded signer (REQ-A4 /
//! AC-A4) and the same mechanism Workstream D's emitter reads through
//! on every emit (REQ-A4 carry-over).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7"
)]

use std::process::Command;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::labeler::signer::{SigningKey, stub::StubSigner};
use proto_blue::crypto::{K256Keypair, Keypair as _};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::watch;
use tower::ServiceExt as _;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();
    std::mem::forget(container);
    Ok((database, pool))
}

/// In-memory signer that wraps a freshly-minted K-256 keypair. Used
/// by the post-provisioning sub-tests so the watch-channel push
/// carries a real DID-bearing signer, exactly the way Workstream A's
/// `generate_key` hot-swap would deliver one to the live process.
struct InMemorySigner {
    keypair: K256Keypair,
    did: String,
}

impl std::fmt::Debug for InMemorySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySigner")
            .field("did", &self.did)
            .field("keypair", &"<redacted>")
            .finish()
    }
}

impl InMemorySigner {
    fn generate() -> Self {
        let keypair = K256Keypair::generate();
        let did = keypair.did();
        Self { keypair, did }
    }
}

impl SigningKey for InMemorySigner {
    fn sign(
        &self,
        payload: &[u8],
    ) -> Result<
        polaris_backend::labeler::signer::Signature,
        polaris_backend::labeler::signer::SigningError,
    > {
        use proto_blue::crypto::Signer as _;
        let bytes = self.keypair.sign(payload).map_err(|_| {
            polaris_backend::labeler::signer::SigningError::Sign {
                reason: "in-memory signer failed",
            }
        })?;
        polaris_backend::labeler::signer::Signature::from_bytes(&bytes)
    }

    fn public_key_did(&self) -> &str {
        &self.did
    }
}

/// Wire the production router around an `ApiState` that holds:
///
/// - the supplied active-signer receiver (so the test can swap signers
///   mid-test via the matching sender),
/// - a real testcontainer Postgres pool,
/// - **no** moderator-auth verifier (the readyz route is on the
///   public subtree so the absence is benign).
fn build_router(
    database: db::Db,
    pool: PgPool,
    signer_rx: watch::Receiver<Arc<dyn SigningKey>>,
) -> Router {
    let crypto = Crypto::new([0_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool, sessions).with_active_signer(signer_rx);
    api::router_with_state(database, state)
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the readyz wire shape mirrors ApiState; four booleans is the spec"
)]
#[derive(Debug, serde::Deserialize)]
struct ReadyzBody {
    ready: bool,
    signing_key_provisioned: bool,
    last_emit_at: Option<String>,
    db_reachable: bool,
    setup_complete: bool,
}

async fn hit_readyz(
    router: &Router,
) -> Result<(StatusCode, ReadyzBody), Box<dyn std::error::Error>> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/readyz")
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    let body: ReadyzBody = serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        let snippet = String::from_utf8_lossy(&bytes);
        panic!("readyz body was not valid JSON: {err}; body: {snippet}")
    });
    Ok((status, body))
}

#[tokio::test]
async fn readyz_503_when_signing_key_is_stub() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP readyz_endpoint::readyz_503_when_signing_key_is_stub: no docker.");
        return Ok(());
    }
    let (database, pool) = boot_db().await?;
    let stub_dir = tempfile::tempdir()?;
    let stub_path = stub_dir.path().join("stub.key");
    let stub: Arc<dyn SigningKey> = Arc::new(StubSigner::new(stub_path));
    assert_eq!(
        stub.public_key_did(),
        "",
        "test precondition: StubSigner advertises the empty DID",
    );
    let (_tx, rx) = watch::channel::<Arc<dyn SigningKey>>(stub);
    let router = build_router(database, pool, rx);

    let (status, body) = hit_readyz(&router).await?;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "stub signer → 503 (orchestrator must NOT route traffic to a labeler with no key)",
    );
    assert!(!body.ready, "ready must be false when the key is a stub");
    assert!(
        !body.signing_key_provisioned,
        "signing_key_provisioned must be false when public_key_did is empty",
    );
    assert!(
        body.db_reachable,
        "db_reachable must be true against a freshly-migrated testcontainer Postgres",
    );
    assert!(body.last_emit_at.is_none(), "no labels emitted yet");
    assert!(
        !body.setup_complete,
        "setup_complete must be false: the wizard has not run",
    );
    Ok(())
}

#[tokio::test]
async fn readyz_200_after_signer_pushed_through_watch_channel()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP readyz_endpoint::readyz_200_after_signer_pushed_through_watch_channel: \
             no docker."
        );
        return Ok(());
    }
    let (database, pool) = boot_db().await?;

    // Phase 1: install the stub via the watch channel; assert 503.
    let stub_dir = tempfile::tempdir()?;
    let stub_path = stub_dir.path().join("stub.key");
    let stub: Arc<dyn SigningKey> = Arc::new(StubSigner::new(stub_path));
    let (tx, rx) = watch::channel::<Arc<dyn SigningKey>>(stub);
    let router = build_router(database, pool.clone(), rx);

    let (status, body) = hit_readyz(&router).await?;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!body.ready);

    // Phase 2: push a real signer through the watch sender — the
    // same mechanism the wizard's `generate_key` handler uses (REQ-A4).
    let real = InMemorySigner::generate();
    let real_did = real.did.clone();
    assert!(!real_did.is_empty(), "real signer must advertise a DID");
    let real_arc: Arc<dyn SigningKey> = Arc::new(real);
    tx.send(real_arc)
        .expect("watch channel must accept the push");

    let (status, body) = hit_readyz(&router).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "real signer + reachable DB → ready=true → 200",
    );
    assert!(body.ready, "ready must be true after the swap");
    assert!(
        body.signing_key_provisioned,
        "signing_key_provisioned must be true once the DID is non-empty",
    );
    assert!(body.db_reachable);
    assert!(
        !body.setup_complete,
        "setup_complete must still be false: the wizard's PLC step has not run",
    );
    Ok(())
}

#[tokio::test]
async fn readyz_setup_complete_flips_when_did_document_updated_at_set()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP readyz_endpoint::readyz_setup_complete_flips_when_did_document_updated_at_set: \
             no docker."
        );
        return Ok(());
    }
    let (database, pool) = boot_db().await?;
    let real = InMemorySigner::generate();
    let arc: Arc<dyn SigningKey> = Arc::new(real);
    let (_tx, rx) = watch::channel::<Arc<dyn SigningKey>>(arc);
    let router = build_router(database, pool.clone(), rx);

    // Pre-condition: ready=true, setup_complete=false.
    let (status, body) = hit_readyz(&router).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(body.ready);
    assert!(!body.setup_complete);

    // Simulate the wizard's PLC step landing: stamp the column.
    sqlx::query("UPDATE polaris_setup_state SET did_document_updated_at = now() WHERE id = TRUE")
        .execute(&pool)
        .await?;

    let (status, body) = hit_readyz(&router).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "ready remains true; setup_complete is informational",
    );
    assert!(body.ready);
    assert!(
        body.setup_complete,
        "setup_complete must be true once did_document_updated_at is NOT NULL",
    );
    Ok(())
}
