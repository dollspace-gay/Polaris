//! AC-A5: with an empty database and no labeler key file on disk,
//! `polaris-backend` must boot, the production router must come up,
//! `/healthz`, `/setup`, and `/oauth/client-metadata.json` must all
//! respond `200 OK`.
//!
//! # Why this test exists
//!
//! Before REQ-A2 / REQ-A5 the `build_signing_key` factory propagated
//! `SigningError::KeyLoad` straight to the binary's exit code whenever
//! the configured signing-key file was missing — which is exactly the
//! state of a fresh deployment before the operator has run the setup
//! wizard. The smoke session against `polarislabeler.bsky.social`
//! caught the chicken-and-egg: the operator can't reach the wizard at
//! `/setup` because the binary refuses to boot, and the wizard's
//! `POST /api/setup/generate-key` is what would write the file.
//!
//! This test pins the boot-from-zero invariant so the regression
//! cannot land again.
//!
//! # What it does NOT assert
//!
//! The labeler subsystem is intentionally NOT wired in this test: the
//! goal is "router serves the three setup-facing routes". The hot-
//! swap path is covered by `tests/generate_key_hot_swaps_signer.rs`;
//! the precondition gate is covered by
//! `tests/action_blocked_before_provisioning.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7"
)]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use polaris_backend::api;
use polaris_backend::api::oauth_metadata::ClientMetadataState;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::{DbConfig, LabelerSigningKeyConfig, Profile};
use polaris_backend::db;
use polaris_backend::labeler::signer::build_signing_key;
use polaris_types::oauth_config::ClientMetadata;
use sqlx::PgPool;
use tempfile::TempDir;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;

/// Probe for a working Docker daemon. Mirrors every other integration
/// test in this crate so the skip behaviour is uniform.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the
/// `(db, pool)` pair. The container handle is leaked so its Drop
/// runs at process exit.
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

/// Owns the `TempDir`s that back the test's "no key file on disk" +
/// "frontend bundle dir" fixtures. Held by the caller for the
/// duration of the request so the temp directories survive past the
/// `Router` construction call.
struct BootFromZeroFixture {
    router: Router,
    /// Kept on the fixture so a future assertion can run a SQL probe
    /// against the same migrated database the router talks to; the
    /// current three tests only need the router but the pool clone
    /// is cheap (`PgPool` is internally `Arc`-shared).
    #[allow(
        dead_code,
        reason = "kept for future SQL-probe assertions; PgPool clone is cheap"
    )]
    pool: PgPool,
    _signing_key_tmp: TempDir,
    _frontend_tmp: TempDir,
}

/// Build the production router around a fresh `ApiState` with NO key
/// file on disk — the build-from-zero posture. The labeler signer
/// factory must resolve to a `StubSigner` (REQ-A2) and the router
/// must come up regardless.
///
/// A minimal polaris-frontend bundle directory is wired in via
/// [`ApiState::with_frontend_dist`] so the SPA fallback resolves
/// `/setup` to a 200. Tests that don't want the SPA fallback can
/// skip the wire-up and accept the 404 that results.
async fn boot_zero_state_router() -> Result<BootFromZeroFixture, Box<dyn std::error::Error>> {
    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([0_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);

    // Point the labeler at a path that does NOT exist — this is the
    // "the operator hasn't run the wizard yet" posture. REQ-A2 says
    // `build_signing_key` must return Ok(StubSigner) here, NOT propagate
    // a `KeyLoad` error.
    let signing_key_tmp = tempfile::tempdir()?;
    let signing_key_path = signing_key_tmp.path().join("not-yet-provisioned.key");
    assert!(
        !signing_key_path.exists(),
        "test precondition: signing-key path must NOT exist on disk",
    );
    let signing_key_cfg = LabelerSigningKeyConfig::FilePlain {
        path: signing_key_path,
    };

    // Drive the factory exactly the same way `main.rs` does. The
    // assertion below pins REQ-A2 at the unit-of-factory level so the
    // test fails loud if anyone regresses the missing-file substitution.
    let signer = build_signing_key(&signing_key_cfg, Profile::Labeler)
        .expect("REQ-A2: factory must return a stub signer for a missing-file path");
    assert_eq!(
        signer.public_key_did(),
        "",
        "REQ-A1: stub signer must advertise the empty DID",
    );
    // Hold the signer alive on the test stack — it's not threaded
    // through ApiState in this minimal fixture because we are not
    // exercising the emit path. The Arc keeps it from being dropped.
    let _signer_keepalive: Arc<_> = signer;

    // Install a non-empty OAuth client-metadata payload so the
    // `/oauth/client-metadata.json` route does not fall back to 404.
    let metadata = ClientMetadata {
        client_id: "https://polaris.example/client.json".to_owned(),
        redirect_uris: vec!["https://polaris.example/auth/atproto/callback".to_owned()],
        response_types: Some(vec!["code".to_owned()]),
        grant_types: Some(vec![
            "authorization_code".to_owned(),
            "refresh_token".to_owned(),
        ]),
        scope: Some("atproto transition:generic".to_owned()),
        token_endpoint_auth_method: Some("none".to_owned()),
        token_endpoint_auth_signing_alg: None,
        application_type: Some("web".to_owned()),
        dpop_bound_access_tokens: Some(true),
        client_name: Some("Polaris (boot-from-zero test)".to_owned()),
        client_uri: None,
        logo_uri: None,
    };
    let oauth_metadata = ClientMetadataState::from_metadata(&metadata);

    // Minimal SPA bundle: just an index.html. The SPA fallback in
    // `api::router_with_state` serves this for any non-API path,
    // including `/setup`.
    let frontend_tmp = tempfile::tempdir()?;
    let index_path = frontend_tmp.path().join("index.html");
    std::fs::write(
        &index_path,
        "<!doctype html><html><body>Setup</body></html>",
    )?;
    let frontend_dist: PathBuf = frontend_tmp.path().to_path_buf();

    let state = ApiState::new(pool.clone(), sessions)
        .with_labeler_signing_key_cfg(signing_key_cfg)
        .with_oauth_client_metadata(oauth_metadata)
        .with_frontend_dist(frontend_dist);

    let router = api::router_with_state(database, state);
    Ok(BootFromZeroFixture {
        router,
        pool,
        _signing_key_tmp: signing_key_tmp,
        _frontend_tmp: frontend_tmp,
    })
}

// ── /healthz returns 200 ────────────────────────────────────────────────

#[tokio::test]
async fn boot_from_zero_serves_healthz() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP boot_from_zero::boot_from_zero_serves_healthz: docker daemon not reachable");
        return Ok(());
    }
    let fixture = boot_zero_state_router().await?;

    let response = fixture
        .router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/healthz must return 200 OK on a freshly-booted zero-state Polaris",
    );
    Ok(())
}

// ── /oauth/client-metadata.json returns 200 ─────────────────────────────

#[tokio::test]
async fn boot_from_zero_serves_oauth_client_metadata() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP boot_from_zero::boot_from_zero_serves_oauth_client_metadata: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let fixture = boot_zero_state_router().await?;

    let response = fixture
        .router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/oauth/client-metadata.json")
                .body(Body::empty())?,
        )
        .await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/oauth/client-metadata.json must return 200 OK when an operator metadata payload is installed",
    );
    Ok(())
}

// ── /setup falls through to the SPA bundle → 200 ────────────────────────
//
// `boot_zero_state_router` installs a minimal frontend-bundle
// directory via [`ApiState::with_frontend_dist`]; the production SPA
// fallback (`tower_http::ServeDir` + `ServeFile` index.html) serves
// the bundle for any non-API path including `/setup`. The fixture
// `index.html` holds an empty `<html>` so this test asserts the
// routing, not the bundle's contents.

#[tokio::test]
async fn boot_from_zero_serves_setup_via_spa_fallback() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP boot_from_zero::boot_from_zero_serves_setup_via_spa_fallback: \
             docker daemon not reachable"
        );
        return Ok(());
    }
    let fixture = boot_zero_state_router().await?;

    let response = fixture
        .router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/setup")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/setup must fall through to the SPA bundle and return 200",
    );
    Ok(())
}
