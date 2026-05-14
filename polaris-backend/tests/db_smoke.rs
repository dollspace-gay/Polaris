//! Database smoke test: spin up Postgres via testcontainers, connect, run
//! migrations, and ping.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable on the host, the test prints a clear skip
//! message and returns successfully. The compile-time requirement
//! (`cargo test -p polaris-backend --no-run --tests`) ALWAYS passes — only
//! the runtime is environment-dependent. This matches the architect's
//! pre-flight: "Test is `#[tokio::test]` ... If Docker absent, the test
//! prints a clear skip message and `return Ok(())`."

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// Probe for a working Docker daemon. We deliberately avoid pulling in a
/// Docker client crate just for this — the `docker info` exit code is the
/// canonical signal, and the test environment either has the CLI on PATH or
/// it doesn't.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn connect_runs_migrations_and_ping_succeeds() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP db_smoke: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service to exercise this test."
        );
        return Ok(());
    }

    // Start a fresh Postgres 16 container with default credentials baked
    // into the module image. testcontainers-modules handles waiting for
    // readiness before returning. The `16-alpine` tag is explicit so the
    // generated `body_tsv` column from migration 11 (which requires
    // Postgres ≥ 12) applies cleanly; the module's default tag is
    // `11-alpine` which would reject the migration.
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;

    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };

    // Connect = migrate. A successful return value implies the
    // `_polaris_schema_version` table exists at version 1.
    let db = db::connect(&cfg).await?;

    // Ping proves the pool can hand out connections post-migration.
    db.ping().await?;

    Ok(())
}
