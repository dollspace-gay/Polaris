//! Firehose cursor persistence: integration test for issue #12.
//!
//! Verifies the cursor-flush path against a live Postgres (testcontainers).
//! The worker exposes [`load_cursor`] / [`flush_cursor`] as `pub(crate)`
//! helpers so this test can exercise the durable-state contract directly,
//! without standing up a WebSocket fixture for the firehose stream.
//!
//! What this test proves:
//!
//! 1. A fresh database (post-migrations) reports cursor `0` — the worker
//!    will start the relay subscription at `?cursor=0`.
//! 2. `flush_cursor` upserts the single-row table and `load_cursor`
//!    observes the new value on a subsequent connection.
//! 3. The DB-side `WHERE firehose_cursor.seq < EXCLUDED.seq` guard
//!    enforces monotonicity: a stale writer cannot rewind the cursor.
//!
//! What this test does **not** prove:
//!
//! - The reconnect / replay path — that's `tests/firehose_reconnect.rs`.
//! - The decode pipeline — `proto-blue-repo`'s unit tests cover that.
//!
//! # Skip behaviour
//!
//! If Docker is unreachable the test prints a clear skip message and
//! returns `Ok(())`, matching the pattern in `tests/db_smoke.rs`. The
//! compile-time check (`cargo test --no-run`) ALWAYS passes — only the
//! runtime is environment-dependent.

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::ingest::firehose;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

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
async fn cursor_load_and_flush_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP firehose_cursor_persistence: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test.",
        );
        return Ok(());
    }

    // Postgres 16-alpine: migration 11 needs generated columns (PG ≥ 12).
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;

    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool();

    // Fresh DB: no row yet → cursor reads as 0.
    let initial = firehose::load_cursor(pool).await?;
    assert_eq!(initial, 0, "fresh DB cursor should be 0");

    // Forward progress: a flush at seq=42 should be observable on the
    // very next load.
    firehose::flush_cursor(pool, 42).await?;
    assert_eq!(firehose::load_cursor(pool).await?, 42);

    // Forward progress again: a flush at seq=1000 supersedes the prior
    // value.
    firehose::flush_cursor(pool, 1000).await?;
    assert_eq!(firehose::load_cursor(pool).await?, 1000);

    // Rewind attempt: a flush at seq=10 must NOT lower the persisted
    // cursor. The DB-side `WHERE … < EXCLUDED.seq` guard enforces this.
    firehose::flush_cursor(pool, 10).await?;
    assert_eq!(
        firehose::load_cursor(pool).await?,
        1000,
        "stale writer must not rewind the cursor",
    );

    // Idempotent re-flush at the current value: no-op (the upsert's
    // WHERE clause excludes equal `seq`), but `load_cursor` still
    // returns the same value.
    firehose::flush_cursor(pool, 1000).await?;
    assert_eq!(firehose::load_cursor(pool).await?, 1000);

    Ok(())
}
