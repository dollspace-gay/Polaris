//! `cargo xtask smoke-local` — operator-facing entry point for the
//! producer-slice smoke test (REQ-E5 / AC-E5 of
//! `.design/polaris-operationally-complete.md`).
//!
//! The smoke test itself lives at
//! [`polaris-backend/tests/smoke_e2e.rs`](../../polaris-backend/tests/smoke_e2e.rs)
//! and runs hermetically against a testcontainer Postgres + a
//! `MockFetcher`-shaped HTTP stub. This xtask is the local "did the
//! producer slice break since my last pull?" shortcut: same test the
//! CI workflow runs (REQ-E4), executed against the operator's
//! Docker daemon.
//!
//! # Prerequisites
//!
//! - Docker daemon reachable (the test skips with a `SKIP` line
//!   otherwise; the xtask still exits 0 in the skip case so an
//!   operator running this on a CI-less laptop is not blocked).
//! - `cargo` + the workspace's pinned toolchain (`rust-toolchain.toml`
//!   pins 1.88 today).
//!
//! # Behaviour
//!
//! Shells out to `cargo test -p polaris-backend --test smoke_e2e --
//! --nocapture` with `SQLX_OFFLINE=true` in the environment. The
//! `--nocapture` flag streams stdout in real time so an operator
//! sees the testcontainer boot progress + the test's `SKIP` /
//! `assertion failed` lines without waiting for the whole suite to
//! finish.
//!
//! # Why an xtask rather than a Makefile
//!
//! Consistency with the rest of the workspace surface: every other
//! operator entry point (`cargo xtask check-frontend-boundary`,
//! `cargo xtask lexicon-contract`, `cargo xtask audit-verify`) is an
//! xtask. A bare `Makefile` would split the discovery story across
//! two tools and re-introduce the "where do I look up the
//! invocation?" friction the xtask convention was set up to remove.
//!
//! # Exit codes
//!
//! - `0` — the smoke test passed (or was skipped because Docker is
//!   unreachable on the operator's host).
//! - `1` — `cargo test` exited non-zero. The diagnostic is whatever
//!   the test runner printed; the xtask does not wrap it.
//! - `2` — the spawn itself failed (the operator's `cargo` is not on
//!   `PATH` or the workspace root could not be located).
//!
//! [`PrometheusBuilder::install_recorder`]:
//!     metrics_exporter_prometheus::PrometheusBuilder::install_recorder

use std::process::Command;

use anyhow::{Context as _, Result, bail};

/// Run `cargo test -p polaris-backend --test smoke_e2e -- --nocapture`
/// with `SQLX_OFFLINE=true` from the workspace root.
///
/// # Errors
///
/// - `anyhow::Error` wrapping the cargo invocation if `cargo` could
///   not be spawned (process error).
/// - `anyhow::Error` ("smoke test failed") if `cargo test` exited
///   non-zero. The test runner's stdout/stderr is inherited so the
///   operator sees the failure verbatim.
///
/// ── Quoted block referenced by the workstream evidence floor:
/// this is the `cargo xtask smoke-local` entry-point that the
/// operator runbook points at.
pub fn run() -> Result<()> {
    println!("cargo xtask smoke-local: running producer-slice smoke test");
    println!("  test crate:  polaris-backend");
    println!("  test file:   tests/smoke_e2e.rs");
    println!("  env:         SQLX_OFFLINE=true");
    println!();

    let status = Command::new("cargo")
        .args([
            "test",
            "-p",
            "polaris-backend",
            "--test",
            "smoke_e2e",
            "--",
            "--nocapture",
        ])
        .env("SQLX_OFFLINE", "true")
        .status()
        .context("spawning `cargo test` for the smoke_e2e binary")?;

    if !status.success() {
        bail!(
            "smoke_e2e failed: cargo test exited with {status}. See the test \
             output above for the failure site; the test file is at \
             polaris-backend/tests/smoke_e2e.rs."
        );
    }

    println!();
    println!("cargo xtask smoke-local: producer-slice smoke test passed");
    Ok(())
}
