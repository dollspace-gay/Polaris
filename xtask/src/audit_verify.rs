//! `cargo xtask audit-verify` — walk the audit-log chain end-to-end
//! (issue #35; design.md §6 + §9).
//!
//! Connects to the database identified by `DATABASE_URL`, calls
//! [`polaris_backend::audit::verify_chain`], and exits 0 on a clean
//! walk or 1 with a precise diagnostic if a row's stored hash does not
//! match the recomputed value.

use anyhow::{Context as _, Result, anyhow};

/// Run the audit-verify subcommand.
///
/// # Errors
///
/// - Returns the `DATABASE_URL` error when the env var is unset.
/// - Returns a wrapped `sqlx::Error` for any underlying DB failure.
/// - Returns the chain-tampered diagnostic when verification fails.
pub fn run() -> Result<()> {
    let url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL env var must be set to run audit-verify")?;

    // xtask is a sync entrypoint; spin up a per-call tokio runtime so
    // the async sqlx + audit calls have somewhere to run.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not build tokio runtime for audit-verify")?;

    rt.block_on(async move {
        let pool = sqlx::PgPool::connect(&url)
            .await
            .context("could not connect to DATABASE_URL")?;

        match polaris_backend::audit::verify_chain(&pool).await {
            Ok(head) => {
                println!("audit-verify: chain clean through seq {head}");
                Ok(())
            }
            Err(err) => Err(anyhow!("audit-verify: chain tampered: {err}")),
        }
    })
}
