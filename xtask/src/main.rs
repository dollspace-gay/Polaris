//! Polaris workspace automation tasks.
//!
//! Invoked via the `cargo xtask` alias defined in `.cargo/config.toml`.
//!
//! # Usage
//!
//! ```text
//! cargo xtask --help
//! cargo xtask check-frontend-boundary
//! ```

use clap::{Parser, Subcommand};

use xtask::check_frontend_boundary;

/// Polaris workspace automation tasks.
#[derive(Debug, Parser)]
#[command(
    name = "xtask",
    about = "Polaris workspace automation — run via `cargo xtask <subcommand>`",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available xtask subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Verify that polaris-frontend contains no references to Polaris mutating
    /// endpoints or internal backend modules (AC-7 of
    /// `.design/polaris-proto-blue-integration.md`).
    CheckFrontendBoundary,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::CheckFrontendBoundary => check_frontend_boundary::run(),
    };

    if let Err(err) = result {
        // `{:#}` walks the anyhow error chain so the operator sees every
        // wrapped context layer on a single line. Exit code 1 is what CI
        // gates on; emitting the chain on stderr keeps stdout free of
        // diagnostic noise when the command is invoked from a script.
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
