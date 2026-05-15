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

use xtask::{audit_verify, check_frontend_boundary, check_wasm_budget, check_wasm_symbols};

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
    /// Verify that the released wasm artifact contains the proto-blue-lexicon
    /// validation engine (AC-16 of
    /// `.design/polaris-proto-blue-integration.md`, issue #34). Reads the
    /// release bundle at
    /// `target/wasm32-unknown-unknown/release/polaris_frontend.wasm` and
    /// fails if no symbol containing `lexicon` / `Lexicons` / `validate`
    /// is present.
    CheckWasmSymbols,
    /// Assert the released wasm artifact stays under the size budget (#71).
    /// Reads `target/wasm32-unknown-unknown/release/polaris_frontend.wasm`
    /// and fails if raw or gzipped bytes exceed the budget. Defaults: 2 MiB
    /// raw, 500 KiB gzipped. Override via `POLARIS_WASM_BUDGET_BYTES` and
    /// `POLARIS_WASM_GZIP_BUDGET_BYTES`.
    CheckWasmBudget,
    /// Walk the hash-chained audit log against the DB identified by
    /// `DATABASE_URL` and report whether every row's stored hash
    /// matches its recomputed value (issue #35; design.md §6 + §9).
    AuditVerify,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::CheckFrontendBoundary => check_frontend_boundary::run(),
        Command::CheckWasmSymbols => check_wasm_symbols::run(),
        Command::CheckWasmBudget => check_wasm_budget::run(),
        Command::AuditVerify => audit_verify::run(),
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
