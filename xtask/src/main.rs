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

use xtask::{
    audit_verify, check_frontend_boundary, check_wasm_budget, check_wasm_symbols, gen_lexicons,
    lexicon_contract, smoke_local,
};

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
    /// Regenerate `polaris-lexicons/src/generated/` from the Lexicon
    /// JSON sources in `lexicons/polaris/`. Invokes `proto-blue-codegen`
    /// via `cargo run --manifest-path` so no prior installation is
    /// required. The operation is idempotent: running twice yields a
    /// zero diff. The CI diff gate enforces this property (REQ-3 / AC-2
    /// of `.design/m5/42-polaris-nsids.md`).
    GenLexicons,
    /// Fetch Bluesky's published lexicon JSONs at a pinned upstream
    /// commit and re-run Polaris's wire-shape validators against the
    /// fresh schemas (REQ-E2 / AC-E2 of
    /// `.design/polaris-operationally-complete.md`). Drift between the
    /// pin and Polaris's wire expectations fails the task with a
    /// diff-style message naming the lexicon path and the offending
    /// field — the GitHub Actions weekly cron at
    /// `.github/workflows/lexicon-contract.yml` opens an issue on each
    /// failure rather than gating PRs.
    LexiconContract,
    /// Run the producer-slice end-to-end smoke test against the
    /// operator's Docker daemon (REQ-E5 / AC-E5 of
    /// `.design/polaris-operationally-complete.md`). Same hermetic
    /// test the CI `test` job runs (REQ-E4); shells out to
    /// `cargo test -p polaris-backend --test smoke_e2e -- --nocapture`
    /// with `SQLX_OFFLINE=true`. Requires Docker for the
    /// testcontainer Postgres; the test prints a `SKIP` line and
    /// returns cleanly when the daemon is unreachable.
    SmokeLocal,
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::CheckFrontendBoundary => check_frontend_boundary::run(),
        Command::CheckWasmSymbols => check_wasm_symbols::run(),
        Command::CheckWasmBudget => check_wasm_budget::run(),
        Command::AuditVerify => audit_verify::run(),
        Command::GenLexicons => gen_lexicons::run(),
        Command::LexiconContract => lexicon_contract::run(),
        Command::SmokeLocal => smoke_local::run(),
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
