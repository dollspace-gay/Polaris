//! `labeler-key-rotate` — one-command labeler signing-key rotation
//! (issue #30, REQ-12, AC-15).
//!
//! Drives the [`polaris_backend::labeler::rotation`] state machine
//! through a complete rotation cycle. The CLI is the operator-side
//! interface; the underlying state machine is reusable from tests
//! (the AC-15 binding test invokes it directly).
//!
//! # Exit codes
//!
//! - `0` — success (rotation completed or `--dry-run` printed).
//! - `1` — user error (bad flags, missing files, unsupported mode).
//! - `2` — PDS / external dependency error (network failure, KMS
//!   transport error). Today this is reserved; #30's `file-plain`
//!   rotation has no external dependency.
//! - `3` — internal / database error (Postgres unreachable, migration
//!   skew, append-only-trigger violation, etc.).
//!
//! # Supported modes
//!
//! - `file-plain` — full implementation.
//! - `passphrase-sealed` / `os-keychain` / `cloud-kms-oracle` — clap
//!   parses them but the state machine short-circuits with
//!   `RotationError::Unsupported`. Follow-up tracked as #64.
//!
//! # Flags
//!
//! - `--mode <m>` — custody mode the new key will live in.
//! - `--dry-run` — print every step's intended action, exit without
//!   persisting anything.
//! - `--resume <id>` — resume an existing rotation row.
//! - `--new-key-path <p>` — `file-plain` only: filesystem path the new
//!   key gets written to.
//! - `--reason <s>` — operator-supplied human-readable reason. Logged
//!   at INFO; persisted via the audit log path landing in #35.

#![doc(html_no_source)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::labeler::rotation::{
    CustodyMode, NextStep, RotationContext, RotationError, RotationPlan, RotationStep, next_step,
};
use tracing::info;
use uuid::Uuid;

const EXIT_USER_ERROR: u8 = 1;
const EXIT_EXTERNAL_ERROR: u8 = 2;
const EXIT_INTERNAL_ERROR: u8 = 3;

/// Wire-shape mirror of [`CustodyMode`], with kebab-case clap-ValueEnum
/// for the `--mode` flag.
#[derive(Debug, Clone, Copy, ValueEnum)]
#[clap(rename_all = "kebab-case")]
enum CliMode {
    FilePlain,
    PassphraseSealed,
    OsKeychain,
    CloudKmsOracle,
}

impl From<CliMode> for CustodyMode {
    fn from(m: CliMode) -> Self {
        match m {
            CliMode::FilePlain => Self::FilePlain,
            CliMode::PassphraseSealed => Self::PassphraseSealed,
            CliMode::OsKeychain => Self::OsKeychain,
            CliMode::CloudKmsOracle => Self::CloudKms,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "labeler-key-rotate",
    version,
    about = "Rotate the Polaris labeler signing key (REQ-12 / AC-15).",
    long_about = "Rotate the Polaris labeler signing key.\n\n\
        Drives a resumable state machine: generate-key → write → publish \
        → record-history → revoke-old → atomic-swap. Each step is \
        idempotent; a crash mid-rotation can be picked up with --resume \
        <rotation_id>.\n\n\
        Supported modes:\n  \
        file-plain          — implemented (issue #30)\n  \
        passphrase-sealed   — stub (issue #64)\n  \
        os-keychain         — stub (issue #64)\n  \
        cloud-kms-oracle    — stub (issue #64)\n\n\
        Exit codes:\n  \
        0 — success\n  \
        1 — user error (bad flags, unsupported mode)\n  \
        2 — external dependency error (PDS, KMS)\n  \
        3 — internal / database error"
)]
struct Cli {
    /// Custody mode for the new signing key.
    #[arg(long, value_enum)]
    mode: CliMode,

    /// Print every step's intended action and exit. Does NOT touch the
    /// DB or the custody store.
    #[arg(long)]
    dry_run: bool,

    /// Resume an in-flight rotation by its `rotation_state.id`.
    #[arg(long, value_name = "ROTATION_ID")]
    resume: Option<Uuid>,

    /// Filesystem path the new key material gets written to.
    /// Required for `--mode file-plain`.
    #[arg(long, value_name = "PATH")]
    new_key_path: Option<PathBuf>,

    /// Operator-supplied human-readable reason for the rotation
    /// (logged at INFO).
    #[arg(long, value_name = "TEXT", default_value = "scheduled rotation")]
    reason: String,
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("user error: {0}")]
    User(String),

    #[error("external error: {0}")]
    External(String),

    #[error("internal error: {0}")]
    Internal(#[source] anyhow::Error),
}

impl AppError {
    const fn exit_code(&self) -> u8 {
        match self {
            Self::User(_) => EXIT_USER_ERROR,
            Self::External(_) => EXIT_EXTERNAL_ERROR,
            Self::Internal(_) => EXIT_INTERNAL_ERROR,
        }
    }
}

impl From<RotationError> for AppError {
    fn from(err: RotationError) -> Self {
        match err {
            RotationError::Unsupported { .. } | RotationError::Init { .. } => {
                Self::User(err.to_string())
            }
            RotationError::Publish { .. } => Self::External(err.to_string()),
            RotationError::GenerateKey
            | RotationError::WriteKey { .. }
            | RotationError::Db(_)
            | RotationError::Signer(_) => Self::Internal(anyhow::Error::new(err)),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt().with_target(false).try_init().ok();
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let code = err.exit_code();
            tracing::error!(error = %err, exit_code = code, "rotation failed");
            // Best-effort stderr summary; ignore failure since there is
            // no useful recovery if stderr is closed.
            let _ = writeln!(std::io::stderr(), "error: {err}");
            ExitCode::from(code)
        }
    }
}

async fn run(cli: Cli) -> Result<(), AppError> {
    let custody_mode: CustodyMode = cli.mode.into();
    info!(
        mode = custody_mode.as_str(),
        reason = %cli.reason,
        dry_run = cli.dry_run,
        resume = ?cli.resume,
        "labeler-key-rotate starting"
    );

    if cli.dry_run {
        print_dry_run(&cli, custody_mode);
        return Ok(());
    }

    // The rotation CLI does not need the full AppConfig; it only needs
    // the DB connection. Reading DATABASE_URL from env keeps the CLI
    // process discipline (#8) without dragging the full AppConfig
    // shape into a one-shot rotation tool.
    let url = std::env::var("DATABASE_URL")
        .map_err(|_| AppError::User("DATABASE_URL must be set for the rotation CLI".to_owned()))?;
    let db_cfg = DbConfig {
        url,
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 5,
    };
    let db = db::connect(&db_cfg)
        .await
        .map_err(|e| AppError::Internal(anyhow::Error::new(e).context("connecting to Postgres")))?;
    let pool = db.pool().clone();

    let mut ctx = if let Some(rotation_id) = cli.resume {
        info!(rotation_id = %rotation_id, "resuming in-flight rotation");
        RotationContext::resume(pool, rotation_id, custody_mode).await?
    } else {
        let new_key_path = cli.new_key_path.clone().ok_or_else(|| {
            AppError::User(
                "--new-key-path is required for a fresh --mode file-plain rotation".to_owned(),
            )
        })?;
        info!(
            new_key_path = %new_key_path.display(),
            "seeding a fresh rotation"
        );
        RotationContext::new_rotation(pool, custody_mode, new_key_path).await?
    };

    ctx.run().await?;

    info!(
        rotation_id = %ctx.plan().id,
        reason = %cli.reason,
        new_did = ctx.plan().new_did.as_deref().unwrap_or("<unset>"),
        "labeler-key-rotate completed; live server will reload on its next poll tick"
    );
    Ok(())
}

/// Print every step's intended action for a clean-room plan; do not
/// touch the DB or the custody store.
///
/// Infallible — every step in the abstract transition table is pure,
/// every print writes to stdout (any IO failure there is unrecoverable
/// from a CLI). The caller observes success via the absent `Err` arm.
fn print_dry_run(cli: &Cli, mode: CustodyMode) {
    println!("labeler-key-rotate --dry-run");
    println!("  mode      : {}", mode.as_str());
    println!("  reason    : {}", cli.reason);
    println!(
        "  new key   : {}",
        cli.new_key_path
            .as_deref()
            .map_or_else(|| "<unset>".to_owned(), |p| p.display().to_string())
    );
    println!("steps (idempotent, resumable):");

    // Drive the pure transition table without any IO.
    let mut plan = RotationPlan {
        id: Uuid::nil(),
        custody_mode: mode,
        last_step: RotationStep::Pending,
        old_did: Some("<active key, looked up at run time>".to_owned()),
        new_did: None,
    };
    let mut idx = 1_u32;
    while let Some(step) = next_step(&plan) {
        println!("  {idx:>2}. {step:?}");
        plan.last_step = match step {
            NextStep::GenerateKey => RotationStep::KeyGenerated,
            NextStep::WriteNewKeyMaterial => RotationStep::KeyWritten,
            NextStep::PublishServiceRecord => RotationStep::ServiceRecordPublished,
            NextStep::RecordHistory => RotationStep::HistoryRecorded,
            NextStep::RevokeOldKey => RotationStep::OldKeyRevoked,
            NextStep::AtomicSwap => RotationStep::Swapped,
        };
        idx += 1;
    }
    println!("  {idx:>2}. (terminal) Complete");
    if !matches!(mode, CustodyMode::FilePlain) {
        println!();
        println!(
            "NOTE: --mode {} is not yet supported in #30; \
             this dry-run printed the abstract sequence only.",
            mode.as_str()
        );
        println!("      Implementation follow-up tracked as #64.");
    }
}
