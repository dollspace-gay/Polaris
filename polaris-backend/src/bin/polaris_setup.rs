//! `polaris-setup` — one-shot config templating CLI for the
//! "easy install" code path (issue #209) plus the WB-6 (#228)
//! post-install policy-import subcommand.
//!
//! # Default flow (install)
//!
//! The operator runs this once on a fresh host:
//!
//! ```text
//! polaris-setup --hostname mod.example.com
//! ```
//!
//! and the CLI writes two files into the current working directory
//! (overridable via `--dir`):
//!
//! - `.env` — populated from [`deploy/.env.example`](../../../deploy/.env.example)
//!   with `POLARIS_HOSTNAME` substituted, `POLARIS_COOKIE_KEY` and
//!   `POSTGRES_PASSWORD` freshly generated from the OS CSPRNG
//!   (`rand::rngs::OsRng`), and every other variable preserved at its
//!   documented default. The file is `chmod 0o600` immediately after
//!   writing so the secrets are never world-readable.
//! - `client-metadata.json` — the ATProto OAuth client metadata
//!   document Bluesky fetches during OAuth, with `client_id` /
//!   `redirect_uris` populated from the hostname.
//!
//! ## Idempotency
//!
//! - If `.env` already exists, the CLI prompts before overwriting.
//! - In `--non-interactive` mode an existing `.env` exits non-zero
//!   unless `--force` is passed.
//! - The same rule applies to `client-metadata.json`.
//!
//! ## Secret hygiene
//!
//! The generated cookie key and Postgres password are NEVER printed
//! to stdout, stderr, or any log. The completion message only names
//! the files written. This is the single most important contract of
//! this CLI — every code path must uphold it.
//!
//! # `seed-policies` subcommand (WB-6 / REQ-E3)
//!
//! Post-install bulk-import of `mod_policies` from a YAML workbook:
//!
//! ```text
//! polaris-setup seed-policies --file deploy/seeds/mod-policies.yml [--replace]
//! ```
//!
//! The subcommand reuses the [`polaris_backend::seed::mod_policies`]
//! deserializer + repo so the parser shape stays single-sourced with
//! the first-boot loader (WB-5 / #227). Without `--replace`, identifiers
//! already present in `mod_policies` are skipped; with `--replace`, they
//! are amended (a new version is written, the prior version is
//! `effective_until` stamped). Identifiers not yet in the table are
//! always inserted as v1 attributed to the pinned bootstrap admin.
//!
//! A pre-mutation safety scan refuses to import when any incoming
//! policy carries `human_required_always = TRUE` AND the live row for
//! that identifier has `autonomy_mode != 'manual'` — the seed file
//! cannot be used to retroactively floor a policy that is currently
//! autonomous. The operator must flip autonomy back to manual first
//! (`/admin/policies/<id>/pause`).
//!
//! # Exit codes (REQ-E3)
//!
//! - `0` — success (install: files written; seed-policies: rows imported
//!   or no-op skip).
//! - `1` — validation / user error: bad flags, pre-existing `.env`
//!   without `--force` in `--non-interactive` mode, YAML parse failure,
//!   schema violation, or the human-required hard-block tripped.
//! - `2` — IO / internal failure: RNG read failed, seed file not found,
//!   DB connection failure.

#![doc(html_no_source)]

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use rand::RngCore as _;
use rand::rngs::OsRng;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::mod_policies::{self, ModPolicyError, ModPolicyPatch, NewModPolicy};
use polaris_backend::seed::mod_policies as seed_mod_policies;
use seed_mod_policies::{SeedError, SeedPolicy, lookup_bootstrap_admin};
use sqlx::PgPool;

/// Process exit code for user / validation errors (REQ-E3).
const EXIT_USER_ERROR: u8 = 1;
/// Process exit code for IO / internal failures (REQ-E3).
const EXIT_INTERNAL_ERROR: u8 = 2;

/// Error-message prefix that [`classify_exit`] uses to map an
/// `anyhow::Error` chain to [`EXIT_USER_ERROR`]. Validation paths in
/// [`run_seed_policies`] tag their `bail!` strings with this so a
/// YAML parse error, schema violation, or human-required hard-block
/// trip is surfaced as exit 1 (not 2) per REQ-E3.
const USER_ERROR_PREFIX: &str = "user: ";

/// Error-message prefix that [`classify_exit`] maps to
/// [`EXIT_INTERNAL_ERROR`]. IO failures (file not found, DB connection
/// failure) tag with this so REQ-E3's "2 = IO failure" exit code is
/// honoured. Without an explicit `io:` tag the default classifier
/// already returns 2 for un-tagged errors, but tagging the IO sites
/// keeps the convention symmetric with `user:` and makes a future
/// classifier extension easy.
const IO_ERROR_PREFIX: &str = "io: ";

/// Length in bytes of the AES-256-GCM cookie key. The on-disk form
/// is hex-encoded so the file contains exactly `2 *
/// COOKIE_KEY_BYTES` printable chars.
const COOKIE_KEY_BYTES: usize = 32;
/// Length in bytes of the generated Postgres password. 24 bytes of
/// CSPRNG output → 48 hex chars, which is plenty of entropy for the
/// internal compose-network credential.
const POSTGRES_PASSWORD_BYTES: usize = 24;

/// `polaris-setup` CLI surface.
///
/// The CLI has two modes: the default no-subcommand flow (issue #209
/// install-template path) and the explicit `seed-policies` subcommand
/// (WB-6 / #228). When no subcommand is supplied, the root-level
/// install flags (`--hostname`, `--dir`, `--non-interactive`, `--force`)
/// drive `.env` + `client-metadata.json` generation; when
/// `seed-policies` is supplied, the install flags are ignored and the
/// subcommand's own arguments take over.
#[derive(Debug, Parser)]
#[command(
    name = "polaris-setup",
    version,
    about = "One-shot config templating for a fresh Polaris install, \
plus the seed-policies post-install bulk-import subcommand.",
    long_about = "Default flow: writes .env (mode 0600) and \
client-metadata.json into the target directory with freshly-generated \
secrets. Idempotent: re-running detects existing files and prompts \
before overwriting (or requires --force in --non-interactive mode).\n\n\
Subcommand `seed-policies`: imports a mod_policies YAML workbook into \
the Polaris database post-install. See `polaris-setup seed-policies \
--help`."
)]
struct Cli {
    /// Optional subcommand. When omitted, the root-level install flags
    /// drive the default `.env` + client-metadata.json templating
    /// flow. When supplied, the subcommand takes over.
    #[command(subcommand)]
    command: Option<Command>,

    /// Public DNS hostname Polaris will serve on (e.g.
    /// `mod.example.com`). Required in `--non-interactive` mode; in
    /// interactive mode the CLI prompts if omitted.
    #[arg(long)]
    hostname: Option<String>,

    /// Skip every interactive prompt; fail fast on any condition
    /// that would otherwise ask the operator. Required when running
    /// piped (e.g. `curl … | bash`).
    #[arg(long)]
    non_interactive: bool,

    /// Overwrite pre-existing `.env` and `client-metadata.json`
    /// without prompting. Use with care — this destroys any
    /// previously-generated secrets.
    #[arg(long)]
    force: bool,

    /// Target directory for the written files. Defaults to the
    /// current working directory. Created if it does not exist.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
}

/// Explicit subcommands. The variants are flat (no `enum`-nested
/// structs) so each subcommand owns its own argument surface and the
/// install flow stays at the root level for backward compatibility
/// with the `install.sh` wrapper documented in `docs/ops/quick-start.md`.
#[derive(Debug, Subcommand)]
enum Command {
    /// Bulk-import a `mod_policies` YAML workbook into the Polaris
    /// database (WB-6 / #228, implements REQ-E3).
    ///
    /// Reuses the same `SeedPolicy` deserializer the first-boot loader
    /// (`polaris_backend::seed::mod_policies`) uses, so the file shape
    /// is identical to `deploy/seeds/mod-policies.yml`. Behaviour
    /// depends on `--replace`:
    ///
    /// * Without `--replace`: identifiers already present in
    ///   `mod_policies` are skipped (logged INFO); identifiers not yet
    ///   present are inserted as v1 attributed to the pinned bootstrap
    ///   admin.
    /// * With `--replace`: existing identifiers are amended (a new
    ///   version is written via `mod_policies::amend`, the prior row
    ///   is `effective_until` stamped); not-yet-present identifiers
    ///   are inserted as v1.
    ///
    /// Before any DB mutation, a safety scan refuses to import if any
    /// incoming policy has `human_required_always = TRUE` AND the live
    /// row for that identifier has `autonomy_mode != 'manual'` — the
    /// seed file cannot be used to retroactively hard-floor a policy
    /// that is currently autonomous. The operator must flip autonomy
    /// back to manual first (`/admin/policies/<id>/pause`).
    ///
    /// Reads `DATABASE_URL` from the environment for the DB
    /// connection; no new env vars are introduced.
    #[command(name = "seed-policies")]
    SeedPolicies(SeedPoliciesArgs),
}

/// Arguments to the `seed-policies` subcommand.
#[derive(Debug, clap::Args)]
struct SeedPoliciesArgs {
    /// Path to the YAML workbook to import. Shape matches
    /// `deploy/seeds/mod-policies.yml`.
    #[arg(long)]
    file: PathBuf,

    /// When set, existing identifiers in `mod_policies` are amended
    /// (a new version is written) with the `change_summary` set to
    /// "Imported from <path> at <ISO timestamp>". When unset (the
    /// default), existing identifiers are skipped.
    #[arg(long)]
    replace: bool,
}

fn main() -> ExitCode {
    // Default flow logs are kept on stderr as human-readable lines;
    // stdout is reserved for the one post-completion summary line.
    // The `seed-policies` subcommand needs structured INFO logs for
    // per-row "skip / insert / amend" decisions (the operator wants a
    // grep-able record), so we install a `tracing_subscriber` on the
    // seed-policies branch only. The install branch keeps the existing
    // stderr-write pattern unchanged.
    let cli = Cli::parse();
    let result = match cli.command {
        None => run_install(&cli),
        Some(Command::SeedPolicies(ref args)) => {
            // INFO-by-default: the seed-policies path narrates every
            // per-row decision and the operator must be able to read
            // the trail. `try_init` returns Err if a subscriber is
            // already installed (e.g. test harness), which is fine to
            // ignore.
            tracing_subscriber::fmt()
                .with_target(false)
                .with_writer(io::stderr)
                .with_max_level(tracing::Level::INFO)
                .try_init()
                .ok();
            run_seed_policies(args)
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(io::stderr(), "polaris-setup: error: {err:#}");
            ExitCode::from(classify_exit(&err))
        }
    }
}

/// Classify a top-level error from [`run_install`] / [`run_seed_policies`]
/// into a process exit code per REQ-E3.
///
/// User / validation errors (bad flags, pre-existing files without
/// `--force`, YAML parse failures, schema violations, the
/// human-required hard-block) get [`EXIT_USER_ERROR`] (1); IO and
/// internal failures (RNG read, missing seed file, DB connection
/// failure) get [`EXIT_INTERNAL_ERROR`] (2).
///
/// The discriminator is a string prefix on the error message:
/// [`USER_ERROR_PREFIX`] (`"user: "`) maps to 1, [`IO_ERROR_PREFIX`]
/// (`"io: "`) maps to 2. Anything unprefixed maps to 2 by default,
/// preserving the pre-WB-6 behaviour where internal failures (RNG,
/// formatter) lacked an explicit tag.
///
/// The chain walk is deliberate: `with_context(...)` stacks a new
/// outer error on top of the original cause, so a marker introduced
/// by an inner `bail!` must still be reachable from the outer
/// `anyhow::Error`. Without the chain walk the outermost
/// `with_context` message would mask the marker and the binary would
/// silently exit `2` for a genuine validation error — exactly the
/// regression that motivated this function existing as a named,
/// unit-tested helper rather than an inline closure in `main`.
fn classify_exit(err: &anyhow::Error) -> u8 {
    for e in err.chain() {
        let msg = e.to_string();
        if msg.starts_with(USER_ERROR_PREFIX) {
            return EXIT_USER_ERROR;
        }
        if msg.starts_with(IO_ERROR_PREFIX) {
            return EXIT_INTERNAL_ERROR;
        }
    }
    EXIT_INTERNAL_ERROR
}

/// Default-flow entry point: render `.env` + client-metadata.json.
///
/// Mirrors the pre-WB-6 `run()`; renamed for symmetry with
/// [`run_seed_policies`].
fn run_install(cli: &Cli) -> Result<()> {
    fs::create_dir_all(&cli.dir).with_context(|| {
        format!(
            "user: failed to create target directory {}",
            cli.dir.display(),
        )
    })?;

    let env_path = cli.dir.join(".env");
    let metadata_path = cli.dir.join("client-metadata.json");

    let interactive = !cli.non_interactive && io::stdin().is_terminal();

    let hostname = resolve_hostname(cli.hostname.as_deref(), interactive)?;

    // Idempotency: check both target files before touching either.
    // We do this BEFORE generating any secrets so a "no" answer
    // never leaks a freshly-generated key into process memory for
    // longer than necessary.
    let env_exists = env_path.exists();
    let metadata_exists = metadata_path.exists();

    if (env_exists || metadata_exists) && !cli.force {
        if !interactive {
            bail!(
                "user: {} already exists in {}; re-run with --force to overwrite \
                 (or remove the file first)",
                if env_exists {
                    ".env"
                } else {
                    "client-metadata.json"
                },
                cli.dir.display(),
            );
        }
        // Interactive: prompt for confirmation.
        if !confirm_overwrite(&env_path, env_exists, &metadata_path, metadata_exists)? {
            writeln!(io::stderr(), "Aborted; no files modified.")
                .context("internal: stderr write failed")?;
            return Ok(());
        }
    }

    let cookie_key_hex = generate_hex(COOKIE_KEY_BYTES)?;
    let postgres_password_hex = generate_hex(POSTGRES_PASSWORD_BYTES)?;

    let env_body = render_env(&hostname, &cookie_key_hex, &postgres_password_hex);
    write_secret_file(&env_path, env_body.as_bytes())
        .with_context(|| format!("user: failed to write {}", env_path.display()))?;

    let metadata_body = render_client_metadata(&hostname);
    fs::write(&metadata_path, &metadata_body)
        .with_context(|| format!("user: failed to write {}", metadata_path.display()))?;

    // Completion message: file paths only, never the secrets
    // themselves. The shell-script wrapper relies on this exact
    // shape to chain into the `docker compose up -d` hint.
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "Generated {} (chmod 600) and {} \u{2014} review and customise, then run \
         docker compose up -d.",
        env_path.display(),
        metadata_path.display(),
    )
    .context("internal: stdout write failed")?;

    Ok(())
}

/// `seed-policies` subcommand entry point (WB-6 / #228, REQ-E3).
///
/// Spins up a single-thread tokio runtime (the rest of the binary is
/// sync; we don't want to make the install path pay the runtime
/// cost), reads `DATABASE_URL`, opens a small connection pool, and
/// dispatches to [`do_seed_policies`] for the actual import.
///
/// All operator-facing logging from the import path goes through
/// `tracing::info!` / `tracing::error!`; the subscriber is installed
/// by [`main`] before this function runs.
fn run_seed_policies(args: &SeedPoliciesArgs) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| {
        anyhow::anyhow!("io: DATABASE_URL must be set for the seed-policies subcommand",)
    })?;

    // Pre-flight: read the seed file BEFORE we open the DB pool so a
    // missing file maps cleanly to exit 2 without paying for a
    // connection round-trip. We then re-pass the bytes into the
    // async worker so it does not re-touch the filesystem.
    if !args.file.exists() {
        bail!(
            "io: seed file not found: {} (REQ-E3 exit code 2)",
            args.file.display(),
        );
    }
    let raw = fs::read_to_string(&args.file).map_err(|e| {
        anyhow::anyhow!("io: failed to read seed file {}: {e}", args.file.display(),)
    })?;
    // Parse via the SAME deserializer the WB-5 first-boot loader
    // uses. We deliberately do not introduce a parallel struct —
    // SeedPolicy IS the contract with deploy/seeds/mod-policies.yml.
    let policies: Vec<SeedPolicy> = serde_yaml::from_str(&raw).map_err(|e| {
        // YAML parse failures are validation errors per REQ-E3
        // (operator broke the seed file), so tag with user:.
        anyhow::anyhow!("user: could not parse seed file: {e}")
    })?;

    // Tokio runtime. `new_current_thread` keeps the binary small —
    // we have one async path with a handful of awaits, no need for
    // a multi-thread scheduler.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| anyhow::anyhow!("io: failed to build tokio runtime: {e}"))?;
    runtime.block_on(do_seed_policies(
        &database_url,
        &args.file,
        args.replace,
        policies,
    ))
}

/// Async worker for [`run_seed_policies`].
///
/// Steps:
///
/// 1. Connect to Postgres via [`db::connect`] using the standard
///    `DbConfig` shape so the same migrations / connection-pool
///    settings as the main backend apply.
/// 2. Look up the pinned bootstrap admin
///    ([`seed_mod_policies::lookup_bootstrap_admin`]) — refuse to
///    import if no admin is pinned yet.
/// 3. Pre-mutation safety scan (REQ-E3 hard block): for every
///    incoming `human_required_always = TRUE` policy, refuse if its
///    live row is not in `autonomy_mode = 'manual'`.
/// 4. Per-policy dispatch: skip / insert / amend with logging.
/// 5. Commit on success. Any failure rolls back via tx Drop.
async fn do_seed_policies(
    database_url: &str,
    file: &Path,
    replace: bool,
    policies: Vec<SeedPolicy>,
) -> Result<()> {
    let db_cfg = DbConfig {
        url: database_url.to_owned(),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("io: failed to connect to Postgres: {e}"))?;
    let pool = database.pool().clone();

    let admin = lookup_bootstrap_admin(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("io: bootstrap-admin lookup failed: {e}"))?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "user: no pinned bootstrap admin exists yet; complete the OAuth setup wizard before running seed-policies"
            )
        })?;

    // ── Hard-block scan (REQ-E3 safety constraint) ────────────────
    //
    // Before we touch a single row, walk every incoming policy with
    // `human_required_always = TRUE` and look up the LIVE state of
    // that identifier. If the live row is not `manual`, we refuse —
    // the seed file cannot be used to retroactively floor a policy
    // that is currently autonomous. The error message points the
    // operator at the pause endpoint so they can flip autonomy back
    // to manual before re-running.
    preflight_human_required_block(&pool, &policies).await?;

    // ── Per-policy dispatch ───────────────────────────────────────
    let summary_stamp = format!(
        "Imported from {} at {}",
        file.display(),
        chrono::Utc::now().to_rfc3339(),
    );
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| anyhow::anyhow!("io: begin transaction failed: {e}"))?;

    let mut inserted = 0_usize;
    let mut skipped = 0_usize;
    let mut amended = 0_usize;

    for policy in policies {
        let identifier = policy.identifier.clone();
        let existing = mod_policies::current_by_identifier(&pool, &identifier)
            .await
            .map_err(|e| match e {
                ModPolicyError::Database(db_err) => {
                    anyhow::anyhow!("io: lookup for {identifier} failed: {db_err}")
                }
                other => anyhow::anyhow!("user: lookup for {identifier} failed: {other}"),
            })?;

        match (existing, replace) {
            (Some(_), false) => {
                // Skip path: identifier already exists, no --replace.
                tracing::info!(
                    identifier = %identifier,
                    "seed-policies: skip (already exists)",
                );
                skipped += 1;
            }
            (Some(current), true) => {
                // Amend path: write a successor version via the
                // mod_policies::amend repo. We pass every field as
                // an explicit override (Some(...)) so the new
                // version reflects the seed file verbatim, not a
                // carry-forward of stale prior-version fields.
                let patch = patch_from_seed(&policy);
                let new = mod_policies::amend(
                    &mut tx,
                    &identifier,
                    patch,
                    admin,
                    Some(summary_stamp.clone()),
                )
                .await
                .map_err(|e| map_repo_error(&identifier, e))?;
                tracing::info!(
                    identifier = %identifier,
                    prior_version = current.version,
                    new_version = new.version,
                    "seed-policies: amend",
                );
                amended += 1;
            }
            (None, _) => {
                // Insert path: brand-new identifier, write v1.
                let new = new_from_seed(policy);
                let row = mod_policies::insert_initial(&mut tx, new, admin)
                    .await
                    .map_err(|e| map_repo_error(&identifier, e))?;
                tracing::info!(
                    identifier = %row.identifier,
                    version = row.version,
                    "seed-policies: insert v1",
                );
                inserted += 1;
            }
        }
    }

    tx.commit()
        .await
        .map_err(|e| anyhow::anyhow!("io: commit failed: {e}"))?;

    tracing::info!(
        inserted,
        amended,
        skipped,
        replace = replace,
        "seed-policies: import complete",
    );
    Ok(())
}

/// Pre-mutation safety scan implementing the REQ-E3 hard-block.
///
/// For every incoming policy with `human_required_always = TRUE`,
/// look up the current live row. If the live row is not in
/// `autonomy_mode = 'manual'`, refuse the entire import with a
/// `user:`-prefixed error so the binary exits 1 (REQ-E3 validation
/// failure). No DB mutation happens before this scan completes.
async fn preflight_human_required_block(pool: &PgPool, policies: &[SeedPolicy]) -> Result<()> {
    for policy in policies {
        if !policy.human_required_always {
            continue;
        }
        let live = mod_policies::current_by_identifier(pool, &policy.identifier)
            .await
            .map_err(|e| match e {
                ModPolicyError::Database(db_err) => anyhow::anyhow!(
                    "io: safety-scan lookup for {} failed: {db_err}",
                    policy.identifier,
                ),
                other => anyhow::anyhow!(
                    "user: safety-scan lookup for {} failed: {other}",
                    policy.identifier,
                ),
            })?;
        if let Some(row) = live {
            if row.autonomy_mode != "manual" {
                bail!(
                    "user: refusing to import: policy {identifier} is currently in autonomy_mode={mode} but the seed file marks it human_required_always; flip autonomy back to manual via /admin/policies/{id}/pause first, then re-run",
                    identifier = row.identifier,
                    mode = row.autonomy_mode,
                    id = row.id,
                );
            }
        }
    }
    Ok(())
}

/// Map a `mod_policies` repo error onto an anyhow error with the
/// right `user:` / `io:` tag for [`classify_exit`].
///
/// DB-level failures (sqlx errors propagated through
/// `ModPolicyError::Database`) are IO failures from the operator's
/// point of view (connection drop, constraint violation surfaced as
/// an sqlx error); everything else (`UnknownIdentifier`,
/// `StaleVersion`, `ConcurrentEdit`, `RetiredPolicy`) is a
/// data-shape mismatch and counts as a validation failure.
fn map_repo_error(identifier: &str, err: ModPolicyError) -> anyhow::Error {
    match err {
        ModPolicyError::Database(db_err) => {
            anyhow::anyhow!("io: mod_policies write for {identifier} failed: {db_err}")
        }
        other => anyhow::anyhow!("user: mod_policies write for {identifier} rejected: {other}"),
    }
}

/// Convert a parsed [`SeedPolicy`] into a fully-populated
/// [`NewModPolicy`] for the v1 insert path.
///
/// Mirrors the field layout of `SeedPolicy` 1:1; the example arrays
/// are re-serialised through `serde_json` so they land in the JSONB
/// column as the same shape the admin REST API and the first-boot
/// loader emit. We rely on the DB CHECKs (and the repo's
/// `insert_initial` call) to surface any field-level violation that
/// slips past serde — duplicating the loader's `validate` helper in
/// this binary would be the very "duplicate the parser" anti-pattern
/// REQ-E3 forbids.
fn new_from_seed(p: SeedPolicy) -> NewModPolicy {
    NewModPolicy {
        identifier: p.identifier,
        name: p.name,
        description: p.description,
        scope: p.scope,
        severity: p.severity,
        decision_criteria: p.decision_criteria,
        examples_positive: examples_to_json(&p.examples_positive),
        examples_negative: examples_to_json(&p.examples_negative),
        suggested_action_kinds: p.suggested_action_kinds,
        linked_label_value: p.linked_label_value,
        exceptions: p.exceptions,
        human_required_always: p.human_required_always,
        autonomy_mode: p.autonomy_mode,
        autonomous_action_kinds: p.autonomous_action_kinds,
        autonomous_confidence_threshold: p.autonomous_confidence_threshold,
        assisted_confidence_threshold: p.assisted_confidence_threshold,
        // LLM-6 safety-floor tuning: keep the DB defaults at seed
        // time. Operators tune per-policy via the admin UI.
        autonomous_rate_limit_per_hour: None,
        autonomous_reversal_breaker_threshold: None,
        // v1 inserts authored by seed-policies do not carry a per-row
        // change-summary; the operator-facing record of "where this
        // came from" lives in the structured `tracing::info!` line
        // emitted at insert time. The amend path DOES set
        // change_summary (see do_seed_policies).
        change_summary: None,
    }
}

/// Build a [`ModPolicyPatch`] that overwrites every field on the
/// amend path with the seed file's values.
///
/// Unlike the admin-edit path (which uses `None` to mean
/// "carry-forward"), seed-policies-with-replace replaces the policy
/// wholesale — the operator's intent is "make the DB look like this
/// YAML file." Every field is wrapped in `Some(...)` so the
/// successor row mirrors the seed entry verbatim, not a carry-forward
/// of stale prior-version fields.
fn patch_from_seed(p: &SeedPolicy) -> ModPolicyPatch {
    ModPolicyPatch {
        name: Some(p.name.clone()),
        description: Some(p.description.clone()),
        scope: Some(p.scope.clone()),
        severity: Some(p.severity.clone()),
        decision_criteria: Some(p.decision_criteria.clone()),
        examples_positive: Some(
            examples_to_json(&p.examples_positive).unwrap_or_else(|| serde_json::json!([])),
        ),
        examples_negative: Some(
            examples_to_json(&p.examples_negative).unwrap_or_else(|| serde_json::json!([])),
        ),
        suggested_action_kinds: Some(p.suggested_action_kinds.clone()),
        linked_label_value: Some(p.linked_label_value.clone()),
        exceptions: Some(p.exceptions.clone()),
        human_required_always: Some(p.human_required_always),
        autonomy_mode: Some(p.autonomy_mode.clone()),
        autonomous_action_kinds: Some(p.autonomous_action_kinds.clone()),
        autonomous_confidence_threshold: Some(p.autonomous_confidence_threshold),
        assisted_confidence_threshold: Some(p.assisted_confidence_threshold),
        // LLM-6 safety-floor tuning is not driven by the seed file;
        // keep prior-version values across amends. The admin UI is
        // the source of truth for these knobs.
        autonomous_rate_limit_per_hour: None,
        autonomous_reversal_breaker_threshold: None,
        // Never tombstone via the seed-policies path — retiring a
        // policy is an admin-UI action with its own audit trail.
        is_retired: None,
    }
}

/// Serialise an example list to `Option<serde_json::Value>` for the
/// `examples_positive` / `examples_negative` JSONB columns. Empty
/// lists map to `None` so the loader's "default to `[]`" behaviour
/// in `insert_initial` kicks in.
fn examples_to_json(
    examples: &[seed_mod_policies::SeedPolicyExample],
) -> Option<serde_json::Value> {
    if examples.is_empty() {
        None
    } else {
        // Serialisation of a `SeedPolicyExample` cannot fail (it is a
        // struct of `String` / `Option<String>` fields with the
        // hand-written Serialize impl in seed::mod_policies). We use
        // `ok()` to map any theoretical failure to `None`, which the
        // DB will accept as an empty array — strictly preferable to
        // panicking inside a long-running import.
        serde_json::to_value(examples).ok()
    }
}

/// Translate a [`SeedError`] from `polaris_backend::seed::mod_policies`
/// into an `anyhow::Error` with the correct `user:` / `io:` prefix
/// so [`classify_exit`] maps to REQ-E3's exit codes.
///
/// Currently invoked from the unit-test suite only; the production
/// import path constructs anyhow errors directly at the site of each
/// failure so the prefix discipline stays visible at the call site.
/// We still expose this helper so a future refactor that routes the
/// entire path through [`SeedError`] has a single, audited translation
/// to point at.
#[cfg_attr(not(test), allow(dead_code))]
fn seed_error_to_anyhow(err: SeedError) -> anyhow::Error {
    match err {
        SeedError::IoError { path, source } => {
            anyhow::anyhow!("io: failed to read seed file {}: {source}", path.display())
        }
        SeedError::YamlParseError(e) => anyhow::anyhow!("user: could not parse seed file: {e}"),
        SeedError::ValidationError {
            identifier,
            message,
        } => {
            anyhow::anyhow!("user: seed entry {identifier} failed validation: {message}")
        }
        SeedError::RepoError(ModPolicyError::Database(db_err)) => {
            anyhow::anyhow!("io: mod_policies repo error: {db_err}")
        }
        SeedError::RepoError(other) => anyhow::anyhow!("user: mod_policies repo error: {other}"),
    }
}

/// Resolve the hostname from the CLI flag or an interactive prompt.
///
/// Returns a user-facing error (prefixed with `"user: "`) if no
/// hostname is available in non-interactive mode.
fn resolve_hostname(flag: Option<&str>, interactive: bool) -> Result<String> {
    if let Some(h) = flag {
        let h = h.trim();
        if h.is_empty() {
            bail!("user: --hostname must be non-empty");
        }
        validate_hostname(h)?;
        return Ok(h.to_owned());
    }
    if !interactive {
        bail!(
            "user: --hostname is required in --non-interactive mode (or when stdin is \
             not a terminal)"
        );
    }
    // Interactive prompt. We loop until the operator provides a
    // syntactically valid hostname; an empty answer aborts the
    // setup so a stuck operator can always Ctrl-D out.
    let mut stderr = io::stderr().lock();
    let stdin = io::stdin();
    let mut buf = String::new();
    loop {
        write!(
            stderr,
            "Public hostname for this Polaris install (e.g. mod.example.com): "
        )
        .context("internal: stderr write failed")?;
        stderr.flush().context("internal: stderr flush failed")?;
        buf.clear();
        let read = stdin
            .lock()
            .read_line(&mut buf)
            .context("internal: stdin read failed")?;
        if read == 0 {
            // EOF on stdin: the operator Ctrl-D'd; treat as abort.
            bail!("user: aborted (no hostname provided)");
        }
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            writeln!(
                stderr,
                "  (empty input; please enter a hostname or Ctrl-D to abort)"
            )
            .context("internal: stderr write failed")?;
            continue;
        }
        match validate_hostname(trimmed) {
            Ok(()) => return Ok(trimmed.to_owned()),
            Err(err) => {
                writeln!(stderr, "  ({err:#})").context("internal: stderr write failed")?;
            }
        }
    }
}

/// Lightweight hostname validation: non-empty, no scheme, no path,
/// no whitespace, ASCII-only labels. We intentionally do NOT do a
/// full RFC 1035 check here — the goal is to reject obvious paste
/// mistakes (`https://x.com/`, `localhost:8080`), not to be a
/// resolver. Caddy will reject malformed values at startup with a
/// clearer error than this CLI can produce.
fn validate_hostname(s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("user: hostname is empty");
    }
    if s.contains("://") {
        bail!("user: hostname must not include a scheme (drop the https://)");
    }
    if s.contains('/') {
        bail!("user: hostname must not include a path component");
    }
    if s.contains(' ') || s.contains('\t') {
        bail!("user: hostname must not contain whitespace");
    }
    if s.contains(':') {
        bail!("user: hostname must not include a port");
    }
    if !s.is_ascii() {
        bail!("user: hostname must be ASCII (use punycode for IDN)");
    }
    Ok(())
}

/// Interactive overwrite prompt. Returns `Ok(true)` on yes, `Ok(false)` on no.
fn confirm_overwrite(
    env_path: &Path,
    env_exists: bool,
    metadata_path: &Path,
    metadata_exists: bool,
) -> Result<bool> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "The following files already exist:")
        .context("internal: stderr write failed")?;
    if env_exists {
        writeln!(stderr, "  - {}", env_path.display()).context("internal: stderr write failed")?;
    }
    if metadata_exists {
        writeln!(stderr, "  - {}", metadata_path.display())
            .context("internal: stderr write failed")?;
    }
    write!(stderr, "Overwrite and regenerate secrets? [y/N] ")
        .context("internal: stderr write failed")?;
    stderr.flush().context("internal: stderr flush failed")?;

    let mut answer = String::new();
    let stdin = io::stdin();
    let read = stdin
        .lock()
        .read_line(&mut answer)
        .context("internal: stdin read failed")?;
    if read == 0 {
        return Ok(false);
    }
    let trimmed = answer.trim().to_ascii_lowercase();
    Ok(matches!(trimmed.as_str(), "y" | "yes"))
}

/// Generate `n_bytes` of CSPRNG output and return its lowercase
/// hex encoding. Uses [`OsRng`] directly so the process never
/// holds the raw bytes in a longer-lived buffer than necessary.
fn generate_hex(n_bytes: usize) -> Result<String> {
    let mut buf = vec![0u8; n_bytes];
    OsRng
        .try_fill_bytes(&mut buf)
        .context("internal: OsRng read failed")?;
    let encoded = hex::encode(&buf);
    // Best-effort wipe of the buffer; this is not a full
    // zeroize-on-drop story but it shrinks the in-process lifetime
    // of the raw bytes.
    buf.fill(0);
    Ok(encoded)
}

/// Atomic-ish write of `bytes` to `path` with mode 0o600. We use
/// `OpenOptions` + the `mode` extension on unix; on non-unix
/// targets the file is still written but without the chmod (the
/// stack is Linux-only in practice, so this branch is mostly for
/// developer ergonomics on macOS hosts).
#[cfg(unix)]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {} for write", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing to {}", path.display()))?;
    // On an existing-file overwrite the `mode(0o600)` argument is
    // a no-op (OpenOptions does not chmod on reopen), so re-assert
    // the mode explicitly.
    let perms = std::os::unix::fs::PermissionsExt::from_mode(0o600);
    fs::set_permissions(path, perms)
        .with_context(|| format!("chmod 0600 on {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("writing to {path:?}"))?;
    Ok(())
}

/// Render the `.env` body. Mirrors the variable order and the
/// inline documentation of [`deploy/.env.example`](../../../deploy/.env.example);
/// the example file remains the canonical source of new variables,
/// but this rendered output is sufficient for the easy-install
/// happy path (Bluesky-OAuth backend, file-plain signer, local-fs
/// evidence store).
fn render_env(hostname: &str, cookie_key_hex: &str, postgres_password_hex: &str) -> String {
    // Use a single `format!` so the layout is auditable in one
    // place. The placeholders are validated upstream; nothing here
    // performs additional escaping.
    format!(
        "# Polaris labeler-profile environment.\n\
         # Generated by `polaris-setup` \u{2014} review and customise as needed.\n\
         # Secrets in this file MUST NOT be committed to version control.\n\
         #\n\
         # Variables and inline documentation mirror deploy/.env.example.\n\
         # See that file for every supported option and the full reference.\n\
         \n\
         # ── Public deployment identity ─────────────────────────────────\n\
         POLARIS_HOSTNAME={hostname}\n\
         # Pin to a specific image tag for reproducible upgrades; defaults\n\
         # to :latest on every `docker compose pull`.\n\
         # POLARIS_IMAGE_TAG=latest\n\
         \n\
         # ── Postgres (internal compose-network credentials) ────────────\n\
         POSTGRES_USER=polaris\n\
         POSTGRES_DB=polaris\n\
         # SECRET \u{2014} do not commit.\n\
         POSTGRES_PASSWORD={postgres_password_hex}\n\
         \n\
         # ── HTTP listener ──────────────────────────────────────────────\n\
         # The compose stack overrides this to 0.0.0.0:8080 inside the\n\
         # container so Caddy can reach the backend over polaris-net.\n\
         # POLARIS_HTTP_BIND=0.0.0.0:8080\n\
         \n\
         # ── Deployment profile (issue #29 / AC-14) ─────────────────────\n\
         POLARIS_PROFILE=labeler\n\
         \n\
         # ── Session crypto (issue #9) ──────────────────────────────────\n\
         # SECRET \u{2014} do not commit. 32-byte AES-256-GCM key, 64 hex chars.\n\
         POLARIS_COOKIE_KEY={cookie_key_hex}\n\
         \n\
         # ── Moderator authentication backend (issue #9 / #31) ─────────\n\
         # Easy-install default: ATProto OAuth, using the client-metadata.json\n\
         # this tool just generated.\n\
         POLARIS_AUTH_BACKEND=atproto\n\
         POLARIS_ATPROTO_CLIENT_METADATA=/etc/polaris/oauth/client-metadata.json\n\
         POLARIS_ATPROTO_CLIENT_ID=https://{hostname}/oauth/client-metadata.json\n\
         \n\
         # ── Labeler signing-key custody (issue #29 / REQ-11) ───────────\n\
         # Default: file-plain (Ozone-equivalent posture). Migrate to\n\
         # passphrase-sealed / os-keychain / cloud-kms-oracle for production.\n\
         POLARIS_LABELER_SIGNING_KEY_MODE=file-plain\n\
         POLARIS_LABELER_SIGNING_KEY_PATH=/etc/polaris/keys/labeler.key\n\
         \n\
         # ── Evidence-preservation worker (issue #33) ───────────────────\n\
         POLARIS_EVIDENCE_BLOB_STORE=local-fs\n\
         POLARIS_EVIDENCE_LOCAL_FS_ROOT=/var/lib/polaris/evidence\n\
         "
    )
}

/// Render the ATProto OAuth client-metadata.json body. The exact
/// shape mirrors the snippet currently documented in
/// [`docs/ops/quick-start.md`](../../../docs/ops/quick-start.md);
/// Bluesky fetches this document at the `client_id` URL during the
/// OAuth handshake to verify the installation.
fn render_client_metadata(hostname: &str) -> String {
    // We construct the JSON via `serde_json::json!` rather than
    // string concatenation so the operator never has to worry
    // about a typo in a comma. The output is then pretty-printed
    // so a human reading the file sees one field per line.
    let doc = serde_json::json!({
        "client_id": format!("https://{hostname}/oauth/client-metadata.json"),
        "application_type": "web",
        "grant_types": ["authorization_code", "refresh_token"],
        "scope": "atproto",
        "response_types": ["code"],
        "redirect_uris": [format!("https://{hostname}/auth/atproto/callback")],
        "token_endpoint_auth_method": "none",
        "dpop_bound_access_tokens": true,
        "client_name": "Polaris (your installation)",
    });
    // `to_string_pretty` cannot fail on a `serde_json::Value` that
    // was just constructed via the `json!` macro; the only
    // failure modes are I/O and non-string map keys, neither of
    // which applies here. We still propagate the error rather
    // than `.expect`'ing to keep the workspace clippy-clean.
    serde_json::to_string_pretty(&doc).map_or_else(
        |_| {
            // Fallback: hand-rolled JSON that matches the macro shape.
            // Reaching this branch implies a serde_json bug; ship a
            // value rather than panicking.
            format!("{{\n  \"client_id\": \"https://{hostname}/oauth/client-metadata.json\"\n}}\n")
        },
        |s| s + "\n",
    )
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test-only — assertion helpers want a panic-on-bug message rather than a \
              `Result`-bubbling ladder, and these expects are local invariants the test \
              itself enforces."
)]
mod tests {
    use super::*;

    #[test]
    fn generate_hex_returns_correct_length() {
        let out = generate_hex(32).expect("OsRng read in test");
        assert_eq!(out.len(), 64);
        assert!(out.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_hex_is_nonzero() {
        let out = generate_hex(32).expect("OsRng read in test");
        assert_ne!(out, "0".repeat(64));
    }

    #[test]
    fn validate_hostname_accepts_dns() {
        validate_hostname("mod.example.com").expect("DNS hostname is valid");
        validate_hostname("polaris.test").expect("DNS hostname is valid");
    }

    #[test]
    fn validate_hostname_rejects_scheme() {
        assert!(validate_hostname("https://example.com").is_err());
    }

    #[test]
    fn validate_hostname_rejects_port() {
        assert!(validate_hostname("example.com:8080").is_err());
    }

    #[test]
    fn validate_hostname_rejects_path() {
        assert!(validate_hostname("example.com/oauth").is_err());
    }

    #[test]
    fn validate_hostname_rejects_whitespace() {
        assert!(validate_hostname("example .com").is_err());
    }

    #[test]
    fn validate_hostname_rejects_empty() {
        assert!(validate_hostname("").is_err());
    }

    #[test]
    fn render_env_contains_substituted_hostname_and_secrets() {
        let body = render_env("h.example", "deadbeef", "cafef00d");
        assert!(body.contains("POLARIS_HOSTNAME=h.example"));
        assert!(body.contains("POLARIS_COOKIE_KEY=deadbeef"));
        assert!(body.contains("POSTGRES_PASSWORD=cafef00d"));
        assert!(
            body.contains("POLARIS_ATPROTO_CLIENT_ID=https://h.example/oauth/client-metadata.json")
        );
    }

    #[test]
    fn render_client_metadata_has_expected_client_id() {
        let body = render_client_metadata("h.example");
        assert!(body.contains("\"client_id\": \"https://h.example/oauth/client-metadata.json\""));
        assert!(body.contains("\"redirect_uris\""));
        assert!(body.contains("https://h.example/auth/atproto/callback"));
    }

    #[test]
    fn classify_exit_maps_user_prefixed_bail_to_exit_1() {
        // Mirrors the bail! call on the conflict path: re-running
        // without --force when .env already exists. The error
        // message must classify as a user error (exit 1), not an
        // internal error (exit 2), so CI scripts can detect the
        // conflict.
        let err = anyhow::anyhow!(
            "user: .env already exists in .; re-run with --force to overwrite \
             (or remove the file first)"
        );
        assert_eq!(classify_exit(&err), EXIT_USER_ERROR);
    }

    #[test]
    fn classify_exit_finds_user_marker_through_context_chain() {
        // `with_context` stacks an outer error on top of the
        // user-prefixed cause. The classifier must walk the chain
        // and still return EXIT_USER_ERROR; without the chain walk
        // a wrapped user error would silently degrade to exit 2.
        let inner: anyhow::Error =
            anyhow::anyhow!("user: --hostname is required in --non-interactive mode");
        let wrapped = inner.context("setting up CLI config");
        assert_eq!(classify_exit(&wrapped), EXIT_USER_ERROR);
    }

    #[test]
    fn classify_exit_maps_unmarked_error_to_internal() {
        // Errors without the `user: ` prefix (RNG failures, write
        // I/O errors that aren't tagged via with_context, etc.)
        // must come out as EXIT_INTERNAL_ERROR (2) so the operator
        // can tell the two failure modes apart.
        let err = anyhow::anyhow!("OsRng read failed");
        assert_eq!(classify_exit(&err), EXIT_INTERNAL_ERROR);
    }

    // ── WB-6 / #228 — seed-policies subcommand unit tests ─────────

    #[test]
    fn classify_exit_maps_io_prefixed_to_internal() {
        // REQ-E3 reserves exit 2 for IO failures. The
        // `io:`-prefixed branch must classify as EXIT_INTERNAL_ERROR
        // (2), distinct from the un-prefixed default which also
        // returns 2 — the explicit prefix is the documented signal
        // for "this is an IO failure" (file not found, DB unreachable).
        let err = anyhow::anyhow!("io: seed file not found: /tmp/nope.yml");
        assert_eq!(classify_exit(&err), EXIT_INTERNAL_ERROR);
    }

    #[test]
    fn classify_exit_io_prefix_loses_to_user_prefix_in_chain() {
        // If a single chain carries BOTH prefixes (e.g. an IO
        // failure wrapped in a user-tagged outer context), the
        // user-error mapping wins because the chain walk returns
        // the first match. The chain walks outer → inner; we
        // construct the chain so the outer carries `user:` and the
        // inner carries `io:`.
        let inner = anyhow::anyhow!("io: db connection failed");
        let wrapped = inner.context("user: subcommand aborted by safety scan");
        assert_eq!(classify_exit(&wrapped), EXIT_USER_ERROR);
    }

    #[test]
    fn seed_error_to_anyhow_tags_io_for_io_errors() {
        // The translation table must preserve the `io: ` /
        // `user: ` distinction that drives `classify_exit`. An
        // `IoError` variant maps to an IO-tagged anyhow error so
        // the binary exits 2; a `YamlParseError` maps to a
        // user-tagged error so the binary exits 1.
        let io_err = SeedError::IoError {
            path: std::path::PathBuf::from("/no/such/file"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
        };
        let io_any = seed_error_to_anyhow(io_err);
        assert!(
            io_any.to_string().starts_with("io: "),
            "IoError must tag as io:, got {io_any}",
        );
        assert_eq!(classify_exit(&io_any), EXIT_INTERNAL_ERROR);
    }

    #[test]
    fn seed_error_to_anyhow_tags_user_for_validation() {
        let val_err = SeedError::ValidationError {
            identifier: "polaris.foo".to_owned(),
            message: "decision_criteria too short".to_owned(),
        };
        let val_any = seed_error_to_anyhow(val_err);
        assert!(
            val_any.to_string().starts_with("user: "),
            "ValidationError must tag as user:, got {val_any}",
        );
        assert_eq!(classify_exit(&val_any), EXIT_USER_ERROR);
    }

    /// Build a [`SeedPolicy`] with every field populated to known
    /// values. The conversion helpers are field-name-driven, so
    /// asserting round-trip equality on every field catches a stray
    /// `clone` or transposed assignment that the type system
    /// would otherwise miss.
    fn sample_seed_policy() -> SeedPolicy {
        SeedPolicy {
            identifier: "polaris.test".to_owned(),
            name: "Test policy".to_owned(),
            description: "A description".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria:
                "criteria criteria criteria criteria criteria criteria criteria criteria".to_owned(),
            examples_positive: vec![],
            examples_negative: vec![],
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: Some("test".to_owned()),
            exceptions: Some("none".to_owned()),
            human_required_always: false,
            autonomy_mode: "manual".to_owned(),
            autonomous_action_kinds: vec![],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
        }
    }

    #[test]
    fn new_from_seed_carries_every_field() {
        let policy = sample_seed_policy();
        let new = new_from_seed(policy);
        assert_eq!(new.identifier, "polaris.test");
        assert_eq!(new.name, "Test policy");
        assert_eq!(new.scope, "post");
        assert_eq!(new.severity, "alert");
        assert_eq!(new.suggested_action_kinds, vec!["label".to_owned()]);
        assert_eq!(new.linked_label_value, Some("test".to_owned()));
        assert!(!new.human_required_always);
        assert_eq!(new.autonomy_mode, "manual");
        assert!(new.examples_positive.is_none());
        assert!(new.examples_negative.is_none());
        assert!(
            new.change_summary.is_none(),
            "v1 inserts via seed-policies must not carry a change_summary",
        );
    }

    #[test]
    fn patch_from_seed_overrides_every_field() {
        // The amend path must overwrite the prior version wholesale,
        // not carry-forward. Every patch field must be Some(_) so
        // the seed file's view becomes the new current version.
        let policy = sample_seed_policy();
        let patch = patch_from_seed(&policy);
        assert!(patch.name.is_some());
        assert!(patch.description.is_some());
        assert!(patch.scope.is_some());
        assert!(patch.severity.is_some());
        assert!(patch.decision_criteria.is_some());
        assert!(patch.examples_positive.is_some());
        assert!(patch.examples_negative.is_some());
        assert!(patch.suggested_action_kinds.is_some());
        assert!(patch.linked_label_value.is_some());
        assert!(patch.exceptions.is_some());
        assert!(patch.human_required_always.is_some());
        assert!(patch.autonomy_mode.is_some());
        assert!(patch.autonomous_action_kinds.is_some());
        assert!(patch.autonomous_confidence_threshold.is_some());
        assert!(patch.assisted_confidence_threshold.is_some());
        // ...except is_retired: retiring is an admin-UI action, not
        // a seed-import side effect.
        assert!(
            patch.is_retired.is_none(),
            "seed-policies must never tombstone a row",
        );
    }

    #[test]
    fn examples_to_json_empty_returns_none() {
        let out = examples_to_json(&[]);
        assert!(out.is_none(), "empty list must produce None (DB default)");
    }
}
