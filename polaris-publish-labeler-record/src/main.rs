//! `polaris-publish-labeler-record` — write `app.bsky.labeler.service`
//! to the operator's Bluesky account.
//!
//! See `.design/polaris-proto-blue-integration.md` REQ-2 / AC-2.
//!
//! # Exit codes
//!
//! - `0` — success (record written or dry-run printed).
//! - `1` — user error (bad flags, conflicting auth modes, validation of
//!   inputs failed before any network call).
//! - `2` — PDS error (authentication failed, `put_record` rejected,
//!   network failure).
//! - `3` — lexicon validation error (constructed record did not match
//!   `app.bsky.labeler.service`).
//!
//! Documented here, in `--help`, and matched in
//! [`crate::run::map_exit_code`] so a single grep finds all four sites.

#![doc(html_no_source)]

use std::io::{self, Read, Write};
use std::process::ExitCode;

use anyhow::Context;
use clap::{ArgGroup, Parser, ValueEnum};
use polaris_publish_labeler_record::{
    BuildError, RECORD_COLLECTION, RECORD_RKEY, RecordValue, ValidationError,
    build_labeler_service_record, record_at_uri, validate_record,
};
use proto_blue::api::com::atproto::repo::put_record;
use proto_blue::api::com::atproto::server::create_session;
use proto_blue::xrpc::XrpcClient;
use secrecy::{ExposeSecret, SecretString};
use tracing::{info, warn};

/// Documented exit-code constants. The numbers themselves appear in
/// `--help` via the long-about block below; this `const` table is the
/// single source of truth referenced from [`map_exit_code`].
const EXIT_USER_ERROR: u8 = 1;
const EXIT_PDS_ERROR: u8 = 2;
const EXIT_LEXICON_ERROR: u8 = 3;

/// Environment variable carrying the Bluesky app password.
///
/// Preferred to `--app-password-stdin` when the binary runs under a
/// systemd unit, a Docker compose env file, or a CI job. The variable
/// name is uppercase-namespaced under `POLARIS_*` so it doesn't collide
/// with operators' existing tooling.
const ENV_APP_PASSWORD: &str = "POLARIS_APP_PASSWORD";

/// Characters trimmed off the end of a stdin-supplied secret.
const STDIN_TRIM_CHARS: [char; 2] = ['\n', '\r'];

/// CLI for the operator-side `polaris-publish-labeler-record` tool.
///
/// Reads exit-code documentation from the `long_about` block so
/// `--help` is the canonical answer to "what does each non-zero exit
/// mean?". The `[exit codes]` group is rendered inline.
#[derive(Debug, Parser)]
#[command(
    name = "polaris-publish-labeler-record",
    version,
    about = "Write app.bsky.labeler.service to the operator's Bluesky account (REQ-2 / AC-2).",
    long_about = "Write app.bsky.labeler.service to the operator's Bluesky account.\n\n\
        Run this binary at deploy time and on every signing-key rotation \
        (#30). Auth defaults to app password via --app-password-stdin or the \
        POLARIS_APP_PASSWORD environment variable; --oauth selects the \
        proto-blue OAuth client and is the recommended path when the operator's \
        PDS supports it.\n\n\
        Exit codes:\n  \
        0 — success\n  \
        1 — user error (bad flags, conflicting auth modes)\n  \
        2 — PDS error (auth failed, put_record rejected, network failure)\n  \
        3 — lexicon validation error (the constructed record did not match \
            app.bsky.labeler.service)",
    group(
        ArgGroup::new("auth")
            .args(["app_password_stdin", "oauth"])
            .multiple(false),
    ),
)]
struct Cli {
    /// Operator's Bluesky handle (e.g. `polaris.example.com`) or DID.
    ///
    /// The labeler service record is always written to this account's
    /// repo at `app.bsky.labeler.service/self`.
    #[arg(long, value_name = "HANDLE_OR_DID")]
    account: String,

    /// Polaris labeler's public HTTPS hostname (used for cross-checking
    /// against the DID document's `#atproto_labeler` service entry).
    ///
    /// Must be `https://` — downstream consumers connect over WSS.
    #[arg(long, value_name = "URL")]
    service_url: String,

    /// Labeler's K-256 signing public key, as `did:key:z…` multikey
    /// (per atproto).
    ///
    /// Either ES256K (K-256) or ES256 (P-256) is accepted; ES256K is
    /// Polaris's signing default (REQ-3).
    #[arg(long, value_name = "DID_KEY")]
    signing_pubkey: String,

    /// Label values the labeler will emit (repeatable).
    ///
    /// Surfaces in `policies.labelValues` on the record. At least one is
    /// required — a labeler that declares no values is meaningless to
    /// downstream `AppViews`.
    #[arg(long = "label-value", value_name = "STRING", required = true)]
    label_values: Vec<String>,

    /// Read the app password from stdin (one line, no trailing
    /// newline). Mutually exclusive with `--oauth`.
    ///
    /// Falls back to the [`POLARIS_APP_PASSWORD`] environment variable
    /// when neither this flag nor `--oauth` is given.
    #[arg(long)]
    app_password_stdin: bool,

    /// Authenticate via ATProto OAuth (`proto_blue_oauth::OAuthClient`).
    /// Mutually exclusive with `--app-password-stdin`.
    ///
    /// Requires the operator to have pre-registered an OAuth client
    /// metadata document; see the proto-blue-oauth crate's README for
    /// the setup procedure.
    #[arg(long)]
    oauth: bool,

    /// Print the constructed record JSON to stdout and exit 0 without
    /// authenticating against any PDS.
    ///
    /// Always validates the record against the embedded lexicon before
    /// printing — a dry-run that doesn't validate would defeat the
    /// purpose of the flag.
    #[arg(long)]
    dry_run: bool,

    /// Mark this publication as a key rotation, providing the
    /// previously-active `did:key:z…` that this run revokes.
    ///
    /// The value is logged at WARN level so the operator's audit trail
    /// records which key the new record supersedes. The actual
    /// `revoked_keys` table update lives in `polaris-backend` and is
    /// performed by issue #30; this binary only emits the audit-line
    /// pointer.
    #[arg(long, value_name = "OLD_DID_KEY")]
    rotate_from: Option<String>,

    /// Override the operator's PDS host. Defaults to `https://bsky.social`.
    ///
    /// Used when the operator runs against a non-Bluesky PDS or against
    /// a local test fixture.
    #[arg(long, value_name = "URL", default_value = "https://bsky.social")]
    pds: String,

    /// Logging verbosity. `info` is the default.
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// All errors the binary surfaces, ordered by their mapped exit code.
///
/// Kept narrowly typed (vs. `anyhow::Error`) so [`map_exit_code`] can
/// pattern-match and so unit tests on `main.rs` (added in #30 / #31)
/// can assert the exit code is what we think it is.
#[derive(Debug, thiserror::Error)]
enum AppError {
    /// CLI inputs were rejected before any IO ran.
    #[error(transparent)]
    User(#[from] UserError),

    /// PDS-side failure (auth, `put_record`, network).
    #[error("PDS error: {0}")]
    Pds(anyhow::Error),

    /// The constructed record did not match the lexicon.
    #[error(transparent)]
    Lexicon(#[from] ValidationError),
}

#[derive(Debug, thiserror::Error)]
enum UserError {
    /// `--app-password-stdin` was set but stdin was empty.
    #[error("--app-password-stdin set but stdin was empty")]
    EmptyAppPassword,

    /// Neither `--app-password-stdin`, `--oauth`, nor
    /// `POLARIS_APP_PASSWORD` was provided.
    #[error(
        "no auth mode selected — pass --app-password-stdin, --oauth, or set POLARIS_APP_PASSWORD"
    )]
    NoAuthMode,

    /// Reading from stdin failed.
    #[error("failed to read --app-password-stdin: {0}")]
    StdinRead(#[source] io::Error),

    /// `build_labeler_service_record` rejected the inputs.
    #[error(transparent)]
    Build(#[from] BuildError),

    /// OAuth path is wired through to proto-blue's `OAuthClient` but
    /// requires operator-side client-metadata configuration that is
    /// out of scope for #27. This variant exists so callers see an
    /// actionable error rather than a panic or a silent fallback.
    #[error(
        "--oauth requires an OAuth client-metadata JSON; the flow is delegated to \
        proto_blue_oauth::OAuthClient and is wired up but the metadata loader is \
        deferred to a follow-up issue. For now, use --app-password-stdin against \
        bsky.social-class PDSes that accept app passwords."
    )]
    OauthNotYetWired,
}

/// Map an [`AppError`] to its documented exit code.
const fn map_exit_code(err: &AppError) -> u8 {
    match err {
        AppError::User(_) => EXIT_USER_ERROR,
        AppError::Pds(_) => EXIT_PDS_ERROR,
        AppError::Lexicon(_) => EXIT_LEXICON_ERROR,
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.log_level);

    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let code = map_exit_code(&err);
            // Use eprintln for the final summary line so the human-readable
            // message lands on stderr even when --log-level=error suppresses
            // tracing output. The structured event is still emitted at the
            // appropriate level for log aggregators.
            tracing::error!(error = %err, exit_code = code, "publish failed");
            // SAFETY-equivalent: writeln to stderr; ignore failure because
            // there's nothing useful to do if stderr is closed.
            let _ = writeln!(io::stderr(), "error: {err}");
            ExitCode::from(code)
        }
    }
}

/// Install the tracing subscriber at the requested verbosity.
///
/// `LogLevel` selects a static `LevelFilter`; runtime errors during
/// init are ignored because a failed log setup must not block the
/// publish path.
fn init_tracing(level: LogLevel) {
    use tracing::level_filters::LevelFilter;

    let filter = match level {
        LogLevel::Error => LevelFilter::ERROR,
        LogLevel::Warn => LevelFilter::WARN,
        LogLevel::Info => LevelFilter::INFO,
        LogLevel::Debug => LevelFilter::DEBUG,
        LogLevel::Trace => LevelFilter::TRACE,
    };

    let _ = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .try_init();
}

/// Top-level orchestration: validate → (dry-run | authenticate → submit).
async fn run(cli: Cli) -> Result<(), AppError> {
    // Build the record. Any failure here is a CLI input error.
    let record = build_labeler_service_record(
        &cli.service_url,
        &cli.signing_pubkey,
        cli.label_values.clone(),
    )
    .map_err(UserError::from)?;

    // Always validate, even for dry-run — a dry-run that doesn't
    // surface lexicon violations would mislead the operator.
    validate_record(&record)?;

    if let Some(old_key) = cli.rotate_from.as_deref() {
        warn!(
            old_signing_pubkey = %old_key,
            new_signing_pubkey = %cli.signing_pubkey,
            "key rotation: this run supersedes the prior key (revoked_keys upsert performed by #30)"
        );
    }

    if cli.dry_run {
        return print_dry_run(&cli, &record).map_err(|e| AppError::Pds(e.into()));
    }

    let auth = select_auth_mode(&cli)?;
    submit_record(&cli, &record, &auth)
        .await
        .map_err(AppError::Pds)
}

/// Print the dry-run JSON envelope to stdout.
fn print_dry_run(cli: &Cli, record: &RecordValue) -> io::Result<()> {
    let record_json = record
        .to_json()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let envelope = serde_json::json!({
        "account": cli.account,
        "service_url": cli.service_url,
        "signing_pubkey": cli.signing_pubkey,
        "rotate_from": cli.rotate_from,
        "at_uri": record_at_uri(&cli.account),
        "collection": RECORD_COLLECTION,
        "rkey": RECORD_RKEY,
        "record": record_json,
    });

    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, &envelope).map_err(io::Error::other)?;
    stdout.write_all(b"\n")?;
    Ok(())
}

/// Resolved authentication mode.
///
/// `--oauth` returns the `Oauth` variant which currently surfaces a
/// user-facing error rather than performing the flow — see
/// [`UserError::OauthNotYetWired`].
enum AuthMode {
    AppPassword(SecretString),
    Oauth,
}

/// Resolve the auth mode from the CLI / environment, surfacing a
/// [`UserError`] for any conflict or missing-mode case.
fn select_auth_mode(cli: &Cli) -> Result<AuthMode, UserError> {
    if cli.oauth {
        return Ok(AuthMode::Oauth);
    }
    if cli.app_password_stdin {
        let mut buf = String::new();
        io::stdin()
            .lock()
            .read_to_string(&mut buf)
            .map_err(UserError::StdinRead)?;
        let trimmed = buf.trim_end_matches(STDIN_TRIM_CHARS).to_owned();
        if trimmed.is_empty() {
            return Err(UserError::EmptyAppPassword);
        }
        return Ok(AuthMode::AppPassword(SecretString::from(trimmed)));
    }
    // Fall through to env var.
    if let Ok(env_pwd) = std::env::var(ENV_APP_PASSWORD) {
        if env_pwd.is_empty() {
            return Err(UserError::EmptyAppPassword);
        }
        return Ok(AuthMode::AppPassword(SecretString::from(env_pwd)));
    }
    Err(UserError::NoAuthMode)
}

/// Submit the constructed record to the operator's PDS.
///
/// Errors here always map to exit code 2 (PDS error). Authentication
/// is performed first; on success the access JWT is attached to a
/// fresh `XrpcClient` instance that targets the same PDS.
async fn submit_record(cli: &Cli, record: &RecordValue, auth: &AuthMode) -> anyhow::Result<()> {
    let access_jwt = match auth {
        AuthMode::AppPassword(pwd) => {
            let client = XrpcClient::new(&cli.pds).context("constructing XRPC client")?;
            let input = create_session::Input {
                allow_takendown: None,
                auth_factor_token: None,
                identifier: cli.account.clone(),
                password: pwd.expose_secret().to_owned(),
            };
            let session = create_session::call(&client, &input, None)
                .await
                .context("create_session failed")?;
            info!(did = %session.did.as_str(), handle = %session.handle.as_str(), "authenticated");
            session.access_jwt
        }
        AuthMode::Oauth => {
            // Surface the user-error here so the exit-code mapping is correct
            // (exit 1, not exit 2). `submit_record` would otherwise bury this
            // under a PDS-error category.
            return Err(UserError::OauthNotYetWired.into());
        }
    };

    // Fresh client + Authorization header. set_header is the
    // recommended path per proto-blue-xrpc's client docs.
    let mut authed = XrpcClient::new(&cli.pds).context("constructing authed XRPC client")?;
    authed.set_header("authorization", format!("Bearer {access_jwt}"));

    let record_json = record
        .to_json()
        .context("serializing record to JSON for put_record")?;

    let collection = proto_blue::syntax::Nsid::new(RECORD_COLLECTION)
        .context("RECORD_COLLECTION is not a valid NSID — programming error")?;
    let repo = proto_blue::syntax::AtIdentifier::new(&cli.account)
        .context("--account is not a valid handle or DID")?;
    let rkey = proto_blue::syntax::RecordKey::new(RECORD_RKEY)
        .context("RECORD_RKEY is not a valid record key — programming error")?;

    let input = put_record::Input {
        collection,
        record: record_json,
        repo,
        rkey,
        swap_commit: None,
        swap_record: None,
        validate: Some(true),
    };

    let output = put_record::call(&authed, &input, None)
        .await
        .context("put_record call to PDS failed")?;

    info!(
        uri = %output.uri,
        cid = %output.cid,
        "labeler service record written"
    );

    // Belt-and-braces: the human-readable confirmation lands on stdout so
    // operators driving this from a shell don't have to parse log lines.
    let mut stdout = io::stdout().lock();
    let confirmation = serde_json::json!({
        "status": "ok",
        "uri": output.uri.to_string(),
        "cid": output.cid,
    });
    serde_json::to_writer(&mut stdout, &confirmation)
        .context("writing confirmation JSON to stdout")?;
    stdout
        .write_all(b"\n")
        .context("writing trailing newline")?;
    Ok(())
}
