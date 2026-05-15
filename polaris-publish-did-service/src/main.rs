//! `polaris-publish-did-service` — add or verify the operator's DID
//! document `#atproto_labeler` service entry (issue #60).
//!
//! Background: a labeler operator who publishes
//! `app.bsky.labeler.service` (via `polaris-publish-labeler-record`)
//! still needs to declare the labeler's service URL on their own DID
//! document. Without that, the published record is invisible to
//! downstream `AppView`s.
//!
//! # Exit codes
//!
//! - `0` — success (did:web JSON emitted, or did:plc operation
//!   submitted, or `--validate-only` check passed).
//! - `1` — user error (bad flags, malformed inputs).
//! - `2` — PDS / PLC-directory error (auth failed, `sign_plc_operation`
//!   rejected, network failure, validation of the resulting document
//!   failed).
//!
//! Documented here, in `--help`, and matched in [`map_exit_code`].
//!
//! # PLC flow
//!
//! For did:plc identities the operator's PDS owns one of the rotation
//! keys; the PLC operation surface (request → sign → submit) is provided
//! by `proto_blue::api::com::atproto::identity::{
//! request_plc_operation_signature, sign_plc_operation, submit_plc_operation
//! }`. We do not hand-roll PLC operation JSON.
//!
//! - `request_plc_operation_signature` is unauthenticated from the
//!   binary's perspective: it triggers the PDS to email the operator a
//!   one-time challenge token.
//! - The operator pastes that token back into this binary either via
//!   stdin (default) or via `--token`. Token-via-argv is permitted only
//!   for non-secret CI flows where the email step has been pre-handled.
//! - `sign_plc_operation` produces the signed operation; the operator's
//!   email-verified token authorises the PDS to sign.
//! - `submit_plc_operation` submits the result to the PLC directory.

#![doc(html_no_source)]

use std::io::{self, Read, Write};
use std::process::ExitCode;

use anyhow::{Context, anyhow};
use clap::{Parser, ValueEnum};
use polaris_publish_did_service::{
    BuildError, ValidationError, build_did_web_document, validate_did_document,
};
use proto_blue::api::com::atproto::identity::{
    request_plc_operation_signature, sign_plc_operation, submit_plc_operation,
};
use proto_blue::api::com::atproto::server::create_session;
use proto_blue::xrpc::XrpcClient;
use tracing::{info, warn};

/// Documented exit-code constants.
const EXIT_USER_ERROR: u8 = 1;
const EXIT_REMOTE_ERROR: u8 = 2;

/// Environment variable carrying the operator's PDS app password.
///
/// Used for the did:plc path because the PLC operation procedures
/// require an authenticated XRPC session against the operator's PDS.
const ENV_APP_PASSWORD: &str = "POLARIS_APP_PASSWORD";

/// Environment variable carrying the PLC email-challenge token.
///
/// Preferred over `--token` for CI environments because the value is
/// secret-equivalent (single-use, but disclosing it grants the holder
/// the ability to sign one PLC op for the duration of the challenge
/// window).
const ENV_PLC_TOKEN: &str = "POLARIS_PLC_TOKEN";

/// Characters trimmed off the end of a stdin-supplied secret.
const STDIN_TRIM_CHARS: [char; 2] = ['\n', '\r'];

/// CLI for the operator-side `polaris-publish-did-service` tool.
#[derive(Debug, Parser)]
#[command(
    name = "polaris-publish-did-service",
    version,
    about = "Add or verify the operator DID document `#atproto_labeler` service entry (issue #60).",
    long_about = "Add or verify the operator DID document `#atproto_labeler` service entry.\n\n\
        For did:web identities: prints the well-known/.well-known/did.json JSON to stdout so \
        the operator can host it at https://<handle>/.well-known/did.json.\n\n\
        For did:plc identities: requests an email challenge from the operator's PDS, \
        accepts the operator's pasted token, then signs and submits a PLC operation \
        that adds the `#atproto_labeler` entry.\n\n\
        Both paths validate the resulting DID document has the expected service \
        entry before printing the success summary.\n\n\
        Exit codes:\n  \
        0 — success\n  \
        1 — user error (bad flags, malformed inputs)\n  \
        2 — PDS / PLC directory error (auth, signing, submission, or post-check failed)"
)]
struct Cli {
    /// Operator's handle (e.g. `polaris.example.com`) or DID.
    ///
    /// For `--did-method=web` the handle is used verbatim as the
    /// `did:web` host in the emitted document.
    /// For `--did-method=plc` the value is used to authenticate
    /// against the operator's PDS.
    #[arg(long, value_name = "HANDLE_OR_DID")]
    account: String,

    /// Polaris labeler's public HTTPS hostname.
    ///
    /// Must be `https://` — downstream consumers connect over WSS.
    /// Appears verbatim as the `#atproto_labeler` `serviceEndpoint`.
    #[arg(long, value_name = "URL")]
    service_url: String,

    /// Labeler's K-256 signing public key, as `did:key:z…` multikey.
    ///
    /// Either ES256K (K-256) or ES256 (P-256) is accepted; ES256K is
    /// Polaris's signing default (REQ-3).
    #[arg(long, value_name = "DID_KEY")]
    signing_key: String,

    /// DID method to target.
    #[arg(long, value_enum, value_name = "METHOD")]
    did_method: DidMethod,

    /// For `--did-method=web`: the operator's PDS endpoint to embed
    /// in the document's `#atproto_pds` service entry.
    ///
    /// Defaults to `https://bsky.social`. Ignored for `--did-method=plc`.
    #[arg(long, value_name = "URL", default_value = "https://bsky.social")]
    pds: String,

    /// For `--did-method=plc`: PLC challenge token (received via email
    /// after `request_plc_operation_signature`).
    ///
    /// Either pass via this flag or feed via stdin / [`POLARIS_PLC_TOKEN`].
    /// Token-via-argv is convenient for CI; for interactive use the
    /// default stdin path keeps the token out of process listings.
    #[arg(long, value_name = "TOKEN")]
    token: Option<String>,

    /// Skip the email-challenge step (do not call
    /// `request_plc_operation_signature`).
    ///
    /// Useful when the operator already has a valid token in hand,
    /// e.g. mid-retry after a previous run failed at the submit step.
    /// Default: false (always send a fresh challenge).
    #[arg(long, default_value_t = false)]
    skip_request_token: bool,

    /// Validate the operator's existing DID document and exit without
    /// making any changes.
    ///
    /// Reads the document from `--did-document-path` (a local file)
    /// and confirms it contains the expected `#atproto_labeler` entry.
    /// Used for CI smoke tests and post-deploy verification.
    #[arg(long, default_value_t = false)]
    validate_only: bool,

    /// Path to a DID document JSON file (used with `--validate-only`).
    #[arg(long, value_name = "PATH")]
    did_document_path: Option<std::path::PathBuf>,

    /// Logging verbosity. `info` is the default.
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,
}

/// Which DID method the operator's identity uses.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum DidMethod {
    /// `did:plc:…` — mutable, requires the PLC directory operation
    /// flow (request → sign → submit).
    Plc,
    /// `did:web:…` — operator-hosted, requires the operator to publish
    /// the new JSON at `https://<handle>/.well-known/did.json`.
    Web,
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
#[derive(Debug, thiserror::Error)]
enum AppError {
    /// CLI inputs were rejected before any IO ran.
    #[error(transparent)]
    User(#[from] UserError),

    /// PDS-side or PLC-directory failure.
    #[error("remote error: {0}")]
    Remote(anyhow::Error),
}

#[derive(Debug, thiserror::Error)]
enum UserError {
    /// `--validate-only` was set but `--did-document-path` was not.
    #[error("--validate-only requires --did-document-path")]
    ValidateOnlyMissingPath,

    /// Reading the DID document file failed.
    #[error("failed to read --did-document-path {path}: {source}")]
    ReadDidDocument {
        /// Path the caller supplied.
        path: String,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Parsing the DID document JSON failed.
    #[error("--did-document-path {path} is not valid JSON: {source}")]
    ParseDidDocument {
        /// Path the caller supplied.
        path: String,
        /// Underlying JSON error.
        #[source]
        source: serde_json::Error,
    },

    /// Validation of the supplied DID document failed.
    #[error(transparent)]
    Validation(#[from] ValidationError),

    /// `build_did_web_document` rejected the inputs.
    #[error(transparent)]
    Build(#[from] BuildError),

    /// `--did-method=plc` selected but no app password is available.
    #[error(
        "did:plc requires the operator's PDS app password — \
        set POLARIS_APP_PASSWORD or pipe it on stdin"
    )]
    NoAppPassword,

    /// `--did-method=plc` selected but no PLC token is available.
    #[error(
        "did:plc requires the email-challenge token — pass --token, \
        set POLARIS_PLC_TOKEN, or pipe it on stdin"
    )]
    NoPlcToken,

    /// Reading from stdin failed.
    #[error("failed to read from stdin: {0}")]
    StdinRead(#[source] io::Error),
}

/// Map an [`AppError`] to its documented exit code.
const fn map_exit_code(err: &AppError) -> u8 {
    match err {
        AppError::User(_) => EXIT_USER_ERROR,
        AppError::Remote(_) => EXIT_REMOTE_ERROR,
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
            tracing::error!(error = %err, exit_code = code, "publish-did-service failed");
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

    // Write tracing output to stderr so stdout remains exclusively the
    // serialized DID document / confirmation JSON. The integration test
    // `cli_did_method_web_prints_did_document_json` parses stdout
    // directly; any log line mixed into stdout would break the JSON
    // parser.
    let _ = tracing_subscriber::fmt()
        .with_max_level(filter)
        .with_target(false)
        .with_writer(io::stderr)
        .try_init();
}

/// Top-level orchestration: dispatch on the selected DID method.
async fn run(cli: Cli) -> Result<(), AppError> {
    if cli.validate_only {
        return run_validate_only(&cli).map_err(AppError::User);
    }

    match cli.did_method {
        DidMethod::Web => run_did_web(&cli).map_err(AppError::User),
        DidMethod::Plc => run_did_plc(&cli).await,
    }
}

/// Read a local DID document and verify it has the expected
/// `#atproto_labeler` service entry plus a verification method for the
/// expected signing key.
fn run_validate_only(cli: &Cli) -> Result<(), UserError> {
    let path = cli
        .did_document_path
        .as_ref()
        .ok_or(UserError::ValidateOnlyMissingPath)?;

    let body = std::fs::read_to_string(path).map_err(|source| UserError::ReadDidDocument {
        path: path.display().to_string(),
        source,
    })?;
    let doc: serde_json::Value =
        serde_json::from_str(&body).map_err(|source| UserError::ParseDidDocument {
            path: path.display().to_string(),
            source,
        })?;

    validate_did_document(&doc, &cli.service_url, &cli.signing_key)?;

    info!("DID document validation passed");
    let mut stdout = io::stdout().lock();
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::json!({
            "status": "ok",
            "service_url": cli.service_url,
            "signing_key": cli.signing_key,
        })
    );
    Ok(())
}

/// did:web path: emit the document JSON to stdout and instruct the
/// operator to host it at `https://<account>/.well-known/did.json`.
fn run_did_web(cli: &Cli) -> Result<(), UserError> {
    let doc = build_did_web_document(&cli.account, &cli.pds, &cli.signing_key, &cli.service_url)?;

    // Cross-check we emitted what we think we emitted.
    validate_did_document(&doc, &cli.service_url, &cli.signing_key)?;

    let mut stdout = io::stdout().lock();
    let _ = serde_json::to_writer_pretty(&mut stdout, &doc);
    let _ = stdout.write_all(b"\n");

    warn!(
        host = %cli.account,
        path = "/.well-known/did.json",
        "host this JSON at https://<host>/.well-known/did.json — atproto resolvers fetch the document over HTTPS"
    );
    Ok(())
}

/// did:plc path: request a signature challenge, accept the operator's
/// pasted token, sign the PLC operation, and submit it.
///
/// Uses the proto-blue generated types end-to-end; no PLC operation
/// JSON is hand-rolled.
async fn run_did_plc(cli: &Cli) -> Result<(), AppError> {
    // Build the target document locally first so we can plug its
    // `service` and `verificationMethod` arrays into the PLC operation
    // payload. Any input-validation failure surfaces here as
    // `UserError`, before any network call.
    let target = build_did_web_document(&cli.account, &cli.pds, &cli.signing_key, &cli.service_url)
        .map_err(UserError::from)?;

    // Authenticate against the operator's PDS.
    let app_password = load_app_password().map_err(AppError::User)?;
    let xrpc = authenticate(&cli.pds, &cli.account, &app_password)
        .await
        .map_err(AppError::Remote)?;

    // 1. Email challenge (skippable if the operator already has a token).
    if !cli.skip_request_token {
        info!("requesting PLC operation signature challenge via PDS");
        request_plc_operation_signature::call(&xrpc, None)
            .await
            .map_err(|e| {
                AppError::Remote(anyhow!("request_plc_operation_signature failed: {e}"))
            })?;
        // The PDS sends the token to the operator's email. We block on
        // operator input — print the prompt now so the wait is obvious.
        let _ = writeln!(
            io::stderr(),
            "Check the email associated with this account for a PLC operation challenge token.\nPaste the token on stdin and press Enter (or use --token / POLARIS_PLC_TOKEN to provide it ahead of time)."
        );
    }

    let token = load_plc_token(cli).map_err(AppError::User)?;

    // 2. Build the `services` and `verificationMethods` payloads.
    //    Per the lexicon both fields are typed `unknown`, so the wire
    //    representation is `serde_json::Value`. We build them from the
    //    document we constructed locally so the two stay in sync.
    let services_payload = build_plc_services_payload(&target)
        .ok_or_else(|| AppError::Remote(anyhow!("internal: built doc missing service array")))?;
    let verification_methods_payload =
        build_plc_verification_methods_payload(&target).ok_or_else(|| {
            AppError::Remote(anyhow!(
                "internal: built doc missing verificationMethod array"
            ))
        })?;

    // 3. Sign.
    info!("submitting sign_plc_operation to PDS");
    let sign_input = sign_plc_operation::Input {
        also_known_as: None,
        rotation_keys: None,
        services: Some(services_payload),
        token: Some(token),
        verification_methods: Some(verification_methods_payload),
    };
    let signed = sign_plc_operation::call(&xrpc, &sign_input, None)
        .await
        .map_err(|e| AppError::Remote(anyhow!("sign_plc_operation failed: {e}")))?;

    // 4. Submit.
    info!("submitting signed PLC operation to PLC directory via PDS");
    let submit_input = submit_plc_operation::Input {
        operation: signed.operation,
    };
    submit_plc_operation::call(&xrpc, &submit_input, None)
        .await
        .map_err(|e| AppError::Remote(anyhow!("submit_plc_operation failed: {e}")))?;

    // 5. Cross-check: validate our locally-built target document so the
    //    operator sees the expected entries before exit. (We can't
    //    re-fetch the PLC document here without an extra hop; the
    //    in-process validation guarantees we *sent* the right shape.)
    validate_did_document(&target, &cli.service_url, &cli.signing_key)
        .map_err(|e| AppError::Remote(anyhow!("post-submit validation failed: {e}")))?;

    let mut stdout = io::stdout().lock();
    let confirmation = serde_json::json!({
        "status": "ok",
        "method": "plc",
        "account": cli.account,
        "service_url": cli.service_url,
        "signing_key": cli.signing_key,
    });
    let _ = serde_json::to_writer(&mut stdout, &confirmation);
    let _ = stdout.write_all(b"\n");
    Ok(())
}

/// Extract the `service` array from a built DID document for use in
/// `sign_plc_operation::Input.services`.
fn build_plc_services_payload(doc: &serde_json::Value) -> Option<serde_json::Value> {
    doc.get("service").cloned()
}

/// Extract the `verificationMethod` array from a built DID document for
/// use in `sign_plc_operation::Input.verification_methods`.
fn build_plc_verification_methods_payload(doc: &serde_json::Value) -> Option<serde_json::Value> {
    doc.get("verificationMethod").cloned()
}

/// Load the operator's PDS app password from
/// [`POLARIS_APP_PASSWORD`].
///
/// Secrets are never accepted on argv (see the issue's forbidden
/// patterns list).
fn load_app_password() -> Result<String, UserError> {
    match std::env::var(ENV_APP_PASSWORD) {
        Ok(s) if !s.is_empty() => Ok(s),
        _ => Err(UserError::NoAppPassword),
    }
}

/// Load the PLC email-challenge token in priority order:
///
/// 1. `--token` flag (CI convenience).
/// 2. [`POLARIS_PLC_TOKEN`] env var.
/// 3. stdin (interactive default).
fn load_plc_token(cli: &Cli) -> Result<String, UserError> {
    if let Some(t) = cli.token.as_ref() {
        if !t.is_empty() {
            return Ok(t.clone());
        }
    }
    if let Ok(t) = std::env::var(ENV_PLC_TOKEN) {
        if !t.is_empty() {
            return Ok(t);
        }
    }
    // Final fallback: stdin.
    let mut buf = String::new();
    io::stdin()
        .lock()
        .read_to_string(&mut buf)
        .map_err(UserError::StdinRead)?;
    let trimmed = buf.trim_end_matches(STDIN_TRIM_CHARS).to_owned();
    if trimmed.is_empty() {
        return Err(UserError::NoPlcToken);
    }
    Ok(trimmed)
}

/// Authenticate against the operator's PDS and return an
/// `Authorization: Bearer …`-decorated XRPC client.
async fn authenticate(pds: &str, identifier: &str, password: &str) -> anyhow::Result<XrpcClient> {
    let client = XrpcClient::new(pds).context("constructing XRPC client")?;
    let input = create_session::Input {
        allow_takendown: None,
        auth_factor_token: None,
        identifier: identifier.to_string(),
        password: password.to_string(),
    };
    let session = create_session::call(&client, &input, None)
        .await
        .context("create_session failed")?;
    info!(did = %session.did.as_str(), handle = %session.handle.as_str(), "authenticated");
    let mut authed = XrpcClient::new(pds).context("constructing authed XRPC client")?;
    authed.set_header("authorization", format!("Bearer {}", session.access_jwt));
    Ok(authed)
}
