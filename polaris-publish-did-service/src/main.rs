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
//!
//! # Auth modes
//!
//! Two PDS authentication modes are supported (mutually exclusive):
//!
//! - **App password** (the historical default): authenticate via
//!   `com.atproto.server.createSession` and attach the resulting JWT
//!   to every XRPC call. Works on private/self-hosted PDSes that
//!   accept app-password sessions for PLC operations.
//! - **OAuth** (`--oauth`, issue #80): authenticate via the ATProto
//!   OAuth client (PAR + PKCE + DPoP) and POST every PLC operation
//!   through an `OAuthSession`. Required for `bsky.social`, which
//!   refuses PLC operations from app-password sessions with
//!   "Bad token scope". Mirrors the `--oauth` wiring in
//!   `polaris-publish-labeler-record` (#61).

#![doc(html_no_source)]

use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, anyhow};
use clap::{ArgGroup, Parser, ValueEnum};
use polaris_publish_did_service::{
    BuildError, ValidationError, build_did_web_document, build_plc_services_payload,
    build_plc_verification_methods_payload, validate_did_document,
};
use proto_blue::api::com::atproto::identity::{
    request_plc_operation_signature, sign_plc_operation, submit_plc_operation,
};
use proto_blue::api::com::atproto::server::create_session;
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::client::dpop_key_from_jwk;
use proto_blue::oauth::{
    DpopNonceCache, OAuthClient, OAuthSession, ResolvedInput, resolve_input,
    validate_client_metadata,
};
use proto_blue::xrpc::XrpcClient;
use secrecy::{ExposeSecret, SecretString};
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
        Auth for did:plc defaults to the POLARIS_APP_PASSWORD app-password path. \
        Pass --oauth (with --client-metadata pointing at the operator-supplied OAuth \
        client metadata JSON) to drive the proto-blue OAuth flow instead — required \
        for bsky.social, which refuses PLC operations from app-password sessions \
        with `Bad token scope` (#80). The OAuth path prints an authorize URL for the \
        operator to open in a browser, then reads the redirected URL back from stdin \
        to complete the code exchange.\n\n\
        Both paths validate the resulting DID document has the expected service \
        entry before printing the success summary.\n\n\
        Exit codes:\n  \
        0 — success\n  \
        1 — user error (bad flags, malformed inputs, missing OAuth client metadata)\n  \
        2 — PDS / PLC directory error (auth, signing, submission, or post-check failed)",
    group(
        ArgGroup::new("plc_auth")
            .args(["app_password_stdin", "oauth"])
            .multiple(false),
    ),
)]
// Five orthogonal boolean flags reflect five independent operator
// switches (auth mode, validate-only, skip-challenge, app-password
// source, OAuth). Collapsing them into an enum would couple unrelated
// choices and lose `clap`'s long-option ergonomics; the lint flags a
// real concern (too many bools is a code smell) but does not apply to
// a flat CLI surface where each bool is a distinct user-facing toggle.
#[allow(
    clippy::struct_excessive_bools,
    reason = "flat CLI surface — each bool is an independent operator flag"
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

    /// Read the app password from stdin (one line, no trailing newline).
    /// Mutually exclusive with `--oauth`.
    ///
    /// Only consulted when `--did-method=plc` is selected. Falls back
    /// to the [`POLARIS_APP_PASSWORD`] environment variable when this
    /// flag is absent and `--oauth` is not set.
    #[arg(long)]
    app_password_stdin: bool,

    /// Authenticate against the operator's PDS via ATProto OAuth
    /// (`proto_blue::oauth::OAuthClient`). Mutually exclusive with
    /// `--app-password-stdin`. Required for `bsky.social`, which
    /// rejects PLC operations from app-password sessions (#80).
    ///
    /// Drives the authorization-code flow with PAR + PKCE + DPoP. The
    /// CLI prints the AS-issued authorize URL to stderr, the operator
    /// completes the in-browser consent, and the CLI reads the
    /// redirected URL back from stdin to extract the `code` parameter.
    /// Requires `--client-metadata` pointing at the operator-supplied
    /// OAuth client metadata JSON.
    #[arg(long)]
    oauth: bool,

    /// Path to the OAuth client-metadata JSON. Required when `--oauth`
    /// is set; ignored otherwise.
    ///
    /// The file is the `client-metadata.json` document the operator
    /// hosts at `client_id` (or, for loopback testing, a local file
    /// that mirrors what would otherwise be hosted). The same loader
    /// (`polaris_types::oauth_config::load_client_metadata`) is shared
    /// with `polaris-publish-labeler-record`'s `--oauth` flow and the
    /// `polaris-backend` ATProto OAuth verifier so the wire shape is
    /// enforced from one place.
    #[arg(long, value_name = "PATH", requires = "oauth")]
    client_metadata: Option<PathBuf>,

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

    /// `--did-method=plc` selected, `--oauth` not set, and no app
    /// password is available via `--app-password-stdin` or
    /// [`POLARIS_APP_PASSWORD`].
    #[error(
        "did:plc requires either --oauth or the operator's PDS app password — \
        set POLARIS_APP_PASSWORD, pass --app-password-stdin and pipe it on stdin, \
        or pass --oauth (with --client-metadata)"
    )]
    NoAppPassword,

    /// `--app-password-stdin` was set but stdin was empty.
    #[error("--app-password-stdin set but stdin was empty")]
    EmptyAppPassword,

    /// `--did-method=plc` selected but no PLC token is available.
    #[error(
        "did:plc requires the email-challenge token — pass --token, \
        set POLARIS_PLC_TOKEN, or pipe it on stdin"
    )]
    NoPlcToken,

    /// Reading from stdin failed.
    #[error("failed to read from stdin: {0}")]
    StdinRead(#[source] io::Error),

    /// `--oauth` was supplied without `--client-metadata`.
    ///
    /// Clap's `requires = "oauth"` on the `--client-metadata` flag
    /// enforces the dependency in one direction; this error covers
    /// the other direction (`--oauth` without `--client-metadata`),
    /// surfaced from [`select_auth_mode`] as a user error (exit 1)
    /// rather than a remote/PDS error (exit 2).
    #[error("--oauth requires --client-metadata pointing at the operator's client-metadata JSON")]
    OauthMissingClientMetadata,

    /// `polaris_types::oauth_config::load_client_metadata` failed.
    ///
    /// The error is preserved via `#[source]` so the chain renders
    /// the underlying read / parse failure under the user-facing
    /// "OAuth client metadata could not be loaded" headline.
    #[error("OAuth client metadata could not be loaded")]
    OauthClientMetadata(#[from] polaris_types::oauth_config::OauthConfigError),
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

/// Resolved authentication mode for the did:plc path.
///
/// Selected by [`select_auth_mode`] from the CLI flags and environment.
/// The `Oauth` variant carries the pre-loaded client metadata so any
/// load / parse failure surfaces as a [`UserError`] (exit 1) at
/// `select_auth_mode` time rather than getting classified as a remote
/// error (exit 2) inside [`run_did_plc`].
///
/// The variant for OAuth boxes its payload so the
/// `clippy::large_enum_variant` lint stays quiet — the
/// `AppPassword(String)` variant is one pointer-sized payload, while
/// the metadata struct carries every nullable `client_*` field.
#[derive(Debug)]
enum AuthMode {
    /// App-password session. Wrapped in `SecretString` so the value is
    /// redacted from `Debug` output and zeroised on drop. Mirrors the
    /// `polaris-publish-labeler-record` `AuthMode::AppPassword` carrier
    /// so the two CLIs share the same secret-handling discipline.
    AppPassword(SecretString),
    Oauth {
        /// Validated client metadata. The atproto-profile check via
        /// `proto_blue::oauth::validate_client_metadata` runs inside
        /// [`run_did_plc_oauth`] (it's a wire-shape assertion, not a
        /// user-input check).
        metadata: Box<polaris_types::oauth_config::ClientMetadata>,
    },
}

/// Resolve the auth mode from the CLI / environment.
///
/// Order of precedence:
///
/// 1. `--oauth` → `AuthMode::Oauth`. Requires `--client-metadata`.
/// 2. `--app-password-stdin` → `AuthMode::AppPassword`, read from stdin.
/// 3. [`POLARIS_APP_PASSWORD`] env var → `AuthMode::AppPassword`.
/// 4. No source available → `UserError::NoAppPassword`.
///
/// Clap's `ArgGroup` already rejects `--oauth` together with
/// `--app-password-stdin` before this function is reached.
fn select_auth_mode(cli: &Cli) -> Result<AuthMode, UserError> {
    if cli.oauth {
        let client_metadata_path = cli
            .client_metadata
            .as_deref()
            .ok_or(UserError::OauthMissingClientMetadata)?;
        let metadata = polaris_types::oauth_config::load_client_metadata(client_metadata_path)?;
        return Ok(AuthMode::Oauth {
            metadata: Box::new(metadata),
        });
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
    if let Ok(env_pwd) = std::env::var(ENV_APP_PASSWORD) {
        if !env_pwd.is_empty() {
            return Ok(AuthMode::AppPassword(SecretString::from(env_pwd)));
        }
    }
    Err(UserError::NoAppPassword)
}

/// did:plc orchestration: build the target document, resolve the
/// auth mode, dispatch to the per-mode driver, then validate the
/// locally-built document and emit the confirmation envelope.
///
/// Uses the proto-blue generated types end-to-end on the XRPC path;
/// the OAuth path drives the same three procedures via
/// `OAuthSession::post`. No PLC operation JSON is hand-rolled.
async fn run_did_plc(cli: &Cli) -> Result<(), AppError> {
    // Build the target document locally first so we can plug its
    // `service` and `verificationMethod` arrays into the PLC operation
    // payload. Any input-validation failure surfaces here as
    // `UserError`, before any network call.
    let target = build_did_web_document(&cli.account, &cli.pds, &cli.signing_key, &cli.service_url)
        .map_err(UserError::from)?;

    // Per the lexicon both `services` and `verificationMethods` are
    // typed `unknown`, so the wire representation is
    // `serde_json::Value`. We build them from the document we
    // constructed locally so the two stay in sync.
    let services_payload = build_plc_services_payload(&target)
        .ok_or_else(|| AppError::Remote(anyhow!("internal: built doc missing service array")))?;
    let verification_methods_payload =
        build_plc_verification_methods_payload(&target).ok_or_else(|| {
            AppError::Remote(anyhow!(
                "internal: built doc missing verificationMethod array"
            ))
        })?;

    let auth = select_auth_mode(cli).map_err(AppError::User)?;

    match auth {
        AuthMode::AppPassword(ref password) => {
            run_did_plc_app_password(
                cli,
                password,
                &services_payload,
                &verification_methods_payload,
            )
            .await?;
        }
        AuthMode::Oauth { metadata } => {
            run_did_plc_oauth(
                cli,
                metadata.as_ref(),
                &services_payload,
                &verification_methods_payload,
            )
            .await?;
        }
    }

    // Cross-check: validate our locally-built target document so the
    // operator sees the expected entries before exit. (We can't
    // re-fetch the PLC document here without an extra hop; the
    // in-process validation guarantees we *sent* the right shape.)
    validate_did_document(&target, &cli.service_url, &cli.signing_key)
        .map_err(|e| AppError::Remote(anyhow!("post-submit validation failed: {e}")))?;

    emit_plc_confirmation(cli).map_err(AppError::Remote)?;
    Ok(())
}

/// App-password branch of [`run_did_plc`].
///
/// Authenticates via `com.atproto.server.createSession`, attaches the
/// resulting JWT to a fresh `XrpcClient`, and drives the
/// `request → sign → submit` triple via the proto-blue typed XRPC
/// procedures.
async fn run_did_plc_app_password(
    cli: &Cli,
    app_password: &SecretString,
    services_payload: &serde_json::Value,
    verification_methods_payload: &serde_json::Value,
) -> Result<(), AppError> {
    // `expose_secret()` is called once at the auth boundary so the
    // plaintext lifetime is the duration of the `authenticate` call;
    // the rest of this function only sees the JWT-bearing `XrpcClient`.
    let xrpc = authenticate(&cli.pds, &cli.account, app_password.expose_secret())
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
        write_plc_token_prompt();
    }

    let token = load_plc_token(cli).map_err(AppError::User)?;

    // 2. Sign.
    info!("submitting sign_plc_operation to PDS");
    let sign_input = sign_plc_operation::Input {
        also_known_as: None,
        rotation_keys: None,
        services: Some(services_payload.clone()),
        token: Some(token),
        verification_methods: Some(verification_methods_payload.clone()),
    };
    let signed = sign_plc_operation::call(&xrpc, &sign_input, None)
        .await
        .map_err(|e| AppError::Remote(anyhow!("sign_plc_operation failed: {e}")))?;

    // 3. Submit.
    info!("submitting signed PLC operation to PLC directory via PDS");
    let submit_input = submit_plc_operation::Input {
        operation: signed.operation,
    };
    submit_plc_operation::call(&xrpc, &submit_input, None)
        .await
        .map_err(|e| AppError::Remote(anyhow!("submit_plc_operation failed: {e}")))?;

    Ok(())
}

/// OAuth branch of [`run_did_plc`].
///
/// Drives PAR + PKCE + DPoP via `proto_blue::oauth::OAuthClient`,
/// then POSTs the three `com.atproto.identity.*` procedures through
/// an `OAuthSession`. The browser-redirect step uses the
/// paste-back-URL convention (same as
/// `polaris-publish-labeler-record`'s `--oauth` flow).
///
/// The three PLC procedures are typed `procedure` lexicons with JSON
/// inputs; we serialise the typed `Input` structs to JSON so the wire
/// shape stays identical to what `proto_blue::api::...::call` would
/// emit on the XRPC path. `request_plc_operation_signature` has no
/// input lexicon — we send `{}` because `OAuthSession::post` always
/// writes a JSON body, and bsky.social's PDS accepts an empty object
/// for procedures with no defined input.
async fn run_did_plc_oauth(
    cli: &Cli,
    metadata: &polaris_types::oauth_config::ClientMetadata,
    services_payload: &serde_json::Value,
    verification_methods_payload: &serde_json::Value,
) -> Result<(), AppError> {
    let session = open_oauth_session(cli, metadata)
        .await
        .map_err(AppError::Remote)?;

    // The PDS the OAuth session is bound to. `resolve_input` returned
    // this as the `aud` of the issued token; every subsequent DPoP
    // proof is signed against this origin. We re-derive it here rather
    // than threading it through `open_oauth_session` so the function
    // stays focused on producing the session.
    let pds_url = cli.pds.trim_end_matches('/').to_owned();

    // 1. Email challenge (skippable if the operator already has a token).
    if !cli.skip_request_token {
        info!("requesting PLC operation signature challenge via PDS (OAuth)");
        let empty = serde_json::Value::Object(serde_json::Map::new());
        let response = session
            .post(
                &format!("{pds_url}/xrpc/com.atproto.identity.requestPlcOperationSignature"),
                &empty,
            )
            .await
            .map_err(|e| {
                AppError::Remote(anyhow!(
                    "request_plc_operation_signature (OAuth) failed: {e}"
                ))
            })?;
        ensure_success(
            &response,
            "com.atproto.identity.requestPlcOperationSignature",
        )
        .map_err(AppError::Remote)?;
        write_plc_token_prompt();
    }

    let token = load_plc_token(cli).map_err(AppError::User)?;

    // 2. Sign. We serialise the typed `sign_plc_operation::Input` to
    //    JSON via the proto-blue derive so the wire shape (camelCase
    //    fields, omitted Nones) matches the XRPC path exactly.
    info!("submitting sign_plc_operation to PDS (OAuth)");
    let sign_input = sign_plc_operation::Input {
        also_known_as: None,
        rotation_keys: None,
        services: Some(services_payload.clone()),
        token: Some(token),
        verification_methods: Some(verification_methods_payload.clone()),
    };
    let sign_body = serde_json::to_value(&sign_input)
        .context("serializing sign_plc_operation::Input to JSON")
        .map_err(AppError::Remote)?;
    let sign_response = session
        .post(
            &format!("{pds_url}/xrpc/com.atproto.identity.signPlcOperation"),
            &sign_body,
        )
        .await
        .map_err(|e| AppError::Remote(anyhow!("sign_plc_operation (OAuth) failed: {e}")))?;
    ensure_success(&sign_response, "com.atproto.identity.signPlcOperation")
        .map_err(AppError::Remote)?;

    let signed_value: serde_json::Value = serde_json::from_slice(&sign_response.body)
        .context("decoding sign_plc_operation response JSON")
        .map_err(AppError::Remote)?;
    let operation = signed_value.get("operation").cloned().ok_or_else(|| {
        AppError::Remote(anyhow!(
            "sign_plc_operation response missing `operation` field"
        ))
    })?;

    // 3. Submit.
    info!("submitting signed PLC operation to PLC directory via PDS (OAuth)");
    let submit_input = submit_plc_operation::Input { operation };
    let submit_body = serde_json::to_value(&submit_input)
        .context("serializing submit_plc_operation::Input to JSON")
        .map_err(AppError::Remote)?;
    let submit_response = session
        .post(
            &format!("{pds_url}/xrpc/com.atproto.identity.submitPlcOperation"),
            &submit_body,
        )
        .await
        .map_err(|e| AppError::Remote(anyhow!("submit_plc_operation (OAuth) failed: {e}")))?;
    ensure_success(&submit_response, "com.atproto.identity.submitPlcOperation")
        .map_err(AppError::Remote)?;

    Ok(())
}

/// Drive the OAuth authorize → callback → token-exchange flow and
/// return an `OAuthSession` that signs subsequent resource-server
/// POSTs with the bound DPoP key.
///
/// Mirrors `polaris-publish-labeler-record::submit_via_oauth` so the
/// two CLIs share the same operator-facing prompt and state-match
/// discipline (we refuse to exchange a code whose callback `state`
/// does not match the value the CLI issued).
async fn open_oauth_session(
    cli: &Cli,
    metadata: &polaris_types::oauth_config::ClientMetadata,
) -> anyhow::Result<OAuthSession> {
    // 1. atproto-profile validation of the loaded metadata. The
    //    polaris-types loader only reads + JSON-decodes; profile
    //    validation reuses proto-blue's `validate_client_metadata`
    //    and lives at the call site so the loader stays free of
    //    proto-blue dependencies on validation.
    validate_client_metadata(metadata)
        .context("OAuth client metadata failed atproto profile validation")?;

    let oauth_client = OAuthClient::new(metadata.clone());
    let identity_resolver = Arc::new(IdResolver::new(IdentityResolverOpts::default(), None));

    // 2. Resolve the operator's account → (did?, pds_url, AS metadata).
    let ResolvedInput {
        did,
        pds_url,
        server_metadata,
    } = resolve_input(&identity_resolver, &oauth_client, &cli.account)
        .await
        .with_context(|| format!("resolving --account {} via OAuth identity", &cli.account))?;
    info!(
        pds_url = %pds_url,
        issuer = %server_metadata.issuer,
        resolved_did = did.as_deref().unwrap_or("(none)"),
        "OAuth account resolution complete"
    );

    // 3. Authorize (PAR + PKCE + DPoP).
    let (authorize_url, auth_state) = oauth_client
        .authorize(&server_metadata)
        .await
        .context("OAuth authorize (PAR) failed")?;

    // 4. Interactive consent — print the URL on stderr (stdout stays
    //    reserved for the final confirmation JSON) and the
    //    paste-back prompt next to it.
    write_oauth_prompt(&authorize_url, &server_metadata.issuer)?;

    // 5. Read the redirected URL back from stdin.
    let pasted = read_oauth_callback_url()?;
    let (code, iss_from_url) = parse_oauth_callback(&pasted, &auth_state)?;

    // 6. Exchange the code; bind the token's `aud` to the resolved PDS.
    let token_set = oauth_client
        .callback_with_iss_and_aud(
            &code,
            iss_from_url.as_deref(),
            Some(&pds_url),
            &auth_state,
            &server_metadata,
        )
        .await
        .context("OAuth code exchange failed")?;
    info!(
        sub = %token_set.sub,
        token_type = %token_set.token_type,
        "OAuth code exchanged, access token issued"
    );

    // 7. Rebuild the DpopKey from the JWK that `authorize()` generated.
    let dpop_key = dpop_key_from_jwk(&auth_state.dpop_key)
        .context("reconstructing DPoP key from auth_state JWK")?;

    // 8. Open the OAuthSession — every subsequent request is signed
    //    with `Authorization: DPoP {token}` plus a fresh DPoP proof,
    //    rotating on server-supplied `DPoP-Nonce` headers.
    Ok(OAuthSession::new(
        token_set,
        dpop_key,
        DpopNonceCache::new(),
    ))
}

/// Bail with an `anyhow::Error` when an `OAuthSession`-issued POST
/// returned a non-2xx response.
///
/// The body is included verbatim in the error message so the operator
/// can see the PDS's structured error (`{"error":"...","message":"..."}`)
/// — the most common failure modes (`InvalidToken`, `ExpiredToken`,
/// `BadTokenScope`) surface there. The procedure name in `endpoint_label`
/// disambiguates which of the three PLC POSTs failed.
fn ensure_success(
    response: &proto_blue::common::fetch::HttpResponse,
    endpoint_label: &str,
) -> anyhow::Result<()> {
    if response.is_success() {
        return Ok(());
    }
    Err(anyhow!(
        "{endpoint_label} returned HTTP {status}: {body}",
        status = response.status,
        body = String::from_utf8_lossy(&response.body)
    ))
}

/// Emit the operator-facing prompt that asks for the emailed PLC
/// challenge token.
///
/// Lives on stderr so stdout stays reserved for the final
/// confirmation JSON (which is parseable by any caller piping into
/// `jq`).
fn write_plc_token_prompt() {
    let _ = writeln!(
        io::stderr(),
        "Check the email associated with this account for a PLC operation challenge token.\nPaste the token on stdin and press Enter (or use --token / POLARIS_PLC_TOKEN to provide it ahead of time)."
    );
}

/// Emit the success-path confirmation envelope to stdout.
///
/// Shared by both auth branches so the success summary surfaces the
/// same key set regardless of how the PLC operation was authorised.
fn emit_plc_confirmation(cli: &Cli) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    let confirmation = serde_json::json!({
        "status": "ok",
        "method": "plc",
        "account": cli.account,
        "service_url": cli.service_url,
        "signing_key": cli.signing_key,
    });
    serde_json::to_writer(&mut stdout, &confirmation)
        .context("writing confirmation JSON to stdout")?;
    stdout
        .write_all(b"\n")
        .context("writing trailing newline")?;
    Ok(())
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

/// Print the OAuth authorize URL and paste-back instructions to stderr.
///
/// Lives on stderr so the success-path stdout (the final
/// `{status, method, account, ...}` envelope) remains parseable by an
/// automation caller that pipes stdout into `jq`. Mirrors
/// `polaris-publish-labeler-record`'s prompt verbatim so the two CLIs
/// surface identical operator UX.
fn write_oauth_prompt(authorize_url: &url::Url, issuer: &str) -> anyhow::Result<()> {
    let mut stderr = io::stderr().lock();
    writeln!(
        stderr,
        "\n=== ATProto OAuth: operator consent required ===\n\
         Authorization server: {issuer}\n\
         \n\
         Open this URL in your browser to authorize:\n  \
         {authorize_url}\n\
         \n\
         After completing consent, your browser will redirect to a\n\
         localhost URL that probably fails to load — that is expected.\n\
         Copy the redirected URL from the browser's address bar and\n\
         paste it back here, then press Enter.\n"
    )
    .context("writing OAuth prompt to stderr")?;
    Ok(())
}

/// Read one line from stdin and return the trimmed result.
///
/// The expected input is a URL (the AS-issued redirect with `code`
/// in the query string). An empty line is treated as a user-error —
/// otherwise we'd hand an empty string to the URL parser and surface
/// a misleading "invalid URL" message.
fn read_oauth_callback_url() -> anyhow::Result<String> {
    let mut line = String::new();
    let mut stdin = io::stdin().lock();
    stdin
        .read_line(&mut line)
        .context("reading the pasted OAuth callback URL from stdin")?;
    let trimmed = line.trim().to_owned();
    if trimmed.is_empty() {
        anyhow::bail!("expected a pasted OAuth callback URL on stdin; got empty input");
    }
    Ok(trimmed)
}

/// Parse the operator-pasted callback URL into `(code, iss?)`.
///
/// Enforces the OAuth state-match check before returning the code —
/// a `state` parameter that doesn't equal the one this CLI generated
/// in `authorize()` indicates either a stale paste from a previous
/// flow or a cross-flow attack; either way, we refuse to exchange
/// the code.
fn parse_oauth_callback(
    pasted: &str,
    auth_state: &proto_blue::oauth::AuthState,
) -> anyhow::Result<(String, Option<String>)> {
    let parsed = url::Url::parse(pasted)
        .with_context(|| format!("pasted callback is not a valid URL: {pasted}"))?;

    let mut code: Option<String> = None;
    let mut state: Option<String> = None;
    let mut iss: Option<String> = None;
    let mut error: Option<String> = None;
    let mut error_description: Option<String> = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "iss" => iss = Some(v.into_owned()),
            "error" => error = Some(v.into_owned()),
            "error_description" => error_description = Some(v.into_owned()),
            _ => {}
        }
    }

    if let Some(err) = error {
        let description = error_description.unwrap_or_default();
        anyhow::bail!("authorization server returned error={err}: {description}");
    }

    let expected_state = auth_state
        .app_state
        .as_deref()
        .context("internal: authorize() did not return an app_state token")?;
    let provided_state =
        state.context("pasted callback URL is missing the `state` query parameter")?;
    if provided_state != expected_state {
        anyhow::bail!(
            "pasted callback `state` does not match the value this CLI issued — refusing to exchange the code"
        );
    }

    let code = code.context("pasted callback URL is missing the `code` query parameter")?;
    Ok((code, iss))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the auth-mode selector. Network-bound paths
    //! (PLC operations, the OAuth code exchange) are exercised by
    //! the operator-driven smoke test, not these unit tests.

    // `clippy::unwrap_used`, `clippy::expect_used`, and `clippy::panic`
    // are allowed in test code per the workspace `rust-quality §7`
    // convention — assertion macros are the canonical failure surface
    // here.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code is allowed to panic — rust-quality §7 convention"
    )]

    use super::{AuthMode, Cli, UserError, select_auth_mode};
    use clap::Parser;
    use secrecy::{ExposeSecret, SecretString};

    /// Parse a `Cli` from a sequence of argv-style strings.
    ///
    /// Wraps `Cli::try_parse_from` so each test names its scenario
    /// without re-writing the required-flag boilerplate (`--account`,
    /// `--service-url`, `--signing-key`, `--did-method`).
    fn parse_cli(extra: &[&str]) -> Cli {
        let mut argv: Vec<String> = vec![
            "polaris-publish-did-service".to_owned(),
            "--account".to_owned(),
            "polaris.example.com".to_owned(),
            "--service-url".to_owned(),
            "https://polaris.example.com".to_owned(),
            "--signing-key".to_owned(),
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme".to_owned(),
            "--did-method".to_owned(),
            "plc".to_owned(),
        ];
        argv.extend(extra.iter().map(|s| (*s).to_owned()));
        Cli::try_parse_from(argv).expect("test argv should parse")
    }

    /// `Cli::try_parse_from` returns an error (not a panic) when the
    /// auth-mode `ArgGroup` is violated. This pins the clap-level
    /// rejection so a refactor that loosens the group fails loudly
    /// without needing a process-spawn smoke test.
    #[test]
    fn cli_rejects_oauth_with_app_password_stdin() {
        let result = Cli::try_parse_from([
            "polaris-publish-did-service",
            "--account",
            "polaris.example.com",
            "--service-url",
            "https://polaris.example.com",
            "--signing-key",
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            "--did-method",
            "plc",
            "--oauth",
            "--app-password-stdin",
        ]);
        assert!(
            result.is_err(),
            "clap should reject --oauth + --app-password-stdin via the ArgGroup"
        );
    }

    /// `--oauth` without `--client-metadata` parses (clap requires
    /// `--client-metadata` to *imply* `--oauth`, not the reverse) but
    /// `select_auth_mode` rejects it as a `UserError`.
    #[test]
    fn select_auth_mode_oauth_without_client_metadata_errors() {
        let cli = parse_cli(&["--oauth"]);
        let err = select_auth_mode(&cli).expect_err("--oauth without --client-metadata must fail");
        assert!(
            matches!(err, UserError::OauthMissingClientMetadata),
            "got {err:?}"
        );
    }

    /// `--oauth --client-metadata <missing-path>` surfaces the
    /// polaris-types loader error via the
    /// `UserError::OauthClientMetadata` variant — i.e. the error
    /// chain points at the loader, not at a generic anyhow.
    #[test]
    fn select_auth_mode_oauth_missing_metadata_file_surfaces_loader_error() {
        let cli = parse_cli(&[
            "--oauth",
            "--client-metadata",
            "/nonexistent/path/client-metadata.json",
        ]);
        let err = select_auth_mode(&cli)
            .expect_err("--client-metadata pointing at a missing file must fail");
        assert!(
            matches!(err, UserError::OauthClientMetadata(_)),
            "got {err:?}"
        );
    }

    /// Verify that the `--client-metadata` flag is rejected by clap
    /// when `--oauth` is absent. This pins the clap `requires =
    /// "oauth"` constraint declared on the flag.
    #[test]
    fn cli_client_metadata_requires_oauth() {
        let result = Cli::try_parse_from([
            "polaris-publish-did-service",
            "--account",
            "polaris.example.com",
            "--service-url",
            "https://polaris.example.com",
            "--signing-key",
            "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            "--did-method",
            "plc",
            "--client-metadata",
            "/tmp/client-metadata.json",
        ]);
        assert!(
            result.is_err(),
            "clap should reject --client-metadata without --oauth"
        );
    }

    /// Pin the `AuthMode::AppPassword` discriminant. Constructing it
    /// from a string and matching against it keeps the enum surface
    /// in this test file so a refactor that renames the variant
    /// fails loudly here.
    #[test]
    fn auth_mode_app_password_variant_pattern_matches() {
        let mode = AuthMode::AppPassword(SecretString::from("test-secret"));
        match mode {
            AuthMode::AppPassword(pwd) => assert_eq!(pwd.expose_secret(), "test-secret"),
            AuthMode::Oauth { .. } => panic!("expected AppPassword variant"),
        }
    }
}
