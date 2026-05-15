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

use std::io::{self, BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context;
use clap::{ArgGroup, Parser, ValueEnum};
use polaris_publish_labeler_record::{
    BuildError, RECORD_COLLECTION, RECORD_RKEY, RecordValue, ValidationError,
    build_labeler_service_record, record_at_uri, validate_record,
};
use proto_blue::api::com::atproto::repo::put_record;
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
        proto-blue OAuth client and drives an interactive authorization-code \
        flow (PAR + PKCE + DPoP) against the operator's PDS. The OAuth path \
        requires --client-metadata pointing at the operator-supplied client \
        metadata JSON; the CLI prints an authorize URL for the operator to \
        open in a browser, then reads the redirected URL back from stdin to \
        complete the exchange.\n\n\
        Exit codes:\n  \
        0 — success\n  \
        1 — user error (bad flags, conflicting auth modes, missing OAuth \
            client metadata)\n  \
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
    /// with `polaris-backend`'s ATProto OAuth verifier so the wire
    /// shape is enforced from one place.
    #[arg(long, value_name = "PATH", requires = "oauth")]
    client_metadata: Option<PathBuf>,

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

    /// `--oauth` was supplied without `--client-metadata`.
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
/// The `Oauth` variant carries the pre-loaded client metadata so any
/// load / parse failure surfaces as a [`UserError`] (exit 1) at
/// `select_auth_mode` time rather than getting classified as a PDS
/// error (exit 2) inside `submit_record`. Path validation is the
/// operator's input check; the actual flow only sees a typed value.
enum AuthMode {
    AppPassword(SecretString),
    Oauth {
        /// Validated client metadata. `validate_client_metadata` (the
        /// atproto-profile check) is run inside [`submit_record`] —
        /// it's a wire-shape assertion, not a user input check, and
        /// it would reuse the same `UserError::OauthClientMetadata`
        /// variant if it ran here.
        ///
        /// Boxed so the `AuthMode::AppPassword(SecretString)` variant
        /// (which is one pointer) doesn't pay the size of every
        /// nullable `client_*` field on the metadata struct — the
        /// `clippy::large_enum_variant` lint flags the gap directly.
        metadata: Box<polaris_types::oauth_config::ClientMetadata>,
    },
}

/// Resolve the auth mode from the CLI / environment, surfacing a
/// [`UserError`] for any conflict, missing-mode case, or
/// failed-to-load client metadata.
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
/// Errors here always map to exit code 2 (PDS error). The branch
/// shape mirrors the auth mode:
///
/// - `AppPassword`: `com.atproto.server.createSession` against
///   `--pds`, attach `Authorization: Bearer <jwt>` to a fresh
///   `XrpcClient`, call `com.atproto.repo.putRecord`.
/// - `Oauth`: load + validate client metadata, resolve the account
///   to a PDS + AS, drive the authorize / callback exchange via
///   `proto_blue::oauth::OAuthClient`, then POST `putRecord` through
///   an `OAuthSession` (which signs each request with the bound DPoP
///   key — `Authorization: DPoP <token>` plus the `DPoP` proof
///   header).
async fn submit_record(cli: &Cli, record: &RecordValue, auth: &AuthMode) -> anyhow::Result<()> {
    let record_json = record
        .to_json()
        .context("serializing record to JSON for put_record")?;

    match auth {
        AuthMode::AppPassword(pwd) => {
            submit_via_app_password(cli, &record_json, pwd).await?;
        }
        AuthMode::Oauth { metadata } => {
            submit_via_oauth(cli, &record_json, metadata.as_ref()).await?;
        }
    }
    Ok(())
}

/// App-password branch of [`submit_record`].
///
/// Preserves the existing exit-code mapping (every error here lands
/// on exit code 2 via the [`AppError::Pds`] wrapper in [`run`]).
async fn submit_via_app_password(
    cli: &Cli,
    record_json: &serde_json::Value,
    pwd: &SecretString,
) -> anyhow::Result<()> {
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

    let mut authed = XrpcClient::new(&cli.pds).context("constructing authed XRPC client")?;
    authed.set_header("authorization", format!("Bearer {}", session.access_jwt));

    let input = build_put_record_input(&cli.account, record_json.clone())?;
    let output = put_record::call(&authed, &input, None)
        .await
        .context("put_record call to PDS failed")?;

    emit_confirmation(&output.uri.to_string(), &output.cid)
}

/// OAuth branch of [`submit_record`].
///
/// Drives PAR + PKCE + DPoP via `proto_blue::oauth::OAuthClient`,
/// then publishes through `proto_blue::oauth::OAuthSession::post`
/// so the access token's DPoP binding is honoured on the
/// resource-server request.
///
/// The browser-redirect step uses the paste-back-URL convention:
/// the CLI prints the authorize URL to stderr, the operator
/// completes consent in their browser, and the CLI reads the
/// resulting redirected URL from stdin to extract `code` (and
/// `iss` when the AS advertises RFC 9207 support). This is simpler
/// than spawning a local HTTP listener and is the lower-failure
/// path for an operator-driven CLI — there is no port to bind
/// (collisions, firewalls, permissions) and no race between
/// listener-up and AS-redirect.
async fn submit_via_oauth(
    cli: &Cli,
    record_json: &serde_json::Value,
    metadata: &polaris_types::oauth_config::ClientMetadata,
) -> anyhow::Result<()> {
    // Step 1: validate the loaded metadata against the atproto OAuth
    // client-metadata profile. The polaris-types loader only does the
    // read + JSON-decode; profile validation lives here because it
    // reuses proto-blue's `validate_client_metadata` and the loader
    // stays free of proto-blue dependencies on validation.
    validate_client_metadata(metadata)
        .context("OAuth client metadata failed atproto profile validation")?;

    let oauth_client = OAuthClient::new(metadata.clone());
    let identity_resolver = Arc::new(IdResolver::new(IdentityResolverOpts::default(), None));

    // Step 2: resolve the operator's account → (did?, pds_url, AS metadata).
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

    // Step 3: authorize. Generates PKCE + DPoP keypair, drives PAR
    // when the AS advertises it.
    let (authorize_url, auth_state) = oauth_client
        .authorize(&server_metadata)
        .await
        .context("OAuth authorize (PAR) failed")?;

    // Step 4: interactive consent. Print the URL on stderr (stdout
    // remains reserved for the final confirmation JSON) and the
    // paste-back prompt next to it.
    write_oauth_prompt(&authorize_url, &server_metadata.issuer)?;

    // Step 5: read the redirected URL back from stdin. The operator's
    // browser fails to load the localhost callback (nothing's listening)
    // and they paste the address-bar URL back here.
    let pasted = read_oauth_callback_url()?;
    let (code, iss_from_url) = parse_oauth_callback(&pasted, &auth_state)?;

    // Step 6: exchange the code. `callback_with_iss_and_aud` enforces
    // RFC 9207 `iss` cross-check when the AS supports it and records
    // the resolved PDS as the token's `aud` (binding subsequent DPoP
    // proofs' `htu` to that audience).
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

    // Step 7: rebuild the DpopKey from the JWK that `authorize()`
    // generated. The serialised JWK in `auth_state.dpop_key` survives
    // the in-memory hop unmodified; `dpop_key_from_jwk` validates the
    // shape (curve, key bytes) before letting us sign anything with it.
    let dpop_key = dpop_key_from_jwk(&auth_state.dpop_key)
        .context("reconstructing DPoP key from auth_state JWK")?;

    // Step 8: open an OAuthSession + POST putRecord. The session
    // automatically attaches `Authorization: DPoP {token}` and a
    // freshly-built DPoP proof to each request, and rotates on
    // server-supplied `DPoP-Nonce` headers.
    let session = OAuthSession::new(token_set, dpop_key, DpopNonceCache::new());
    publish_via_oauth_session(&session, &pds_url, &cli.account, record_json).await
}

/// Build the `put_record::Input` value for the operator's account.
///
/// Factored out so both auth branches share the same field-by-field
/// construction (and the same `Nsid` / `AtIdentifier` / `RecordKey`
/// error context strings — there is one wire shape, so there should
/// be one builder).
fn build_put_record_input(
    account: &str,
    record_json: serde_json::Value,
) -> anyhow::Result<put_record::Input> {
    let collection = proto_blue::syntax::Nsid::new(RECORD_COLLECTION)
        .context("RECORD_COLLECTION is not a valid NSID — programming error")?;
    let repo = proto_blue::syntax::AtIdentifier::new(account)
        .context("--account is not a valid handle or DID")?;
    let rkey = proto_blue::syntax::RecordKey::new(RECORD_RKEY)
        .context("RECORD_RKEY is not a valid record key — programming error")?;

    Ok(put_record::Input {
        collection,
        record: record_json,
        repo,
        rkey,
        swap_commit: None,
        swap_record: None,
        validate: Some(true),
    })
}

/// POST the constructed `put_record::Input` through an
/// `OAuthSession`. The wire-shape conversion (Input → JSON Value)
/// mirrors what `put_record::call` does internally for the `XrpcClient`
/// path; we do it explicitly here because `OAuthSession::post` takes
/// a generic JSON value rather than a typed XRPC body so the DPoP
/// proof can be built around the resource-server URL we choose.
async fn publish_via_oauth_session(
    session: &OAuthSession,
    pds_url: &str,
    account: &str,
    record_json: &serde_json::Value,
) -> anyhow::Result<()> {
    let input = build_put_record_input(account, record_json.clone())?;
    let input_value =
        serde_json::to_value(&input).context("serializing put_record::Input to JSON")?;

    let endpoint = format!(
        "{}/xrpc/com.atproto.repo.putRecord",
        pds_url.trim_end_matches('/')
    );
    let response = session
        .post(&endpoint, &input_value)
        .await
        .context("OAuth-bound put_record POST failed")?;

    if !response.is_success() {
        anyhow::bail!(
            "put_record returned HTTP {}: {}",
            response.status,
            String::from_utf8_lossy(&response.body)
        );
    }

    let output: put_record::Output =
        serde_json::from_slice(&response.body).context("decoding put_record response JSON")?;
    emit_confirmation(&output.uri.to_string(), &output.cid)
}

/// Write the human-readable confirmation envelope to stdout.
///
/// Single source of truth for the success summary so both auth
/// branches surface the same key set (`status`, `uri`, `cid`).
fn emit_confirmation(uri: &str, cid: &str) -> anyhow::Result<()> {
    info!(uri = %uri, cid = %cid, "labeler service record written");

    let mut stdout = io::stdout().lock();
    let confirmation = serde_json::json!({
        "status": "ok",
        "uri": uri,
        "cid": cid,
    });
    serde_json::to_writer(&mut stdout, &confirmation)
        .context("writing confirmation JSON to stdout")?;
    stdout
        .write_all(b"\n")
        .context("writing trailing newline")?;
    Ok(())
}

/// Print the OAuth authorize URL and paste-back instructions to stderr.
///
/// Lives on stderr so the success-path stdout (the final
/// `{status,uri,cid}` envelope) remains parseable by an automation
/// caller that pipes stdout into `jq`.
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
