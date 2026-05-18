//! `polaris-setup` — one-shot config templating CLI for the
//! "easy install" code path (issue #209).
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
//! # Idempotency
//!
//! - If `.env` already exists, the CLI prompts before overwriting.
//! - In `--non-interactive` mode an existing `.env` exits non-zero
//!   unless `--force` is passed.
//! - The same rule applies to `client-metadata.json`.
//!
//! # Secret hygiene
//!
//! The generated cookie key and Postgres password are NEVER printed
//! to stdout, stderr, or any log. The completion message only names
//! the files written. This is the single most important contract of
//! this CLI — every code path must uphold it.
//!
//! # Exit codes
//!
//! - `0` — both files written (or preserved with operator consent).
//! - `1` — user error: bad flags, missing tty for prompts,
//!   pre-existing `.env` with no `--force` in `--non-interactive`
//!   mode, write permission denied, etc.
//! - `2` — internal error (RNG read failed, formatter error).

#![doc(html_no_source)]

use std::fs::{self, OpenOptions};
use std::io::{self, BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context as _, Result, bail};
use clap::Parser;
use rand::RngCore as _;
use rand::rngs::OsRng;

const EXIT_USER_ERROR: u8 = 1;
const EXIT_INTERNAL_ERROR: u8 = 2;

/// Length in bytes of the AES-256-GCM cookie key. The on-disk form
/// is hex-encoded so the file contains exactly `2 *
/// COOKIE_KEY_BYTES` printable chars.
const COOKIE_KEY_BYTES: usize = 32;
/// Length in bytes of the generated Postgres password. 24 bytes of
/// CSPRNG output → 48 hex chars, which is plenty of entropy for the
/// internal compose-network credential.
const POSTGRES_PASSWORD_BYTES: usize = 24;

/// `polaris-setup` CLI surface.
#[derive(Debug, Parser)]
#[command(
    name = "polaris-setup",
    version,
    about = "One-shot config templating for a fresh Polaris install.",
    long_about = "Writes .env (mode 0600) and client-metadata.json into the \
target directory with freshly-generated secrets. Idempotent: re-running \
detects existing files and prompts before overwriting (or requires --force \
in --non-interactive mode)."
)]
struct Cli {
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

fn main() -> ExitCode {
    // Logging stays on stderr; stdout is reserved for the one
    // post-completion summary line. We intentionally do NOT install
    // a tracing subscriber here — this binary should produce
    // human-readable output, not structured logs.
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(io::stderr(), "polaris-setup: error: {err:#}");
            ExitCode::from(classify_exit(&err))
        }
    }
}

/// Classify a top-level error from [`run`] into a process exit
/// code. User-facing errors (bad flags, pre-existing files without
/// `--force`, validation failures) get `EXIT_USER_ERROR` (1);
/// everything else is treated as internal (`EXIT_INTERNAL_ERROR`,
/// 2).
///
/// We mark user errors by prefixing the error or context message
/// with the literal `"user: "` token and then look it up in the
/// chain here. The chain walk is deliberate: `with_context(...)`
/// stacks a new outer error on top of the original cause, so a
/// user-level marker introduced by an inner `bail!` must still be
/// reachable from the outer `anyhow::Error`. Without the chain walk
/// the outermost `with_context` message would mask the marker and
/// the binary would silently exit `2` ("internal error") for a
/// genuine operator mistake — exactly the regression that motivated
/// this function existing as a named, unit-tested helper rather
/// than an inline closure in `main`.
fn classify_exit(err: &anyhow::Error) -> u8 {
    if err.chain().any(|e| e.to_string().starts_with("user: ")) {
        EXIT_USER_ERROR
    } else {
        EXIT_INTERNAL_ERROR
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

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
}
