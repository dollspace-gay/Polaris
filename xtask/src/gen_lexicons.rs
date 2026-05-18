//! `cargo xtask gen-lexicons` — regenerate `polaris-lexicons/src/generated/`
//! from the Lexicon JSON sources in `lexicons/polaris/`.
//!
//! # What it does
//!
//! Invokes the published `proto-blue-codegen` CLI — the AT Protocol
//! Lexicon-to-Rust code generator — installed via:
//!
//! ```text
//! cargo install --locked proto-blue-codegen
//! ```
//!
//! The binary must be on `PATH`. Both `~/.cargo/bin` (the default
//! `cargo install` destination) and `/usr/local/bin` qualify. If the
//! binary is missing, this command surfaces a clear actionable error
//! rather than running silently against a stale tree.
//!
//! Input:  `<workspace-root>/lexicons/polaris/*.json`
//! Output: `<workspace-root>/polaris-lexicons/src/generated/`
//!
//! # Idempotence
//!
//! Running `cargo xtask gen-lexicons` twice on the same source tree
//! produces a zero diff on `polaris-lexicons/src/generated/`. The CI
//! diff gate (`git diff --exit-code polaris-lexicons/src/generated`)
//! relies on this property.
//!
//! # Why not a workspace dependency
//!
//! `proto-blue-codegen` is a CLI binary, not a library, and it lives in
//! the upstream proto-blue workspace (a separate repo). Wiring it in as
//! a path-dep would bind Polaris's clone layout to the upstream's; a
//! crates.io dep would pull a binary crate's whole transitive build into
//! every Polaris build. Invoking it as a CLI installed once per
//! workspace is the standard codegen-tool pattern (cf. `wasm-bindgen-cli`,
//! `trunk`, `sqlx-cli`).
//!
//! See `polaris-lexicons/README.md` for the reproducibility story.

use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

/// CLI binary name. `cargo install proto-blue-codegen` puts an executable
/// of this name on `PATH` (`~/.cargo/bin/proto-blue-codegen`).
const PROTO_BLUE_CODEGEN_BIN: &str = "proto-blue-codegen";

/// Run `cargo xtask gen-lexicons`.
///
/// Locates the workspace root via `CARGO_MANIFEST_DIR`, resolves the
/// lexicon input directory and the generated output directory, then
/// shells out to the installed `proto-blue-codegen` CLI.
///
/// # Errors
///
/// - Returns an error if the workspace root cannot be located.
/// - Returns an actionable error if `proto-blue-codegen` is not on
///   `PATH`, naming the `cargo install` command needed to fix it.
/// - Returns an error if the CLI exits non-zero (codegen failure).
pub fn run() -> Result<()> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir).parent().ok_or_else(|| {
        anyhow::anyhow!("xtask manifest dir has no parent — broken workspace layout")
    })?;

    let lexicons_dir = workspace_root.join("lexicons").join("polaris");
    let output_dir = workspace_root
        .join("polaris-lexicons")
        .join("src")
        .join("generated");

    println!("cargo xtask gen-lexicons: regenerating polaris-lexicons/src/generated/");
    println!("  input:  {}", lexicons_dir.display());
    println!("  output: {}", output_dir.display());
    println!("  codegen: {PROTO_BLUE_CODEGEN_BIN} (resolved from PATH)");
    println!();

    let spawn_result = Command::new(PROTO_BLUE_CODEGEN_BIN)
        .arg("--lexicons")
        .arg(&lexicons_dir)
        .arg("--output")
        .arg(&output_dir)
        .status();

    let status = match spawn_result {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            bail!(
                "`{PROTO_BLUE_CODEGEN_BIN}` not found on PATH.\n\n\
                 Polaris regenerates its Lexicon-derived types with the published \
                 `proto-blue-codegen` CLI. Install it once with:\n\n\
                 \tcargo install --locked proto-blue-codegen\n\n\
                 Then rerun `cargo xtask gen-lexicons`."
            );
        }
        Err(e) => {
            return Err(e).context(format!("spawning `{PROTO_BLUE_CODEGEN_BIN}`"));
        }
    };

    if !status.success() {
        bail!(
            "proto-blue-codegen exited with {status}. Check stderr above for the \
             error; common causes are a missing lexicons directory or a malformed \
             Lexicon JSON."
        );
    }

    // Normalize the generated tree with rustfmt. proto-blue-codegen
    // emits canonical-but-not-formatted output (e.g. long single-line
    // enum variants); the checked-in tree is the post-rustfmt form,
    // and the CI sync gate (`git diff --exit-code`) compares against
    // that form. Running fmt here means a fresh codegen + a CI check
    // converge on the same bytes regardless of which proto-blue-codegen
    // version produced them — only the semantic structure has to
    // match, not the formatting accidents of any one codegen release.
    fmt_generated_tree(&output_dir)?;

    println!();
    println!("cargo xtask gen-lexicons: done — polaris-lexicons/src/generated/ updated");
    Ok(())
}

/// Walk `dir` and pass every `*.rs` file to a single `rustfmt`
/// invocation. Done with `walkdir` (already in `xtask`'s deps for the
/// other subcommands) rather than rustfmt's `--recursive` flag, which
/// only landed in nightly-stable rustfmt as of 1.84 — relying on it
/// would bind `xtask` to a newer-than-pinned toolchain. `--edition`
/// matches the workspace's `edition = "2024"` so rustfmt parses macros
/// and trait bounds the same way the compiler will.
fn fmt_generated_tree(dir: &Path) -> Result<()> {
    println!();
    println!("cargo xtask gen-lexicons: running rustfmt on the generated tree");

    let mut rs_files: Vec<std::path::PathBuf> = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|e| e == "rs") {
            rs_files.push(entry.into_path());
        }
    }

    if rs_files.is_empty() {
        bail!(
            "no .rs files found under {} to fmt — codegen produced an empty tree",
            dir.display()
        );
    }

    let status = Command::new("rustfmt")
        .arg("--edition")
        .arg("2024")
        .args(&rs_files)
        .status()
        .context("spawning `rustfmt`")?;
    if !status.success() {
        bail!(
            "rustfmt exited with {status} while normalizing the generated \
             lexicon tree at {}",
            dir.display()
        );
    }
    Ok(())
}
