//! `cargo xtask gen-lexicons` — regenerate `polaris-lexicons/src/generated/`
//! from the Lexicon JSON sources in `lexicons/polaris/`.
//!
//! # What it does
//!
//! Invokes `proto-blue-codegen` — the AT Protocol Lexicon-to-Rust code
//! generator that lives at
//! `/home/doll/proto-blue/proto-blue/crates/proto-blue-codegen` — via
//! `cargo run --manifest-path` so the invocation is reproducible from any
//! clean clone of the Polaris workspace without requiring a prior
//! `cargo install proto-blue-codegen` step.
//!
//! Input:  `<workspace-root>/lexicons/polaris/*.json`
//! Output: `<workspace-root>/polaris-lexicons/src/generated/`
//!
//! # Idempotence
//!
//! Running `cargo xtask gen-lexicons` twice on the same source tree produces
//! a zero diff on `polaris-lexicons/src/generated/`. The CI diff gate
//! (`git diff --exit-code polaris-lexicons/src/generated`) relies on this
//! property.
//!
//! # Hard-coded path
//!
//! The `proto-blue-codegen` manifest path is hard-coded to its known
//! on-disk location (`/home/doll/proto-blue/proto-blue/…`). If you are
//! working from a different machine, either:
//!
//! 1. Adjust `PROTO_BLUE_CODEGEN_MANIFEST` below and commit the change, or
//! 2. `cargo install --path /path/to/proto-blue-codegen` once and use the
//!    installed binary directly.
//!
//! See `polaris-lexicons/README.md` for the reproducibility story.

use std::path::Path;
use std::process::Command;

use anyhow::{Context as _, Result, bail};

/// Absolute path to the `proto-blue-codegen` crate manifest.
///
/// Invoked via `cargo run --manifest-path` so no prior install is needed.
const PROTO_BLUE_CODEGEN_MANIFEST: &str =
    "/home/doll/proto-blue/proto-blue/crates/proto-blue-codegen/Cargo.toml";

/// Run `cargo xtask gen-lexicons`.
///
/// Locates the workspace root via `CARGO_MANIFEST_DIR`, resolves the
/// lexicon input directory and the generated output directory, then
/// shells out to `proto-blue-codegen`.
///
/// # Errors
///
/// - Returns an error if the workspace root cannot be located.
/// - Returns an error if `cargo run` cannot be spawned.
/// - Returns an error if `cargo run` exits non-zero (codegen failure).
pub fn run() -> Result<()> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .parent()
        .ok_or_else(|| anyhow::anyhow!("xtask manifest dir has no parent — broken workspace layout"))?;

    let lexicons_dir = workspace_root.join("lexicons").join("polaris");
    let output_dir = workspace_root
        .join("polaris-lexicons")
        .join("src")
        .join("generated");

    println!("cargo xtask gen-lexicons: regenerating polaris-lexicons/src/generated/");
    println!("  input:  {}", lexicons_dir.display());
    println!("  output: {}", output_dir.display());
    println!("  codegen: {PROTO_BLUE_CODEGEN_MANIFEST}");
    println!();

    let status = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--manifest-path",
            PROTO_BLUE_CODEGEN_MANIFEST,
            "--",
            "--lexicons",
        ])
        .arg(&lexicons_dir)
        .arg("--output")
        .arg(&output_dir)
        .status()
        .context("spawning `cargo run --manifest-path proto-blue-codegen`")?;

    if !status.success() {
        bail!(
            "proto-blue-codegen exited with {status}. Check stderr above for the \
             error; common causes are a missing lexicons directory or a malformed \
             Lexicon JSON."
        );
    }

    println!();
    println!("cargo xtask gen-lexicons: done — polaris-lexicons/src/generated/ updated");
    Ok(())
}
