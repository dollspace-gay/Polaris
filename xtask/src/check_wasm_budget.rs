//! Wasm bundle-size budget gate (#71).
//!
//! AC: the release wasm artifact must stay under an operator-defined raw-size
//! budget. The default ceiling (2 MiB) is generous over the 2026-05-14
//! baseline (1.4 MiB) but tight enough to flag a >40% bundle growth on a
//! single PR — the kind of unintentional tree-shaken-dep restoration that
//! bloats wasm without anyone noticing.
//!
//! Gzip-side budgets are out of scope here because the operator's CDN /
//! reverse-proxy applies its own compression and brotli/gzip ratios depend
//! on configuration outside Polaris. Raw bytes are the binding gate.
//!
//! Budget is read from `POLARIS_WASM_BUDGET_BYTES` when set, falling back
//! to the constant below.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};

/// Default location of the release wasm artifact in the Polaris tree.
const ARTIFACT_PATH: &str = "target/wasm32-unknown-unknown/release/polaris_frontend.wasm";

/// Default uncompressed-bundle ceiling: 2 MiB.
const DEFAULT_RAW_BUDGET: u64 = 2 * 1024 * 1024;

/// Entry point invoked from `cargo xtask check-wasm-budget`.
///
/// # Errors
///
/// Returns an error if the artifact is missing or exceeds the budget.
pub fn run() -> Result<()> {
    let artifact_path = PathBuf::from(ARTIFACT_PATH);
    let budget = budget_from_env("POLARIS_WASM_BUDGET_BYTES", DEFAULT_RAW_BUDGET)?;
    check_wasm_budget(&artifact_path, budget)
}

/// Read a `u64`-valued env var, falling back to `default` when unset.
fn budget_from_env(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(raw) => raw
            .parse::<u64>()
            .with_context(|| format!("{name} must be a u64 byte count; got {raw:?}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow!("{name} is set but not valid UTF-8")),
    }
}

/// Compare the artifact's raw size against the budget.
///
/// # Errors
///
/// Returns an error if reading the artifact fails or the budget is exceeded.
pub fn check_wasm_budget(artifact_path: &Path, raw_budget: u64) -> Result<()> {
    let bytes = fs::read(artifact_path).with_context(|| {
        format!(
            "missing release wasm artifact at {}; run `cargo build --release --target wasm32-unknown-unknown -p polaris-frontend` first",
            artifact_path.display(),
        )
    })?;
    let raw_size = bytes.len() as u64;

    if raw_size > raw_budget {
        return Err(anyhow!(
            "wasm bundle exceeds raw budget: {raw_size} bytes > {raw_budget} bytes (POLARIS_WASM_BUDGET_BYTES)"
        ));
    }

    let pct = (raw_size * 100) / raw_budget.max(1);
    println!("check-wasm-budget: {raw_size} bytes raw ({pct}% of {raw_budget})");
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic per rust-quality §7"
)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn under_budget_passes() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let payload = vec![0u8; 1024];
        let mut handle = tmp.reopen().unwrap();
        handle.write_all(&payload).unwrap();
        check_wasm_budget(tmp.path(), 2048).expect("under budget");
    }

    #[test]
    fn over_budget_errors() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let payload = vec![0u8; 4096];
        let mut handle = tmp.reopen().unwrap();
        handle.write_all(&payload).unwrap();
        let err = check_wasm_budget(tmp.path(), 1024).unwrap_err().to_string();
        assert!(err.contains("raw budget"), "got: {err}");
    }

    #[test]
    fn missing_artifact_errors_with_build_hint() {
        let err = check_wasm_budget(Path::new("definitely/does/not/exist.wasm"), 1024)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cargo build --release"), "got: {err}");
    }
}
