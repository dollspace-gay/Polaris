//! Bundle-symbol scanner for the released wasm artifact (issue #34 / AC-16).
//!
//! AC-16 of `.design/polaris-proto-blue-integration.md` requires that the
//! `proto-blue-lexicon` validation engine actually ship inside the
//! `polaris-frontend` wasm bundle — without it the inline client-side
//! validation contract collapses into a silent server-side fallback.
//! Dead-code elimination during the release build is the most plausible
//! way for the engine to vanish from the artifact while every other
//! check still passes (the crate compiles cleanly, the registry is
//! constructible from a unit test, etc.), so we need a bundle-time
//! assertion.
//!
//! [`run`] reads the standard release artifact path
//! (`target/wasm32-unknown-unknown/release/polaris_frontend.wasm`),
//! walks the module's `name` custom section + export/import lists, and
//! asserts that at least one symbol whose name contains `lexicon`,
//! `Lexicons`, or `validate` is present. Any of those is sufficient
//! evidence that the validation engine survived dead-code elimination.
//!
//! [`scan_wasm_bytes`] is the testable seam: pass in arbitrary wasm
//! bytes (e.g. a synthetic module constructed in an integration test)
//! and get back an iterator of every symbol the scanner found, so the
//! test can assert both the positive and negative case without
//! invoking a full cargo build.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};
use wasmparser::{KnownCustom, Name, Parser, Payload};

/// Default location of the release wasm artifact in the Polaris tree.
///
/// `cargo build --release --target wasm32-unknown-unknown -p polaris-frontend`
/// emits the file here. The xtask resolves the path relative to the
/// workspace root because `cargo xtask` inherits cargo's cwd.
const ARTIFACT_PATH: &str = "target/wasm32-unknown-unknown/release/polaris_frontend.wasm";

/// Substrings the scanner accepts as evidence that the lexicon
/// validation engine survived dead-code elimination.
///
/// `lexicon` — the engine's crate name; mangled Rust function symbols
/// from `proto_blue_lexicon` carry it. `Lexicons` — the engine's
/// top-level type; appears in both the function-name section and any
/// public exports we may add over time. `validate` — the engine's
/// public entry points (`validate_record` / `validate_object` /
/// `validate_value`); generic substring catches mangled monomorphised
/// forms too. Matching is case-sensitive on purpose: a hit on the
/// lowercase form alone is a 99%-true-positive signal.
const LEXICON_SYMBOL_NEEDLES: &[&str] = &["lexicon", "Lexicons", "validate"];

/// Drive the symbol scan against the default artifact path and print a
/// CI-friendly summary.
///
/// # Errors
///
/// - Returns an error with a clear remediation message if the artifact
///   does not exist at the standard release path. Operators see the
///   exact `cargo build` command to run.
/// - Returns an error if the artifact exists but contains no symbols
///   matching the lexicon needles — the validation engine has been
///   tree-shaken out of the bundle and AC-16's "zero HTTP roundtrip"
///   promise can't hold.
/// - Returns the underlying [`wasmparser`] error if the artifact is not
///   a valid wasm module.
pub fn run() -> Result<()> {
    let path = Path::new(ARTIFACT_PATH);
    if !path.exists() {
        return Err(anyhow!(
            "wasm artifact not found at `{ARTIFACT_PATH}`; run \
             `cargo build --release --target wasm32-unknown-unknown -p polaris-frontend` first",
        ));
    }

    let bytes = std::fs::read(path)
        .with_context(|| format!("reading wasm artifact at `{ARTIFACT_PATH}`"))?;

    let report = scan_wasm_bytes(&bytes)?;

    if report.lexicon_symbol_count == 0 {
        return Err(anyhow!(
            "check-wasm-symbols: no symbol containing any of {:?} found in `{}` \
             (total symbols inspected: {}). The lexicon validation engine was \
             tree-shaken out of the bundle — AC-16 requires it to be present.",
            LEXICON_SYMBOL_NEEDLES,
            ARTIFACT_PATH,
            report.total_symbols,
        ));
    }

    println!(
        "check-wasm-symbols: lexicon engine present in `{}` \
         ({} matching symbol(s) out of {} inspected)",
        ARTIFACT_PATH, report.lexicon_symbol_count, report.total_symbols,
    );
    Ok(())
}

/// Result of a single wasm scan: how many symbols were inspected and
/// how many matched the lexicon needles.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanReport {
    /// Total number of symbols (name-section entries + import names +
    /// export names) inspected.
    pub total_symbols: usize,
    /// How many of those symbols matched any of [`LEXICON_SYMBOL_NEEDLES`].
    pub lexicon_symbol_count: usize,
}

/// Walk `wasm_bytes` and count symbols matching the lexicon needles.
///
/// Public so the integration test (`xtask/tests/check_wasm_symbols.rs`)
/// can drive the scanner against synthetic modules without building the
/// frontend.
///
/// # Errors
///
/// Returns the underlying [`wasmparser`] error if the bytes are not a
/// valid wasm module. Malformed `name` subsections are tolerated — they
/// are skipped without aborting the scan, because tooling like
/// `wasm-opt` can occasionally produce custom-section payloads that
/// some `wasmparser` versions disagree with.
pub fn scan_wasm_bytes(wasm_bytes: &[u8]) -> Result<ScanReport> {
    let mut report = ScanReport::default();

    let parser = Parser::new(0);
    for payload in parser.parse_all(wasm_bytes) {
        let payload = payload.context("parsing wasm payload")?;
        match payload {
            // The `name` custom section is the primary source for
            // mangled function names. We tolerate per-subsection
            // failures so a malformed name table doesn't abort the
            // whole scan.
            Payload::CustomSection(reader) => {
                if let KnownCustom::Name(name_reader) = reader.as_known() {
                    for subsection in name_reader {
                        let Ok(subsection) = subsection else {
                            continue;
                        };
                        scan_name_subsection(&subsection, &mut report);
                    }
                }
            }
            // Exports are user-visible symbol names — the JS shim's
            // entry points to the wasm bundle. Importantly the wasm-
            // bindgen toolchain re-emits any Rust function reachable
            // from JS into the export table, so a `validate_*` entry
            // point exposed via wasm-bindgen would show up here.
            Payload::ExportSection(reader) => {
                for export in reader {
                    let Ok(export) = export else {
                        continue;
                    };
                    report.total_symbols += 1;
                    if matches_lexicon_needle(export.name) {
                        report.lexicon_symbol_count += 1;
                    }
                }
            }
            // Imports come from JS shim sites; we count them for the
            // total so the report number is meaningful, but a hit on
            // an import would also count as evidence (an "import"
            // named `__wbg_validate_record_...` is the wasm-bindgen
            // glue that calls our engine). The `Imports` enum carries
            // a single-import variant plus two compact-encoding
            // variants for grouped imports; we handle each so a
            // future wasm-tools output shape change does not silently
            // skip relevant symbols.
            Payload::ImportSection(reader) => {
                for group in reader {
                    let Ok(group) = group else {
                        continue;
                    };
                    scan_import_group(&group, &mut report);
                }
            }
            _ => {}
        }
    }

    Ok(report)
}

/// Walk a single import-section group, bumping the running totals for
/// every name string the variant exposes.
fn scan_import_group(group: &wasmparser::Imports<'_>, report: &mut ScanReport) {
    match group {
        wasmparser::Imports::Single(_, import) => {
            report.total_symbols += 1;
            if matches_lexicon_needle(import.module) || matches_lexicon_needle(import.name) {
                report.lexicon_symbol_count += 1;
            }
        }
        wasmparser::Imports::Compact1 { module, items } => {
            // The module name is a single string shared across the
            // group; count it once.
            report.total_symbols += 1;
            let module_hit = matches_lexicon_needle(module);
            if module_hit {
                report.lexicon_symbol_count += 1;
            }
            for item in items.clone() {
                let Ok(item) = item else { continue };
                report.total_symbols += 1;
                if matches_lexicon_needle(item.name) {
                    report.lexicon_symbol_count += 1;
                }
            }
        }
        wasmparser::Imports::Compact2 { module, names, .. } => {
            report.total_symbols += 1;
            if matches_lexicon_needle(module) {
                report.lexicon_symbol_count += 1;
            }
            for name in names.clone() {
                let Ok(name) = name else { continue };
                report.total_symbols += 1;
                if matches_lexicon_needle(name) {
                    report.lexicon_symbol_count += 1;
                }
            }
        }
    }
}

/// Walk a single `name`-subsection variant, bumping the running totals.
fn scan_name_subsection(subsection: &Name<'_>, report: &mut ScanReport) {
    match subsection {
        Name::Module { name, .. } => {
            report.total_symbols += 1;
            if matches_lexicon_needle(name) {
                report.lexicon_symbol_count += 1;
            }
        }
        Name::Function(map)
        | Name::Type(map)
        | Name::Table(map)
        | Name::Memory(map)
        | Name::Global(map)
        | Name::Element(map)
        | Name::Data(map)
        | Name::Tag(map) => scan_name_map(map.clone(), report),
        // Local / Label / Field maps are indirect (per-function name
        // tables); the symbol form we want lives in the top-level
        // function map already counted by `Name::Function`. Skipping
        // them keeps the scanner's runtime bounded on large bundles
        // without sacrificing detection.
        _ => {}
    }
}

/// Walk a [`wasmparser::NameMap`] and bump the running totals for every
/// entry whose name string matches any [`LEXICON_SYMBOL_NEEDLES`] entry.
fn scan_name_map(map: wasmparser::NameMap<'_>, report: &mut ScanReport) {
    for naming in map {
        let Ok(naming) = naming else {
            continue;
        };
        report.total_symbols += 1;
        if matches_lexicon_needle(naming.name) {
            report.lexicon_symbol_count += 1;
        }
    }
}

/// Case-sensitive substring match against [`LEXICON_SYMBOL_NEEDLES`].
fn matches_lexicon_needle(name: &str) -> bool {
    LEXICON_SYMBOL_NEEDLES.iter().any(|n| name.contains(n))
}

/// Default release-artifact path, exposed so the integration test can
/// emit a synthetic version at the same location and verify the
/// existence-check arm of [`run`].
#[must_use]
pub fn artifact_path() -> PathBuf {
    PathBuf::from(ARTIFACT_PATH)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    /// Minimal valid wasm header (`\0asm` + version 1). Useful as a base
    /// for synthetic modules in unit tests.
    const WASM_HEADER: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn empty_wasm_module_finds_no_symbols() {
        let report = scan_wasm_bytes(WASM_HEADER).expect("header-only wasm parses");
        assert_eq!(report.total_symbols, 0);
        assert_eq!(report.lexicon_symbol_count, 0);
    }

    #[test]
    fn matches_lexicon_needle_positive() {
        assert!(matches_lexicon_needle(
            "proto_blue_lexicon::Lexicons::validate_record"
        ));
        assert!(matches_lexicon_needle("validate_object"));
        assert!(matches_lexicon_needle("lexicon"));
        assert!(matches_lexicon_needle("Lexicons"));
    }

    #[test]
    fn matches_lexicon_needle_negative() {
        assert!(!matches_lexicon_needle("polaris_frontend::App"));
        assert!(!matches_lexicon_needle("leptos::mount::mount_to_body"));
        assert!(!matches_lexicon_needle("Wibble"));
    }
}
