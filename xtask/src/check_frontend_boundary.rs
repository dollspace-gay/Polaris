//! Frontend / backend boundary scanner.
//!
//! Implements `cargo xtask check-frontend-boundary` per AC-7 of
//! `.design/polaris-proto-blue-integration.md`: the Leptos frontend in
//! `polaris-frontend/` may reach `proto-blue` directly for public ATProto
//! reads, but every non-public read and every mutation must route through
//! `polaris-backend`'s `/api/*` surface via the typed [`PolarisApiClient`].
//!
//! This module enforces that contract mechanically. It walks
//! `polaris-frontend/src/**/*.rs`, strips line comments (without breaking
//! `//` inside string literals — see [`strip_comment`]), and runs a static
//! list of [`Pattern`]s against each remaining active line. Inline
//! `// xtask-allow: <pattern-name>` markers on the same or previous non-
//! blank line opt a single line out and are logged in the run summary so
//! allowlists never accumulate silently.
//!
//! # Path-aware skips
//!
//! Some rules are meaningful only outside specific directories. For
//! example, the `hardcoded_mutating_route` rule exists to catch frontend
//! code bypassing the typed [`PolarisApiClient`] with raw `/api/...`
//! string literals — but the literals are legitimate (and required)
//! inside `PolarisApiClient`'s own gateway implementation. A
//! [`Pattern`] therefore carries an optional
//! [`skip_paths_starting_with`](Pattern::skip_paths_starting_with) list
//! of path prefixes; the scanner pre-filters the pattern out for any
//! file whose path matches one of those prefixes (slash-normalized).
//! Other patterns still apply to the same file, and the per-line
//! `// xtask-allow:` mechanism is unchanged.
//!
//! The scanner core is exposed via [`scan_text`] and
//! [`scan_text_with_allows`] so integration tests can drive it from in-
//! memory fixtures without a filesystem walk.
//!
//! [`PolarisApiClient`]: https://docs.rs/polaris-frontend

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};
use regex::Regex;
use walkdir::WalkDir;

/// Default scan root: the frontend `src` tree at the repository root.
///
/// The xtask alias (`cargo xtask = "run --package xtask --"`) inherits
/// `cargo`'s working directory, which is always the workspace root, so a
/// repo-relative path resolves correctly from any invocation site.
const FRONTEND_SRC: &str = "polaris-frontend/src";

/// Inline override marker. A line containing the marker (substring match)
/// suppresses any violation whose [`Pattern::name`] equals `<name>` on the
/// same line or on the immediately preceding non-blank line.
///
/// Allowed uses are still logged in the summary so a human can audit the
/// allowlist without grepping the tree.
const ALLOW_PREFIX: &str = "xtask-allow:";

/// A single forbidden pattern.
///
/// Patterns are static data (defined in [`patterns`]) rather than code so
/// adding or revising a rule is a one-line edit. Each `Pattern` carries a
/// stable machine-readable [`name`](Self::name) used by inline allow
/// markers and a human-readable [`message`](Self::message) printed on
/// violation.
#[derive(Debug)]
pub struct Pattern {
    /// Short, stable identifier used in `// xtask-allow: <name>` markers.
    pub name: &'static str,
    /// Compiled regex run against every active (non-comment) line.
    pub regex: Regex,
    /// Human-readable explanation printed on violation.
    pub message: &'static str,
    /// Optional list of path prefixes (slash-normalized) for which this
    /// pattern is *not* applied.
    ///
    /// Some rules are meaningful only outside specific directories — for
    /// instance, a hardcoded-route rule meant for non-gateway code should
    /// not fire inside the gateway itself. When `Some(&[..])`, the
    /// scanner skips this pattern for any file whose path (after
    /// normalizing `\` to `/`) contains one of the listed prefixes as a
    /// sub-path. When `None`, the pattern applies everywhere.
    pub skip_paths_starting_with: Option<&'static [&'static str]>,
}

/// A single recorded violation: a pattern matched an active line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// File path the violation was found in. For scanner tests driven by
    /// [`scan_text`] this is the caller-supplied logical name.
    pub path: PathBuf,
    /// 1-based line number of the matching line.
    pub line_number: usize,
    /// [`Pattern::name`] of the pattern that fired.
    pub pattern_name: &'static str,
    /// Verbatim text of the matching line (with the comment portion
    /// stripped — i.e. exactly what the scanner matched against).
    pub line_text: String,
}

/// A single recorded allow: a pattern would have fired but an inline
/// `// xtask-allow: <name>` marker suppressed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allow {
    /// File path the allowed match was found in.
    pub path: PathBuf,
    /// 1-based line number of the suppressed match.
    pub line_number: usize,
    /// [`Pattern::name`] of the pattern that was suppressed.
    pub pattern_name: &'static str,
    /// Verbatim text of the suppressed line.
    pub line_text: String,
}

/// Result of a scan: every recorded violation plus every recorded allow.
///
/// The split lets the caller fail on violations while still printing every
/// allow to the run summary — see [`run`].
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Patterns that fired without an `xtask-allow` override.
    pub violations: Vec<Violation>,
    /// Patterns that fired *with* an `xtask-allow` override.
    pub allows: Vec<Allow>,
}

/// Static pattern set. Order is stable; the run summary prints violations
/// in file/line order rather than pattern order, so the slice order here
/// is purely cosmetic.
///
/// All regexes are compile-time string literals. The `expect` calls below
/// are exercised by [`tests::patterns_all_compile`] so a typo in this
/// list fails `cargo test` before it ever runs in CI as a panic. Narrow
/// allow with rationale per the rust-quality skill's `expect_used`
/// guidance.
///
/// # Panics
///
/// Panics if any literal regex below is malformed. The patterns are
/// compile-time string constants exercised by the integration test
/// `patterns_all_compile`, so a malformed regex would fail
/// `cargo test -p xtask` before any operator hit the panic in CI.
#[allow(clippy::expect_used)]
#[must_use]
pub fn patterns() -> Vec<Pattern> {
    vec![
        Pattern {
            name: "polaris_backend_import",
            // The Rust-identifier form (underscored) — what an actual
            // `use polaris_backend::…;` or `polaris_backend::foo()` call
            // would produce. The hyphenated `polaris-backend` only appears
            // in prose / Cargo manifests and is intentionally not matched.
            regex: Regex::new(r"\bpolaris_backend\b")
                .expect("static regex `polaris_backend_import` must compile"),
            message: "polaris-frontend must not import polaris_backend internals; route via PolarisApiClient HTTP.",
            skip_paths_starting_with: None,
        },
        Pattern {
            name: "hardcoded_mutating_route",
            // Match string-literal occurrences of Polaris mutating route
            // prefixes. The Leptos frontend must reach these through the
            // typed `PolarisApiClient`; a raw literal in source is the
            // tell-tale of someone bypassing the boundary with a stray
            // `gloo_net::http::Request::post(...)` or `XrpcClient` call.
            //
            // The list mirrors the mutating surface called out in
            // `.design/polaris-proto-blue-integration.md` §D. New mutating
            // route prefixes are added here as they appear in the backend.
            //
            // The gateway implementation in `polaris-frontend/src/api_client/`
            // is the *legitimate* home for these literals — the rule
            // exists to catch code that bypasses the gateway, not the
            // gateway itself. Path-aware skip below ensures the rule
            // still applies everywhere else in the frontend tree.
            regex: Regex::new(
                r#""/api/(cases|actions|incidents|auth|admin|reports|observations|moderators|audit)\b"#,
            )
            .expect("static regex `hardcoded_mutating_route` must compile"),
            message: "polaris-frontend must call mutating /api/* routes via PolarisApiClient, not raw string literals.",
            skip_paths_starting_with: Some(&["polaris-frontend/src/api_client/"]),
        },
        Pattern {
            name: "unsafe_keyword",
            // Workspace lints already deny `unsafe_code`, but defense in
            // depth: the boundary check is the last line before the rule
            // ships, and an inline `#[allow(unsafe_code)]` could slip past
            // the rustc deny in a leaf module without this independent
            // check.
            regex: Regex::new(r"\bunsafe\b")
                .expect("static regex `unsafe_keyword` must compile"),
            message: "polaris-frontend must not contain `unsafe` — workspace lints deny it and so does this boundary check.",
            skip_paths_starting_with: None,
        },
        Pattern {
            name: "tokio_runtime",
            // The frontend runs on `wasm-bindgen-futures`, never on tokio.
            // Catching `tokio::` here keeps a stray
            // `tokio::sync::Mutex` (or similar) from quietly compiling on
            // the native build path and silently breaking the wasm one.
            regex: Regex::new(r"\btokio\b")
                .expect("static regex `tokio_runtime` must compile"),
            message: "polaris-frontend uses wasm-bindgen-futures; tokio must not appear in its source tree.",
            skip_paths_starting_with: None,
        },
    ]
}

/// Look up the user-facing [`Pattern::message`] for a pattern name. Used
/// by the run summary so each violation line carries the explanation a
/// developer needs to fix it without grepping this module.
fn message_for(patterns: &[Pattern], name: &str) -> &'static str {
    patterns
        .iter()
        .find(|p| p.name == name)
        .map_or("unknown pattern", |p| p.message)
}

/// Drive the scan and print a CI-friendly summary.
///
/// Walks every `*.rs` file under [`FRONTEND_SRC`] and exits 0 on a clean
/// scan, non-zero (via `Err`) on any violation. Returns a wrapping
/// [`anyhow::Error`] whose `{:#}` rendering names the violation count;
/// the table of violations is already printed to stdout before the error
/// returns, so CI logs carry both forms.
pub fn run() -> Result<()> {
    let patterns = patterns();
    let report = scan_tree(Path::new(FRONTEND_SRC))
        .with_context(|| format!("scanning frontend tree at `{FRONTEND_SRC}`"))?;

    // Allows are *informational* — print them first so the operator sees
    // every override regardless of whether the run passed or failed.
    if !report.allows.is_empty() {
        println!("xtask-allow overrides applied (informational):");
        for a in &report.allows {
            println!(
                "  {}:{}  [{}]  {}",
                a.path.display(),
                a.line_number,
                a.pattern_name,
                a.line_text.trim(),
            );
        }
        println!();
    }

    if report.violations.is_empty() {
        let files_scanned = count_rs_files(Path::new(FRONTEND_SRC))?;
        println!("check-frontend-boundary: 0 violations in {files_scanned} file(s) scanned.");
        return Ok(());
    }

    println!("check-frontend-boundary: violations found:");
    println!();
    for v in &report.violations {
        println!(
            "  {}:{}  [{}]\n      {}\n      reason: {}",
            v.path.display(),
            v.line_number,
            v.pattern_name,
            v.line_text.trim(),
            message_for(&patterns, v.pattern_name),
        );
    }
    println!();

    Err(anyhow!(
        "{} violation(s) found — see output above",
        report.violations.len()
    ))
}

/// Scan a filesystem tree rooted at `root`. Public so an end-to-end
/// integration test can drive the scanner against the real frontend tree.
pub fn scan_tree(root: &Path) -> Result<ScanReport> {
    let patterns = patterns();
    let mut report = ScanReport::default();

    for entry in WalkDir::new(root) {
        let entry = entry.with_context(|| format!("walking `{}`", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let text = std::fs::read_to_string(entry.path())
            .with_context(|| format!("reading `{}`", entry.path().display()))?;
        let file_report = scan_text_with_allows(entry.path(), &text, &patterns);
        report.violations.extend(file_report.violations);
        report.allows.extend(file_report.allows);
    }

    // Stable ordering: by file path then line number. WalkDir's traversal
    // order is platform-dependent (typically alphabetic on Linux, but not
    // guaranteed), so we sort to keep CI output reproducible.
    report
        .violations
        .sort_by(|a, b| (a.path.as_path(), a.line_number).cmp(&(b.path.as_path(), b.line_number)));
    report
        .allows
        .sort_by(|a, b| (a.path.as_path(), a.line_number).cmp(&(b.path.as_path(), b.line_number)));

    Ok(report)
}

/// Convenience scanner that returns only the violation list. Used by
/// fixture tests that don't care about the allow summary.
#[must_use]
pub fn scan_text(name: &str, text: &str) -> Vec<Violation> {
    let patterns = patterns();
    scan_text_with_allows(Path::new(name), text, &patterns).violations
}

/// Scan `text` (associated with logical path `name`) against `patterns`
/// and return the full [`ScanReport`].
///
/// Behaviour:
///
/// 1. Lines whose first non-whitespace character is `//` are skipped
///    entirely (pure comments).
/// 2. On other lines, the comment suffix (`// …` not inside a string
///    literal) is stripped before matching.
/// 3. The stripped line is matched against every pattern.
/// 4. If a pattern fires, the same line and the previous non-blank line
///    are checked for `xtask-allow: <pattern.name>`. A match records an
///    [`Allow`]; otherwise a [`Violation`].
#[must_use]
pub fn scan_text_with_allows(name: &Path, text: &str, patterns: &[Pattern]) -> ScanReport {
    let mut violations = Vec::new();
    let mut allows = Vec::new();

    // Slash-normalized form of the logical path, used to evaluate each
    // pattern's `skip_paths_starting_with` list. Computed once per scan
    // (not once per line) because the path doesn't change as we iterate.
    let path_for_skip = normalize_path_for_skip(name);

    // We need access to the previous non-blank line's raw text to look
    // for above-line `xtask-allow` markers. The previous line is the raw
    // line (comment-stripped or not) because the marker itself lives
    // inside a comment.
    let raw_lines: Vec<&str> = text.lines().collect();

    for (idx, raw_line) in raw_lines.iter().enumerate() {
        let line_number = idx + 1;

        // Skip pure comment lines outright — the rule is "comments don't
        // count" and an `xtask-allow` line is itself a comment, but it
        // never carries a real pattern match.
        if is_pure_comment_line(raw_line) {
            continue;
        }

        let active = strip_comment(raw_line);
        if active.trim().is_empty() {
            continue;
        }

        for pat in patterns {
            // Path-aware pre-filter: some patterns are intentionally
            // inert inside specific directories (e.g. the hardcoded-
            // route rule does not fire inside `PolarisApiClient`'s own
            // gateway implementation).
            if pattern_skips_path(pat, &path_for_skip) {
                continue;
            }

            if !pat.regex.is_match(active) {
                continue;
            }

            if has_allow_marker(raw_line, pat.name)
                || prev_non_blank_has_allow_marker(&raw_lines, idx, pat.name)
            {
                allows.push(Allow {
                    path: name.to_path_buf(),
                    line_number,
                    pattern_name: pat.name,
                    line_text: active.to_string(),
                });
            } else {
                violations.push(Violation {
                    path: name.to_path_buf(),
                    line_number,
                    pattern_name: pat.name,
                    line_text: active.to_string(),
                });
            }
        }
    }

    ScanReport { violations, allows }
}

/// True when `line`'s first non-whitespace characters are `//` (i.e. the
/// whole line is a Rust line comment, including `///` and `//!`).
fn is_pure_comment_line(line: &str) -> bool {
    line.trim_start().starts_with("//")
}

/// Render `path` with `/` separators for path-skip comparisons.
///
/// Windows yields `\`-separated paths from `WalkDir`; the scanner's
/// skip prefixes are written with `/` because they appear in user-facing
/// documentation. Normalizing once at the entry point keeps the
/// comparison deterministic across platforms.
fn normalize_path_for_skip(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// True if `pat` should be suppressed entirely for the file at the
/// slash-normalized `normalized_path`.
///
/// The match is a substring check rather than a literal `starts_with`,
/// so the same skip prefix works whether the scanner was driven with a
/// relative root (`polaris-frontend/src`) — the production path — or
/// an absolute root, as the end-to-end integration test does. In both
/// cases the slash-normalized path contains the skip prefix as a
/// sub-path.
fn pattern_skips_path(pat: &Pattern, normalized_path: &str) -> bool {
    let Some(prefixes) = pat.skip_paths_starting_with else {
        return false;
    };
    prefixes
        .iter()
        .any(|prefix| normalized_path.contains(prefix))
}

/// Strip the trailing `// …` comment off `line` without breaking `//`
/// sequences that appear inside string literals.
///
/// Implementation note: a tiny state machine tracks whether we are inside
/// a `"…"` double-quoted string, treating `\"` as an escape. Rust also
/// supports raw strings (`r"…"`, `r#"…"#`) but the boundary check has
/// never needed to discriminate those — the patterns we match never
/// appear in raw-string content in the frontend tree, and a raw string
/// containing `//` would just be the URL case the in-string tracking
/// already covers. Block comments (`/* … */`) are not stripped; rustfmt
/// keeps doc comments on `//`/`///` lines and the frontend tree has no
/// block-comment patterns to mask matches.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if in_string {
            if b == b'\\' && i + 1 < bytes.len() {
                // Skip the escaped byte. UTF-8 multibyte sequences after a
                // backslash are not standard Rust escape syntax (`\u{…}`
                // is delimited by braces), so a one-byte skip is safe for
                // valid Rust source.
                i += 2;
                continue;
            }
            if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            // Found a comment start outside any string — truncate here.
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// True if `line` (raw, including any comment portion) contains an
/// `xtask-allow: <pattern_name>` marker.
fn has_allow_marker(line: &str, pattern_name: &str) -> bool {
    let Some(pos) = line.find(ALLOW_PREFIX) else {
        return false;
    };
    let after = line[pos + ALLOW_PREFIX.len()..].trim_start();
    // The marker is `xtask-allow: <name>` — accept either a bare name or
    // a comma-separated list so a single line can opt out of multiple
    // patterns.
    after
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .any(|tok| tok == pattern_name)
}

/// Inspect the previous non-blank line (above `idx`) for an
/// `xtask-allow` marker naming `pattern_name`. Returns false when no
/// such line exists.
fn prev_non_blank_has_allow_marker(lines: &[&str], idx: usize, pattern_name: &str) -> bool {
    let mut i = idx;
    while i > 0 {
        i -= 1;
        if lines[i].trim().is_empty() {
            continue;
        }
        return has_allow_marker(lines[i], pattern_name);
    }
    false
}

/// Count `.rs` files under `root`. Used purely for the clean-scan
/// summary line ("0 violations in N file(s) scanned").
fn count_rs_files(root: &Path) -> Result<usize> {
    let mut n = 0_usize;
    for entry in WalkDir::new(root) {
        let entry = entry.with_context(|| format!("walking `{}`", root.display()))?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
            n += 1;
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comment_handles_url_in_string() {
        assert_eq!(
            strip_comment(r#"let url = "https://api.bsky.app/foo";"#),
            r#"let url = "https://api.bsky.app/foo";"#,
        );
    }

    #[test]
    fn strip_comment_removes_trailing_comment() {
        assert_eq!(strip_comment(r"let x = 1; // trailing"), "let x = 1; ",);
    }

    #[test]
    fn strip_comment_handles_escaped_quote() {
        // A `\"` inside the string must not close the string early.
        assert_eq!(
            strip_comment(r#"let s = "a\"b"; // tail"#),
            r#"let s = "a\"b"; "#,
        );
    }

    #[test]
    fn pure_comment_line_detected() {
        assert!(is_pure_comment_line("// hi"));
        assert!(is_pure_comment_line("    //! doc"));
        assert!(is_pure_comment_line("/// outer doc"));
        assert!(!is_pure_comment_line("let x = 1; // tail"));
        assert!(!is_pure_comment_line(""));
    }

    #[test]
    fn allow_marker_recognised() {
        assert!(has_allow_marker(
            "use polaris_backend::foo; // xtask-allow: polaris_backend_import",
            "polaris_backend_import",
        ));
        assert!(!has_allow_marker(
            "use polaris_backend::foo; // xtask-allow: tokio_runtime",
            "polaris_backend_import",
        ));
    }

    #[test]
    fn allow_marker_accepts_comma_list() {
        assert!(has_allow_marker(
            "let x = unsafe { 0 }; // xtask-allow: unsafe_keyword, tokio_runtime",
            "tokio_runtime",
        ));
    }
}
