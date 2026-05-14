//! Fixture tests for the frontend-boundary scanner.
//!
//! Drives [`xtask::check_frontend_boundary::scan_text`] against three
//! in-memory fixtures: a clean one, one that fires every pattern, and one
//! that uses the `// xtask-allow:` override. The patterns the scanner
//! exposes (and the regexes behind them) are the source of truth — these
//! tests pin the contract so a regression in the pattern list is caught
//! before it lands in CI.

use std::path::Path;
use xtask::check_frontend_boundary::{Pattern, patterns, scan_text, scan_text_with_allows};

/// A frontend file with none of the forbidden patterns. Mirrors the
/// shape of `polaris-frontend/src/api_client/native.rs` (uses
/// `reqwest`, talks to a `base` URL, calls `/healthz`) — every value
/// that *could* be confused for a violation (the `/api/` substring on
/// the doc-comment line, the word `tokio` inside a string literal in a
/// hypothetical config) is exercised.
const CLEAN: &str = r#"
//! Native (`reqwest`-backed) Polaris API client.
//!
//! Talks to the Axum backend at `/api/*` and `/healthz`.

use reqwest::Client;

pub struct NativePolarisApiClient {
    base: String,
    client: Client,
}

impl NativePolarisApiClient {
    pub fn new(base: impl Into<String>) -> Result<Self, String> {
        let client = Client::builder()
            .cookie_store(true)
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { base: base.into(), client })
    }

    pub async fn healthz(&self) -> Result<String, String> {
        let url = format!("{}/healthz", self.base.trim_end_matches('/'));
        let resp = self.client.get(&url).send().await.map_err(|e| e.to_string())?;
        resp.text().await.map_err(|e| e.to_string())
    }
}
"#;

/// A file that fires every forbidden pattern. Each violation has a
/// trailing comment naming the pattern so the test failure messages are
/// self-explanatory if the scanner regresses.
const VIOLATING: &str = r#"
use polaris_backend::api::mutations::create_incident;
use tokio::sync::Mutex;

pub async fn submit(case_id: &str) {
    let url = "/api/cases/submit";
    let _guard = unsafe { std::ptr::null::<u8>() };
    let _ = (polaris_backend::PRIVATE_KEY, url);
}
"#;

/// A file that fires every pattern but suppresses each one with an
/// inline `// xtask-allow:` marker. Verifies that the override applies
/// per-pattern (the marker on one line does not silence other patterns
/// on other lines).
const WITH_ALLOW: &str = r#"
// xtask-allow: polaris_backend_import
use polaris_backend::types::Subject;

use tokio::sync::Mutex; // xtask-allow: tokio_runtime

pub fn raw() {
    let _url = "/api/admin/seed"; // xtask-allow: hardcoded_mutating_route
    // xtask-allow: unsafe_keyword
    let _ = unsafe { 0_u8 };
}
"#;

#[test]
fn patterns_all_compile() {
    // The `patterns()` function uses `expect(...)` on each `Regex::new`
    // call. The narrow allow is justified because every entry is
    // exercised here — a typo in any regex literal fails this test
    // rather than the production binary.
    let pats = patterns();
    assert!(!pats.is_empty(), "patterns must not be empty");
    let names: Vec<&'static str> = pats.iter().map(|p: &Pattern| p.name).collect();
    assert!(names.contains(&"polaris_backend_import"));
    assert!(names.contains(&"hardcoded_mutating_route"));
    assert!(names.contains(&"unsafe_keyword"));
    assert!(names.contains(&"tokio_runtime"));
}

#[test]
fn clean_fixture_has_no_violations() {
    let violations = scan_text("clean.rs", CLEAN);
    assert!(
        violations.is_empty(),
        "expected zero violations on clean fixture, got: {violations:#?}",
    );
}

#[test]
fn violating_fixture_fires_every_pattern() {
    let violations = scan_text("violating.rs", VIOLATING);

    let fired: std::collections::BTreeSet<&'static str> =
        violations.iter().map(|v| v.pattern_name).collect();

    for required in [
        "polaris_backend_import",
        "hardcoded_mutating_route",
        "unsafe_keyword",
        "tokio_runtime",
    ] {
        assert!(
            fired.contains(required),
            "expected pattern `{required}` to fire on violating fixture; \
             actually fired: {fired:?}",
        );
    }
}

#[test]
fn allow_marker_suppresses_violation_to_allow_list() {
    let pats = patterns();
    let report = scan_text_with_allows(Path::new("with_allow.rs"), WITH_ALLOW, &pats);

    assert!(
        report.violations.is_empty(),
        "expected zero violations with allow markers, got: {:#?}",
        report.violations,
    );

    // All four patterns are exercised in the fixture; each must show up
    // as an *allow*, not silently disappear.
    let allowed: std::collections::BTreeSet<&'static str> =
        report.allows.iter().map(|a| a.pattern_name).collect();
    for required in [
        "polaris_backend_import",
        "hardcoded_mutating_route",
        "unsafe_keyword",
        "tokio_runtime",
    ] {
        assert!(
            allowed.contains(required),
            "expected pattern `{required}` to appear as an allow; \
             actually allowed: {allowed:?}",
        );
    }
}

#[test]
fn comment_only_lines_are_skipped() {
    // Pure comment containing both `polaris_backend` and the `/api/...`
    // shape must not fire — comments are stripped before matching.
    let src = r#"
//! polaris_backend::api::cases::"/api/cases/x" — discussed only in docs
/// also unsafe and tokio are mentioned, but only in this comment
"#;
    let violations = scan_text("comment_only.rs", src);
    assert!(
        violations.is_empty(),
        "comment-only fixture must not fire any pattern, got: {violations:#?}",
    );
}

#[test]
fn trailing_comment_does_not_fire() {
    // A trailing comment that happens to contain a forbidden token is
    // ignored — the active portion of the line is what matters.
    let src = "let x = 1; // polaris_backend reference in comment\n";
    let violations = scan_text("trailing.rs", src);
    assert!(
        violations.is_empty(),
        "trailing comment must not fire any pattern, got: {violations:#?}",
    );
}

#[test]
fn url_in_string_is_not_flagged_as_polaris_route() {
    // The `hardcoded_mutating_route` pattern anchors on the opening
    // quote of a string literal (`"/api/cases/...`), so a URL pointing
    // at an external host that happens to contain `/api/cases/` is
    // NOT a Polaris own-host mutating call and must not fire. This
    // also exercises the comment-strip state machine: the `//` in
    // `https://` must not be treated as a comment start (otherwise
    // the trailing `// tail` comment would survive into the active
    // line and confuse downstream tooling).
    let src = r#"let s = "https://example.com/api/cases/x"; // tail"#;
    let violations = scan_text("url.rs", src);
    assert!(
        violations.is_empty(),
        "external URL containing `/api/cases/` must not fire \
         hardcoded_mutating_route, got: {violations:#?}",
    );
}

#[test]
fn hardcoded_polaris_route_literal_fires() {
    // The intended catch: a bare `"/api/cases/..."` literal (Polaris
    // own-host route, no scheme/host prefix) is exactly the bypass
    // the boundary check exists to flag.
    let src = r#"let path = "/api/cases/123/escalate";"#;
    let violations = scan_text("bypass.rs", src);
    assert_eq!(
        violations.len(),
        1,
        "bare `/api/cases/...` literal must fire hardcoded_mutating_route, \
         got: {violations:#?}",
    );
    assert_eq!(violations[0].pattern_name, "hardcoded_mutating_route");
}

#[test]
fn path_aware_skip_silences_gateway_route_literals() {
    // A hardcoded-route literal inside `polaris-frontend/src/api_client/`
    // is the legitimate gateway implementation, not a bypass. The
    // path-aware skip on `hardcoded_mutating_route` must suppress it.
    let src = r#"let path = format!("/api/cases/{id}/actions");"#;
    let pats = patterns();
    let report = scan_text_with_allows(
        Path::new("polaris-frontend/src/api_client/wasm.rs"),
        src,
        &pats,
    );
    assert!(
        report.violations.is_empty(),
        "route literal inside the gateway directory must not fire \
         hardcoded_mutating_route, got: {:#?}",
        report.violations,
    );
    assert!(
        report.allows.is_empty(),
        "path-aware skip should pre-filter the pattern (no allow either), \
         got: {:#?}",
        report.allows,
    );
}

#[test]
fn path_aware_skip_does_not_apply_outside_gateway_directory() {
    // The same route literal in non-gateway code must still fire — the
    // skip is intentionally narrow to the `api_client/` directory.
    let src = r#"let path = format!("/api/cases/{id}/actions");"#;
    let pats = patterns();
    let report = scan_text_with_allows(
        Path::new("polaris-frontend/src/pages/case_view.rs"),
        src,
        &pats,
    );
    assert_eq!(
        report.violations.len(),
        1,
        "route literal outside the gateway must still fire \
         hardcoded_mutating_route, got: {:#?}",
        report.violations,
    );
    assert_eq!(
        report.violations[0].pattern_name,
        "hardcoded_mutating_route"
    );
}

#[test]
fn above_line_allow_marker_works() {
    // Marker on the previous non-blank line suppresses the next active
    // match. The intervening blank line should not break the chain.
    let src = "\
// xtask-allow: polaris_backend_import\n\
\n\
use polaris_backend::foo;\n\
";
    let violations = scan_text("above_allow.rs", src);
    assert!(
        violations.is_empty(),
        "above-line allow marker should suppress next-line violation, got: {violations:#?}",
    );
}
