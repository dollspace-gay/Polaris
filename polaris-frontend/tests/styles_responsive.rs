//! AC-B4 — the dashboard grid collapses to a single column at the mobile
//! breakpoint.
//!
//! Pure file parser: read `styles/pattern-dashboard.css`, find the
//! `.pattern-dashboard__grid` rule's `grid-template-columns`, find the
//! same property re-declared inside the `@media (max-width: 768px)`
//! block, and assert the two values differ.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use std::fs;
use std::path::PathBuf;

use regex::Regex;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strip CSS comments so commentary about the grid does not confuse the
/// rule walker.
fn strip_css_comments(input: &str) -> String {
    let re = Regex::new(r"(?s)/\*.*?\*/").expect("comment regex");
    re.replace_all(input, "").into_owned()
}

/// Slice the body of a CSS rule whose selector matches `header_re`.
/// Walks the brace tree from the first `{` after the selector header.
fn slice_block(body: &str, header_re: &Regex) -> Option<String> {
    let m = header_re.find(body)?;
    let after = &body[m.end()..];
    let open = after.find('{')?;
    let rest = &after[open + 1..];
    let mut depth = 1usize;
    for (idx, ch) in rest.char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[..idx].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract the `grid-template-columns: …;` value from a CSS rule body.
fn grid_template(rule_body: &str) -> Option<String> {
    let re = Regex::new(r"grid-template-columns\s*:\s*([^;]+);").expect("gtc regex");
    re.captures(rule_body).map(|c| c[1].trim().to_owned())
}

#[test]
fn dashboard_grid_collapses_at_768px_breakpoint() {
    let path = crate_root().join("styles").join("pattern-dashboard.css");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let stripped = strip_css_comments(&body);

    // Desktop rule lives at the top level — match a selector header that
    // starts with `.pattern-dashboard__grid` and is NOT nested inside a
    // media query. Approach: walk top-level rules, find the first
    // `.pattern-dashboard__grid` outside any `@media` block.
    let desktop_header =
        Regex::new(r"(?m)^\s*\.pattern-dashboard__grid\s*").expect("desktop header");
    let desktop_block = slice_block(&stripped, &desktop_header)
        .expect("`.pattern-dashboard__grid` rule must exist at the top level");
    let desktop_gtc = grid_template(&desktop_block)
        .expect("desktop `.pattern-dashboard__grid` must declare `grid-template-columns`");

    // Mobile rule lives inside `@media (max-width: 768px) { … }`. Slice
    // that block, then locate the `.pattern-dashboard__grid` rule inside.
    let mq_header = Regex::new(r"@media\s*\(\s*max-width\s*:\s*768px\s*\)\s*").expect("mq header");
    let mq_block = slice_block(&stripped, &mq_header)
        .expect("pattern-dashboard.css must contain a `@media (max-width: 768px)` block (REQ-B4)");
    let mobile_header = Regex::new(r"\.pattern-dashboard__grid\s*").expect("mobile header");
    let mobile_block = slice_block(&mq_block, &mobile_header)
        .expect("mobile @media block must redeclare `.pattern-dashboard__grid`");
    let mobile_gtc = grid_template(&mobile_block)
        .expect("mobile `.pattern-dashboard__grid` must redeclare `grid-template-columns`");

    assert_ne!(
        desktop_gtc, mobile_gtc,
        "mobile breakpoint must change `.pattern-dashboard__grid`'s \
         `grid-template-columns` (desktop = `{desktop_gtc}`, mobile = `{mobile_gtc}`)",
    );

    // The single-column collapse is the contract; sanity-check that
    // mobile actually picks a single-track layout.
    assert!(
        mobile_gtc.contains("1fr") && !mobile_gtc.contains("repeat"),
        "mobile `grid-template-columns` should be a single-track layout, got `{mobile_gtc}`",
    );
}
