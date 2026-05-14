//! End-to-end smoke for the frontend-boundary scanner.
//!
//! Walks the real `polaris-frontend/src/` via the public scanner API
//! (`scan_tree`) and asserts zero violations on the current state. This
//! is the same path the binary's `run` function takes, minus the
//! stdout printing — so a regression in the frontend code that the
//! boundary check would have caught also fails this test, making
//! `cargo test -p xtask` a strict superset of `cargo xtask
//! check-frontend-boundary` for CI purposes.

// Test code: panic-on-failure is the test contract. The rust-quality
// skill explicitly allows `unwrap`/`expect` in test code; we narrow the
// allow here rather than at every call site to keep the test concise
// and the rationale in one place.
#![allow(clippy::expect_used)]

use std::path::PathBuf;

use xtask::check_frontend_boundary::scan_tree;

/// Resolve `<repo-root>/polaris-frontend/src` from this test's
/// `CARGO_MANIFEST_DIR` (`<repo-root>/xtask`). `cargo test` always sets
/// `CARGO_MANIFEST_DIR`, so the lookup is stable regardless of which
/// working directory the user invoked the test from.
fn frontend_src() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .expect("xtask crate dir has a parent (the workspace root)")
        .join("polaris-frontend")
        .join("src")
}

#[test]
fn current_frontend_tree_has_zero_violations() {
    let root = frontend_src();
    let report =
        scan_tree(&root).expect("scan_tree must succeed against the in-tree frontend source");

    assert!(
        report.violations.is_empty(),
        "polaris-frontend has boundary violations: {:#?}",
        report.violations,
    );
}
