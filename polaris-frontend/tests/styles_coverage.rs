//! AC-B2 — every BEM class name referenced in the Rust source has at least
//! one matching selector in `polaris-frontend/styles/`.
//!
//! The test is a native-only file parser. It walks `src/{pages,components}`
//! and the rest of the source tree, extracts every `class="…"` literal,
//! splits multi-class strings on whitespace, then asserts each class
//! appears (as `.<class>`) in at least one of the CSS files under
//! `polaris-frontend/styles/`.
//!
//! Why native: this exercises the Rust *source* and the on-disk CSS, not
//! the wasm bundle — no browser runtime, no `wasm-bindgen-test`.
//!
//! Dynamic class strings (e.g. `let row_class = move || { … }`) are not
//! found by the `class="…"` literal walk; they are detected by a separate
//! regex that picks up the string literals inside helper closures whose
//! identifier ends in `_class` or matches the `let class = if …` shape.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use walkdir::WalkDir;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Walk `<root>/src` and return every `class="…"` literal value, split
/// on whitespace into individual class names.
fn extract_static_classes(src_dir: &Path) -> BTreeSet<String> {
    let class_re = Regex::new(r#"class\s*=\s*"([^"]+)""#).expect("regex");
    let mut classes = BTreeSet::new();
    for entry in WalkDir::new(src_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
    {
        let Ok(body) = fs::read_to_string(entry.path()) else {
            continue;
        };
        for caps in class_re.captures_iter(&body) {
            for tok in caps[1].split_whitespace() {
                // Empty / placeholder tokens never reach the DOM.
                if !tok.is_empty() {
                    classes.insert(tok.to_owned());
                }
            }
        }
    }
    classes
}

/// Walk the same source tree and pick up class names that only appear
/// inside Rust string literals of helper closures (`row_class`,
/// `counter_class`, `item_class`, anonymous `let class = …` ternaries,
/// etc.). The match is conservative: we only mine string literals from
/// `*.rs` files inside `src/` whose content shape is `"foo foo--bar"` and
/// the line is part of a class-selecting expression. To stay deterministic,
/// we just extract every `"…"` literal that is composed exclusively of
/// BEM-shaped tokens (`[a-z][a-z0-9-]*(?:__[a-z0-9-]+)?(?:--[a-z0-9-]+)?`).
fn extract_dynamic_classes(src_dir: &Path) -> BTreeSet<String> {
    // BEM-shape token: lower-case block name, optional `__elem` and `--mod`.
    let bem_re =
        Regex::new(r"^[a-z][a-z0-9-]*(?:__[a-z0-9-]+)?(?:--[a-z0-9-]+)?$").expect("bem regex");
    // Plain double-quoted string literal that does NOT contain a quote
    // (good enough for the Rust source we ship; no raw strings carry
    // class lists in this crate).
    let str_re = Regex::new(r#""([^"\\]*)""#).expect("string-literal regex");

    let mut classes = BTreeSet::new();
    for entry in WalkDir::new(src_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
    {
        let Ok(body) = fs::read_to_string(entry.path()) else {
            continue;
        };
        // Only mine lines that look like they are building a class string:
        // a literal containing `__` or `--` plus the surrounding closure
        // / let-binding hint. We accept any line that mentions `class`
        // as a heuristic and then validates each token by shape.
        for line in body.lines() {
            if !line.contains("class") && !line.contains("__") {
                continue;
            }
            for caps in str_re.captures_iter(line) {
                let raw = &caps[1];
                if !raw.contains("__") && !raw.contains("--") {
                    continue;
                }
                for tok in raw.split_whitespace() {
                    if bem_re.is_match(tok) {
                        classes.insert(tok.to_owned());
                    }
                }
            }
        }
    }
    classes
}

/// Read every `.css` file under `polaris-frontend/styles/` and return its
/// concatenated contents. The contrast / token tests parse the same
/// files; we keep the IO local to each test so failures are diagnosable
/// from the test binary alone.
fn read_all_css(styles_dir: &Path) -> String {
    let mut out = String::new();
    for entry in WalkDir::new(styles_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("css"))
    {
        let body = fs::read_to_string(entry.path())
            .unwrap_or_else(|e| panic!("read {}: {e}", entry.path().display()));
        out.push_str(&body);
        out.push('\n');
    }
    out
}

#[test]
fn every_class_literal_has_a_matching_css_selector() {
    let root = crate_root();
    let src = root.join("src");
    let styles = root.join("styles");

    assert!(src.is_dir(), "src/ missing: {}", src.display());
    assert!(styles.is_dir(), "styles/ missing: {}", styles.display());

    let mut classes = extract_static_classes(&src);
    classes.extend(extract_dynamic_classes(&src));

    assert!(
        !classes.is_empty(),
        "no class literals extracted — coverage walker is broken",
    );

    let css_body = read_all_css(&styles);

    let mut missing: Vec<String> = Vec::new();
    for class in &classes {
        // A class is "covered" if `.{class}` appears anywhere as a selector
        // fragment. We use a word-boundary check to avoid matching
        // `.foo-bar` when the class is `.foo` (the trailing char after
        // `.foo` must not be `[a-z0-9_-]`).
        let needle = format!(".{class}");
        let Some(idx) = css_body.find(&needle) else {
            missing.push(class.clone());
            continue;
        };
        let tail_byte = css_body.as_bytes().get(idx + needle.len()).copied();
        let trailing_is_part_of_longer_class = matches!(
            tail_byte,
            Some(b) if b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
        );
        if trailing_is_part_of_longer_class {
            // The first occurrence was a longer class. Scan all
            // occurrences and accept if any one ends cleanly.
            let mut covered = false;
            let mut start = 0usize;
            while let Some(off) = css_body[start..].find(&needle) {
                let abs = start + off;
                let next = css_body.as_bytes().get(abs + needle.len()).copied();
                let bad = matches!(
                    next,
                    Some(b) if b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
                );
                if !bad {
                    covered = true;
                    break;
                }
                start = abs + needle.len();
            }
            if !covered {
                missing.push(class.clone());
            }
        }
    }

    assert!(
        missing.is_empty(),
        "the following BEM classes are referenced in Rust source but have \
         no matching CSS selector under polaris-frontend/styles/:\n  {}",
        missing.join("\n  "),
    );
}
