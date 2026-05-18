//! AC-B5 — every literal colour value lives in `tokens.css`. Component
//! files must reference the design tokens via `var(--…)` rather than
//! hard-coding hex / rgb / hsl literals.
//!
//! Two pure-Rust file parsers run here:
//!
//! 1. `no_literal_colors_outside_tokens_css` — scans every `.css` file
//!    under `polaris-frontend/styles/` *except* `tokens.css` for literal
//!    hex (`#[0-9a-fA-F]{3,8}`), `rgb(`, `rgba(`, `hsl(`, `hsla(`. Any
//!    match is a hard failure.
//!
//! 2. `tokens_define_both_light_and_dark_palettes` — parses `tokens.css`
//!    and asserts the required custom properties appear under `:root`
//!    AND inside a `@media (prefers-color-scheme: dark)` block, so the
//!    dark palette is genuinely overridden (not just inherited).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use std::fs;
use std::path::PathBuf;

use regex::Regex;
use walkdir::WalkDir;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn styles_dir() -> PathBuf {
    crate_root().join("styles")
}

/// Strip CSS `/* … */` comments so literal-colour mentions inside
/// documentation prose don't trip the test.
fn strip_css_comments(input: &str) -> String {
    let re = Regex::new(r"(?s)/\*.*?\*/").expect("comment regex");
    re.replace_all(input, "").into_owned()
}

#[test]
fn no_literal_colors_outside_tokens_css() {
    let styles = styles_dir();
    assert!(styles.is_dir(), "styles/ missing");

    // Hex literal `#fff`, `#ffffff`, `#ffffffff` (with alpha), etc.
    // Anchored on a non-word character so we don't catch `#fragment`
    // anchors-inside-prose; CSS doesn't put `#` in URL contexts here.
    let hex_re = Regex::new(r"#[0-9a-fA-F]{3,8}\b").expect("hex regex");
    let fn_re = Regex::new(r"\b(?:rgb|rgba|hsl|hsla)\s*\(").expect("color-fn regex");

    let mut offenses: Vec<String> = Vec::new();

    for entry in WalkDir::new(&styles)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("css"))
    {
        let path = entry.path();
        if path.file_name().and_then(|s| s.to_str()) == Some("tokens.css") {
            continue;
        }
        let body =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let stripped = strip_css_comments(&body);

        for caps in hex_re.find_iter(&stripped) {
            offenses.push(format!(
                "{}: literal hex colour `{}`",
                path.display(),
                caps.as_str(),
            ));
        }
        for caps in fn_re.find_iter(&stripped) {
            let kw = caps
                .as_str()
                .trim_end_matches(|c: char| c == '(' || c.is_whitespace());
            // Allow `rgba(0,0,0,X)` inside shadow tokens? No — REQ-B5 says
            // tokens.css is the only file where literal colour values are
            // permitted. Component CSS must reference shadow-* tokens.
            offenses.push(format!(
                "{}: literal colour function `{kw}(…)`",
                path.display(),
            ));
        }
    }

    assert!(
        offenses.is_empty(),
        "literal colour values are forbidden outside tokens.css (REQ-B5 / AC-B5):\n  {}",
        offenses.join("\n  "),
    );
}

/// The set of custom properties the design contract names explicitly.
/// Each MUST appear in `:root` and (for the colour-bearing ones) inside
/// the dark-mode media block.
const REQUIRED_TOKENS_ROOT: &[&str] = &[
    "--color-bg-primary",
    "--color-bg-secondary",
    "--color-bg-elevated",
    "--color-fg-primary",
    "--color-fg-secondary",
    "--color-fg-muted",
    "--color-accent",
    "--color-accent-fg",
    "--color-danger",
    "--color-danger-fg",
    "--color-success",
    "--color-success-fg",
    "--color-warning",
    "--color-warning-fg",
    "--color-border",
    "--color-border-focus",
    "--space-xs",
    "--space-sm",
    "--space-md",
    "--space-lg",
    "--space-xl",
    "--radius-sm",
    "--radius-md",
    "--radius-lg",
    "--font-sans",
    "--font-mono",
    "--font-size-xs",
    "--font-size-sm",
    "--font-size-base",
    "--font-size-lg",
    "--font-size-xl",
    "--line-height-tight",
    "--line-height-normal",
    "--line-height-loose",
];

/// Colour tokens (only these need a dark-mode override).
const REQUIRED_TOKENS_DARK: &[&str] = &[
    "--color-bg-primary",
    "--color-bg-secondary",
    "--color-bg-elevated",
    "--color-fg-primary",
    "--color-fg-secondary",
    "--color-fg-muted",
    "--color-accent",
    "--color-accent-fg",
    "--color-danger",
    "--color-danger-fg",
    "--color-success",
    "--color-success-fg",
    "--color-warning",
    "--color-warning-fg",
    "--color-border",
    "--color-border-focus",
];

/// Slice `:root { … }`'s body from the file. The token file is
/// hand-written and uses the `:root { … }` selector exactly once at the
/// top level, so a balanced-brace walk from the opening `{` is reliable.
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

#[test]
fn tokens_define_both_light_and_dark_palettes() {
    let path = styles_dir().join("tokens.css");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let stripped = strip_css_comments(&body);

    // `:root { … }` block at the top level.
    let root_header = Regex::new(r"(?m)^\s*:root\s*").expect("root header");
    let root_block = slice_block(&stripped, &root_header)
        .expect("tokens.css must contain a `:root { … }` block");

    for token in REQUIRED_TOKENS_ROOT {
        assert!(
            root_block.contains(&format!("{token}:")),
            "tokens.css `:root` is missing required token `{token}`",
        );
    }

    // Dark-mode block: `@media (prefers-color-scheme: dark)`. The block
    // we care about is the **inner** `:root { … }` *inside* it. We slice
    // the whole `@media` body first, then the nested `:root` body.
    let dark_header =
        Regex::new(r"@media\s*\(\s*prefers-color-scheme\s*:\s*dark\s*\)\s*").expect("dark header");
    let dark_block = slice_block(&stripped, &dark_header)
        .expect("tokens.css must contain a `@media (prefers-color-scheme: dark)` block");
    let dark_root_block = slice_block(&dark_block, &root_header)
        .expect("dark-mode block must contain its own `:root { … }`");

    for token in REQUIRED_TOKENS_DARK {
        assert!(
            dark_root_block.contains(&format!("{token}:")),
            "tokens.css dark-mode `:root` is missing required colour token `{token}`",
        );
    }
}
