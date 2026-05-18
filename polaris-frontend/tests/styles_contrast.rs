//! AC-B3 — WCAG AA contrast for every named fg/bg token pairing in both
//! light and dark mode.
//!
//! Pure-Rust static check: parse `polaris-frontend/styles/tokens.css`,
//! pull out the hex value of each `--color-*` token under `:root` (light
//! palette) and under the dark-mode `:root` (overrides), then run the
//! WCAG 2.x relative-luminance formula over each named pair.
//!
//! Pairs checked (light + dark):
//!   - fg-primary    vs bg-primary            (≥ 4.5:1)
//!   - fg-primary    vs bg-elevated           (≥ 4.5:1)
//!   - fg-primary    vs bg-secondary          (≥ 4.5:1)
//!   - fg-secondary  vs bg-primary            (≥ 4.5:1)
//!   - fg-muted      vs bg-primary            (≥ 4.5:1)
//!   - accent-fg     vs accent                (≥ 4.5:1)
//!   - danger-fg     vs danger                (≥ 4.5:1)
//!   - success-fg    vs success               (≥ 4.5:1)
//!   - warning-fg    vs warning               (≥ 4.5:1)
//!   - danger        vs bg-elevated           (≥ 4.5:1) — REQ-B3 lex error
//!   - border-focus  vs bg-elevated           (≥ 3.0:1) — focus ring is
//!     non-text per WCAG §1.4.11
//!
//! REQ-B3 requires the lexicon-error text colour to satisfy AA against the
//! panel background; `composer__lex-error` is rendered with
//! `var(--color-danger)` on a `--color-bg-elevated` background.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use regex::Regex;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn strip_css_comments(input: &str) -> String {
    let re = Regex::new(r"(?s)/\*.*?\*/").expect("comment regex");
    re.replace_all(input, "").into_owned()
}

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

/// Parse `--color-foo: #rrggbb;` declarations from a CSS rule body.
fn parse_color_tokens(rule_body: &str) -> BTreeMap<String, [u8; 3]> {
    let re = Regex::new(r"(--color-[a-z0-9-]+)\s*:\s*#([0-9a-fA-F]{3,8})\s*;")
        .expect("color decl regex");
    let mut out = BTreeMap::new();
    for caps in re.captures_iter(rule_body) {
        let name = caps[1].to_owned();
        let hex = &caps[2];
        if let Some(rgb) = hex_to_rgb(hex) {
            out.insert(name, rgb);
        }
    }
    out
}

fn hex_to_rgb(hex: &str) -> Option<[u8; 3]> {
    let bytes = match hex.len() {
        3 => {
            // `#rgb` shorthand: each char doubles.
            let chars: Vec<char> = hex.chars().collect();
            vec![
                u8::from_str_radix(&format!("{}{}", chars[0], chars[0]), 16).ok()?,
                u8::from_str_radix(&format!("{}{}", chars[1], chars[1]), 16).ok()?,
                u8::from_str_radix(&format!("{}{}", chars[2], chars[2]), 16).ok()?,
            ]
        }
        6 | 8 => {
            // 6 = `rrggbb`, 8 = `rrggbbaa` (drop the alpha — contrast is
            // computed on RGB; alpha-aware contrast needs a composite
            // background, which we'd derive from the parent token, out
            // of scope for the static check).
            vec![
                u8::from_str_radix(&hex[0..2], 16).ok()?,
                u8::from_str_radix(&hex[2..4], 16).ok()?,
                u8::from_str_radix(&hex[4..6], 16).ok()?,
            ]
        }
        _ => return None,
    };
    Some([bytes[0], bytes[1], bytes[2]])
}

/// sRGB channel → linear (WCAG 2.x).
fn srgb_to_linear(channel: u8) -> f64 {
    let c = f64::from(channel) / 255.0;
    if c <= 0.039_28 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

/// Relative luminance per WCAG 2.x §1.4.3.
fn relative_luminance(rgb: [u8; 3]) -> f64 {
    let r = srgb_to_linear(rgb[0]);
    let g = srgb_to_linear(rgb[1]);
    let b = srgb_to_linear(rgb[2]);
    0.2126 * r + 0.7152 * g + 0.0722 * b
}

/// Contrast ratio per WCAG 2.x §1.4.3.
fn contrast_ratio(fg: [u8; 3], bg: [u8; 3]) -> f64 {
    let lf = relative_luminance(fg);
    let lb = relative_luminance(bg);
    let (lighter, darker) = if lf > lb { (lf, lb) } else { (lb, lf) };
    (lighter + 0.05) / (darker + 0.05)
}

fn token(palette: &BTreeMap<String, [u8; 3]>, name: &str) -> [u8; 3] {
    *palette
        .get(name)
        .unwrap_or_else(|| panic!("missing token `{name}` in palette"))
}

/// Named pair to check, with its WCAG threshold.
struct Pair {
    fg: &'static str,
    bg: &'static str,
    threshold: f64,
    /// Human label used in failure messages.
    note: &'static str,
}

/// Pairs that must clear AA for both light and dark mode.
const PAIRS: &[Pair] = &[
    Pair {
        fg: "--color-fg-primary",
        bg: "--color-bg-primary",
        threshold: 4.5,
        note: "body text on primary background",
    },
    Pair {
        fg: "--color-fg-primary",
        bg: "--color-bg-elevated",
        threshold: 4.5,
        note: "body text on elevated panel",
    },
    Pair {
        fg: "--color-fg-primary",
        bg: "--color-bg-secondary",
        threshold: 4.5,
        note: "body text on secondary background",
    },
    Pair {
        fg: "--color-fg-secondary",
        bg: "--color-bg-primary",
        threshold: 4.5,
        note: "secondary text on primary background",
    },
    Pair {
        fg: "--color-fg-muted",
        bg: "--color-bg-primary",
        threshold: 4.5,
        note: "muted text on primary background",
    },
    Pair {
        fg: "--color-accent-fg",
        bg: "--color-accent",
        threshold: 4.5,
        note: "accent button label on accent fill",
    },
    Pair {
        fg: "--color-danger-fg",
        bg: "--color-danger",
        threshold: 4.5,
        note: "danger button label on danger fill",
    },
    Pair {
        fg: "--color-success-fg",
        bg: "--color-success",
        threshold: 4.5,
        note: "success label on success fill",
    },
    Pair {
        fg: "--color-warning-fg",
        bg: "--color-warning",
        threshold: 4.5,
        note: "warning label on warning fill",
    },
    Pair {
        // REQ-B3: lexicon-error text uses `--color-danger` against the
        // panel background (`--color-bg-elevated`).
        fg: "--color-danger",
        bg: "--color-bg-elevated",
        threshold: 4.5,
        note: "lexicon-error text on panel (REQ-B3)",
    },
    Pair {
        // Focus ring is non-text — WCAG 1.4.11 sets the threshold at 3:1.
        fg: "--color-border-focus",
        bg: "--color-bg-elevated",
        threshold: 3.0,
        note: "focus ring on panel (WCAG 1.4.11 non-text)",
    },
];

fn load_palettes() -> (BTreeMap<String, [u8; 3]>, BTreeMap<String, [u8; 3]>) {
    let path = crate_root().join("styles").join("tokens.css");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let stripped = strip_css_comments(&body);

    let root_header = Regex::new(r"(?m)^\s*:root\s*").expect("root header");
    let light_block = slice_block(&stripped, &root_header)
        .expect("tokens.css must contain a top-level `:root { … }` block");
    let light = parse_color_tokens(&light_block);

    let dark_header =
        Regex::new(r"@media\s*\(\s*prefers-color-scheme\s*:\s*dark\s*\)\s*").expect("dark header");
    let dark_outer = slice_block(&stripped, &dark_header)
        .expect("tokens.css must contain a dark-mode `@media` block");
    let dark_inner = slice_block(&dark_outer, &root_header)
        .expect("dark-mode `@media` block must redeclare `:root { … }`");
    // Dark palette inherits the light defaults; overlay the dark
    // overrides on top so pairs reference the effective dark value.
    let mut dark = light.clone();
    for (k, v) in parse_color_tokens(&dark_inner) {
        dark.insert(k, v);
    }

    (light, dark)
}

#[test]
fn light_mode_text_pairs_meet_wcag_aa() {
    let (light, _) = load_palettes();
    let mut failures = Vec::new();
    for pair in PAIRS {
        if pair.threshold > 4.0 {
            // text-class pairs (≥ 4.5)
            let fg = token(&light, pair.fg);
            let bg = token(&light, pair.bg);
            let ratio = contrast_ratio(fg, bg);
            if ratio < pair.threshold {
                failures.push(format!(
                    "light: {} on {} ({}) — ratio {:.2}:1 < {:.1}:1 [{}]",
                    pair.fg, pair.bg, pair.note, ratio, pair.threshold, pair.note,
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "WCAG AA text-contrast failures (light mode):\n  {}",
        failures.join("\n  "),
    );
}

#[test]
fn dark_mode_text_pairs_meet_wcag_aa() {
    let (_, dark) = load_palettes();
    let mut failures = Vec::new();
    for pair in PAIRS {
        if pair.threshold > 4.0 {
            let fg = token(&dark, pair.fg);
            let bg = token(&dark, pair.bg);
            let ratio = contrast_ratio(fg, bg);
            if ratio < pair.threshold {
                failures.push(format!(
                    "dark: {} on {} ({}) — ratio {:.2}:1 < {:.1}:1",
                    pair.fg, pair.bg, pair.note, ratio, pair.threshold,
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "WCAG AA text-contrast failures (dark mode):\n  {}",
        failures.join("\n  "),
    );
}

#[test]
fn light_mode_accent_pairs_meet_wcag_non_text() {
    let (light, _) = load_palettes();
    let mut failures = Vec::new();
    for pair in PAIRS {
        if pair.threshold <= 4.0 {
            // non-text (≥ 3.0) — focus ring etc.
            let fg = token(&light, pair.fg);
            let bg = token(&light, pair.bg);
            let ratio = contrast_ratio(fg, bg);
            if ratio < pair.threshold {
                failures.push(format!(
                    "light non-text: {} on {} ({}) — ratio {:.2}:1 < {:.1}:1",
                    pair.fg, pair.bg, pair.note, ratio, pair.threshold,
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "WCAG 1.4.11 non-text-contrast failures (light mode):\n  {}",
        failures.join("\n  "),
    );
}

#[test]
fn dark_mode_accent_pairs_meet_wcag_non_text() {
    let (_, dark) = load_palettes();
    let mut failures = Vec::new();
    for pair in PAIRS {
        if pair.threshold <= 4.0 {
            let fg = token(&dark, pair.fg);
            let bg = token(&dark, pair.bg);
            let ratio = contrast_ratio(fg, bg);
            if ratio < pair.threshold {
                failures.push(format!(
                    "dark non-text: {} on {} ({}) — ratio {:.2}:1 < {:.1}:1",
                    pair.fg, pair.bg, pair.note, ratio, pair.threshold,
                ));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "WCAG 1.4.11 non-text-contrast failures (dark mode):\n  {}",
        failures.join("\n  "),
    );
}

#[test]
fn wcag_formula_sanity_check_white_on_black() {
    // White on black is the classic 21:1 reference. If the formula
    // implementation drifts, this catches it.
    let ratio = contrast_ratio([255, 255, 255], [0, 0, 0]);
    assert!(
        (ratio - 21.0).abs() < 0.01,
        "WCAG formula sanity check failed: expected 21.0, got {ratio}",
    );
}
