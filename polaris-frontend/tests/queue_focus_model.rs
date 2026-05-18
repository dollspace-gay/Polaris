//! AC-4 (issue #91, mod-workstation feature #1) — mechanical guarantees
//! around the triage-queue focus model:
//!
//! 1. `.triage-queue__row--focused` carries a visible focus ring
//!    (`outline:` or `box-shadow:` non-zero) — this is the WCAG
//!    §2.4.7 "focus visible" contract.
//! 2. `.triage-queue__keymap-overlay` exists so the `?`-toggled help
//!    surface has somewhere to land.
//! 3. Pure helpers `next_focus` / `prev_focus` round-trip across an
//!    end-to-end wrap (top→bottom→top) so the keymap is reversible.
//!
//! Pure-native: parses `polaris-frontend/styles/queue.css` and calls
//! into the published helpers in [`polaris_frontend::pages::queue`].
//! No wasm-bindgen, no DOM.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]

use std::fs;
use std::path::PathBuf;

use polaris_frontend::pages::queue::{next_focus, prev_focus, target_is_editable};
use regex::Regex;

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Strip CSS `/* … */` comments so prose mentions of `outline:` etc.
/// inside file-level comments don't trip the property walker.
fn strip_css_comments(input: &str) -> String {
    let re = Regex::new(r"(?s)/\*.*?\*/").expect("comment regex");
    re.replace_all(input, "").into_owned()
}

/// Slice the body of a CSS rule whose selector matches `header_re`.
/// Walks the brace tree from the first `{` after the selector header.
/// Returns the slice between the matched braces.
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

fn queue_css() -> String {
    let path = crate_root().join("styles").join("queue.css");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    strip_css_comments(&body)
}

#[test]
fn focused_row_has_a_visible_focus_ring() {
    let body = queue_css();
    // Selector header: anything that starts with `.triage-queue__row--focused`
    // at the top of a rule (matches both the standalone class rule and
    // the comma-grouped `.triage-queue__row--focused, .triage-queue__row:focus-visible` form).
    let header = Regex::new(r"\.triage-queue__row--focused\b").expect("focused selector");
    let rule = slice_block(&body, &header)
        .expect("`.triage-queue__row--focused` rule must exist in queue.css");

    // The focus ring is satisfied by `outline:` or `box-shadow:` with a
    // non-zero / non-`none` value. Walk both properties; accept either.
    let outline_re = Regex::new(r"outline\s*:\s*([^;]+);").expect("outline prop regex");
    let box_shadow_re = Regex::new(r"box-shadow\s*:\s*([^;]+);").expect("box-shadow prop regex");

    let outline_visible = outline_re.captures_iter(&rule).any(|c| {
        let v = c[1].trim();
        // `outline: none`, `outline: 0`, `outline: 0 …` do not count.
        !v.is_empty() && v != "none" && !v.starts_with('0')
    });
    let shadow_visible = box_shadow_re.captures_iter(&rule).any(|c| {
        let v = c[1].trim();
        !v.is_empty() && v != "none"
    });

    assert!(
        outline_visible || shadow_visible,
        "`.triage-queue__row--focused` must declare a visible focus ring \
         (`outline:` or `box-shadow:` non-zero); rule body:\n{rule}",
    );
}

#[test]
fn keymap_overlay_rule_exists() {
    let body = queue_css();
    let header = Regex::new(r"\.triage-queue__keymap-overlay\b").expect("overlay selector");
    let rule = slice_block(&body, &header)
        .expect("`.triage-queue__keymap-overlay` rule must exist in queue.css");
    // The overlay must declare *some* layout / surface property; bare-
    // empty rules are a smell. We just assert the body is non-trivial.
    assert!(
        rule.trim().len() > 10,
        "overlay rule looks empty; body:\n{rule}",
    );
}

#[test]
fn reviewed_modifier_rule_exists() {
    // The `r` key flips an in-page reviewed state; the modifier class
    // MUST exist so the visual feedback is wired even though the
    // persisted form ships with #93.
    let body = queue_css();
    let header = Regex::new(r"\.triage-queue__row--reviewed\b").expect("reviewed selector");
    let _ = slice_block(&body, &header)
        .expect("`.triage-queue__row--reviewed` rule must exist in queue.css");
}

#[test]
fn focus_helpers_round_trip_through_wrap() {
    // 5-row list. Forward sweep: 0 → 1 → … → 4 → 0. Reverse sweep
    // from row 0: 0 → 4 → 3 → … → 0. The wrap matches the Reddit
    // modqueue UX so a moderator never strands themselves at an edge.
    let len = 5_usize;
    let mut idx = 0_usize;
    for _ in 0..len {
        idx = next_focus(idx, len);
    }
    assert_eq!(idx, 0, "forward sweep over a full cycle returns to 0");

    // Reverse sweep, starting from 0 (so the first prev wraps to 4).
    let mut idx = 0_usize;
    for _ in 0..len {
        idx = prev_focus(idx, len);
    }
    assert_eq!(idx, 0, "reverse sweep over a full cycle returns to 0");
}

#[test]
fn keymap_suppression_catches_form_fields() {
    // The architect's pre-flight requires single-letter keys NOT to
    // fire while a moderator is typing reasoning. Mechanical guard:
    // form controls suppress, plain elements do not.
    assert!(target_is_editable("INPUT", None));
    assert!(target_is_editable("TEXTAREA", None));
    assert!(target_is_editable("DIV", Some("true")));
    assert!(!target_is_editable("BODY", None));
    assert!(!target_is_editable("LI", None));
}
