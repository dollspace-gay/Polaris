//! Policy-reference allow-list for the action submission endpoint.
//!
//! The submit-action handler validates every `policy_refs` entry against
//! [`KNOWN_POLICY_REFS`] before persisting the row. Submitting an action
//! without a recognised policy clause is rejected at the API edge so the
//! audit trail (design.md §5.5) cites only enumerable policies.
//!
//! This list is a **placeholder**. Issue #3 / M3 will replace it with a
//! configuration-driven policy registry that the operator curates per
//! deployment; the contract of "every action cites at least one known policy"
//! survives that refactor.

/// Known policy clause identifiers. An action's `policy_refs` must be
/// non-empty and every entry must appear in this slice.
///
/// The string form is `polaris.<topic>` for the placeholder set; M3 will
/// migrate to operator-defined identifiers (e.g.
/// `community-guidelines.harassment.v3`). Tests pin the exact wire strings
/// so a regression that silently rewords or drops an entry is caught.
pub const KNOWN_POLICY_REFS: &[&str] = &[
    "polaris.harassment",
    "polaris.spam",
    "polaris.csam",
    "polaris.impersonation",
    "polaris.copyright",
];

/// Returns `true` when `value` is a recognised policy reference.
///
/// Linear scan of [`KNOWN_POLICY_REFS`]; the list is fewer than ten entries
/// today, so the constant factor is negligible compared to a `HashSet` build.
#[must_use]
pub fn is_known_policy_ref(value: &str) -> bool {
    KNOWN_POLICY_REFS.contains(&value)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn known_set_matches_design_placeholder() {
        // Pin the exact wire strings. M3 will rotate this set; this test is
        // the deliberate review gate that forces the rotation to be
        // intentional rather than accidental.
        assert_eq!(
            KNOWN_POLICY_REFS,
            &[
                "polaris.harassment",
                "polaris.spam",
                "polaris.csam",
                "polaris.impersonation",
                "polaris.copyright",
            ]
        );
    }

    #[test]
    fn is_known_accepts_listed_entries() {
        for entry in KNOWN_POLICY_REFS {
            assert!(is_known_policy_ref(entry), "expected {entry} to be known");
        }
    }

    #[test]
    fn is_known_rejects_unlisted_entries() {
        assert!(!is_known_policy_ref(""));
        assert!(!is_known_policy_ref("polaris.unknown"));
        assert!(!is_known_policy_ref("POLARIS.HARASSMENT")); // case-sensitive
    }
}
