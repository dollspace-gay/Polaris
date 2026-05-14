//! Routing-relevant moderator + category types.
//!
//! `design.md` §5.4 — the triage router chooses a moderator (or refuses)
//! based on **category required-training**, **moderator specialty**, **calibration
//! state**, and **exposure budget**. This module carries the typed inputs that
//! the routing engine in `polaris-backend` consumes.
//!
//! # Why separate from [`crate::report::ReportCategory`]
//!
//! `ReportCategory` is intentionally a free-form string newtype: ATProto
//! report categories evolve faster than schema migrations, so the wire form
//! is preserved verbatim and validated at the API boundary. Routing, in
//! contrast, must reason over a **closed set** of categories with stable
//! semantics — "CSAM" must always mean the specialist-training-required
//! variant, regardless of whether the wire string is `csam`, `child-abuse`,
//! or some future synonym. [`RoutingCategory`] is therefore the canonical
//! routing-time discriminator; the [`RoutingCategory::from_wire`] helper maps
//! the open string set to the closed routing set.

use std::collections::HashSet;

/// Routing-time category discriminator.
///
/// A **closed** enumeration of the categories the router knows how to handle.
/// See module-level docs for why this is separate from the wire-flexible
/// [`crate::report::ReportCategory`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RoutingCategory {
    /// Child Sexual Abuse Material.
    ///
    /// Requires specialist-trained moderators (`csam_trained = true`); if
    /// none are available the router refuses and emits a forwarding
    /// directive to NCMEC + Bluesky per `design.md` §5.4.
    Csam,
    /// Child Sexual Exploitation Material — non-image-hash CSE content
    /// (grooming, sextortion). Same routing rules as [`Self::Csam`].
    Csem,
    /// Targeted harassment / brigading.
    Harassment,
    /// Spam / mass low-effort posting.
    Spam,
    /// Impersonation of an account or organization.
    Impersonation,
    /// DMCA / copyright complaint.
    Copyright,
    /// Misinformation / civic-integrity claim.
    Misinformation,
    /// Catch-all: anything that doesn't match the above.
    Other,
}

impl RoutingCategory {
    /// Stable lowercase-snake wire form.
    ///
    /// Used by the repo / log / API boundaries when serialising the routing
    /// category to a TEXT column or a JSON envelope. Stable across schema
    /// migrations.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Csam => "csam",
            Self::Csem => "csem",
            Self::Harassment => "harassment",
            Self::Spam => "spam",
            Self::Impersonation => "impersonation",
            Self::Copyright => "copyright",
            Self::Misinformation => "misinformation",
            Self::Other => "other",
        }
    }

    /// Parse a [`RoutingCategory`] from its wire form.
    ///
    /// Returns `None` for unknown strings. Callers that need a fallback for
    /// unknown values should map `None` to [`Self::Other`] explicitly so the
    /// fallback choice is visible at the call site.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "csam" => Some(Self::Csam),
            "csem" => Some(Self::Csem),
            "harassment" => Some(Self::Harassment),
            "spam" => Some(Self::Spam),
            "impersonation" => Some(Self::Impersonation),
            "copyright" => Some(Self::Copyright),
            "misinformation" => Some(Self::Misinformation),
            "other" => Some(Self::Other),
            _ => None,
        }
    }

    /// Whether this category requires a moderator with the
    /// `csam_trained = true` flag.
    ///
    /// True for [`Self::Csam`] and [`Self::Csem`] per `design.md` §5.4;
    /// false for every other variant.
    #[must_use]
    pub const fn requires_specialist_training(self) -> bool {
        matches!(self, Self::Csam | Self::Csem)
    }
}

impl std::fmt::Display for RoutingCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-moderator exposure budget for graphic content (design.md §5.7).
///
/// Newtype wrapper around `u32` so the routing engine cannot accidentally
/// confuse it with `current_load` or any other count. The value is "remaining
/// graphic-content units this moderator may be routed today"; zero means the
/// moderator is at their daily cap and the router must skip them.
///
/// Defaults to [`ExposureBudget::UNLIMITED`] — the placeholder the router
/// uses until issue #23 lands the per-moderator daily-cap accounting that
/// computes the real value.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct ExposureBudget(pub u32);

impl ExposureBudget {
    /// Sentinel meaning "no cap" — used until #23 lands real accounting.
    pub const UNLIMITED: Self = Self(u32::MAX);

    /// Construct an [`ExposureBudget`] from a unit count.
    #[must_use]
    pub const fn new(remaining: u32) -> Self {
        Self(remaining)
    }

    /// Unwrap to the raw `u32` remaining count.
    #[must_use]
    pub const fn into_inner(self) -> u32 {
        self.0
    }

    /// `true` iff the moderator has no remaining budget.
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.0 == 0
    }
}

impl Default for ExposureBudget {
    fn default() -> Self {
        Self::UNLIMITED
    }
}

impl std::fmt::Display for ExposureBudget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == Self::UNLIMITED {
            f.write_str("unlimited")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Moderator specialty / calibration / exposure snapshot consumed by the
/// routing engine.
///
/// All four fields drive the [`crate::routing::RoutingCategory`]-aware
/// decision in `polaris-backend::routing::route` (design.md §5.4):
///
/// - `csam_trained` — gates CSAM/CSEM eligibility.
/// - `calibration_complete` — if false, the moderator may only see
///   easy-mode categories and every decision enters shadow review.
/// - `specialties` — preferred routing pool for matching categories;
///   moderators outside this set are still eligible as generalists.
/// - `exposure_budget_remaining` — design.md §5.7; routing skips a
///   moderator with [`ExposureBudget::is_exhausted`] returning true.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModeratorSpecialty {
    /// Whether this moderator has completed CSAM training.
    pub csam_trained: bool,
    /// Whether this moderator has cleared the calibration threshold.
    pub calibration_complete: bool,
    /// Categories this moderator is a recognised specialist in.
    pub specialties: HashSet<RoutingCategory>,
    /// Remaining graphic-content exposure budget for the current period.
    pub exposure_budget_remaining: ExposureBudget,
}

impl Default for ModeratorSpecialty {
    fn default() -> Self {
        Self {
            csam_trained: false,
            calibration_complete: false,
            specialties: HashSet::new(),
            exposure_budget_remaining: ExposureBudget::UNLIMITED,
        }
    }
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

    #[test]
    fn routing_category_round_trips_through_wire_form() {
        for c in [
            RoutingCategory::Csam,
            RoutingCategory::Csem,
            RoutingCategory::Harassment,
            RoutingCategory::Spam,
            RoutingCategory::Impersonation,
            RoutingCategory::Copyright,
            RoutingCategory::Misinformation,
            RoutingCategory::Other,
        ] {
            assert_eq!(RoutingCategory::from_wire(c.as_str()), Some(c));
        }
    }

    #[test]
    fn routing_category_rejects_unknown_wire_form() {
        assert!(RoutingCategory::from_wire("MOdErAtor").is_none());
        assert!(RoutingCategory::from_wire("").is_none());
    }

    #[test]
    fn requires_specialist_training_is_true_for_csam_csem_only() {
        assert!(RoutingCategory::Csam.requires_specialist_training());
        assert!(RoutingCategory::Csem.requires_specialist_training());
        for c in [
            RoutingCategory::Harassment,
            RoutingCategory::Spam,
            RoutingCategory::Impersonation,
            RoutingCategory::Copyright,
            RoutingCategory::Misinformation,
            RoutingCategory::Other,
        ] {
            assert!(!c.requires_specialist_training(), "{c:?} should not");
        }
    }

    #[test]
    fn exposure_budget_default_is_unlimited() {
        assert_eq!(ExposureBudget::default(), ExposureBudget::UNLIMITED);
        assert!(!ExposureBudget::default().is_exhausted());
    }

    #[test]
    fn exposure_budget_zero_is_exhausted() {
        assert!(ExposureBudget::new(0).is_exhausted());
        assert!(!ExposureBudget::new(1).is_exhausted());
    }

    #[test]
    fn exposure_budget_display_distinguishes_unlimited() {
        assert_eq!(ExposureBudget::UNLIMITED.to_string(), "unlimited");
        assert_eq!(ExposureBudget::new(5).to_string(), "5");
    }
}
