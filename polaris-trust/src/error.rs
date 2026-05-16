//! Error type for the [`crate::TrustPolicy`] save / validate path
//! (issue #144 / M5 #47 PR 1).
//!
//! The variants are intentionally narrow + structured so the admin
//! save endpoint (#148 / PR 5) can return them as `400 Bad Request`
//! responses with diagnostic context the operator UI can render
//! inline.
//!
//! Subsequent PRs extend this enum additively as new factors land:
//!
//! - PR 2 (#145): per-category weights → additional `WeightOutOfRange`
//!   cases under the `per_category[<category>]` path.
//! - PR 3 (#146): time decay → `InvalidHalfLife(f32)`.
//! - PR 4 (#147): per-subject-class weights → additional out-of-range
//!   cases under `per_subject_class[<kind>]`.

use thiserror::Error;

/// Validation error for a [`crate::TrustPolicy`].
///
/// Returned by [`crate::validate`] at policy-save time; the admin
/// endpoint surfaces this as `400 Bad Request` with the structured
/// fields so the policy-editor UI can highlight the offending field.
#[derive(Debug, Error, PartialEq)]
pub enum TrustPolicyError {
    /// A weight field is outside the legal `[0.0, 1.0]` range, or is
    /// `NaN` / infinite. `field` names the path
    /// (e.g. `"flat"`, `"per_category"`); `value` is the offending float.
    #[error("weight `{field}` out of range: {value} (must be finite in [0.0, 1.0])")]
    WeightOutOfRange {
        /// Logical path of the offending field.
        field: &'static str,
        /// The bad value.
        value: f32,
    },

    /// TimeDecay::half_life_days is not finite, or is `<= 0` (PR 3 / #146).
    #[error("invalid time-decay half_life_days: {0} (must be finite and > 0)")]
    InvalidHalfLife(f32),
}
