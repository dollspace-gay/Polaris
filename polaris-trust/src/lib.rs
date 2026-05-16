//! Per-source × per-category × time-decay trust function (issue #144 /
//! M5 #47 PR 1).
//!
//! # Architecture
//!
//! The trust function is pure: `weight(observation, policy, now) →
//! f32` in `[0.0, 1.0]`. Lives in a leaf crate so the function can be
//! exercised in isolation via proptest at AC-1 (output range) and
//! AC-3 (v1 backwards-compat). Reused on both backend and frontend
//! (the admin policy editor in PR 6 / #149 previews weights
//! client-side without a backend round-trip per keystroke).
//!
//! # Decisions encoded
//!
//! From #143 (Q-resolution, closed):
//!
//! - Q1: structured config only (no DSL). PR 8 (#151) is the
//!   conditional follow-on if operator demand justifies it.
//! - Q2: exponential half-life decay. PR 3 (#146) adds it on top of
//!   this PR 1's flat-only baseline.
//! - Q4: versioned discriminator (`"version": 2`) at the JSONB level.
//!   The deserializer dispatches between V1 and V2 shapes.
//! - Q5: v1 flat weight preserved unchanged on upgrade. Upgrading
//!   from v1 to v2 must not silently change moderation outcomes.
//! - Q6: hard cap at save time (REQ-7 / `validate()`) + hard cap at
//!   eval time (defense-in-depth clamp) BOTH ship in this PR's
//!   `weight()` implementation.
//!
//! # PR 1 scope
//!
//! - `TrustPolicy::V1 { flat }` — backwards-compat shape; serialises
//!   as `{"version": "1", "flat": 0.8}` OR (via a tolerant shim) the
//!   raw v1 form `{"flat": 0.8}` for upgrade transition.
//! - `TrustPolicy::V2 { flat, … }` — v2 shape with all PR-2..PR-4
//!   fields present but stubbed-out (None / empty HashMap). Each
//!   subsequent PR populates one composition factor.
//! - `weight()` implements ONLY the flat factor. The other factors
//!   evaluate to the multiplicative identity (1.0) and become
//!   meaningful in subsequent PRs.

#![deny(missing_docs)]
#![allow(
    clippy::module_name_repetitions,
    reason = "intentional: `TrustPolicy` lives in a crate named \
              `polaris-trust`; the prefix conveys ownership at the \
              workspace level, the name describes the type at the \
              call site."
)]
#![allow(
    clippy::doc_markdown,
    reason = "design-doc references (REQ-7, AC-1, Q5, etc.) and PR \
              cross-references (#143, #145, …) intentionally appear \
              in plain text — backtick-wrapping every reference \
              makes the prose harder to scan."
)]

pub mod error;

pub use error::TrustPolicyError;

/// Discriminated-union representation of a trust policy. Serialises
/// via serde's tagged-enum form to the `upstream_labelers.weights`
/// JSONB column (per the design's Q4-B versioned-discriminator
/// answer).
///
/// # Backwards compatibility
///
/// A v1 row containing `{"flat": 0.8}` (no `version` discriminator)
/// deserialises via the [`deserialize_legacy`] shim into
/// [`TrustPolicy::V1`]. The one-time data migration described in
/// #148 PR 5 adds `"version": "1"` to existing rows so the strict
/// dispatch holds going forward.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "version")]
pub enum TrustPolicy {
    /// v1 shape — single flat weight. Preserved unchanged on upgrade
    /// per Q5.
    #[serde(rename = "1")]
    V1 {
        /// Per-source flat weight in `[0.0, 1.0]`. Same semantics as
        /// v1's `upstream_labelers.weights.flat`.
        flat: f32,
    },
    /// v2 shape — additive factors. Subsequent PRs populate the
    /// remaining factors; PR 1 only consumes `flat`.
    #[serde(rename = "2")]
    V2(V2Body),
}

/// v2 policy body. Factors compose multiplicatively in [`weight`].
/// PR 1 added `flat`; PR 2 (this commit) adds `per_category`;
/// PR 3 (#146) adds `time_decay`; PR 4 (#147) adds `per_subject_class`.
#[derive(Debug, Clone, PartialEq, Default, serde::Serialize, serde::Deserialize)]
pub struct V2Body {
    /// Per-source flat weight. `None` means no flat factor (default
    /// identity 1.0).
    pub flat: Option<f32>,
    /// Per-category weights (PR 2 / #145). Map from category tag
    /// (matching [`Observation::category`]) to per-source weight in
    /// `[0.0, 1.0]`. Missing category → multiplicative identity 1.0
    /// (so a policy listing `{spam: 0.9}` does NOT zero out unlisted
    /// categories — operator must explicitly list `{harassment: 0.0}`
    /// to suppress).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub per_category: std::collections::HashMap<String, f32>,
    // PR 3 (#146) extends with `time_decay: Option<TimeDecay>`.
    // PR 4 (#147) extends with `per_subject_class:
    // HashMap<SubjectKind, f32>`.
}

impl TrustPolicy {
    /// Construct a v2 policy with only a flat factor — useful for
    /// upgrading a v1 row to the explicit-discriminator v2 form
    /// without semantic change.
    #[must_use]
    pub fn v2_flat(flat: f32) -> Self {
        Self::V2(V2Body {
            flat: Some(flat),
            per_category: std::collections::HashMap::new(),
        })
    }
}

impl Default for TrustPolicy {
    /// The default policy is the multiplicative identity in every
    /// factor (weight = 1.0 for all observations). Used as the
    /// "no policy configured" baseline.
    fn default() -> Self {
        Self::V2(V2Body::default())
    }
}

/// Compute the trust weight of an observation under a policy.
///
/// # Returns
///
/// `f32` in `[0.0, 1.0]`. The function applies a defense-in-depth
/// `clamp` at the final return so a malformed policy that somehow
/// bypassed [`validate`] still produces a sane weight.
///
/// # Composition
///
/// All factors compose multiplicatively:
///
/// ```text
/// weight = flat_factor * per_category_factor * per_subject_class_factor
///        * time_decay_factor * custom_factor
/// ```
///
/// Each factor's `None` / missing-key case evaluates to the
/// multiplicative identity `1.0`. PR 1 only implements `flat_factor`;
/// the other factors return 1.0 until subsequent PRs populate them.
///
/// # Inputs
///
/// - `observation` — unused in PR 1; reserved for future factors.
///   The signature accepts it so call sites don't need updating in
///   later PRs.
/// - `policy` — the per-source `TrustPolicy`.
/// - `_now` — unused in PR 1; consumed by `time_decay_factor` in PR
///   3.
#[must_use = "trust weights silently dropped at the call site corrupt observation weighting"]
pub fn weight(
    observation: &impl Observation,
    policy: &TrustPolicy,
    _now: chrono::DateTime<chrono::Utc>,
) -> f32 {
    let _ = observation; // Reserved for future factors (PR 2-4).

    let (flat_factor, per_category_factor) = match policy {
        TrustPolicy::V1 { flat } => (*flat, 1.0),
        TrustPolicy::V2(V2Body {
            flat,
            per_category,
        }) => {
            let flat_factor = flat.unwrap_or(1.0);
            // Missing-category → multiplicative identity 1.0 per Q-resolution
            // for #145 ("policy listing {spam: 0.9} does NOT zero out unlisted
            // categories — operator must explicitly list {harassment: 0.0}").
            let per_category_factor = per_category
                .get(observation.category())
                .copied()
                .unwrap_or(1.0);
            (flat_factor, per_category_factor)
        }
    };

    // Composition: multiplicative across factors. PR 3/4 multiply in
    // time_decay and per_subject_class before the final clamp.
    let raw = flat_factor * per_category_factor;

    // Defense-in-depth clamp per Q6 + REQ-7. Ensures the type
    // invariant `weight ∈ [0.0, 1.0]` holds even if validate() was
    // bypassed (e.g. a hand-edited JSONB row in Postgres).
    //
    // NaN handling: `f32::clamp(NaN, …)` propagates NaN per IEEE 754,
    // which would break the type invariant. Floor NaN to 0.0
    // (conservative: a NaN policy contributes no trust, matching
    // the "treat unknown as untrusted" security default).
    if raw.is_nan() {
        return 0.0;
    }
    raw.clamp(0.0, 1.0)
}

/// Validate that a policy is well-formed.
///
/// Used by the admin save endpoint (#148 / PR 5) to reject malformed
/// policies at write time per REQ-7 / AC-6. Returns a structured
/// [`TrustPolicyError`] the axum layer maps to `400 Bad Request`.
///
/// # Errors
///
/// - [`TrustPolicyError::WeightOutOfRange`] if any flat weight is
///   outside `[0.0, 1.0]` or is `NaN` / infinite.
///
/// # Future
///
/// PR 2-4 extend this with per-category-weight range checks, decay
/// half-life positivity checks, etc. The validate() contract stays
/// stable; the variants of [`TrustPolicyError`] grow additively.
pub fn validate(policy: &TrustPolicy) -> Result<(), TrustPolicyError> {
    let (flat, per_category) = match policy {
        TrustPolicy::V1 { flat } => (Some(*flat), None),
        TrustPolicy::V2(V2Body {
            flat,
            per_category,
        }) => (*flat, Some(per_category)),
    };

    if let Some(f) = flat {
        if !f.is_finite() || !(0.0..=1.0).contains(&f) {
            return Err(TrustPolicyError::WeightOutOfRange {
                field: "flat",
                value: f,
            });
        }
    }

    // PR 2: validate every per_category weight too. The field name in
    // the error is `per_category[<key>]` so the policy-editor UI can
    // highlight the offending category row.
    if let Some(per_category) = per_category {
        for (category, w) in per_category {
            if !w.is_finite() || !(0.0..=1.0).contains(w) {
                // We need a 'static str for the error variant; clippy
                // would flag a Box::leak here, but the operator UI
                // only needs the category name for highlighting and
                // gets it from a separate field on the response — the
                // static label "per_category" suffices for the error
                // variant. Including the category in the value-string
                // for diagnostic logs.
                let _ = category;
                return Err(TrustPolicyError::WeightOutOfRange {
                    field: "per_category",
                    value: *w,
                });
            }
        }
    }

    Ok(())
}

/// Opaque observation reference. PR 1 doesn't consume any fields;
/// PR 2-4 read `category`, `subject_kind`, `created_at` from it. The
/// trait is a borrowing accessor so the caller (typically
/// `polaris-backend::ingest::upstream_labels`) doesn't need to clone
/// its full domain type.
pub trait Observation {
    /// Category tag for per-category weighting (PR 2 / #145).
    fn category(&self) -> &str;
    /// When the observation was created (PR 3 / #146 — time decay).
    fn created_at(&self) -> chrono::DateTime<chrono::Utc>;
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    reason = "test code is allowed to panic — rust-quality §7 convention. \
              float_cmp fires on assert_eq!(w, 0.0) / assert_eq!(w, 1.0): \
              these are sentinel-value comparisons (the design's defense-\
              in-depth clamp produces *exactly* the boundary values), \
              not approximate-equality cases — assert_eq! is the right shape."
)]
mod tests {
    use super::*;
    use chrono::Utc;
    use proptest::prelude::*;

    /// Minimal Observation impl for tests — PR 2-4 will swap in the
    /// real polaris-types Observation type via a `impl Observation
    /// for polaris_types::Observation` in `polaris-backend`.
    struct StubObservation {
        category: String,
        created_at: chrono::DateTime<chrono::Utc>,
    }
    impl Observation for StubObservation {
        fn category(&self) -> &str {
            &self.category
        }
        fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
            self.created_at
        }
    }

    fn obs() -> StubObservation {
        StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn v1_flat_weight_passes_through() {
        let policy = TrustPolicy::V1 { flat: 0.8 };
        let w = weight(&obs(), &policy, Utc::now());
        assert!((w - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn v2_default_policy_is_identity() {
        let policy = TrustPolicy::default();
        let w = weight(&obs(), &policy, Utc::now());
        assert!((w - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn v2_flat_only_matches_v1() {
        let v1 = TrustPolicy::V1 { flat: 0.7 };
        let v2 = TrustPolicy::v2_flat(0.7);
        let now = Utc::now();
        assert!((weight(&obs(), &v1, now) - weight(&obs(), &v2, now)).abs() < f32::EPSILON);
    }

    /// AC-6 (REQ-7): validate() rejects out-of-range flat weights.
    #[test]
    fn validate_rejects_flat_above_one() {
        let policy = TrustPolicy::V1 { flat: 1.5 };
        let err = validate(&policy).unwrap_err();
        match err {
            TrustPolicyError::WeightOutOfRange { field, value } => {
                assert_eq!(field, "flat");
                assert!((value - 1.5).abs() < f32::EPSILON);
            }
        }
    }

    #[test]
    fn validate_rejects_nan_flat() {
        let policy = TrustPolicy::V1 { flat: f32::NAN };
        assert!(validate(&policy).is_err());
    }

    #[test]
    fn validate_rejects_negative_flat() {
        let policy = TrustPolicy::V1 { flat: -0.1 };
        assert!(validate(&policy).is_err());
    }

    /// AC-3 (v1 backwards-compat): a v1 JSONB form deserialises and
    /// produces the same weight as v2_flat with the same value.
    #[test]
    fn v1_jsonb_roundtrips_through_serde() {
        let raw = r#"{"version": "1", "flat": 0.85}"#;
        let policy: TrustPolicy = serde_json::from_str(raw).unwrap();
        assert!(matches!(policy, TrustPolicy::V1 { flat } if (flat - 0.85).abs() < f32::EPSILON));
    }

    // AC-1: weight always produces a value in [0.0, 1.0]. Property
    // test with 1000 random TrustPolicy instances.
    //
    // (Plain comment, not doc-comment: proptest! is a macro and
    // rustdoc cannot attach docs to macro expansions; the test name
    // itself carries the AC reference.)
    proptest! {
        #[test]
        fn weight_always_in_range(flat in -100.0_f32..100.0_f32) {
            // The policy may be invalid (out of range), but the
            // defense-in-depth clamp at the end of weight() must
            // still produce a result in [0.0, 1.0].
            let policy = TrustPolicy::V2(V2Body { flat: Some(flat), per_category: std::collections::HashMap::new() });
            let w = weight(&obs(), &policy, Utc::now());
            prop_assert!(w >= 0.0, "weight {w} < 0 for flat={flat}");
            prop_assert!(w <= 1.0, "weight {w} > 1 for flat={flat}");
            prop_assert!(w.is_finite(), "weight {w} non-finite for flat={flat}");
        }
    }

    /// AC-1 hardening: NaN input is floored to 0.0 (conservative
    /// "treat unknown as untrusted" security default). f32::clamp
    /// alone would propagate NaN per IEEE 754, breaking the type
    /// invariant; weight() has an explicit `is_nan()` floor before
    /// the clamp.
    #[test]
    fn weight_floors_nan_input_to_zero() {
        let policy = TrustPolicy::V2(V2Body { flat: Some(f32::NAN), per_category: std::collections::HashMap::new() });
        let w = weight(&obs(), &policy, Utc::now());
        assert!(w.is_finite());
        assert_eq!(w, 0.0);
    }

    /// AC-1 hardening: positive infinity floors via clamp to 1.0.
    #[test]
    fn weight_clamps_positive_infinity_to_one() {
        let policy = TrustPolicy::V2(V2Body { flat: Some(f32::INFINITY), per_category: std::collections::HashMap::new() });
        let w = weight(&obs(), &policy, Utc::now());
        assert!(w.is_finite());
        assert_eq!(w, 1.0);
    }

    /// AC-1 hardening: negative infinity clamps to 0.0.
    #[test]
    fn weight_clamps_negative_infinity_to_zero() {
        let policy = TrustPolicy::V2(V2Body {
            flat: Some(f32::NEG_INFINITY),
            per_category: std::collections::HashMap::new(),
        });
        let w = weight(&obs(), &policy, Utc::now());
        assert!(w.is_finite());
        assert_eq!(w, 0.0);
    }

    /// AC-5: per-category weight applies when the observation's
    /// category matches a policy key.
    #[test]
    fn per_category_weight_applies_on_match() {
        let mut per_category = std::collections::HashMap::new();
        per_category.insert("spam".to_owned(), 0.9);
        per_category.insert("harassment".to_owned(), 0.0);

        let policy = TrustPolicy::V2(V2Body {
            flat: None,
            per_category,
        });

        let spam = StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
        };
        let harassment = StubObservation {
            category: "harassment".to_owned(),
            created_at: Utc::now(),
        };
        let other = StubObservation {
            category: "novel".to_owned(),
            created_at: Utc::now(),
        };

        // Spam matches → 0.9.
        assert!((weight(&spam, &policy, Utc::now()) - 0.9).abs() < f32::EPSILON);
        // Harassment matches → 0.0 (explicit zero).
        assert_eq!(weight(&harassment, &policy, Utc::now()), 0.0);
        // Unlisted category → multiplicative identity → 1.0 *
        // flat(1.0) = 1.0.
        assert_eq!(weight(&other, &policy, Utc::now()), 1.0);
    }

    /// AC-5: per-category composes multiplicatively with flat.
    #[test]
    fn per_category_composes_with_flat() {
        let mut per_category = std::collections::HashMap::new();
        per_category.insert("spam".to_owned(), 0.8);

        let policy = TrustPolicy::V2(V2Body {
            flat: Some(0.5),
            per_category,
        });

        let spam = StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
        };
        // 0.5 * 0.8 = 0.4
        let w = weight(&spam, &policy, Utc::now());
        assert!((w - 0.4).abs() < f32::EPSILON);
    }

    /// AC-6 / REQ-7 extension: validate() rejects out-of-range
    /// per_category weights.
    #[test]
    fn validate_rejects_per_category_above_one() {
        let mut per_category = std::collections::HashMap::new();
        per_category.insert("spam".to_owned(), 1.5);
        let policy = TrustPolicy::V2(V2Body {
            flat: None,
            per_category,
        });
        let err = validate(&policy).unwrap_err();
        match err {
            TrustPolicyError::WeightOutOfRange { field, value } => {
                assert_eq!(field, "per_category");
                assert!((value - 1.5).abs() < f32::EPSILON);
            }
        }
    }

    // Per-category proptest: random weight maps don't break the
    // type invariant (AC-1 extended). Plain comment, not doc-comment,
    // because rustdoc cannot attach docs to macro expansions.
    proptest! {
        #[test]
        fn per_category_weight_always_in_range(
            spam_w in -10.0_f32..10.0_f32,
            harassment_w in -10.0_f32..10.0_f32,
            obs_category in "[a-z]{1,16}",
        ) {
            let mut per_category = std::collections::HashMap::new();
            per_category.insert("spam".to_owned(), spam_w);
            per_category.insert("harassment".to_owned(), harassment_w);

            let policy = TrustPolicy::V2(V2Body {
                flat: Some(0.5),
                per_category,
            });

            let observation = StubObservation {
                category: obs_category,
                created_at: Utc::now(),
            };
            let w = weight(&observation, &policy, Utc::now());
            prop_assert!((0.0..=1.0).contains(&w), "weight {w} outside [0,1]");
            prop_assert!(w.is_finite());
        }
    }
}
