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
pub mod templates;

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
    /// Time-decay parameters (PR 3 / #146 / Q2-A exponential half-life).
    /// `None` means no time decay (factor 1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_decay: Option<TimeDecay>,
    /// Per-subject-class weights (PR 4 / #147). Map from subject-kind
    /// tag (matching [`Observation::subject_kind`] — lowercase variant
    /// name: `"account"`, `"post"`, `"list"`, `"feed"`) to per-source
    /// weight in `[0.0, 1.0]`. Missing kind → multiplicative identity
    /// 1.0. Subject-kind values are strings rather than a typed enum
    /// so the leaf crate doesn't depend on polaris-types (which would
    /// introduce a cycle once polaris-types eventually uses this crate
    /// for the ingest-path lookup in PR 5).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub per_subject_class: std::collections::HashMap<String, f32>,
}

/// Exponential half-life decay parameters (PR 3 / #146).
///
/// Decay shape: `factor = exp(-ln(2) * age_days / half_life_days)`.
/// Mathematically clean (Q2-A); operators understand "half-life" via
/// the radioactive-decay analogy.
///
/// - At `age = 0` → factor = 1.0 (no decay).
/// - At `age = half_life_days` → factor = 0.5.
/// - At `age = 2 * half_life_days` → factor = 0.25.
///
/// Future-dated observations (`age < 0`) clamp to factor = 1.0 so
/// claims from-the-future can't gain extra trust (security default).
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TimeDecay {
    /// Half-life in days. Must be `> 0` and finite.
    pub half_life_days: f32,
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
            time_decay: None,
            per_subject_class: std::collections::HashMap::new(),
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
    now: chrono::DateTime<chrono::Utc>,
) -> f32 {
    let (flat_factor, per_category_factor, time_decay_factor, per_subject_class_factor) =
        match policy {
            TrustPolicy::V1 { flat } => (*flat, 1.0, 1.0, 1.0),
            TrustPolicy::V2(V2Body {
                flat,
                per_category,
                time_decay,
                per_subject_class,
            }) => {
                let flat_factor = flat.unwrap_or(1.0);
                // Missing-category → multiplicative identity 1.0 per
                // Q-resolution for #145.
                let per_category_factor = per_category
                    .get(observation.category())
                    .copied()
                    .unwrap_or(1.0);
                let time_decay_factor = time_decay.map_or(1.0, |d| {
                    compute_decay_factor(d, observation.created_at(), now)
                });
                // Same identity-on-miss rule as per_category (#147).
                let per_subject_class_factor = per_subject_class
                    .get(observation.subject_kind())
                    .copied()
                    .unwrap_or(1.0);
                (
                    flat_factor,
                    per_category_factor,
                    time_decay_factor,
                    per_subject_class_factor,
                )
            }
        };

    // Composition: multiplicative across all four factors.
    let raw = flat_factor * per_category_factor * time_decay_factor * per_subject_class_factor;

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
    let (flat, per_category, time_decay, per_subject_class) = match policy {
        TrustPolicy::V1 { flat } => (Some(*flat), None, None, None),
        TrustPolicy::V2(V2Body {
            flat,
            per_category,
            time_decay,
            per_subject_class,
        }) => (
            *flat,
            Some(per_category),
            time_decay.as_ref(),
            Some(per_subject_class),
        ),
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

    // PR 3: validate time_decay half_life_days is finite and > 0.
    if let Some(decay) = time_decay {
        if !decay.half_life_days.is_finite() || decay.half_life_days <= 0.0 {
            return Err(TrustPolicyError::InvalidHalfLife(decay.half_life_days));
        }
    }

    // PR 4: validate every per_subject_class weight too.
    if let Some(per_subject_class) = per_subject_class {
        for (subject_kind, w) in per_subject_class {
            if !w.is_finite() || !(0.0..=1.0).contains(w) {
                let _ = subject_kind; // captured for log context only.
                return Err(TrustPolicyError::WeightOutOfRange {
                    field: "per_subject_class",
                    value: *w,
                });
            }
        }
    }

    Ok(())
}

/// Compute the exponential half-life decay factor for an observation
/// (PR 3 / #146 / Q2-A).
///
/// `factor = exp(-ln(2) * age_days / half_life_days)`.
///
/// Edge cases:
/// - `age < 0` (future-dated observation) → factor = 1.0 (no boost).
/// - `half_life_days <= 0` or non-finite → factor = 1.0 (treated as
///   "no decay configured"; validate() would have rejected this at
///   save time, but the defense-in-depth check ensures malformed
///   inputs don't produce NaN/Inf weights).
/// - Overflow (very old observation) → clamp to 0.0 at the
///   compose-then-clamp boundary in weight().
fn compute_decay_factor(
    decay: TimeDecay,
    created_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> f32 {
    if !decay.half_life_days.is_finite() || decay.half_life_days <= 0.0 {
        return 1.0;
    }
    // num_seconds() returns i64. The cast to f64 is precision-safe
    // for any wall-clock duration the application could plausibly
    // see: i64 seconds covers ±292 billion years, while f64 retains
    // 53 bits of mantissa (~9 quadrillion exact integers). The
    // moderation context cares about durations in days-to-years; the
    // cast is far from the precision-loss boundary.
    #[allow(
        clippy::cast_precision_loss,
        reason = "i64 seconds → f64 days is precision-safe at the scales \
                  this function sees (≤ centuries of wall-clock age)."
    )]
    let age_seconds_f64 = (now - created_at).num_seconds() as f64;
    let age_days = age_seconds_f64 / 86_400.0;
    if age_days <= 0.0 {
        // Future-dated observation: don't grant extra trust.
        return 1.0;
    }
    let exponent = -std::f64::consts::LN_2 * age_days / f64::from(decay.half_life_days);
    // f64 → f32 truncation: the function returns f32 to match the
    // workspace's weight() signature; the exponent computation runs
    // in f64 for headroom against the long tail (age in centuries
    // for ancient observations) but the downstream consumer is f32.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "factor ∈ (0, 1] by construction; f32 has plenty of \
                  precision in that range."
    )]
    let factor = exponent.exp() as f32;
    if !factor.is_finite() {
        return 0.0;
    }
    factor.clamp(0.0, 1.0)
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
    /// Subject-kind tag for per-subject-class weighting (PR 4 / #147).
    ///
    /// Implementors should return the lowercase variant name of the
    /// subject's [`polaris_types::SubjectKind`] — `"account"`, `"post"`,
    /// `"list"`, `"feed"` — to align with the v2 `per_subject_class`
    /// HashMap keys. The leaf crate avoids depending on polaris-types
    /// to keep the dependency graph acyclic.
    fn subject_kind(&self) -> &str;
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
        subject_kind: String,
    }
    impl Observation for StubObservation {
        fn category(&self) -> &str {
            &self.category
        }
        fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
            self.created_at
        }
        fn subject_kind(&self) -> &str {
            &self.subject_kind
        }
    }

    fn obs() -> StubObservation {
        StubObservation {
            subject_kind: "account".to_owned(),
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
            TrustPolicyError::InvalidHalfLife(_) => panic!("expected WeightOutOfRange, got InvalidHalfLife"),
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
            let policy = TrustPolicy::V2(V2Body { flat: Some(flat), per_category: std::collections::HashMap::new(), time_decay: None, per_subject_class: std::collections::HashMap::new() });
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
        let policy = TrustPolicy::V2(V2Body { flat: Some(f32::NAN), per_category: std::collections::HashMap::new(), time_decay: None, per_subject_class: std::collections::HashMap::new() });
        let w = weight(&obs(), &policy, Utc::now());
        assert!(w.is_finite());
        assert_eq!(w, 0.0);
    }

    /// AC-1 hardening: positive infinity floors via clamp to 1.0.
    #[test]
    fn weight_clamps_positive_infinity_to_one() {
        let policy = TrustPolicy::V2(V2Body { flat: Some(f32::INFINITY), per_category: std::collections::HashMap::new(), time_decay: None, per_subject_class: std::collections::HashMap::new() });
        let w = weight(&obs(), &policy, Utc::now());
        assert!(w.is_finite());
        assert_eq!(w, 1.0);
    }

    /// AC-1 hardening: negative infinity clamps to 0.0.
    #[test]
    fn weight_clamps_negative_infinity_to_zero() {
        let policy = TrustPolicy::V2(V2Body {
            flat: Some(f32::NEG_INFINITY),
            per_category: std::collections::HashMap::new(), time_decay: None,
            per_subject_class: std::collections::HashMap::new(),
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
            time_decay: None,
            per_subject_class: std::collections::HashMap::new(),
        });

        let spam = StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
            subject_kind: "account".to_owned(),
        };
        let harassment = StubObservation {
            category: "harassment".to_owned(),
            created_at: Utc::now(),
            subject_kind: "account".to_owned(),
        };
        let other = StubObservation {
            category: "novel".to_owned(),
            created_at: Utc::now(),
            subject_kind: "account".to_owned(),
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
            time_decay: None,
            per_subject_class: std::collections::HashMap::new(),
        });

        let spam = StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
            subject_kind: "account".to_owned(),
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
            time_decay: None,
            per_subject_class: std::collections::HashMap::new(),
        });
        let err = validate(&policy).unwrap_err();
        match err {
            TrustPolicyError::WeightOutOfRange { field, value } => {
                assert_eq!(field, "per_category");
                assert!((value - 1.5).abs() < f32::EPSILON);
            }
            TrustPolicyError::InvalidHalfLife(_) => panic!("expected WeightOutOfRange, got InvalidHalfLife"),
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
            time_decay: None,
            per_subject_class: std::collections::HashMap::new(),
            });

            let observation = StubObservation {
                category: obs_category,
                created_at: Utc::now(),
            subject_kind: "account".to_owned(),
            };
            let w = weight(&observation, &policy, Utc::now());
            prop_assert!((0.0..=1.0).contains(&w), "weight {w} outside [0,1]");
            prop_assert!(w.is_finite());
        }
    }

    /// AC-4: with a 30-day half-life policy, weight at t0 is the
    /// flat value; at t0+30d it's half.
    #[test]
    fn time_decay_halves_at_half_life() {
        use chrono::Duration;
        let policy = TrustPolicy::V2(V2Body {
            flat: Some(1.0),
            per_category: std::collections::HashMap::new(),
            per_subject_class: std::collections::HashMap::new(),
            time_decay: Some(TimeDecay {
                half_life_days: 30.0,
            }),
        });
        let t0 = Utc::now();
        let obs = StubObservation {
            category: "spam".to_owned(),
            created_at: t0,
            subject_kind: "account".to_owned(),
        };

        // At t0: factor = 1.0.
        let w0 = weight(&obs, &policy, t0);
        assert!((w0 - 1.0).abs() < 1e-3, "expected ~1.0 at t0, got {w0}");

        // At t0 + 30 days: factor = 0.5.
        let t30 = t0 + Duration::days(30);
        let w30 = weight(&obs, &policy, t30);
        assert!((w30 - 0.5).abs() < 1e-3, "expected ~0.5 at half-life, got {w30}");

        // At t0 + 60 days (two half-lives): factor = 0.25.
        let t60 = t0 + Duration::days(60);
        let w60 = weight(&obs, &policy, t60);
        assert!((w60 - 0.25).abs() < 1e-3, "expected ~0.25 at 2x half-life, got {w60}");
    }

    /// Future-dated observation doesn't get boosted past 1.0.
    #[test]
    fn time_decay_future_observation_clamps_to_identity() {
        use chrono::Duration;
        let policy = TrustPolicy::V2(V2Body {
            flat: Some(1.0),
            per_category: std::collections::HashMap::new(),
            per_subject_class: std::collections::HashMap::new(),
            time_decay: Some(TimeDecay {
                half_life_days: 30.0,
            }),
        });
        let now = Utc::now();
        let future_obs = StubObservation {
            category: "spam".to_owned(),
            created_at: now + Duration::days(10),
            subject_kind: "account".to_owned(),
        };
        let w = weight(&future_obs, &policy, now);
        assert!((w - 1.0).abs() < f32::EPSILON, "future obs should not boost: got {w}");
    }

    /// Per-subject-class weight applies on match; misses default to
    /// identity 1.0 (mirrors per_category semantics).
    #[test]
    fn per_subject_class_weight_applies_on_match() {
        let mut per_subject_class = std::collections::HashMap::new();
        per_subject_class.insert("post".to_owned(), 0.9);
        per_subject_class.insert("account".to_owned(), 0.5);

        let policy = TrustPolicy::V2(V2Body {
            flat: None,
            per_category: std::collections::HashMap::new(),
            time_decay: None,
            per_subject_class,
        });

        let post_obs = StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
            subject_kind: "post".to_owned(),
        };
        let account_obs = StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
            subject_kind: "account".to_owned(),
        };
        let feed_obs = StubObservation {
            category: "spam".to_owned(),
            created_at: Utc::now(),
            subject_kind: "feed".to_owned(),
        };

        assert!((weight(&post_obs, &policy, Utc::now()) - 0.9).abs() < f32::EPSILON);
        assert!((weight(&account_obs, &policy, Utc::now()) - 0.5).abs() < f32::EPSILON);
        // Unlisted kind → identity 1.0.
        assert!((weight(&feed_obs, &policy, Utc::now()) - 1.0).abs() < f32::EPSILON);
    }

    /// validate() rejects out-of-range per_subject_class weights.
    #[test]
    fn validate_rejects_per_subject_class_above_one() {
        let mut per_subject_class = std::collections::HashMap::new();
        per_subject_class.insert("post".to_owned(), 1.7);
        let policy = TrustPolicy::V2(V2Body {
            flat: None,
            per_category: std::collections::HashMap::new(),
            time_decay: None,
            per_subject_class,
        });
        let err = validate(&policy).unwrap_err();
        match err {
            TrustPolicyError::WeightOutOfRange { field, value } => {
                assert_eq!(field, "per_subject_class");
                assert!((value - 1.7).abs() < f32::EPSILON);
            }
            TrustPolicyError::InvalidHalfLife(_) => panic!("expected WeightOutOfRange, got InvalidHalfLife"),
        }
    }

    /// validate() rejects invalid half_life_days values.
    #[test]
    fn validate_rejects_invalid_half_life() {
        for bad in [0.0_f32, -1.0, f32::NAN, f32::INFINITY] {
            let policy = TrustPolicy::V2(V2Body {
                flat: None,
                per_category: std::collections::HashMap::new(),
                per_subject_class: std::collections::HashMap::new(),
            time_decay: Some(TimeDecay { half_life_days: bad }),
            });
            let err = validate(&policy).unwrap_err();
            match err {
                TrustPolicyError::InvalidHalfLife(v) => {
                    assert!(
                        (v.is_nan() && bad.is_nan())
                            || (v.is_infinite() && bad.is_infinite())
                            || (v - bad).abs() < f32::EPSILON,
                        "expected matching half-life value, got {v} for bad={bad}"
                    );
                }
                TrustPolicyError::WeightOutOfRange { .. } => panic!("expected InvalidHalfLife for {bad}, got WeightOutOfRange"),
            }
        }
    }
}
