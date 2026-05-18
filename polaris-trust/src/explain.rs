//! [`explain`] — decompose a weight computation into named factors
//! (issue #150 / M5 #47 PR 7).
//!
//! Powers two consumers with one source of truth:
//!
//! - The `polaris trust-policy explain <obs_id>` admin CLI (a future
//!   bin that wires into polaris-backend; this module ships the
//!   pure-logic explain function, not the CLI itself — that bin lives
//!   in polaris-backend where it has DB access to look up observations
//!   by ID).
//! - The case-view UI's per-observation "why is this weighted at
//!   X?" affordance (#149 PR 6 preview UI shares this Decomposition
//!   shape via serde).
//!
//! Serializable so the admin CLI's `--format json` and the case-view
//! API both work off the same wire shape.

use serde::{Deserialize, Serialize};

use crate::{Observation, TrustPolicy, V2Body, compute_decay_factor};

/// Per-factor breakdown of a weight computation.
///
/// All factor fields are the multiplicative contribution before the
/// final defense-in-depth clamp. `final_weight` is the post-clamp
/// value — the same number [`crate::weight`] returns for the same
/// inputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decomposition {
    /// Flat per-source factor. 1.0 means "no flat weight configured".
    pub flat_factor: f32,
    /// Per-category factor. 1.0 means "no matching category in policy".
    pub per_category_factor: f32,
    /// Per-subject-class factor. 1.0 means "no matching subject_kind in policy".
    pub per_subject_class_factor: f32,
    /// Time-decay factor in `[0.0, 1.0]`. 1.0 means "no decay
    /// configured" OR "observation is fresh".
    pub time_decay_factor: f32,
    /// Pre-clamp raw weight (product of factors).
    pub raw_weight: f32,
    /// Post-clamp final weight — what [`crate::weight`] returns.
    pub final_weight: f32,
    /// Snapshot of the inputs that fed into the computation. Useful
    /// for log lines and forensic queries.
    pub inputs: ExplanationInputs,
}

/// Snapshot of the inputs to a weight computation. Mirrored to the
/// admin CLI's `--format json` output and the case-view "why?"
/// affordance for full reproducibility.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplanationInputs {
    /// Observation category at evaluation time.
    pub category: String,
    /// Observation subject_kind at evaluation time.
    pub subject_kind: String,
    /// Observation creation timestamp (for the decay factor).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Evaluation wall-clock time.
    pub now: chrono::DateTime<chrono::Utc>,
}

/// Decompose a weight computation into named factors.
///
/// Returns the same `final_weight` as [`crate::weight`] for the same
/// `(observation, policy, now)` triple — `Decomposition::final_weight`
/// is the same number.
#[must_use]
pub fn explain(
    observation: &impl Observation,
    policy: &TrustPolicy,
    now: chrono::DateTime<chrono::Utc>,
) -> Decomposition {
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
                let per_category_factor = per_category
                    .get(observation.category())
                    .copied()
                    .unwrap_or(1.0);
                let time_decay_factor = time_decay.map_or(1.0, |d| {
                    compute_decay_factor(d, observation.created_at(), now)
                });
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

    let raw_weight =
        flat_factor * per_category_factor * time_decay_factor * per_subject_class_factor;
    let final_weight = if raw_weight.is_nan() {
        0.0
    } else {
        raw_weight.clamp(0.0, 1.0)
    };

    Decomposition {
        flat_factor,
        per_category_factor,
        per_subject_class_factor,
        time_decay_factor,
        raw_weight,
        final_weight,
        inputs: ExplanationInputs {
            category: observation.category().to_owned(),
            subject_kind: observation.subject_kind().to_owned(),
            created_at: observation.created_at(),
            now,
        },
    }
}

impl Decomposition {
    /// Render as a human-readable text table for the `polaris
    /// trust-policy explain <obs_id>` CLI's default text mode.
    ///
    /// The wire-form output (the admin endpoint + case-view UI)
    /// uses the serde-Serialize shape directly; this is a
    /// presentation helper for the CLI.
    #[must_use]
    pub fn to_text_table(&self) -> String {
        format!(
            "Observation\n  category:     {category}\n  subject_kind: {kind}\n  created_at:   {created}\n  evaluated at: {now}\n\nFactors\n  flat_factor               = {flat:.4}\n  per_category_factor       = {cat:.4}\n  per_subject_class_factor  = {kindf:.4}\n  time_decay_factor         = {tdf:.4}\n\n  raw_weight                = {raw:.4}\n  final_weight              = {final_w:.4}\n",
            category = self.inputs.category,
            kind = self.inputs.subject_kind,
            created = self.inputs.created_at.to_rfc3339(),
            now = self.inputs.now.to_rfc3339(),
            flat = self.flat_factor,
            cat = self.per_category_factor,
            kindf = self.per_subject_class_factor,
            tdf = self.time_decay_factor,
            raw = self.raw_weight,
            final_w = self.final_weight,
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp,
    reason = "test code is allowed to panic — rust-quality §7 convention. \
              float_cmp on sentinel-value comparisons; not approximate equality."
)]
mod tests {
    use super::*;
    use crate::{TimeDecay, weight};
    use chrono::Utc;

    struct StubObs {
        category: String,
        subject_kind: String,
        created_at: chrono::DateTime<chrono::Utc>,
    }
    impl Observation for StubObs {
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

    #[test]
    fn explain_final_weight_equals_weight() {
        let mut per_category = std::collections::HashMap::new();
        per_category.insert("spam".to_owned(), 0.8);
        let policy = TrustPolicy::V2(V2Body {
            flat: Some(0.7),
            per_category,
            time_decay: Some(TimeDecay {
                half_life_days: 30.0,
            }),
            per_subject_class: std::collections::HashMap::new(),
        });
        let now = Utc::now();
        let obs = StubObs {
            category: "spam".to_owned(),
            subject_kind: "account".to_owned(),
            created_at: now - chrono::Duration::days(15),
        };
        let dec = explain(&obs, &policy, now);
        let w = weight(&obs, &policy, now);
        assert!((dec.final_weight - w).abs() < f32::EPSILON);
    }

    #[test]
    fn explain_factors_compose_to_raw() {
        let policy = TrustPolicy::v2_flat(0.5);
        let now = Utc::now();
        let obs = StubObs {
            category: "spam".to_owned(),
            subject_kind: "account".to_owned(),
            created_at: now,
        };
        let dec = explain(&obs, &policy, now);
        // raw = 0.5 * 1.0 * 1.0 * 1.0 = 0.5
        assert_eq!(dec.flat_factor, 0.5);
        assert_eq!(dec.per_category_factor, 1.0);
        assert_eq!(dec.per_subject_class_factor, 1.0);
        assert_eq!(dec.time_decay_factor, 1.0);
        assert_eq!(dec.raw_weight, 0.5);
        assert_eq!(dec.final_weight, 0.5);
    }

    #[test]
    fn to_text_table_renders_all_named_factors() {
        let policy = TrustPolicy::v2_flat(0.5);
        let now = Utc::now();
        let obs = StubObs {
            category: "spam".to_owned(),
            subject_kind: "account".to_owned(),
            created_at: now,
        };
        let dec = explain(&obs, &policy, now);
        let table = dec.to_text_table();
        for expected in [
            "flat_factor",
            "per_category_factor",
            "per_subject_class_factor",
            "time_decay_factor",
            "raw_weight",
            "final_weight",
            "spam",
            "account",
        ] {
            assert!(
                table.contains(expected),
                "table missing {expected:?}: {table}",
            );
        }
    }

    #[test]
    fn explain_serializes_to_json_stably() {
        let policy = TrustPolicy::v2_flat(0.5);
        let now = Utc::now();
        let obs = StubObs {
            category: "spam".to_owned(),
            subject_kind: "account".to_owned(),
            created_at: now,
        };
        let dec = explain(&obs, &policy, now);
        let json = serde_json::to_string(&dec).unwrap();
        // Round-trip back through serde.
        let back: Decomposition = serde_json::from_str(&json).unwrap();
        assert_eq!(dec, back);
    }
}
