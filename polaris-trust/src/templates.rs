//! Shipped default [`TrustPolicy`] templates (REQ-3 / issue #148).
//!
//! Operators pick a template as a starting point in the admin policy
//! editor (#149 PR 6) and tweak the values; the templates themselves
//! are deliberately conservative defaults that match the language in
//! the design doc.
//!
//! All templates produce policies that pass [`crate::validate`]; a
//! `#[test]` in this module exercises that invariant for every shipped
//! template so a future addition that ships a broken default catches
//! at CI time, not after deployment.

use chrono::{DateTime, Utc};

use crate::{TimeDecay, TrustPolicy, V2Body};

/// "Moderate trust for spam, 30-day decay." Recommended starting
/// point for community labelers ingesting upstream spam signals;
/// you keep the labeler's reputation for spam-classification but
/// fold in the design's "older labels carry less weight" defaults.
#[must_use]
pub fn moderate_spam_30d_decay() -> TrustPolicy {
    let mut per_category = std::collections::HashMap::new();
    per_category.insert("spam".to_owned(), 0.85);
    TrustPolicy::V2(V2Body {
        flat: Some(0.7),
        per_category,
        time_decay: Some(TimeDecay {
            half_life_days: 30.0,
        }),
        per_subject_class: std::collections::HashMap::new(),
    })
}

/// "High trust for CSAM hash matches, no decay." For PhotoDNA-style
/// hash-match signals where a positive is functionally a fact;
/// time-decay would be inappropriate (the hash match doesn't become
/// less true with age).
#[must_use]
pub fn high_csam_no_decay() -> TrustPolicy {
    let mut per_category = std::collections::HashMap::new();
    per_category.insert("csam".to_owned(), 1.0);
    TrustPolicy::V2(V2Body {
        flat: Some(1.0),
        per_category,
        time_decay: None,
        per_subject_class: std::collections::HashMap::new(),
    })
}

/// "Low trust for harassment, 7-day decay." Harassment labels from
/// upstream labelers are noisy (subjective vocabulary, false-positive
/// prone). Lower flat weight + short half-life so a single
/// upstream-labeler call doesn't dominate.
#[must_use]
pub fn low_harassment_7d_decay() -> TrustPolicy {
    let mut per_category = std::collections::HashMap::new();
    per_category.insert("harassment".to_owned(), 0.5);
    TrustPolicy::V2(V2Body {
        flat: Some(0.3),
        per_category,
        time_decay: Some(TimeDecay {
            half_life_days: 7.0,
        }),
        per_subject_class: std::collections::HashMap::new(),
    })
}

/// All shipped templates. Indexable by stable string key — useful
/// for the admin UI's "load template" dropdown.
#[must_use]
pub fn all() -> Vec<(&'static str, TrustPolicy)> {
    vec![
        ("moderate_spam_30d_decay", moderate_spam_30d_decay()),
        ("high_csam_no_decay", high_csam_no_decay()),
        ("low_harassment_7d_decay", low_harassment_7d_decay()),
    ]
}

/// Look up a template by stable key. `None` if the key is unknown.
#[must_use]
pub fn by_name(name: &str) -> Option<TrustPolicy> {
    all().into_iter().find(|(k, _)| *k == name).map(|(_, p)| p)
}

/// Reference timestamp helper for documenting template-relative ages.
/// Exposed for use in the admin UI's "preview weights at age T" panel.
#[must_use]
pub fn reference_now() -> DateTime<Utc> {
    Utc::now()
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
    use crate::validate;

    /// Every shipped template MUST pass validate(). A broken default
    /// shouldn't ship.
    #[test]
    fn all_shipped_templates_validate() {
        for (name, policy) in all() {
            assert!(
                validate(&policy).is_ok(),
                "template {name} should validate, got {:?}",
                validate(&policy),
            );
        }
    }

    #[test]
    fn by_name_finds_known_templates() {
        assert!(by_name("moderate_spam_30d_decay").is_some());
        assert!(by_name("high_csam_no_decay").is_some());
        assert!(by_name("low_harassment_7d_decay").is_some());
    }

    #[test]
    fn by_name_returns_none_for_unknown() {
        assert!(by_name("nonexistent").is_none());
    }

    #[test]
    fn high_csam_has_no_decay() {
        let policy = high_csam_no_decay();
        match policy {
            TrustPolicy::V2(body) => {
                assert!(
                    body.time_decay.is_none(),
                    "CSAM hash matches should not decay"
                );
            }
            TrustPolicy::V1 { .. } => panic!("template should be V2"),
        }
    }

    #[test]
    fn moderate_spam_has_30d_half_life() {
        let policy = moderate_spam_30d_decay();
        match policy {
            TrustPolicy::V2(body) => {
                let decay = body
                    .time_decay
                    .expect("spam template should have time_decay");
                assert!((decay.half_life_days - 30.0).abs() < f32::EPSILON);
            }
            TrustPolicy::V1 { .. } => panic!("template should be V2"),
        }
    }
}
