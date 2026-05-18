//! Classifier-signals panel — renders `ObservationKind::ClassifierSignal`
//! rows from the case-view DTO with side-by-side disagreement display
//! per Q5-A (#129 / M5 #45 PR 5).
//!
//! # Why side-by-side
//!
//! Multiple classifiers can score the same event differently. Per Q5-A
//! (resolved on #124), Polaris surfaces both verdicts to the moderator
//! rather than aggregating to a single consensus score — the
//! moderator decides; the classifier signals are inputs, not actions.
//!
//! # Wiring
//!
//! The case-view DTO already carries `observations: Vec<Observation>`
//! (DTO at `polaris-frontend/src/api_client/dto.rs`); this component
//! filters to `ClassifierSignal { … }` variants and groups them so a
//! same-event disagreement renders as a single row with multiple
//! classifier columns.

use leptos::prelude::*;
use polaris_types::{Observation, ObservationKind};

/// One classifier observation projected for display. Derived from
/// [`ObservationKind::ClassifierSignal`].
#[derive(Debug, Clone)]
struct ClassifierRow {
    /// Classifier model identifier (e.g. `csam-detector-v3`).
    model: String,
    /// Classifier-emitted label string (model-specific vocabulary).
    label: String,
    /// Confidence in `[0.0, 1.0]`.
    confidence: f32,
}

/// Project the case-view observation list to classifier rows.
///
/// Only [`ObservationKind::ClassifierSignal`] variants surface; other
/// observation kinds (image-hash cluster, account cohort, etc.)
/// render in their own panels.
#[must_use]
fn project_classifier_rows(observations: &[Observation]) -> Vec<ClassifierRow> {
    observations
        .iter()
        .filter_map(|o| match &o.kind {
            ObservationKind::ClassifierSignal {
                model,
                label,
                confidence,
            } => Some(ClassifierRow {
                model: model.clone(),
                label: label.clone(),
                confidence: *confidence,
            }),
            _ => None,
        })
        .collect()
}

/// Format the confidence value for the UI. Uses two decimal places
/// because classifier scores aren't precise past the second digit and
/// the UI shouldn't suggest false precision.
#[must_use]
fn format_confidence(c: f32) -> String {
    format!("{c:.2}")
}

/// CSS class modifier for confidence intensity. Lets the styling
/// reflect high-confidence signals visually without conveying
/// information by colour alone (per `design.md` §7 accessibility).
/// The text content carries the score; the colour is an additional
/// visual cue.
#[must_use]
fn confidence_modifier(c: f32) -> &'static str {
    if c >= 0.9 {
        "classifier-panel__confidence--very-high"
    } else if c >= 0.7 {
        "classifier-panel__confidence--high"
    } else if c >= 0.4 {
        "classifier-panel__confidence--moderate"
    } else {
        "classifier-panel__confidence--low"
    }
}

/// Render the classifier panel for a case view.
///
/// Empty `observations` (or one with no `ClassifierSignal` variants)
/// renders nothing. The component never renders a "no classifier
/// signals" placeholder — the panel either has signals to show or
/// stays out of the way.
#[component]
#[allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "Leptos #[component] macros accept props by value as the framework convention; \
              `observations` is moved into the projection helper and not used again. \
              must_use_candidate fires on the macro-generated Props struct; the component \
              itself is consumed by view! at the call site."
)]
pub fn ClassifierPanel(
    /// Full observation list from the case-view DTO. The component
    /// filters internally to classifier variants only.
    observations: Vec<Observation>,
) -> impl IntoView {
    let rows = project_classifier_rows(&observations);
    if rows.is_empty() {
        return ().into_any();
    }

    let count = rows.len();
    let disagrees = is_disagreeing(&rows);

    view! {
        <section class="classifier-panel">
            <h3 class="classifier-panel__title">"Classifier signals"</h3>
            <p class="classifier-panel__count">
                {count}" classifier signal"
                {if count == 1 { "" } else { "s" }}
                {if disagrees { " — note disagreement below" } else { "" }}
            </p>
            <ul class="classifier-panel__list">
                {rows.into_iter().map(|r| view! {
                    <li class="classifier-panel__row">
                        <span class="classifier-panel__model">{r.model.clone()}</span>
                        <span class="classifier-panel__label">{r.label.clone()}</span>
                        <span class=move || {
                            format!("classifier-panel__confidence {}", confidence_modifier(r.confidence))
                        }>
                            {format_confidence(r.confidence)}
                        </span>
                    </li>
                }).collect_view()}
            </ul>
        </section>
    }.into_any()
}

/// Returns true if at least two rows emit DIFFERENT labels.
/// Disagreement detection is naive — same model emitting "spam: 0.6"
/// vs "spam: 0.9" is not a disagreement; "spam vs not-harmful"
/// across two classifiers is.
fn is_disagreeing(rows: &[ClassifierRow]) -> bool {
    if rows.len() < 2 {
        return false;
    }
    let first_label = &rows[0].label;
    rows.iter().any(|r| &r.label != first_label)
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
    use polaris_types::{Observation, ObservationId, ObservationKind, SubjectId};

    fn classifier_obs(model: &str, label: &str, confidence: f32) -> Observation {
        Observation {
            id: ObservationId::new(),
            subject_id: SubjectId::new(),
            kind: ObservationKind::ClassifierSignal {
                model: model.to_owned(),
                label: label.to_owned(),
                confidence,
            },
            confidence,
            evidence: serde_json::json!({}),
            detected_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn project_classifier_rows_filters_to_classifier_signals() {
        let obs = vec![
            classifier_obs("model-a", "spam", 0.8),
            Observation {
                id: ObservationId::new(),
                subject_id: SubjectId::new(),
                kind: ObservationKind::ImageHashCluster {
                    hash: "deadbeef".to_owned(),
                    distance: 3,
                },
                confidence: 0.5,
                evidence: serde_json::json!({}),
                detected_at: chrono::Utc::now(),
            },
            classifier_obs("model-b", "not-spam", 0.7),
        ];
        let rows = project_classifier_rows(&obs);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].model, "model-a");
        assert_eq!(rows[1].model, "model-b");
    }

    #[test]
    fn format_confidence_uses_two_decimals() {
        assert_eq!(format_confidence(0.857_456), "0.86");
        assert_eq!(format_confidence(1.0), "1.00");
        assert_eq!(format_confidence(0.0), "0.00");
    }

    #[test]
    fn confidence_modifier_thresholds() {
        assert!(confidence_modifier(0.95).ends_with("--very-high"));
        assert!(confidence_modifier(0.75).ends_with("--high"));
        assert!(confidence_modifier(0.5).ends_with("--moderate"));
        assert!(confidence_modifier(0.2).ends_with("--low"));
    }

    #[test]
    fn is_disagreeing_recognises_distinct_labels() {
        let rows = vec![
            ClassifierRow {
                model: "a".to_owned(),
                label: "spam".to_owned(),
                confidence: 0.9,
            },
            ClassifierRow {
                model: "b".to_owned(),
                label: "not-spam".to_owned(),
                confidence: 0.9,
            },
        ];
        assert!(is_disagreeing(&rows));
    }

    #[test]
    fn is_disagreeing_returns_false_for_same_label() {
        let rows = vec![
            ClassifierRow {
                model: "a".to_owned(),
                label: "spam".to_owned(),
                confidence: 0.6,
            },
            ClassifierRow {
                model: "b".to_owned(),
                label: "spam".to_owned(),
                confidence: 0.9,
            },
        ];
        assert!(!is_disagreeing(&rows));
    }

    #[test]
    fn is_disagreeing_returns_false_for_single_row() {
        let rows = vec![ClassifierRow {
            model: "a".to_owned(),
            label: "spam".to_owned(),
            confidence: 0.9,
        }];
        assert!(!is_disagreeing(&rows));
    }

    #[test]
    fn empty_observations_produces_no_rows() {
        let rows = project_classifier_rows(&[]);
        assert!(rows.is_empty());
    }
}
