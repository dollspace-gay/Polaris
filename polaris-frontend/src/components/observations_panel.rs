//! `ObservationsPanel` — pattern-engine observations attached to a case.
//!
//! Surfaces every [`polaris_types::ObservationKind`] except
//! `ClassifierSignal` (which has a dedicated [`crate::components::classifier_panel::ClassifierPanel`]).
//! Classifier signals get their own panel because the disagreement-
//! surfacing rendering (#129 / M5 #45 PR 5) is qualitatively different
//! from the rest of the pattern-engine signal set.
//!
//! # Renders
//!
//! - `ImageHashCluster { hash, distance }` — perceptual-hash dedup
//!   signal (#17 SimHash).
//! - `AccountCohort { cohort_id, similarity_score }` — MinHash
//!   account-cohort detection (#18).
//! - `ReplyBrigade { thread_uri }` — coordinated reply-brigade
//!   signal (#73 moderator-behaviour anomaly companion).
//! - `ExternalLabel { source, label_value, weight }` — third-party
//!   labeler signal ingested via #32.
//! - `ReportVolumeAnomaly { window_seconds, observed, expected_mean,
//!   expected_stddev }` — report-volume z-score detection (#19).
//! - `ModeratorBehaviorAnomaly { moderator_id, window_seconds,
//!   action_count, expected_mean, expected_stddev }` — moderator
//!   behaviour anomaly (#73 / T1).
//!
//! Each row carries the observation's calibrated `confidence` score
//! from the case-view DTO (the outer pattern-engine confidence —
//! distinct from per-variant scores) so moderators can sort the
//! signals by trustworthiness.

use leptos::prelude::*;
use polaris_types::{Observation, ObservationKind};

/// Render the case's pattern-engine observation list (excluding
/// classifier signals, which have a dedicated panel).
#[component]
#[allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "Leptos #[component] macros accept props by value as the framework convention."
)]
pub fn ObservationsPanel(
    /// All observation rows from the case-view DTO. The component
    /// filters out `ClassifierSignal` internally so the classifier
    /// panel can own them.
    observations: Vec<Observation>,
) -> impl IntoView {
    let rows: Vec<Observation> = observations
        .into_iter()
        .filter(|o| !matches!(o.kind, ObservationKind::ClassifierSignal { .. }))
        .collect();

    if rows.is_empty() {
        return ().into_any();
    }
    let count = rows.len();

    view! {
        <section class="observations-panel" role="region" aria-label="Pattern observations">
            <h3 class="observations-panel__title">"Pattern observations"</h3>
            <p class="observations-panel__count">
                {count}" pattern-engine signal"{if count == 1 { "" } else { "s" }}
            </p>
            <ul class="observations-panel__list">
                {rows.into_iter().map(render_observation).collect_view()}
            </ul>
        </section>
    }
    .into_any()
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "Iterator-collect chain moves Observation values; borrowing would require \
              the caller to materialise a `&Observation` collection."
)]
fn render_observation(obs: Observation) -> impl IntoView {
    let confidence = obs.confidence.clamp(0.0, 1.0);
    let confidence_text = format!("{confidence:.2}");
    let confidence_modifier = match confidence {
        c if c >= 0.9 => "observations-panel__confidence--very-high",
        c if c >= 0.7 => "observations-panel__confidence--high",
        c if c >= 0.4 => "observations-panel__confidence--moderate",
        _ => "observations-panel__confidence--low",
    };
    let (kind_label, detail) = format_observation(&obs.kind);
    let detected = obs.detected_at.to_rfc3339();

    view! {
        <li class="observations-panel__row">
            <header class="observations-panel__row-head">
                <span class="observations-panel__kind">{kind_label}</span>
                <span class=move || format!("observations-panel__confidence {confidence_modifier}")>
                    {confidence_text}
                </span>
                <time class="observations-panel__detected">{detected}</time>
            </header>
            <p class="observations-panel__detail">{detail}</p>
        </li>
    }
}

/// Project an `ObservationKind` into (label, detail-string) for
/// rendering. Each variant has its own structured detail so the
/// moderator sees the actual signal, not a generic "observation".
fn format_observation(kind: &ObservationKind) -> (&'static str, String) {
    match kind {
        ObservationKind::ImageHashCluster { hash, distance } => (
            "Image hash cluster",
            format!("hash {hash}, hamming distance {distance}"),
        ),
        ObservationKind::AccountCohort {
            cohort_id,
            similarity_score,
        } => (
            "Account cohort",
            format!("cohort {cohort_id}, similarity {similarity_score:.2}"),
        ),
        ObservationKind::ReplyBrigade { thread_uri } => {
            ("Reply brigade", format!("targets thread {thread_uri}"))
        }
        ObservationKind::ExternalLabel {
            source,
            label_value,
            weight,
        } => (
            "External label",
            format!("upstream {source} labelled {label_value:?} (operator-weight {weight:.2})"),
        ),
        ObservationKind::ReportVolumeAnomaly { category, z_score } => (
            "Report-volume anomaly",
            format!("category {category}, z-score {z_score:.2} above baseline"),
        ),
        ObservationKind::ModeratorBehaviorAnomaly {
            moderator_id,
            action_count,
            window_secs,
        } => (
            "Moderator-behavior anomaly",
            format!("mod {moderator_id}: {action_count} actions in {window_secs}s rolling window"),
        ),
        ObservationKind::ClassifierSignal { .. } => (
            "Classifier signal",
            // Defensive — ClassifierSignal is filtered out before
            // render_observation runs. Render a minimal label rather
            // than panic so a future code-path slip surfaces visibly
            // rather than crashing the case view.
            "(rendered by ClassifierPanel)".to_owned(),
        ),
        ObservationKind::LlmRecommendation {
            model,
            recommended_action_kind,
            confidence,
            ..
        } => (
            // LLM-3 (#233) lands the typed variant + DB schema; the
            // dedicated `LlmRecommendationPanel` (REQ-J1, LLM-11) will
            // render the full envelope. Until that panel ships,
            // surfacing a minimal chip in the existing observations
            // panel keeps the signal visible without requiring the
            // moderator to refresh after the LLM-11 PR lands.
            "LLM recommendation",
            format!(
                "{model} suggests {recommended_action_kind} \
                 (confidence {confidence:.2})"
            ),
        ),
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
    use polaris_types::{ObservationId, SubjectId};

    fn obs(kind: ObservationKind, confidence: f32) -> Observation {
        Observation {
            id: ObservationId::new(),
            subject_id: SubjectId::new(),
            kind,
            confidence,
            evidence: serde_json::json!({}),
            detected_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn classifier_signals_are_filtered_out() {
        let obs = vec![
            obs(
                ObservationKind::ClassifierSignal {
                    model: "spam-v1".to_owned(),
                    label: "spam".to_owned(),
                    confidence: 0.8,
                },
                0.8,
            ),
            obs(
                ObservationKind::ImageHashCluster {
                    hash: "deadbeef".to_owned(),
                    distance: 3,
                },
                0.7,
            ),
        ];
        let filtered: Vec<_> = obs
            .into_iter()
            .filter(|o| !matches!(o.kind, ObservationKind::ClassifierSignal { .. }))
            .collect();
        assert_eq!(filtered.len(), 1);
        assert!(matches!(
            filtered[0].kind,
            ObservationKind::ImageHashCluster { .. }
        ));
    }

    #[test]
    fn format_observation_image_hash_includes_distance() {
        let kind = ObservationKind::ImageHashCluster {
            hash: "abc123".to_owned(),
            distance: 5,
        };
        let (label, detail) = format_observation(&kind);
        assert_eq!(label, "Image hash cluster");
        assert!(detail.contains("abc123"));
        assert!(detail.contains("hamming distance 5"));
    }

    #[test]
    fn format_observation_external_label_carries_source_and_weight() {
        let kind = ObservationKind::ExternalLabel {
            source: polaris_types::Did::new("did:plc:upstream"),
            label_value: polaris_types::LabelValue::new("spam"),
            weight: 0.85,
        };
        let (label, detail) = format_observation(&kind);
        assert_eq!(label, "External label");
        assert!(detail.contains("did:plc:upstream"));
        assert!(detail.contains("spam"));
        assert!(detail.contains("0.85"));
    }

    #[test]
    fn format_observation_report_volume_includes_stats() {
        let kind = ObservationKind::ReportVolumeAnomaly {
            category: "spam".to_owned(),
            z_score: 4.2,
        };
        let (label, detail) = format_observation(&kind);
        assert_eq!(label, "Report-volume anomaly");
        assert!(detail.contains("spam"));
        assert!(detail.contains("4.20") || detail.contains("4.2"));
    }

    #[test]
    fn classifier_kind_renders_a_label_rather_than_panic() {
        // Defensive: ClassifierSignal is filtered out before reaching
        // format_observation, but if a code-path slip ever feeds one
        // through, the function returns a label instead of panicking.
        let kind = ObservationKind::ClassifierSignal {
            model: "m".to_owned(),
            label: "l".to_owned(),
            confidence: 0.5,
        };
        let (label, _) = format_observation(&kind);
        assert_eq!(label, "Classifier signal");
    }
}
