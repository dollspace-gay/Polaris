//! [`Observation`] — a pattern-engine emission attached to a [`crate::subject::Subject`].
//!
//! Per `design.md` §3.2 and §4: the pattern engine emits *observations*, not
//! actions. An observation is a signal — image-hash cluster, account cohort,
//! reply brigade, report-volume anomaly, external label, ML classifier
//! score — that contributes to a subject's risk profile but never directly
//! drives a moderation decision. Humans make decisions; observations inform
//! them.

use chrono::{DateTime, Utc};

use crate::ids::{Did, LabelValue, ObservationId, SubjectId};

/// The discriminator-with-evidence enum for observations.
///
/// Each variant carries the structured fields that the corresponding pattern
/// detector emits. The free-form `evidence: serde_json::Value` on
/// [`Observation`] is for additional detector-specific context that doesn't
/// fit a stable schema (e.g. raw hash bytes, cohort member lists).
///
/// # Serde representation
///
/// `#[serde(tag = "kind", content = "data")]` produces a discriminated wire
/// form: `{"kind":"image_hash_cluster","data":{"hash":"...","distance":3}}`.
/// This matches the §4 design where the enum discriminator is the `kind`
/// column and the payload is `evidence`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum ObservationKind {
    /// SimHash/perceptual-hash cluster: this subject's content matches a
    /// known abusive-content hash within `distance`.
    ImageHashCluster {
        /// Hex-encoded perceptual hash.
        hash: String,
        /// Hamming distance from the reference hash.
        distance: u32,
    },
    /// Account-cohort match: this subject was created in the same narrow
    /// window as other suspicious accounts.
    AccountCohort {
        /// Opaque cohort identifier assigned by the pattern engine.
        cohort_id: String,
        /// 0.0–1.0 similarity score within the cohort.
        similarity_score: f32,
    },
    /// Reply-brigade match: this subject's replies on `thread_uri` are part
    /// of a coordinated reply burst.
    ReplyBrigade {
        /// AT-URI of the thread the brigade targeted.
        thread_uri: String,
    },
    /// Report-volume anomaly: incoming reports against this subject's
    /// `category` are above the expected baseline by `z_score` standard
    /// deviations.
    ReportVolumeAnomaly {
        /// The report category that spiked.
        category: String,
        /// Z-score above the trailing baseline.
        z_score: f32,
    },
    /// An ATProto label from a third-party labeler (`design.md` §5.9).
    ExternalLabel {
        /// DID of the labeler.
        source: Did,
        /// Label value emitted by the upstream labeler.
        label_value: LabelValue,
        /// Operator-configured trust weight for this upstream.
        weight: f32,
    },
    /// An ML classifier signal (`design.md` §3.2).
    ClassifierSignal {
        /// Classifier model identifier (e.g. `csam-detector-v3`).
        model: String,
        /// Classifier-emitted label.
        label: String,
        /// 0.0–1.0 classifier confidence.
        confidence: f32,
    },
}

impl ObservationKind {
    /// Wire discriminator string. Mirrors the `kind` column's CHECK constraint.
    #[must_use]
    pub const fn discriminator(&self) -> &'static str {
        match self {
            Self::ImageHashCluster { .. } => "image_hash_cluster",
            Self::AccountCohort { .. } => "account_cohort",
            Self::ReplyBrigade { .. } => "reply_brigade",
            Self::ReportVolumeAnomaly { .. } => "report_volume_anomaly",
            Self::ExternalLabel { .. } => "external_label",
            Self::ClassifierSignal { .. } => "classifier_signal",
        }
    }
}

/// A pattern-engine observation attached to a [`crate::subject::Subject`].
///
/// Maps 1:1 with a row in the `observations` table.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Observation {
    /// Polaris-internal identifier.
    pub id: ObservationId,
    /// Subject this observation is attached to.
    pub subject_id: SubjectId,
    /// Discriminator + structured payload.
    pub kind: ObservationKind,
    /// Detector confidence (0.0–1.0). Distinct from the per-variant
    /// confidence fields (e.g. classifier confidence) — the outer
    /// `confidence` is the cross-detector calibrated value the pattern
    /// engine assigns; the per-variant fields are the detector's raw output.
    pub confidence: f32,
    /// Free-form additional evidence the detector chose to attach.
    pub evidence: serde_json::Value,
    /// When the observation was recorded.
    pub detected_at: DateTime<Utc>,
}

/// Caller-supplied fields for inserting a new [`Observation`].
///
/// The repo populates `id` and `detected_at`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct NewObservation {
    /// Subject to attach this observation to.
    pub subject_id: SubjectId,
    /// Discriminator + payload.
    pub kind: ObservationKind,
    /// Confidence (0.0–1.0).
    pub confidence: f32,
    /// Free-form additional evidence.
    pub evidence: serde_json::Value,
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
    fn observation_kind_image_hash_round_trips_through_serde() {
        let ok = ObservationKind::ImageHashCluster {
            hash: "deadbeef".to_owned(),
            distance: 4,
        };
        let json = serde_json::to_string(&ok).expect("serialize");
        let back: ObservationKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ok, back);
    }

    #[test]
    fn observation_kind_external_label_round_trips_through_serde() {
        let ok = ObservationKind::ExternalLabel {
            source: Did::new("did:plc:upstream"),
            label_value: LabelValue::new("spam"),
            weight: 0.8,
        };
        let json = serde_json::to_string(&ok).expect("serialize");
        let back: ObservationKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ok, back);
    }

    #[test]
    fn discriminator_matches_serde_tag() {
        let ok = ObservationKind::ReplyBrigade {
            thread_uri: "at://x".to_owned(),
        };
        let json = serde_json::to_string(&ok).expect("serialize");
        assert!(
            json.contains("\"kind\":\"reply_brigade\""),
            "expected discriminator in wire form, got {json}",
        );
        assert_eq!(ok.discriminator(), "reply_brigade");
    }
}
