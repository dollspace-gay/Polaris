//! [`Escalation`] — cross-instance federation record for pattern evidence.
//!
//! An escalation is the unit of cross-instance federation: one Polaris instance
//! sends an escalation to a peer instance carrying the safe-to-federate subset
//! of an incident's pattern evidence (observations + evidence pointers). The
//! receiving instance decides independently whether to act.
//!
//! # Privacy boundary
//!
//! `Escalation` deliberately omits all internal-only fields (`id`,
//! `assigned_moderator`, audit chain entries) that must not cross instance
//! boundaries. The [`crate::lexicon_mapping`] module enforces this boundary
//! explicitly with `// privacy: <field> never federated` annotations on each
//! dropped field.
//!
//! # Module position
//!
//! `Escalation` is domain-level (no ATProto wire types). The mapping to/from
//! the wire lexicon lives in [`crate::lexicon_mapping`].

use chrono::{DateTime, Utc};

use crate::evidence::EvidencePointer;
use crate::ids::{Did, EscalationId};
use crate::observation::ObservationKind;

/// The ATProto subject of an escalation: either a bare account DID (for
/// account-level concerns) or an AT-URI (for record-level concerns).
///
/// Maps to `gay.dollspace.polaris.escalation#mainSubjectRefs` on the wire.
/// Non-ATProto Polaris subjects (internal aggregates, cohort IDs) are not
/// federable and must not appear here.
///
/// # Serde representation
///
/// Uses adjacently-tagged form `{"kind":"did","value":"did:plc:…"}` /
/// `{"kind":"at_uri","value":"at://…"}`. The internally-tagged form
/// `#[serde(tag = "kind")]` does not support newtype variants containing a
/// plain `String` — Rust's serde derives reject that combination.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum SubjectRef {
    /// The concern is about the account as a whole.
    Did(String),
    /// The concern is about a specific record.
    AtUri(String),
}

impl SubjectRef {
    /// Borrow the inner string regardless of variant.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Did(s) | Self::AtUri(s) => s.as_str(),
        }
    }
}

/// A single observation embedded in an [`Escalation`].
///
/// Carries the cross-detector calibrated confidence (as `f32`, 0.0–1.0) and
/// the discriminated [`ObservationKind`] — only the five safe-to-federate
/// variants. On the wire, the confidence is represented as a scaled integer
/// (×1000, clamped to [0, 1000]).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EmbeddedObservation {
    /// Cross-detector calibrated confidence (0.0–1.0).
    ///
    /// This is the outer pattern-engine confidence, not the per-variant
    /// detector-raw value. On the wire it is stored as an `i64` scaled
    /// integer (`confidence * 1000.0`, rounded) to avoid ATProto's lack of
    /// a float type.
    pub confidence: f32,
    /// The discriminated observation kind.
    ///
    /// Only the five safe-to-federate variants may be present in an
    /// `EmbeddedObservation`. The `ReportVolumeAnomaly` and
    /// `ModeratorBehaviorAnomaly` variants are internal-only and will
    /// cause `to_lexicon_observation` to return
    /// `MappingError::UnsupportedVariant`.
    pub observation: ObservationKind,
}

/// Cross-instance federation record for pattern evidence.
///
/// One Polaris instance creates an `Escalation` and posts it to a peer
/// instance's ATProto PDS as a `gay.dollspace.polaris.escalation` record.
/// The receiving instance ingests it via `from_lexicon_escalation`.
///
/// # Internal-only fields
///
/// The `id`, `source_did`, and `target_did` are internal coordination fields.
/// `id` is never federated (it is the source instance's primary key).
/// `source_did` and `target_did` are present on the internal struct for
/// routing / audit purposes but are also present on the wire (`source`,
/// `target`) — they are the ATProto participant DIDs and are explicitly
/// required by the Lexicon.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Escalation {
    /// Polaris-internal identifier.
    ///
    /// NEVER federated — dropped at the to-wire boundary.
    /// `// privacy: id never federated`
    pub id: EscalationId,

    /// DID of the source labeler instance (the one creating this escalation).
    ///
    /// Present on the wire as the `source` field.
    pub source_did: Did,

    /// DID of the target labeler instance (the recipient).
    ///
    /// Present on the wire as the `target` field.
    pub target_did: Did,

    /// The ATProto subject of this escalation: either a DID or AT-URI.
    ///
    /// Present on the wire as the `subject` field.
    pub subject: SubjectRef,

    /// Human-readable reason for escalating.
    ///
    /// Present on the wire as the `reason` field.
    pub reason: String,

    /// Observations (safe-to-federate subset) supporting this escalation.
    ///
    /// Present on the wire as the `observations` field.
    pub observations: Vec<EmbeddedObservation>,

    /// Evidence CAR file pointers.
    ///
    /// Present on the wire as the `evidence` field (optional; omitted when
    /// empty to save bytes).
    pub evidence: Vec<EvidencePointer>,

    /// When this escalation was created.
    ///
    /// Present on the wire as the `createdAt` field.
    pub created_at: DateTime<Utc>,
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
    use crate::ids::EscalationId;
    use crate::observation::ObservationKind;

    fn sample() -> Escalation {
        Escalation {
            id: EscalationId::new(),
            source_did: Did::new("did:plc:source"),
            target_did: Did::new("did:plc:target"),
            subject: SubjectRef::Did("did:plc:subject".to_owned()),
            reason: "Coordinated inauthentic behavior".to_owned(),
            observations: vec![EmbeddedObservation {
                confidence: 0.85,
                observation: ObservationKind::ReplyBrigade {
                    thread_uri: "at://did:plc:x/app.bsky.feed.post/abc".to_owned(),
                },
            }],
            evidence: vec![],
            created_at: DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
        }
    }

    #[test]
    fn escalation_round_trips_through_serde() {
        let e = sample();
        let json = serde_json::to_string(&e).expect("serialize");
        let back: Escalation = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(e, back);
    }

    #[test]
    fn subject_ref_did_borrow() {
        let s = SubjectRef::Did("did:plc:foo".to_owned());
        assert_eq!(s.as_str(), "did:plc:foo");
    }

    #[test]
    fn subject_ref_at_uri_borrow() {
        let s = SubjectRef::AtUri("at://did:plc:x/app.bsky.feed.post/3l".to_owned());
        assert_eq!(s.as_str(), "at://did:plc:x/app.bsky.feed.post/3l");
    }
}
