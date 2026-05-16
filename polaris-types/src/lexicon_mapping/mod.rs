//! Privacy-boundary mapping between internal polaris-types and the generated
//! `polaris-lexicons` wire types.
//!
//! # Responsibility
//!
//! This module is the *only* place in `polaris-types` that references
//! `polaris-lexicons` wire shapes. Every conversion is hand-written so that:
//!
//! - Internal-only fields (`id`, moderator identifiers, audit chain hashes,
//!   reporter DIDs) are explicitly DROPPED at the to-wire boundary and never
//!   cross instance boundaries.
//! - Variants that carry internal-only data (`ReportVolumeAnomaly`,
//!   `ModeratorBehaviorAnomaly`) are rejected with a typed error rather than
//!   silently truncating their payloads.
//! - Scaled-integer ↔ `f32` conversions are clamped and round-tripped
//!   correctly.
//!
//! # Confidence scaling
//!
//! ATProto Lexicons have no float type. Confidence values (0.0–1.0) are
//! transported as scaled integers in [0, 1000]:
//!
//! - **to-wire**: `(f32 * 1000.0).clamp(0.0, 1000.0).round() as i64`
//! - **from-wire**: `wire_value as f32 / 1000.0`
//!
//! # Privacy annotations
//!
//! Each internal-only field that is dropped at the to-wire boundary is
//! annotated with a `// privacy: <field> never federated` comment at the
//! drop site.
//!
//! # Errors
//!
//! All fallible conversions return [`MappingError`]. There are no panics or
//! unwraps in non-test code.

pub mod error;

use polaris_lexicons::gay::dollspace::polaris as wire;

use crate::escalation::{
    EmbeddedObservation, Escalation, EscalationMessage, SignatureStatus, SubjectRef,
};
use crate::evidence::EvidencePointer;
use crate::ids::{Did, EscalationMessageId};
use crate::observation::ObservationKind;
use chrono::{DateTime, Utc};

pub use error::MappingError;

// ─── confidence scaling helpers ─────────────────────────────────────────────

/// Scale an internal `f32` confidence (0.0–1.0) to the wire integer [0, 1000].
///
/// Explicit clamp prevents overflow / NaN propagation (rust-quality §6).
/// The cast is safe: after `clamp(0.0, 1000.0)` the value is in [0.0, 1000.0],
/// `round()` gives [0.0, 1000.0] exactly, and `i64` can hold every integer in
/// that range without truncation.
#[inline]
#[allow(
    clippy::cast_possible_truncation,
    reason = "value is clamped to [0.0, 1000.0] before cast; no truncation possible"
)]
fn confidence_to_wire(c: f32) -> i64 {
    (c * 1000.0).clamp(0.0, 1000.0).round() as i64
}

/// Convert a wire-form scaled integer back to `f32` confidence.
///
/// The precision loss from `i64 → f32` is intentional: the wire values are
/// bounded to [0, 1000] (scaled integers), so the maximum precision loss is
/// negligible (< 1 ULP at this scale) and within the design's ±0.001 tolerance.
#[inline]
#[allow(
    clippy::cast_precision_loss,
    reason = "wire values are bounded [0, 1000]; precision loss < 1 ULP at this scale"
)]
fn confidence_from_wire(v: i64) -> f32 {
    v as f32 / 1000.0
}

// ─── EvidencePointer ────────────────────────────────────────────────────────

/// Convert an internal [`EvidencePointer`] to the wire
/// `gay.dollspace.polaris.evidencePointer#main` type.
///
/// # Errors
///
/// - [`MappingError::FieldOutOfRange`] if `byte_length` exceeds `i64::MAX`
///   (would overflow the wire's signed integer).
///
/// # Examples
///
/// ```rust
/// use polaris_types::evidence::EvidencePointer;
/// use polaris_types::lexicon_mapping::to_lexicon_evidence_pointer;
///
/// let ep = EvidencePointer {
///     car_cid: "bafyreifoo".to_owned(),
///     media_type: "application/vnd.ipld.car".to_owned(),
///     byte_length: 1024,
/// };
/// let wire = to_lexicon_evidence_pointer(&ep).unwrap();
/// assert_eq!(wire.car_cid, "bafyreifoo");
/// assert_eq!(wire.byte_length, 1024_i64);
/// ```
#[must_use = "call from_lexicon_evidence_pointer to convert the result back"]
pub fn to_lexicon_evidence_pointer(
    ep: &EvidencePointer,
) -> Result<wire::evidence_pointer::Main, MappingError> {
    let byte_length = i64::try_from(ep.byte_length).map_err(|_| MappingError::FieldOutOfRange {
        field: "byte_length",
        value: ep.byte_length.to_string(),
    })?;

    Ok(wire::evidence_pointer::Main {
        car_cid: ep.car_cid.clone(),
        media_type: ep.media_type.clone(),
        byte_length,
    })
}

/// Convert a wire `gay.dollspace.polaris.evidencePointer#main` into an
/// internal [`EvidencePointer`].
///
/// # Errors
///
/// - [`MappingError::FieldOutOfRange`] if `byte_length` is negative (wire
///   integers are signed; a negative value has no valid internal
///   representation).
///
/// # Examples
///
/// ```rust
/// use polaris_types::lexicon_mapping::{to_lexicon_evidence_pointer, from_lexicon_evidence_pointer};
/// use polaris_types::evidence::EvidencePointer;
///
/// let orig = EvidencePointer {
///     car_cid: "bafyreifoo".to_owned(),
///     media_type: "application/vnd.ipld.car".to_owned(),
///     byte_length: 2048,
/// };
/// let wire = to_lexicon_evidence_pointer(&orig).unwrap();
/// let back = from_lexicon_evidence_pointer(wire).unwrap();
/// assert_eq!(orig, back);
/// ```
#[must_use = "inspect the Ok value or propagate the Err"]
pub fn from_lexicon_evidence_pointer(
    wire: wire::evidence_pointer::Main,
) -> Result<EvidencePointer, MappingError> {
    let byte_length = u64::try_from(wire.byte_length).map_err(|_| MappingError::FieldOutOfRange {
        field: "byte_length",
        value: wire.byte_length.to_string(),
    })?;

    Ok(EvidencePointer {
        car_cid: wire.car_cid,
        media_type: wire.media_type,
        byte_length,
    })
}

// ─── ObservationKind ────────────────────────────────────────────────────────

/// Convert an internal [`ObservationKind`] to the wire
/// `EmbeddedObservationObservationRefs` union discriminator.
///
/// Only the five safe-to-federate variants are supported. The two
/// internal-only variants are rejected:
///
/// - `ReportVolumeAnomaly` → `Err(MappingError::UnsupportedVariant { discriminator: "report_volume_anomaly" })`
/// - `ModeratorBehaviorAnomaly` → `Err(MappingError::UnsupportedVariant { discriminator: "moderator_behavior_anomaly" })`
///
/// # Errors
///
/// - [`MappingError::UnsupportedVariant`] for the two internal-only variants.
///
/// # Examples
///
/// ```rust
/// use polaris_types::observation::ObservationKind;
/// use polaris_types::lexicon_mapping::to_lexicon_observation_kind;
///
/// let kind = ObservationKind::ReplyBrigade {
///     thread_uri: "at://did:plc:x/app.bsky.feed.post/abc".to_owned(),
/// };
/// let wire = to_lexicon_observation_kind(&kind, 0.9).unwrap();
/// ```
#[must_use = "inspect the Ok value or propagate the Err"]
pub fn to_lexicon_observation_kind(
    kind: &ObservationKind,
    _confidence: f32,
) -> Result<wire::escalation::EmbeddedObservationObservationRefs, MappingError> {
    use wire::escalation::EmbeddedObservationObservationRefs as Refs;

    match kind {
        ObservationKind::ImageHashCluster { hash, distance } => {
            Ok(Refs::DollspacePolarisObservationImageHashCluster(Box::new(
                wire::observation::ImageHashCluster {
                    hash: hash.clone(),
                    distance: i64::from(*distance),
                },
            )))
        }
        ObservationKind::AccountCohort {
            cohort_id,
            similarity_score,
        } => Ok(Refs::DollspacePolarisObservationAccountCohort(Box::new(
            wire::observation::AccountCohort {
                cohort_id: cohort_id.clone(),
                similarity_score: confidence_to_wire(*similarity_score),
            },
        ))),
        ObservationKind::ReplyBrigade { thread_uri } => {
            let at_uri = proto_blue_syntax::AtUri::new(thread_uri)
                .map_err(|_| MappingError::MalformedAtUri {
                    value: thread_uri.clone(),
                })?;
            Ok(Refs::DollspacePolarisObservationReplyBrigade(Box::new(
                wire::observation::ReplyBrigade { thread_uri: at_uri },
            )))
        }
        ObservationKind::ExternalLabel {
            source,
            label_value,
            weight,
        } => {
            let wire_did = proto_blue_syntax::Did::new(source.as_str())
                .map_err(|_| MappingError::MalformedDid {
                    value: source.0.clone(),
                })?;
            Ok(Refs::DollspacePolarisObservationExternalLabel(Box::new(
                wire::observation::ExternalLabel {
                    source: wire_did,
                    label_value: label_value.0.clone(),
                    weight: confidence_to_wire(*weight),
                },
            )))
        }
        ObservationKind::ClassifierSignal {
            model,
            label,
            confidence: signal_confidence,
        } => Ok(Refs::DollspacePolarisObservationClassifierSignal(Box::new(
            wire::observation::ClassifierSignal {
                model: model.clone(),
                label: label.clone(),
                confidence: confidence_to_wire(*signal_confidence),
            },
        ))),
        // privacy: ReportVolumeAnomaly carries internal operator signal — never federated
        ObservationKind::ReportVolumeAnomaly { .. } => Err(MappingError::UnsupportedVariant {
            discriminator: "report_volume_anomaly",
        }),
        // privacy: ModeratorBehaviorAnomaly carries moderator_id — never federated
        ObservationKind::ModeratorBehaviorAnomaly { .. } => {
            Err(MappingError::UnsupportedVariant {
                discriminator: "moderator_behavior_anomaly",
            })
        }
    }
}

/// Convert a wire `EmbeddedObservationObservationRefs` union to an internal
/// [`ObservationKind`] and `f32` confidence.
///
/// Returns `(confidence, ObservationKind)` where `confidence` is only
/// meaningful for variants that carry a wire-level confidence field
/// (`AccountCohort::similarity_score`, `ExternalLabel::weight`,
/// `ClassifierSignal::confidence`). For `ImageHashCluster` and `ReplyBrigade`
/// the returned confidence is `0.0` — callers should use the outer
/// [`EmbeddedObservation::confidence`] instead.
///
/// # Errors
///
/// - [`MappingError::UnsupportedVariant`] if the wire form contains the
///   catch-all `Other` arm (unrecognised discriminator).
/// - [`MappingError::MalformedDid`] if an `ExternalLabel`'s `source` DID
///   fails to re-serialise as a plain string (should not occur with valid wire
///   data).
/// - [`MappingError::MalformedAtUri`] if a `ReplyBrigade`'s `thread_uri`
///   fails to re-serialise (should not occur with valid wire data).
///
/// # Examples
///
/// ```rust
/// use polaris_types::observation::ObservationKind;
/// use polaris_types::lexicon_mapping::{to_lexicon_observation_kind, from_lexicon_observation_kind};
///
/// let orig = ObservationKind::ImageHashCluster {
///     hash: "deadbeef".to_owned(),
///     distance: 3,
/// };
/// let wire = to_lexicon_observation_kind(&orig, 0.7).unwrap();
/// let (_, back) = from_lexicon_observation_kind(wire).unwrap();
/// assert_eq!(orig, back);
/// ```
#[must_use = "inspect the Ok value or propagate the Err"]
pub fn from_lexicon_observation_kind(
    wire: wire::escalation::EmbeddedObservationObservationRefs,
) -> Result<(f32, ObservationKind), MappingError> {
    use wire::escalation::EmbeddedObservationObservationRefs as Refs;

    match wire {
        Refs::DollspacePolarisObservationImageHashCluster(inner) => {
            let distance = u32::try_from(inner.distance).map_err(|_| {
                MappingError::FieldOutOfRange {
                    field: "distance",
                    value: inner.distance.to_string(),
                }
            })?;
            Ok((
                0.0,
                ObservationKind::ImageHashCluster {
                    hash: inner.hash.clone(),
                    distance,
                },
            ))
        }
        Refs::DollspacePolarisObservationAccountCohort(inner) => Ok((
            confidence_from_wire(inner.similarity_score),
            ObservationKind::AccountCohort {
                cohort_id: inner.cohort_id.clone(),
                similarity_score: confidence_from_wire(inner.similarity_score),
            },
        )),
        Refs::DollspacePolarisObservationReplyBrigade(inner) => Ok((
            0.0,
            ObservationKind::ReplyBrigade {
                thread_uri: inner.thread_uri.to_string(),
            },
        )),
        Refs::DollspacePolarisObservationExternalLabel(inner) => {
            let source = crate::ids::Did::new(inner.source.as_str());
            let label_value = crate::ids::LabelValue::new(inner.label_value.as_str());
            let weight = confidence_from_wire(inner.weight);
            Ok((
                weight,
                ObservationKind::ExternalLabel {
                    source,
                    label_value,
                    weight,
                },
            ))
        }
        Refs::DollspacePolarisObservationClassifierSignal(inner) => {
            let signal_confidence = confidence_from_wire(inner.confidence);
            Ok((
                signal_confidence,
                ObservationKind::ClassifierSignal {
                    model: inner.model.clone(),
                    label: inner.label.clone(),
                    confidence: signal_confidence,
                },
            ))
        }
        Refs::Other => Err(MappingError::UnsupportedVariant {
            discriminator: "unknown",
        }),
    }
}

// ─── EmbeddedObservation ────────────────────────────────────────────────────

/// Convert an internal [`EmbeddedObservation`] to the wire
/// `gay.dollspace.polaris.escalation#embeddedObservation` type.
///
/// # Errors
///
/// - [`MappingError::UnsupportedVariant`] if the [`ObservationKind`] is one
///   of the two internal-only variants (`ReportVolumeAnomaly`,
///   `ModeratorBehaviorAnomaly`).
/// - [`MappingError::MalformedDid`] / [`MappingError::MalformedAtUri`] if a
///   string field fails wire validation.
///
/// # Examples
///
/// ```rust
/// use polaris_types::escalation::EmbeddedObservation;
/// use polaris_types::observation::ObservationKind;
/// use polaris_types::lexicon_mapping::to_lexicon_embedded_observation;
///
/// let obs = EmbeddedObservation {
///     confidence: 0.75,
///     observation: ObservationKind::ImageHashCluster {
///         hash: "deadbeef".to_owned(),
///         distance: 2,
///     },
/// };
/// let wire = to_lexicon_embedded_observation(&obs).unwrap();
/// assert_eq!(wire.confidence, 750);
/// ```
#[must_use = "inspect the Ok value or propagate the Err"]
pub fn to_lexicon_embedded_observation(
    obs: &EmbeddedObservation,
) -> Result<wire::escalation::EmbeddedObservation, MappingError> {
    let observation = to_lexicon_observation_kind(&obs.observation, obs.confidence)?;
    Ok(wire::escalation::EmbeddedObservation {
        confidence: confidence_to_wire(obs.confidence),
        observation,
    })
}

/// Convert a wire `EmbeddedObservation` to the internal
/// [`EmbeddedObservation`].
///
/// # Errors
///
/// - [`MappingError::UnsupportedVariant`] if the discriminator is not in the
///   safe-to-federate set.
/// - [`MappingError::FieldOutOfRange`] if a numeric field is out of range.
/// - [`MappingError::MalformedDid`] / [`MappingError::MalformedAtUri`] for
///   string field issues.
///
/// # Examples
///
/// ```rust
/// use polaris_types::escalation::EmbeddedObservation;
/// use polaris_types::observation::ObservationKind;
/// use polaris_types::lexicon_mapping::{to_lexicon_embedded_observation, from_lexicon_embedded_observation};
///
/// let orig = EmbeddedObservation {
///     confidence: 0.5,
///     observation: ObservationKind::ReplyBrigade {
///         thread_uri: "at://did:plc:x/app.bsky.feed.post/abc".to_owned(),
///     },
/// };
/// let wire = to_lexicon_embedded_observation(&orig).unwrap();
/// let back = from_lexicon_embedded_observation(wire).unwrap();
/// assert_eq!(orig.observation, back.observation);
/// ```
#[must_use = "inspect the Ok value or propagate the Err"]
pub fn from_lexicon_embedded_observation(
    wire: wire::escalation::EmbeddedObservation,
) -> Result<EmbeddedObservation, MappingError> {
    let confidence = confidence_from_wire(wire.confidence);
    let (_, observation) = from_lexicon_observation_kind(wire.observation)?;
    Ok(EmbeddedObservation {
        confidence,
        observation,
    })
}

// ─── Escalation ─────────────────────────────────────────────────────────────

/// Convert an internal [`Escalation`] to the wire
/// `gay.dollspace.polaris.escalation#main` type.
///
/// Internal-only fields dropped at this boundary:
///
/// - `id` — `// privacy: id never federated` (Polaris-internal primary key)
///
/// # Errors
///
/// - [`MappingError::UnsupportedVariant`] if any embedded observation uses an
///   internal-only variant.
/// - [`MappingError::MalformedDid`] if `source_did` or `target_did` is not a
///   valid ATProto DID.
/// - [`MappingError::MalformedAtUri`] if the subject is an `AtUri` that fails
///   wire validation.
/// - [`MappingError::FieldOutOfRange`] if any `byte_length` in evidence
///   overflows `i64`.
///
/// # Examples
///
/// ```rust
/// use polaris_types::escalation::{Escalation, EmbeddedObservation, SubjectRef};
/// use polaris_types::evidence::EvidencePointer;
/// use polaris_types::ids::{Did, EscalationId};
/// use polaris_types::observation::ObservationKind;
/// use polaris_types::lexicon_mapping::to_lexicon_escalation;
/// use chrono::Utc;
///
/// let esc = Escalation {
///     id: EscalationId::new(),
///     source_did: Did::new("did:plc:source"),
///     target_did: Did::new("did:plc:target"),
///     subject: SubjectRef::Did("did:plc:subject".to_owned()),
///     reason: "test".to_owned(),
///     observations: vec![],
///     evidence: vec![],
///     created_at: Utc::now(),
/// };
/// let wire = to_lexicon_escalation(&esc).unwrap();
/// assert_eq!(wire.reason, "test");
/// ```
#[must_use = "inspect the Ok value or propagate the Err"]
pub fn to_lexicon_escalation(
    escalation: &Escalation,
) -> Result<wire::escalation::Main, MappingError> {
    // privacy: id never federated — dropped here; Polaris-internal primary key

    let source = proto_blue_syntax::Did::new(escalation.source_did.as_str()).map_err(|_| {
        MappingError::MalformedDid {
            value: escalation.source_did.0.clone(),
        }
    })?;

    let target = proto_blue_syntax::Did::new(escalation.target_did.as_str()).map_err(|_| {
        MappingError::MalformedDid {
            value: escalation.target_did.0.clone(),
        }
    })?;

    let subject = match &escalation.subject {
        SubjectRef::Did(did_str) => {
            let wire_did = proto_blue_syntax::Did::new(did_str).map_err(|_| {
                MappingError::MalformedDid {
                    value: did_str.clone(),
                }
            })?;
            wire::escalation::MainSubjectRefs::DollspacePolarisEscalationSubjectAccount(Box::new(
                wire::escalation::SubjectAccount { did: wire_did },
            ))
        }
        SubjectRef::AtUri(uri_str) => {
            let wire_uri = proto_blue_syntax::AtUri::new(uri_str).map_err(|_| {
                MappingError::MalformedAtUri {
                    value: uri_str.clone(),
                }
            })?;
            wire::escalation::MainSubjectRefs::DollspacePolarisEscalationSubjectRecord(Box::new(
                wire::escalation::SubjectRecord {
                    uri: wire_uri,
                    cid: None,
                },
            ))
        }
    };

    let observations = escalation
        .observations
        .iter()
        .map(to_lexicon_embedded_observation)
        .collect::<Result<Vec<_>, _>>()?;

    let evidence = if escalation.evidence.is_empty() {
        None
    } else {
        Some(
            escalation
                .evidence
                .iter()
                .map(to_lexicon_evidence_pointer)
                .collect::<Result<Vec<_>, _>>()?,
        )
    };

    let created_at = proto_blue_syntax::Datetime::from_utc(escalation.created_at);

    Ok(wire::escalation::Main {
        r#type: wire::escalation::TYPE.to_owned(),
        source,
        target,
        subject,
        reason: escalation.reason.clone(),
        observations,
        evidence,
        created_at,
    })
}

/// Convert a wire `gay.dollspace.polaris.escalation#main` into an internal
/// [`Escalation`].
///
/// # Notes on `id`
///
/// The wire format has no `id` field — it is an internal Polaris identifier.
/// `from_lexicon_escalation` mints a fresh [`crate::ids::EscalationId`] for
/// the resulting struct so the internal type invariant (every `Escalation` has
/// an id) holds. Callers that persist the escalation to a database should
/// replace this generated id with the repo-assigned id immediately after
/// insertion.
///
/// # Errors
///
/// - [`MappingError::MissingRequired`] if the `subject` field contains the
///   catch-all `Other` arm.
/// - [`MappingError::MalformedDid`] if the `source` or `target` DID strings
///   have an unexpected format.
/// - [`MappingError::MalformedAtUri`] if a record-subject AT-URI is
///   malformed.
/// - [`MappingError::UnsupportedVariant`] if any embedded observation uses an
///   unknown discriminator.
/// - [`MappingError::FieldOutOfRange`] if any numeric field is out of range.
///
/// # Examples
///
/// ```rust
/// use polaris_types::escalation::{Escalation, SubjectRef};
/// use polaris_types::ids::{Did, EscalationId};
/// use polaris_types::lexicon_mapping::{to_lexicon_escalation, from_lexicon_escalation};
/// use chrono::Utc;
///
/// let orig = Escalation {
///     id: EscalationId::new(),
///     source_did: Did::new("did:plc:source"),
///     target_did: Did::new("did:plc:target"),
///     subject: SubjectRef::Did("did:plc:subject".to_owned()),
///     reason: "test".to_owned(),
///     observations: vec![],
///     evidence: vec![],
///     created_at: Utc::now(),
/// };
/// let wire = to_lexicon_escalation(&orig).unwrap();
/// let back = from_lexicon_escalation(wire).unwrap();
/// assert_eq!(orig.source_did, back.source_did);
/// assert_eq!(orig.reason, back.reason);
/// ```
#[must_use = "inspect the Ok value or propagate the Err"]
pub fn from_lexicon_escalation(
    wire: wire::escalation::Main,
) -> Result<Escalation, MappingError> {
    let source_did = Did::new(wire.source.as_str());
    let target_did = Did::new(wire.target.as_str());

    let subject = match wire.subject {
        wire::escalation::MainSubjectRefs::DollspacePolarisEscalationSubjectAccount(account) => {
            SubjectRef::Did(account.did.as_str().to_owned())
        }
        wire::escalation::MainSubjectRefs::DollspacePolarisEscalationSubjectRecord(record) => {
            SubjectRef::AtUri(record.uri.to_string())
        }
        wire::escalation::MainSubjectRefs::Other => {
            return Err(MappingError::MissingRequired { field: "subject" });
        }
    };

    let observations = wire
        .observations
        .into_iter()
        .map(from_lexicon_embedded_observation)
        .collect::<Result<Vec<_>, _>>()?;

    let evidence = wire
        .evidence
        .unwrap_or_default()
        .into_iter()
        .map(from_lexicon_evidence_pointer)
        .collect::<Result<Vec<_>, _>>()?;

    // Parse the ATProto Datetime back to chrono::DateTime<Utc>.
    let created_at = {
        let s = wire.created_at.as_str();
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .map_err(|_| MappingError::FieldOutOfRange {
                field: "created_at",
                value: s.to_owned(),
            })?
    };

    Ok(Escalation {
        // A fresh id is minted here because the wire format has no `id` field.
        // Callers persisting this escalation should replace it with the
        // repo-assigned id. See the `# Notes on id` section in the doc comment.
        id: crate::ids::EscalationId::new(),
        source_did,
        target_did,
        subject,
        reason: wire.reason,
        observations,
        evidence,
        created_at,
    })
}

// ── EscalationMessage (#110 / M5 #43 PR 4) ────────────────────────────────

/// Convert an internal [`EscalationMessage`] into its wire form for
/// publication via `gay.dollspace.polaris.escalationMessage`.
///
/// # Privacy boundary
///
/// Two internal-only fields are **silently dropped** at this boundary:
///
/// - `id: EscalationMessageId` — the local primary key assigned by the
///   receiving instance. Never federated.
/// - `signature_status: SignatureStatus` — the local verification verdict.
///   Computed by the receiving instance from the record's signature; never
///   present on the wire.
///
/// # Errors
///
/// Currently infallible — the function returns `Result` for forward-
/// compatibility with future fields that may require validation.
#[must_use = "the wire-form message is the value to publish; dropping it leaks the privacy strip"]
pub fn to_lexicon_escalation_message(
    msg: &EscalationMessage,
) -> Result<wire::escalation_message::Main, MappingError> {
    // privacy: EscalationMessageId never federated — `msg.id` is dropped here.
    // privacy: SignatureStatus never federated — `msg.signature_status` is dropped here.
    let escalation = proto_blue_syntax::AtUri::new(&msg.escalation_at_uri).map_err(|_| {
        MappingError::MalformedAtUri {
            value: msg.escalation_at_uri.clone(),
        }
    })?;
    let source = proto_blue_syntax::Did::new(&msg.source_did).map_err(|_| {
        MappingError::MalformedDid {
            value: msg.source_did.clone(),
        }
    })?;
    let signed_at = proto_blue_syntax::Datetime::from_utc(msg.signed_at);
    Ok(wire::escalation_message::Main {
        r#type: wire::escalation_message::TYPE.to_owned(),
        body: msg.body.clone(),
        escalation,
        signed_at,
        source,
    })
}

/// Convert an inbound wire `gay.dollspace.polaris.escalationMessage` record
/// into an internal [`EscalationMessage`].
///
/// # Post-conditions
///
/// - `id` is set to a freshly minted [`EscalationMessageId`] (the local PK
///   — never carried on the wire).
/// - `signature_status` is set to [`SignatureStatus::Unsigned`]. The caller
///   is responsible for updating this to [`SignatureStatus::Verified`] or
///   [`SignatureStatus::VerifyFailed`] after running the verifier.
///
/// # Errors
///
/// Returns [`MappingError::InvalidDatetime`] if `wire.signed_at` is not a
/// well-formed RFC 3339 timestamp.
pub fn from_lexicon_escalation_message(
    wire_msg: wire::escalation_message::Main,
) -> Result<EscalationMessage, MappingError> {
    let signed_at_str = wire_msg.signed_at.as_str().to_owned();
    let signed_at: DateTime<Utc> = DateTime::parse_from_rfc3339(&signed_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|source| MappingError::InvalidDatetime {
            value: signed_at_str,
            source,
        })?;

    Ok(EscalationMessage {
        id: EscalationMessageId::new(),
        // AtUri exposes its raw form via Display; no public as_str accessor.
        escalation_at_uri: wire_msg.escalation.to_string(),
        source_did: wire_msg.source.as_str().to_owned(),
        body: wire_msg.body,
        signed_at,
        signature_status: SignatureStatus::Unsigned,
    })
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
    use crate::escalation::{EmbeddedObservation, Escalation, SubjectRef};
    use crate::evidence::EvidencePointer;
    use crate::ids::{Did, EscalationId};
    use crate::observation::ObservationKind;

    fn utc_epoch() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0).unwrap()
    }

    fn sample_escalation() -> Escalation {
        Escalation {
            id: EscalationId::new(),
            source_did: Did::new("did:plc:source"),
            target_did: Did::new("did:plc:target"),
            subject: SubjectRef::Did("did:plc:subject".to_owned()),
            reason: "Coordinated inauthentic behavior".to_owned(),
            observations: vec![
                EmbeddedObservation {
                    confidence: 0.85,
                    observation: ObservationKind::ReplyBrigade {
                        thread_uri: "at://did:plc:x/app.bsky.feed.post/abc".to_owned(),
                    },
                },
                EmbeddedObservation {
                    confidence: 0.60,
                    observation: ObservationKind::ImageHashCluster {
                        hash: "deadbeef".to_owned(),
                        distance: 3,
                    },
                },
            ],
            evidence: vec![EvidencePointer {
                car_cid: "bafyreifoo".to_owned(),
                media_type: "application/vnd.ipld.car".to_owned(),
                byte_length: 1024,
            }],
            created_at: utc_epoch(),
        }
    }

    #[test]
    fn evidence_pointer_round_trips() {
        let ep = EvidencePointer {
            car_cid: "bafyreifoo".to_owned(),
            media_type: "application/vnd.ipld.car".to_owned(),
            byte_length: 4096,
        };
        let wire = to_lexicon_evidence_pointer(&ep).unwrap();
        assert_eq!(wire.byte_length, 4096_i64);
        let back = from_lexicon_evidence_pointer(wire).unwrap();
        assert_eq!(ep, back);
    }

    #[test]
    fn escalation_round_trip_source_target_reason() {
        let orig = sample_escalation();
        let wire = to_lexicon_escalation(&orig).unwrap();
        let back = from_lexicon_escalation(wire).unwrap();
        assert_eq!(orig.source_did, back.source_did);
        assert_eq!(orig.target_did, back.target_did);
        assert_eq!(orig.reason, back.reason);
        assert_eq!(orig.observations.len(), back.observations.len());
        assert_eq!(orig.evidence.len(), back.evidence.len());
    }

    #[test]
    fn escalation_id_not_in_wire_form() {
        let orig = sample_escalation();
        let wire = to_lexicon_escalation(&orig).unwrap();
        let wire_json = serde_json::to_string(&wire).unwrap();
        assert!(
            !wire_json.contains(&orig.id.to_string()),
            "id must not appear in wire JSON"
        );
    }

    #[test]
    fn confidence_scaling_round_trips() {
        for c in [0.0_f32, 0.5, 0.999, 1.0] {
            let scaled = confidence_to_wire(c);
            let back = confidence_from_wire(scaled);
            // Allow ±0.001 rounding error
            assert!(
                (c - back).abs() < 0.002,
                "confidence {c} → {scaled} → {back}: round-trip error too large"
            );
        }
    }

    #[test]
    fn report_volume_anomaly_rejected_at_to_wire() {
        let kind = ObservationKind::ReportVolumeAnomaly {
            category: "spam".to_owned(),
            z_score: 3.2,
        };
        let result = to_lexicon_observation_kind(&kind, 0.7);
        assert!(
            matches!(
                result,
                Err(MappingError::UnsupportedVariant {
                    discriminator: "report_volume_anomaly"
                })
            ),
            "expected UnsupportedVariant, got {result:?}"
        );
    }

    #[test]
    fn moderator_behavior_anomaly_rejected_at_to_wire() {
        let kind = ObservationKind::ModeratorBehaviorAnomaly {
            moderator_id: crate::ids::ModeratorId::new(),
            action_count: 100,
            window_secs: 3600,
        };
        let result = to_lexicon_observation_kind(&kind, 0.9);
        assert!(
            matches!(
                result,
                Err(MappingError::UnsupportedVariant {
                    discriminator: "moderator_behavior_anomaly"
                })
            ),
            "expected UnsupportedVariant, got {result:?}"
        );
    }

    #[test]
    fn subject_at_uri_round_trips() {
        let orig = Escalation {
            id: EscalationId::new(),
            source_did: Did::new("did:plc:source"),
            target_did: Did::new("did:plc:target"),
            subject: SubjectRef::AtUri(
                "at://did:plc:x/app.bsky.feed.post/3labc".to_owned(),
            ),
            reason: "record-level concern".to_owned(),
            observations: vec![],
            evidence: vec![],
            created_at: utc_epoch(),
        };
        let wire = to_lexicon_escalation(&orig).unwrap();
        let back = from_lexicon_escalation(wire).unwrap();
        assert!(matches!(back.subject, SubjectRef::AtUri(_)));
        assert_eq!(orig.subject.as_str(), back.subject.as_str());
    }

    #[test]
    fn classifier_signal_round_trips() {
        let obs = EmbeddedObservation {
            confidence: 0.77,
            observation: ObservationKind::ClassifierSignal {
                model: "spam-v2".to_owned(),
                label: "spam".to_owned(),
                confidence: 0.88,
            },
        };
        let wire = to_lexicon_embedded_observation(&obs).unwrap();
        let back = from_lexicon_embedded_observation(wire).unwrap();
        assert_eq!(obs.observation, back.observation);
    }
}
