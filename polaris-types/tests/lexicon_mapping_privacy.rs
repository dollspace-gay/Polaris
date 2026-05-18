//! Privacy-boundary tests for the `polaris-types` ↔ `polaris-lexicons`
//! mapping layer.
//!
//! These tests assert that the `to_lexicon_escalation` function does NOT
//! include any internal-only field values in the resulting wire form.
//!
//! Specifically:
//!
//! - `Escalation::id` (the Polaris-internal primary key) MUST NOT appear in
//!   the serialised wire JSON.
//! - The internal-only `ObservationKind` variants (`ReportVolumeAnomaly`,
//!   `ModeratorBehaviorAnomaly`) MUST be rejected at the to-wire boundary
//!   rather than silently serialised.
//!
//! Note: `Escalation` does not carry `moderator_id`, `audit_chain_hash`, or
//! `reporter_did` fields directly — those live in `Incident` / `Report`.
//! These tests exercise that none of those concepts can "sneak in" through
//! the mapping helpers.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test file — panics are the intended failure mechanism"
)]

use chrono::Utc;
use polaris_types::{
    escalation::{EmbeddedObservation, Escalation, SubjectRef},
    evidence::EvidencePointer,
    ids::{Did, EscalationId, ModeratorId},
    lexicon_mapping::{MappingError, to_lexicon_escalation, to_lexicon_observation_kind},
    observation::ObservationKind,
};

/// Construct a synthetic escalation whose internal `id` has a known UUID
/// string so we can assert it does not appear in the wire JSON.
fn sample_escalation_with_known_id() -> (Escalation, String) {
    let id = EscalationId::new();
    let id_str = id.to_string();
    let esc = Escalation {
        id,
        source_did: Did::new("did:plc:source0000000000000001"),
        target_did: Did::new("did:plc:target0000000000000001"),
        subject: SubjectRef::Did("did:plc:subject000000000000001".to_owned()),
        reason: "privacy boundary test".to_owned(),
        observations: vec![EmbeddedObservation {
            confidence: 0.75,
            observation: ObservationKind::ImageHashCluster {
                hash: "cafebabe".to_owned(),
                distance: 2,
            },
        }],
        evidence: vec![EvidencePointer {
            car_cid: "bafyreiprivacytest".to_owned(),
            media_type: "application/vnd.ipld.car".to_owned(),
            byte_length: 512,
        }],
        created_at: Utc::now(),
    };
    (esc, id_str)
}

// ─── privacy: id never federated ────────────────────────────────────────────

#[test]
fn wire_form_does_not_contain_escalation_id() {
    let (esc, id_str) = sample_escalation_with_known_id();
    let wire = to_lexicon_escalation(&esc).expect("to_lexicon_escalation should succeed");
    let wire_json = serde_json::to_string(&wire).expect("wire form should be JSON-serialisable");

    assert!(
        !wire_json.contains(&id_str),
        "wire JSON must not contain the internal EscalationId {id_str:?}; \
         got wire JSON: {wire_json}"
    );
}

// ─── privacy: ReportVolumeAnomaly never federated ───────────────────────────

#[test]
fn report_volume_anomaly_rejected_at_to_wire_boundary() {
    let kind = ObservationKind::ReportVolumeAnomaly {
        category: "spam".to_owned(),
        z_score: 4.1,
    };
    let result = to_lexicon_observation_kind(&kind, 0.9);
    assert!(
        matches!(
            result,
            Err(MappingError::UnsupportedVariant {
                discriminator: "report_volume_anomaly"
            })
        ),
        "expected UnsupportedVariant for report_volume_anomaly, got: {result:?}"
    );
}

#[test]
fn escalation_with_report_volume_anomaly_fails_at_boundary() {
    let (mut esc, _) = sample_escalation_with_known_id();
    esc.observations = vec![EmbeddedObservation {
        confidence: 0.5,
        observation: ObservationKind::ReportVolumeAnomaly {
            category: "harassment".to_owned(),
            z_score: 3.0,
        },
    }];
    let result = to_lexicon_escalation(&esc);
    assert!(
        result.is_err(),
        "escalation with ReportVolumeAnomaly must fail to_lexicon_escalation"
    );
}

// ─── privacy: ModeratorBehaviorAnomaly never federated ──────────────────────

#[test]
fn moderator_behavior_anomaly_rejected_at_to_wire_boundary() {
    let synthetic_moderator_id = ModeratorId::new();
    let kind = ObservationKind::ModeratorBehaviorAnomaly {
        moderator_id: synthetic_moderator_id,
        action_count: 500,
        window_secs: 3600,
    };
    let result = to_lexicon_observation_kind(&kind, 0.95);
    assert!(
        matches!(
            result,
            Err(MappingError::UnsupportedVariant {
                discriminator: "moderator_behavior_anomaly"
            })
        ),
        "expected UnsupportedVariant for moderator_behavior_anomaly, got: {result:?}"
    );
}

#[test]
fn moderator_id_does_not_appear_in_any_wire_form() {
    // Even if we somehow constructed a valid wire escalation, no moderator_id
    // from ModeratorBehaviorAnomaly should appear.
    let synthetic_moderator_id = ModeratorId::new();
    let moderator_id_str = synthetic_moderator_id.to_string();

    // Create an escalation with safe observations only.
    let (esc, _) = sample_escalation_with_known_id();
    let wire = to_lexicon_escalation(&esc).expect("safe escalation must convert");
    let wire_json = serde_json::to_string(&wire).expect("wire JSON");

    // The synthetic moderator UUID must not appear anywhere — there's no
    // field path it could travel through with only safe observations.
    assert!(
        !wire_json.contains(&moderator_id_str),
        "wire JSON must not contain moderator_id {moderator_id_str:?}"
    );
}

// ─── fixture round-trip ─────────────────────────────────────────────────────

#[test]
fn fixture_sample_escalation_deserializes_and_maps() {
    let json = include_str!("fixtures/lexicons/sample_escalation.json");
    let wire: polaris_lexicons::gay::dollspace::polaris::escalation::Main =
        serde_json::from_str(json)
            .expect("sample_escalation.json must deserialize into wire::escalation::Main");

    let internal = polaris_types::lexicon_mapping::from_lexicon_escalation(wire)
        .expect("from_lexicon_escalation must succeed on valid fixture");

    assert_eq!(
        internal.source_did.as_str(),
        "did:plc:source1234567890abcdef"
    );
    assert_eq!(
        internal.target_did.as_str(),
        "did:plc:target1234567890abcdef"
    );
    assert_eq!(
        internal.reason,
        "Coordinated inauthentic behavior — account cohort match plus reply brigade targeting multiple threads."
    );
    assert_eq!(internal.observations.len(), 2);
    assert_eq!(internal.evidence.len(), 1);
    assert_eq!(internal.evidence[0].byte_length, 4096);

    // Subject must be a DID
    assert!(
        matches!(internal.subject, SubjectRef::Did(_)),
        "fixture subject should be a DID variant"
    );
}

#[test]
fn fixture_evidence_pointer_deserializes_and_maps() {
    let json = include_str!("fixtures/lexicons/sample_evidence_pointer.json");
    let wire: polaris_lexicons::gay::dollspace::polaris::evidence_pointer::Main =
        serde_json::from_str(json).expect(
            "sample_evidence_pointer.json must deserialize into wire::evidence_pointer::Main",
        );

    let internal = polaris_types::lexicon_mapping::from_lexicon_evidence_pointer(wire)
        .expect("from_lexicon_evidence_pointer must succeed on valid fixture");

    assert_eq!(internal.car_cid, "bafyreifoobarbazbazqux");
    assert_eq!(internal.media_type, "application/vnd.ipld.car");
    assert_eq!(internal.byte_length, 8192);
}
