//! Privacy-boundary enforcement tests for federation publish (issue #109, AC-4).
//!
//! These tests assert that the wire form produced by the publish path
//! (`OutboundPublisher::publish_escalation` → `to_lexicon_escalation`) does
//! not leak internal-only fields to the federation wire.
//!
//! # AC-4 requirement
//!
//! The serialized wire form must not contain:
//! - The internal `Escalation::id` (Polaris-internal primary key, never federated)
//! - Any `ObservationKind::ModeratorBehaviorAnomaly` data (carries `moderator_id`)
//! - Any `ObservationKind::ReportVolumeAnomaly` data (internal operator signal)
//!
//! The privacy boundary lives in `polaris_types::lexicon_mapping::to_lexicon_escalation`.
//! These tests verify the boundary is effective by:
//! 1. Building escalations that exercise each privacy-boundary rule.
//! 2. Asserting that the mapping function either strips the field silently
//!    (e.g. `id`) or returns a typed `MappingError` for internal-only variants.
//! 3. Verifying that the XRPC request body sent by `OutboundPublisher` does
//!    not contain any forbidden substrings (Test 4).
//!
//! The tests do NOT need a live PDS or a real signer — the privacy boundary
//! is in the mapping layer, before any network call.
//!
//! # Note on field scope
//!
//! The `Escalation` struct itself only carries fields that are safe to
//! federate — `moderator_id`, `audit_chain_hash`, `reporter_did`, and
//! `exposure_metadata` are never part of `Escalation`. They are excluded at
//! the *construction site* (where an `Incident` is converted to an
//! `Escalation`). The privacy tests here focus on what the mapping layer
//! additionally enforces (id-stripping, internal observation variants).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::items_after_statements,
    clippy::unnecessary_literal_bound,
    clippy::default_trait_access,
    reason = "integration test file — panics are the correct failure signal"
)]

use chrono::Utc;
use polaris_types::escalation::{EmbeddedObservation, Escalation, SubjectRef};
use polaris_types::ids::{Did, EscalationId, ModeratorId};
use polaris_types::lexicon_mapping::to_lexicon_escalation;
use polaris_types::observation::ObservationKind;

// ── Fixtures ────────────────────────────────────────────────────────────────

/// Build a safe, federation-ready `Escalation` with only public fields.
fn make_safe_escalation() -> Escalation {
    Escalation {
        id: EscalationId::new(),
        source_did: Did::new("did:plc:source_operator_instance"),
        target_did: Did::new("did:plc:target_operator_instance"),
        subject: SubjectRef::Did("did:plc:subject_account".to_owned()),
        reason: "subject is evading action across both instances".to_owned(),
        observations: vec![],
        evidence: vec![],
        created_at: Utc::now(),
    }
}

/// Build an `Escalation` with a `ModeratorBehaviorAnomaly` observation —
/// an internal-only variant that must never be federated.
fn make_escalation_with_moderator_anomaly() -> Escalation {
    Escalation {
        id: EscalationId::new(),
        source_did: Did::new("did:plc:source_operator_instance"),
        target_did: Did::new("did:plc:target_operator_instance"),
        subject: SubjectRef::Did("did:plc:subject_account".to_owned()),
        reason: "internal anomaly detected".to_owned(),
        observations: vec![EmbeddedObservation {
            confidence: 0.95,
            // privacy: ModeratorBehaviorAnomaly carries moderator_id — never federated
            observation: ObservationKind::ModeratorBehaviorAnomaly {
                moderator_id: ModeratorId::new(),
                action_count: 200,
                window_secs: 3600,
            },
        }],
        evidence: vec![],
        created_at: Utc::now(),
    }
}

/// Build an `Escalation` with a `ReportVolumeAnomaly` observation —
/// another internal-only variant.
fn make_escalation_with_report_volume_anomaly() -> Escalation {
    Escalation {
        id: EscalationId::new(),
        source_did: Did::new("did:plc:source_operator_instance"),
        target_did: Did::new("did:plc:target_operator_instance"),
        subject: SubjectRef::Did("did:plc:subject_account".to_owned()),
        reason: "internal volume spike".to_owned(),
        observations: vec![EmbeddedObservation {
            confidence: 0.8,
            // privacy: ReportVolumeAnomaly carries internal operator signal — never federated
            observation: ObservationKind::ReportVolumeAnomaly {
                category: "spam".to_owned(),
                z_score: 4.1,
            },
        }],
        evidence: vec![],
        created_at: Utc::now(),
    }
}

// ── Test 1: Escalation id must not appear in the wire form ───────────────────

/// AC-4: The internal `Escalation::id` must not appear anywhere in the
/// serialized wire record.
///
/// The `id` is a Polaris-internal primary key used for routing and audit
/// on the source instance. A foreign operator must never be able to
/// correlate it with internal case management data.
#[test]
fn wire_form_does_not_contain_internal_id() {
    let esc = make_safe_escalation();
    let id_str = esc.id.to_string();

    let wire = to_lexicon_escalation(&esc).expect("safe escalation must map without error");
    let wire_json = serde_json::to_string(&wire).expect("wire form must be JSON-serializable");

    assert!(
        !wire_json.contains(&id_str),
        "wire JSON must not contain the internal EscalationId ({id_str}); got: {wire_json}",
    );
}

// ── Test 2: ModeratorBehaviorAnomaly causes MappingError ─────────────────────

/// AC-4: `ObservationKind::ModeratorBehaviorAnomaly` must cause a typed
/// `MappingError::UnsupportedVariant` — not silently pass through.
///
/// This observation variant carries a `moderator_id` that identifies an
/// internal operator. If it passed through to the wire, the target instance
/// could infer moderator identities from the observation data.
#[test]
fn moderator_behavior_anomaly_observation_is_rejected_by_mapping() {
    let esc = make_escalation_with_moderator_anomaly();
    let result = to_lexicon_escalation(&esc);
    assert!(
        result.is_err(),
        "ModeratorBehaviorAnomaly must cause a mapping error, not succeed"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            polaris_types::lexicon_mapping::MappingError::UnsupportedVariant {
                discriminator: "moderator_behavior_anomaly"
            }
        ),
        "expected UnsupportedVariant for moderator_behavior_anomaly, got {err:?}",
    );
}

// ── Test 3: ReportVolumeAnomaly causes MappingError ──────────────────────────

/// AC-4: `ObservationKind::ReportVolumeAnomaly` must cause a typed
/// `MappingError::UnsupportedVariant` — not silently pass through.
///
/// This observation variant carries internal operator signal (report category
/// and volume statistics) that should not be shared with peer instances.
#[test]
fn report_volume_anomaly_observation_is_rejected_by_mapping() {
    let esc = make_escalation_with_report_volume_anomaly();
    let result = to_lexicon_escalation(&esc);
    assert!(
        result.is_err(),
        "ReportVolumeAnomaly must cause a mapping error, not succeed"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(
            err,
            polaris_types::lexicon_mapping::MappingError::UnsupportedVariant {
                discriminator: "report_volume_anomaly"
            }
        ),
        "expected UnsupportedVariant for report_volume_anomaly, got {err:?}",
    );
}

// ── Test 4: public fields ARE present (sanity / regression guard) ─────────────

/// Sanity check: verify that the mapping layer does NOT strip fields that
/// should be present in the wire form.
///
/// A stripper that removes all fields would trivially pass Tests 1–3.
/// This test ensures the non-sensitive fields survive the mapping.
#[test]
fn wire_form_contains_expected_public_fields() {
    let esc = make_safe_escalation();
    let source_did = esc.source_did.0.clone();
    let target_did = esc.target_did.0.clone();
    let reason = esc.reason.clone();

    let wire = to_lexicon_escalation(&esc).expect("safe escalation must map without error");
    let wire_json = serde_json::to_string(&wire).expect("wire form must be JSON-serializable");

    assert!(
        wire_json.contains(&source_did),
        "wire JSON must contain source_did ({source_did}); got: {wire_json}",
    );
    assert!(
        wire_json.contains(&target_did),
        "wire JSON must contain target_did ({target_did}); got: {wire_json}",
    );
    assert!(
        wire_json.contains(&reason),
        "wire JSON must contain reason ({reason}); got: {wire_json}",
    );
}

// ── Test 5: publish path sends only public fields in XRPC body ───────────────

/// Verify that `OutboundPublisher::publish_escalation` calls the mapping
/// layer before invoking the XRPC transport, and that the request body
/// recorded by the mock transport does not contain the internal id.
///
/// This test uses a `RecordingFetcher` that captures the serialised request
/// body and asserts the privacy-sensitive EscalationId substring is absent.
#[tokio::test]
async fn publish_path_body_does_not_contain_internal_id() {
    use std::sync::{Arc, Mutex};

    use polaris_backend::federation::publish::OutboundPublisher;
    use polaris_backend::labeler::signer::{Signature, SigningError, SigningKey};
    use tokio::sync::watch;

    // ── Signer ────────────────────────────────────────────────────────
    struct NoopSigner;
    impl std::fmt::Debug for NoopSigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "NoopSigner")
        }
    }
    impl SigningKey for NoopSigner {
        fn sign(&self, _: &[u8]) -> Result<Signature, SigningError> {
            Ok(Signature([0u8; 64]))
        }
        fn public_key_did(&self) -> &str {
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }
    }

    let signer: Arc<dyn SigningKey> = Arc::new(NoopSigner);
    let (_tx, rx) = watch::channel(signer);

    // ── Recording mock fetcher ────────────────────────────────────────
    #[derive(Clone)]
    struct RecordingFetcher {
        recorded: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl proto_blue::common::fetch::FetchHandler for RecordingFetcher {
        async fn fetch(
            &self,
            req: proto_blue::common::fetch::HttpRequest,
        ) -> Result<proto_blue::common::fetch::HttpResponse, proto_blue::common::fetch::FetchError>
        {
            if let Some(body) = req.body {
                self.recorded.lock().unwrap().push(body);
            }
            // Return a minimal createRecord response with the correct
            // content-type so the XRPC client parses it as JSON.
            let response_bytes = br#"{"uri":"at://did:plc:source/gay.dollspace.polaris.escalation/fake","cid":"bafyreifake","validationStatus":"valid"}"#.to_vec();
            let mut headers = std::collections::BTreeMap::new();
            headers.insert("content-type".to_owned(), "application/json".to_owned());
            Ok(proto_blue::common::fetch::HttpResponse {
                status: 200,
                headers,
                body: response_bytes,
            })
        }
    }

    let recorded = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let fetcher = RecordingFetcher {
        recorded: Arc::clone(&recorded),
    };
    let xrpc = Arc::new(
        proto_blue::xrpc::XrpcClient::with_fetch_handler("https://bsky.social", Arc::new(fetcher))
            .unwrap(),
    );

    let publisher = OutboundPublisher::new(
        rx,
        xrpc,
        Some("did:plc:source_operator_instance".to_owned()),
    );

    let esc = make_safe_escalation();
    let id_str = esc.id.to_string();

    // Publish — we expect success (mock returns a valid CID).
    let result = publisher.publish_escalation(&esc).await;
    assert!(
        result.is_ok(),
        "publish_escalation must succeed against the mock fetcher: {result:?}"
    );

    // Inspect every recorded request body.
    let bodies = recorded.lock().unwrap();
    assert!(
        !bodies.is_empty(),
        "at least one XRPC request must have been recorded"
    );
    for body in bodies.iter() {
        let body_str = String::from_utf8_lossy(body);
        assert!(
            !body_str.contains(&id_str),
            "request body must not contain the internal EscalationId ({id_str}); \
             got: {body_str}",
        );
    }
}
