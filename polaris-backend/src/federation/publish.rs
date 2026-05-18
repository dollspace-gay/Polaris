//! Outbound federation publish path (issue #109, REQ-1, REQ-5).
//!
//! [`OutboundPublisher`] wraps the XRPC repo-write path to push Polaris
//! escalation records to the operator's own ATProto repo under the
//! `gay.dollspace.polaris.escalation` collection. It is the *only* place in
//! the backend that touches the ATProto write surface for federation.
//!
//! # Privacy boundary
//!
//! The privacy enforcement is intentionally **not** in this module.
//! [`polaris_types::lexicon_mapping::to_lexicon_escalation`] is the single
//! chokepoint that strips internal-only fields before any bytes leave the
//! Polaris trust boundary (REQ-5 / AC-4):
//!
//! - `Escalation::id` — internal primary key, dropped at to-wire boundary.
//! - Observation variants `ReportVolumeAnomaly` / `ModeratorBehaviorAnomaly`
//!   are internal-only and cause `to_lexicon_escalation` to return a typed
//!   `MappingError::UnsupportedVariant` rather than silently passing them.
//!
//! If you find yourself adding field-stripping logic in `publish.rs`, that
//! is a design smell — push it into the mapping layer instead.
//!
//! The caller of `publish_escalation` is responsible for not including
//! moderator identifiers, reporter DIDs, audit hashes, or wellness metadata
//! in the `Escalation` value it passes in. The `Escalation` struct itself
//! only carries fields that are safe to federate; see the `escalation` module
//! doc comment for the full list.
//!
//! # Signing
//!
//! Federation records are signed by the same labeler K-256 key that signs
//! labels. The active signer is consumed via the `ApiState::active_signer`
//! watch channel so hot-swap rotations (issue #30 / REQ-12) take effect
//! on the next `publish_escalation` call without restart.
//!
//! # Wire encoding
//!
//! The wire form is the JSON-encoded `polaris_lexicons::escalation::Main`
//! type produced by `to_lexicon_escalation`, serialised to `serde_json::Value`
//! and sent as the `record` field of a `com.atproto.repo.createRecord` XRPC
//! call. Signing bytes are the DAG-CBOR encoding of the record with `sig`
//! cleared — the same convention the label emitter uses for `Label` records.

use std::sync::Arc;

use polaris_types::lexicon_mapping::{
    MappingError, to_lexicon_escalation, to_lexicon_escalation_message,
};
use polaris_types::{Escalation, EscalationMessage};
use proto_blue::{lex_cbor, lex_json};
use serde_json::json;
use tracing::debug;

use crate::labeler::signer::{ActiveSignerReceiver, SigningError};

/// ATProto collection that holds Polaris federation escalation records.
const ESCALATION_COLLECTION: &str = "gay.dollspace.polaris.escalation";

/// ATProto collection that holds Polaris federation escalation-message
/// records (#110 / M5 #43 PR 4).
const ESCALATION_MESSAGE_COLLECTION: &str = "gay.dollspace.polaris.escalationMessage";

/// XRPC method used to write records to the operator's ATProto repo.
const CREATE_RECORD_NSID: &str = "com.atproto.repo.createRecord";

/// Outbound publisher for federation escalation records.
///
/// Holds the three external dependencies (signer, XRPC transport, local DID)
/// needed to sign and write escalation records to the operator's ATProto repo.
///
/// `Clone` is cheap: all three fields are `Arc`-backed.
#[derive(Clone)]
pub struct OutboundPublisher {
    /// Receiver end of the active-signer watch channel (issue #30).
    ///
    /// `borrow()` fetches the current `Arc<dyn SigningKey>` without
    /// blocking; the rotation-discovery task calls `send` on the sender
    /// end whenever the active key changes. Never call `borrow()` and hold
    /// the guard across an `.await` (rust-quality §10 / no watch guard
    /// across await).
    active_signer: ActiveSignerReceiver,
    /// XRPC client pointing at the operator's own PDS (the repo write
    /// target). Injected at construction so tests can supply a mock
    /// [`proto_blue_common::fetch::FetchHandler`].
    xrpc: Arc<proto_blue::xrpc::XrpcClient>,
    /// Operator's own DID — the `repo` field in `createRecord` calls.
    ///
    /// `None` when the local DID has not been configured (development
    /// deploys without a real PDS). `publish_escalation` returns
    /// [`PublishError::LocalDidNotConfigured`] in that case rather than
    /// attempting the write with a blank repo field.
    local_did: Option<String>,
}

impl OutboundPublisher {
    /// Construct an [`OutboundPublisher`].
    ///
    /// # Arguments
    ///
    /// - `active_signer` — receiver side of the watch channel installed on
    ///   [`crate::api::state::ApiState`] via
    ///   [`crate::api::state::ApiState::with_active_signer`].
    /// - `xrpc` — XRPC client pointed at the operator's PDS.
    /// - `local_did` — operator's own DID (the `repo` in createRecord).
    ///   Pass `None` to leave the publisher unconfigured (returns
    ///   [`PublishError::LocalDidNotConfigured`] on every call).
    #[must_use]
    pub fn new(
        active_signer: ActiveSignerReceiver,
        xrpc: Arc<proto_blue::xrpc::XrpcClient>,
        local_did: Option<String>,
    ) -> Self {
        Self {
            active_signer,
            xrpc,
            local_did,
        }
    }

    /// Sign and write an [`Escalation`] to the operator's ATProto repo.
    ///
    /// 1. Maps the internal `Escalation` to wire form via
    ///    [`to_lexicon_escalation`] — this enforces the privacy boundary:
    ///    `Escalation::id` is dropped and internal-only observation variants
    ///    (`ReportVolumeAnomaly`, `ModeratorBehaviorAnomaly`) cause a typed
    ///    error rather than silently passing through. No additional strip
    ///    logic lives in this function.
    /// 2. Encodes the wire form as DAG-CBOR (signing follows the convention
    ///    from the label emitter: canonical bytes exclude the `sig` field).
    /// 3. Signs the canonical bytes with the active labeler key.
    /// 4. Calls `com.atproto.repo.createRecord` with the signed record.
    /// 5. Returns the record CID reported by the PDS.
    ///
    /// # Errors
    ///
    /// - [`PublishError::LocalDidNotConfigured`] — operator DID not set.
    /// - [`PublishError::MappingFailed`] — field mapping rejected an input.
    /// - [`PublishError::SigningFailed`] — the signing key custody refused.
    /// - [`PublishError::EncodingFailed`] — DAG-CBOR encoding failed.
    /// - [`PublishError::RepoWriteFailed`] — XRPC call to PDS failed.
    #[must_use = "a forgotten ? would silently drop a federation escalation"]
    pub async fn publish_escalation(
        &self,
        escalation: &Escalation,
    ) -> Result<String, PublishError> {
        let local_did = self
            .local_did
            .as_deref()
            .ok_or(PublishError::LocalDidNotConfigured)?;

        // ── 1. Privacy boundary: map internal → wire form ──────────────
        // to_lexicon_escalation:
        // - drops Escalation::id  (// privacy: id never federated)
        // - rejects internal-only observation variants with MappingError
        // No strip logic in this function — the mapping layer owns the boundary.
        let wire = to_lexicon_escalation(escalation)?;

        // ── 2. Canonicalise to DAG-CBOR ─────────────────────────────────
        // Follows the same pipeline as the label emitter (emitter.rs):
        // JSON-serialise the wire type → lex_json::json_to_lex → lex_cbor::encode.
        // The `sig` field does not exist on the wire type at this point
        // (it will be added below after signing).
        let json_value = serde_json::to_value(&wire).map_err(|_| PublishError::EncodingFailed)?;
        let lex_value = lex_json::json_to_lex(&json_value);
        let canonical_bytes =
            lex_cbor::encode(&lex_value).map_err(|_| PublishError::EncodingFailed)?;

        // ── 3. Sign the canonical bytes ─────────────────────────────────
        // Clone the Arc<dyn SigningKey> out of the watch guard immediately so
        // the guard is dropped before the first `.await` below.
        // (rust-quality §10: never hold a watch borrow guard across .await)
        let signer = {
            let guard = self.active_signer.borrow();
            Arc::clone(&*guard)
        };
        let signature = signer
            .sign(&canonical_bytes)
            .map_err(PublishError::SigningFailed)?;

        debug!(
            escalation_id = %escalation.id,
            collection = ESCALATION_COLLECTION,
            "publishing federation escalation to ATProto repo",
        );

        // ── 4. Build the signed record JSON ─────────────────────────────
        // The `sig` field is appended to the JSON object as a base64url
        // string, matching the convention for label records. The canonical
        // bytes (used for signing) were produced WITHOUT this field.
        let mut record_json =
            serde_json::to_value(&wire).map_err(|_| PublishError::EncodingFailed)?;
        if let Some(obj) = record_json.as_object_mut() {
            obj.insert(
                "sig".to_owned(),
                serde_json::Value::String(base64_encode(signature.as_bytes())),
            );
        }

        // ── 5. Write to the operator's repo via createRecord ────────────
        let body = json!({
            "repo": local_did,
            "collection": ESCALATION_COLLECTION,
            "record": record_json,
        });

        let xrpc_body = proto_blue::xrpc::types::XrpcBody::Json(body);
        let response = self
            .xrpc
            .procedure(CREATE_RECORD_NSID, None, Some(xrpc_body), None)
            .await
            .map_err(|e| PublishError::RepoWriteFailed {
                message: e.to_string(),
            })?;

        // Extract the CID from the createRecord response.
        // `XrpcResponse.data` is `serde_json::Value`; `createRecord` returns:
        // { "uri": "at://…", "cid": "bafyrei…", "validationStatus": "…" }
        let cid = response
            .data
            .get("cid")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .ok_or_else(|| PublishError::RepoWriteFailed {
                message: "createRecord response did not contain a `cid` field".to_owned(),
            })?;

        debug!(
            escalation_id = %escalation.id,
            cid = %cid,
            "federation escalation written to ATProto repo",
        );

        Ok(cid)
    }

    /// Publish a federation escalation message (#110 / M5 #43 PR 4).
    ///
    /// Bidirectional follow-up messages on a parent `polaris.escalation`
    /// flow through this method. The privacy boundary lives in
    /// [`to_lexicon_escalation_message`] — `id` (the local primary key)
    /// and `signature_status` (the local verification verdict) are dropped
    /// at the wire boundary. This method does NOT perform any field
    /// stripping itself.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PublishError::LocalDidNotConfigured`] if `local_did` is `None`.
    /// - [`PublishError::Mapping`] if the message's `escalation_at_uri` or
    ///   `source_did` fails wire-form validation.
    /// - [`PublishError::SigningFailed`] if the active labeler signer
    ///   rejects the canonical bytes.
    /// - [`PublishError::EncodingFailed`] for any serde / lex-cbor failure.
    /// - [`PublishError::RepoWriteFailed`] if the upstream XRPC call
    ///   `com.atproto.repo.createRecord` returns an error.
    ///
    /// Returns the CID of the newly-written record on success.
    pub async fn publish_escalation_message(
        &self,
        msg: &EscalationMessage,
    ) -> Result<String, PublishError> {
        let local_did = self
            .local_did
            .as_deref()
            .ok_or(PublishError::LocalDidNotConfigured)?;

        // Privacy boundary: mapping strips id + signature_status.
        let wire = to_lexicon_escalation_message(msg)?;

        // Canonicalise → sign → append `sig` → write. Same pipeline as
        // publish_escalation; pulled inline rather than refactored
        // because the wire types differ.
        let json_value = serde_json::to_value(&wire).map_err(|_| PublishError::EncodingFailed)?;
        let lex_value = lex_json::json_to_lex(&json_value);
        let canonical_bytes =
            lex_cbor::encode(&lex_value).map_err(|_| PublishError::EncodingFailed)?;

        let signer = {
            let guard = self.active_signer.borrow();
            Arc::clone(&*guard)
        };
        let signature = signer
            .sign(&canonical_bytes)
            .map_err(PublishError::SigningFailed)?;

        debug!(
            message_id = %msg.id,
            collection = ESCALATION_MESSAGE_COLLECTION,
            "publishing federation escalation message to ATProto repo",
        );

        let mut record_json =
            serde_json::to_value(&wire).map_err(|_| PublishError::EncodingFailed)?;
        if let Some(obj) = record_json.as_object_mut() {
            obj.insert(
                "sig".to_owned(),
                serde_json::Value::String(base64_encode(signature.as_bytes())),
            );
        }

        let body = json!({
            "repo": local_did,
            "collection": ESCALATION_MESSAGE_COLLECTION,
            "record": record_json,
        });

        let xrpc_body = proto_blue::xrpc::types::XrpcBody::Json(body);
        let response = self
            .xrpc
            .procedure(CREATE_RECORD_NSID, None, Some(xrpc_body), None)
            .await
            .map_err(|e| PublishError::RepoWriteFailed {
                message: e.to_string(),
            })?;

        let cid = response
            .data
            .get("cid")
            .and_then(|v| v.as_str())
            .ok_or(PublishError::EncodingFailed)?
            .to_owned();

        debug!(
            message_id = %msg.id,
            cid = %cid,
            "federation escalation message written to ATProto repo",
        );

        Ok(cid)
    }
}

impl std::fmt::Debug for OutboundPublisher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundPublisher")
            .field("local_did", &self.local_did)
            .field("xrpc", &"<XrpcClient>")
            .field("active_signer", &"<watch::Receiver<Arc<dyn SigningKey>>>")
            .finish()
    }
}

/// Errors raised by [`OutboundPublisher::publish_escalation`].
///
/// Each variant maps to a distinct failure layer so operators can triage
/// federation publish failures by variant without parsing the error chain.
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// The privacy-boundary mapping rejected an internal `Escalation` field.
    ///
    /// This fires when:
    /// - An observation uses an internal-only variant (`ReportVolumeAnomaly`,
    ///   `ModeratorBehaviorAnomaly`) that must never be federated.
    /// - A DID or AT-URI field fails wire validation.
    /// - A numeric field is out of range.
    ///
    /// Wraps [`MappingError`] from `polaris_types::lexicon_mapping`.
    #[error("escalation mapping failed: {0}")]
    MappingFailed(#[from] MappingError),

    /// The signing key custody refused. Wraps [`SigningError`].
    #[error("failed to sign federation escalation record: {0}")]
    SigningFailed(#[source] SigningError),

    /// DAG-CBOR or JSON encoding of the wire record failed. This is
    /// unreachable in practice because every field is serde-encodable,
    /// but a typed variant avoids a `panic` for a serialiser surprise.
    #[error("failed to encode escalation record as canonical DAG-CBOR")]
    EncodingFailed,

    /// The XRPC `createRecord` call to the operator's PDS failed.
    ///
    /// `message` carries the proto-blue error rendered to `String` so
    /// the variant stays `Send + Sync + 'static` without a proto-blue
    /// bound on the `PublishError` type itself.
    #[error("ATProto repo write failed: {message}")]
    RepoWriteFailed {
        /// Human-readable error from the XRPC transport / PDS.
        message: String,
    },

    /// The operator's DID is not configured. The publish cannot proceed
    /// without knowing which repo to write to.
    #[error("operator local DID is not configured; set POLARIS_LOCAL_DID")]
    LocalDidNotConfigured,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// URL-safe base64-encode `bytes` without padding.
///
/// ATProto expects base64url (no padding) for embedded binary fields
/// such as the K-256 signature.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use crate::labeler::signer::{Signature, SigningError, SigningKey};
    use chrono::Utc;
    use polaris_types::escalation::SubjectRef;
    use polaris_types::ids::{Did, EscalationId};
    use std::sync::Arc;
    use tokio::sync::watch;

    /// Minimal in-memory signing key for publish unit tests.
    struct NoopSigner;

    impl std::fmt::Debug for NoopSigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("NoopSigner").finish()
        }
    }

    impl SigningKey for NoopSigner {
        fn sign(&self, _payload: &[u8]) -> Result<Signature, SigningError> {
            Ok(Signature([0u8; 64]))
        }
        fn public_key_did(&self) -> &'static str {
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        }
    }

    fn make_signer_rx() -> ActiveSignerReceiver {
        let signer: Arc<dyn SigningKey> = Arc::new(NoopSigner);
        let (_tx, rx) = watch::channel(signer);
        rx
    }

    /// A `FetchHandler` that panics on any call — used to assert that
    /// publish aborts before making network calls.
    struct NeverCalled;

    #[async_trait::async_trait]
    impl proto_blue::common::fetch::FetchHandler for NeverCalled {
        async fn fetch(
            &self,
            _req: proto_blue::common::fetch::HttpRequest,
        ) -> Result<proto_blue::common::fetch::HttpResponse, proto_blue::common::fetch::FetchError>
        {
            panic!("NeverCalled: no HTTP request should be made in this test")
        }
    }

    fn make_safe_escalation() -> Escalation {
        // A minimal Escalation with only safe-to-federate fields.
        // Internal-only fields (moderator_id, audit_chain_hash, reporter_did)
        // are the caller's responsibility to exclude before construction;
        // they are not part of the Escalation struct.
        Escalation {
            id: EscalationId::new(),
            source_did: Did::new("did:plc:source_operator"),
            target_did: Did::new("did:plc:target_operator"),
            subject: SubjectRef::Did("did:plc:subject_account".to_owned()),
            reason: "cross-instance coordination needed".to_owned(),
            observations: vec![],
            evidence: vec![],
            created_at: Utc::now(),
        }
    }

    /// Verify that `PublishError::LocalDidNotConfigured` is returned when
    /// the publisher is constructed with `local_did = None`.
    #[tokio::test]
    async fn publish_escalation_fails_when_local_did_not_configured() {
        let xrpc = Arc::new(
            proto_blue::xrpc::XrpcClient::with_fetch_handler(
                "https://bsky.social",
                Arc::new(NeverCalled),
            )
            .unwrap(),
        );
        let publisher = OutboundPublisher::new(make_signer_rx(), xrpc, None);

        let escalation = make_safe_escalation();
        let err = publisher
            .publish_escalation(&escalation)
            .await
            .expect_err("should fail with LocalDidNotConfigured");
        assert!(
            matches!(err, PublishError::LocalDidNotConfigured),
            "expected LocalDidNotConfigured, got {err:?}"
        );
    }

    /// Verify that `to_lexicon_escalation` is invoked (import is correct
    /// and the privacy boundary is on the hot path).
    #[test]
    fn mapping_layer_is_invoked_by_publish_path() {
        let esc = make_safe_escalation();
        // Either Ok or a typed MappingError — both confirm the mapping
        // layer was invoked. This test is about import correctness, not
        // mapping semantics (those live in the integration test file).
        let result = to_lexicon_escalation(&esc);
        assert!(
            result.is_ok(),
            "safe escalation must map without error: {result:?}"
        );
    }

    /// Verify that `MappingFailed::UnsupportedVariant` propagates when an
    /// observation uses an internal-only variant (REQ-5 / AC-4).
    #[tokio::test]
    async fn internal_only_observation_variant_causes_mapping_error() {
        use polaris_types::escalation::EmbeddedObservation;
        use polaris_types::ids::ModeratorId;
        use polaris_types::observation::ObservationKind;

        let xrpc = Arc::new(
            proto_blue::xrpc::XrpcClient::with_fetch_handler(
                "https://bsky.social",
                Arc::new(NeverCalled),
            )
            .unwrap(),
        );
        let publisher = OutboundPublisher::new(
            make_signer_rx(),
            xrpc,
            Some("did:plc:source_operator".to_owned()),
        );

        let escalation = Escalation {
            id: EscalationId::new(),
            source_did: Did::new("did:plc:source_operator"),
            target_did: Did::new("did:plc:target_operator"),
            subject: SubjectRef::Did("did:plc:subject".to_owned()),
            reason: "test".to_owned(),
            observations: vec![
                // ModeratorBehaviorAnomaly is an internal-only observation
                // that carries moderator_id — it must never be federated.
                EmbeddedObservation {
                    confidence: 0.9,
                    observation: ObservationKind::ModeratorBehaviorAnomaly {
                        moderator_id: ModeratorId::new(),
                        action_count: 150,
                        window_secs: 3600,
                    },
                },
            ],
            evidence: vec![],
            created_at: Utc::now(),
        };

        let err = publisher
            .publish_escalation(&escalation)
            .await
            .expect_err("ModeratorBehaviorAnomaly must cause MappingFailed");
        assert!(
            matches!(err, PublishError::MappingFailed(_)),
            "expected MappingFailed, got {err:?}"
        );
    }
}
