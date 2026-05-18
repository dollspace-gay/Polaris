//! Library half of `polaris-publish-did-service` (issue #60).
//!
//! Pure, testable functions for constructing and validating the
//! operator's DID document so it contains a `#atproto_labeler` service
//! entry pointing at the Polaris labeler's public hostname. Without
//! that entry, the `app.bsky.labeler.service` record published by
//! `polaris-publish-labeler-record` is invisible — downstream `AppView`s
//! resolve the operator's DID, fail to find the labeler service, and
//! silently skip the record.
//!
//! The CLI / network / PLC-flow glue lives in `main.rs`; this module is
//! deliberately I/O-free so the document-construction and validation
//! paths are unit-testable without a PDS, a PLC directory, or an email
//! inbox in the loop.
//!
//! # Design notes
//!
//! - **did:web** path: returns the DID document JSON the operator hosts
//!   at `https://<handle>/.well-known/did.json`. No network calls are
//!   needed — the operator copies the JSON onto the static-file host
//!   that already serves their handle.
//! - **did:plc** path: the document is mutated by a signed PLC
//!   operation through the operator's PDS. The PLC operation surface
//!   is provided by `proto_blue::api::com::atproto::identity::{
//!   requestPlcOperationSignature, signPlcOperation, submitPlcOperation
//!   }`; this library does not hand-roll PLC operation JSON.
//! - **Validation is shape-only.** [`validate_did_document`] confirms
//!   the document has a `#atproto_labeler` service entry pointing at
//!   the expected URL and a verification method for the expected
//!   `did:key:z…`. It does not verify cryptographic signatures or the
//!   PLC operation chain — that's the PLC directory's job.
//!
//! [`polaris-publish-labeler-record`]: ../polaris_publish_labeler_record/index.html

use serde_json::{Value, json};
use thiserror::Error;

/// Identifier of the labeler service entry on an operator's DID
/// document, per the atproto spec.
///
/// Always written as a relative `#fragment` so the entry is
/// resolvable regardless of whether the document is rehosted at a
/// different base.
pub const LABELER_SERVICE_ID: &str = "#atproto_labeler";

/// `type` discriminator for the labeler service entry. Mirrors the
/// upstream `AtprotoPersonalDataServer` convention.
pub const LABELER_SERVICE_TYPE: &str = "AtprotoLabeler";

/// Identifier of the PDS service entry on an atproto DID document.
pub const PDS_SERVICE_ID: &str = "#atproto_pds";

/// `type` discriminator for the PDS service entry.
pub const PDS_SERVICE_TYPE: &str = "AtprotoPersonalDataServer";

/// Identifier of the atproto signing-key verification method, written
/// as a relative `#fragment` per atproto convention.
pub const ATPROTO_VERIFICATION_ID: &str = "#atproto";

/// Identifier of the labeler signing-key verification method, written
/// as a relative `#fragment` per atproto convention. Paired with
/// [`LABELER_SERVICE_ID`] in the DID document so downstream consumers
/// can resolve the labeler's signing key via DID resolution and
/// verify the signatures on emitted `com.atproto.label.defs#label`
/// records.
pub const ATPROTO_LABEL_VERIFICATION_ID: &str = "#atproto_label";

/// `type` discriminator for the verification method. ATProto uses the
/// W3C Multikey 2024 spec.
pub const ATPROTO_VERIFICATION_TYPE: &str = "Multikey";

/// Errors that [`build_did_web_document`] can return.
///
/// Every variant is driven by caller-supplied input — there is no IO
/// inside [`build_did_web_document`], so each error maps to "user
/// error" (exit code 1) in the binary.
#[derive(Debug, Error)]
pub enum BuildError {
    /// `signing_pubkey_did` was not a parseable `did:key:z…` multikey.
    #[error("invalid did:key for --signing-key: {0}")]
    InvalidDidKey(String),

    /// `signing_pubkey_did` parsed but did not name a K-256 / P-256
    /// curve.
    ///
    /// Polaris signs labels with K-256 (REQ-3); declaring any other
    /// curve in the DID document would cause downstream verifier
    /// mismatch at signature-check time.
    #[error("unsupported did:key curve: {0}")]
    UnsupportedDidKeyCurve(String),

    /// `service_url` failed URL parsing.
    #[error("invalid --service-url: {0}")]
    InvalidServiceUrl(String),

    /// `service_url` parsed but was not an HTTPS URL.
    ///
    /// Downstream consumers connect over WSS; a plaintext URL here
    /// would silently degrade to a no-TLS connection at deploy time.
    #[error("--service-url must use https:// scheme, got: {0}")]
    NonHttpsServiceUrl(String),

    /// `did_pds_endpoint` failed URL parsing.
    #[error("invalid PDS endpoint: {0}")]
    InvalidPdsEndpoint(String),

    /// `did_pds_endpoint` parsed but was not an HTTPS URL.
    #[error("PDS endpoint must use https:// scheme, got: {0}")]
    NonHttpsPdsEndpoint(String),

    /// `handle` was empty or could not be encoded into a did:web id.
    #[error("invalid handle for did:web id derivation: {0}")]
    InvalidHandle(String),
}

/// Errors that [`validate_did_document`] can return.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// The document had no top-level `service` array.
    #[error("DID document missing top-level `service` array")]
    MissingServiceArray,

    /// The document had a `service` field but it was not a JSON array.
    #[error("DID document `service` field is not an array")]
    ServiceNotArray,

    /// No service entry with `id == #atproto_labeler` was present.
    #[error("DID document missing `#atproto_labeler` service entry")]
    MissingLabelerService,

    /// A `#atproto_labeler` entry was present but its `type` did not
    /// equal `AtprotoLabeler`.
    #[error("`#atproto_labeler` entry has wrong type: expected `AtprotoLabeler`, got `{0}`")]
    WrongLabelerType(String),

    /// The `#atproto_labeler` entry's `serviceEndpoint` did not match
    /// the value the caller expected.
    #[error("`#atproto_labeler` serviceEndpoint mismatch: expected `{expected}`, got `{actual}`")]
    LabelerEndpointMismatch {
        /// The URL the caller expected to find.
        expected: String,
        /// The URL actually present in the document.
        actual: String,
    },

    /// The document had no top-level `verificationMethod` array.
    #[error("DID document missing top-level `verificationMethod` array")]
    MissingVerificationMethodArray,

    /// The `verificationMethod` field was not a JSON array.
    #[error("DID document `verificationMethod` field is not an array")]
    VerificationMethodNotArray,

    /// No verification method declared the expected signing key.
    #[error(
        "DID document missing verification method for expected signing key `{expected_did_key}`"
    )]
    MissingSigningKey {
        /// The `did:key:z…` value the caller expected to find.
        expected_did_key: String,
    },
}

/// Build an atproto DID document containing a `#atproto_labeler`
/// service entry pointing at `service_url`.
///
/// This is the JSON the operator publishes at
/// `https://<handle>/.well-known/did.json` for did:web identities.
/// For did:plc identities the caller submits the document via the
/// PLC operation surface; either way, the document shape is the same.
///
/// The returned document declares:
///
/// - `id`: `did:web:<handle>` (handle is used verbatim — the operator
///   must ensure their handle is already the did:web identifier they
///   intend to publish).
/// - `alsoKnownAs`: `["at://<handle>"]` so atproto resolvers can
///   round-trip handle ↔ DID.
/// - `verificationMethod`: one Multikey entry for the labeler's
///   signing key.
/// - `service`: the PDS entry plus the `#atproto_labeler` entry.
///
/// # Errors
///
/// Returns a [`BuildError`] when any of the URL or did:key inputs are
/// malformed. URL inputs must use the `https://` scheme.
pub fn build_did_web_document(
    handle: &str,
    did_pds_endpoint: &str,
    signing_pubkey_did: &str,
    service_url: &str,
) -> Result<Value, BuildError> {
    if handle.is_empty() {
        return Err(BuildError::InvalidHandle("(empty)".to_string()));
    }
    // The handle must not contain a scheme — it's a bare hostname like
    // `polaris.example.com`. A URL-shaped handle would silently produce
    // a broken did:web id.
    if handle.contains("://") || handle.contains('/') {
        return Err(BuildError::InvalidHandle(handle.to_string()));
    }

    let parsed_service_url = url::Url::parse(service_url)
        .map_err(|e| BuildError::InvalidServiceUrl(format!("{service_url}: {e}")))?;
    if parsed_service_url.scheme() != "https" {
        return Err(BuildError::NonHttpsServiceUrl(service_url.to_string()));
    }

    let parsed_pds = url::Url::parse(did_pds_endpoint)
        .map_err(|e| BuildError::InvalidPdsEndpoint(format!("{did_pds_endpoint}: {e}")))?;
    if parsed_pds.scheme() != "https" {
        return Err(BuildError::NonHttpsPdsEndpoint(
            did_pds_endpoint.to_string(),
        ));
    }

    // Validate the signing key. We capture the multikey portion (everything
    // after `did:key:`) to emit it as `publicKeyMultibase` per atproto
    // convention (matches the shape `proto_blue_identity::synthesize_did_key_doc`
    // produces and what `ensure_atp_document` expects to find).
    let parsed = proto_blue::crypto::parse_did_key(signing_pubkey_did)
        .map_err(|e| BuildError::InvalidDidKey(format!("{signing_pubkey_did}: {e}")))?;
    if parsed.jwt_alg != "ES256K" && parsed.jwt_alg != "ES256" {
        return Err(BuildError::UnsupportedDidKeyCurve(parsed.jwt_alg));
    }
    let multikey = signing_pubkey_did
        .strip_prefix("did:key:")
        .ok_or_else(|| BuildError::InvalidDidKey(signing_pubkey_did.to_string()))?;

    let did_id = format!("did:web:{handle}");

    Ok(json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1",
        ],
        "id": did_id,
        "alsoKnownAs": [format!("at://{handle}")],
        "verificationMethod": [{
            "id": ATPROTO_VERIFICATION_ID,
            "type": ATPROTO_VERIFICATION_TYPE,
            "controller": did_id,
            "publicKeyMultibase": multikey,
        }],
        "service": [
            {
                "id": PDS_SERVICE_ID,
                "type": PDS_SERVICE_TYPE,
                "serviceEndpoint": did_pds_endpoint,
            },
            {
                "id": LABELER_SERVICE_ID,
                "type": LABELER_SERVICE_TYPE,
                "serviceEndpoint": service_url,
            },
        ],
    }))
}

/// Validate that `doc` contains the expected `#atproto_labeler`
/// service entry and a verification method for the expected signing
/// key.
///
/// The check is shape-only: it confirms the structural fields exist
/// with the right values. Cryptographic signature verification of
/// the underlying PLC operation chain is delegated to the PLC
/// directory.
///
/// # Errors
///
/// Returns a [`ValidationError`] when the document is missing a
/// `#atproto_labeler` service entry, when the entry points at a
/// different URL than `expected_service_url`, or when no
/// `verificationMethod` declares `expected_signing_pubkey_did` as a
/// Multikey.
pub fn validate_did_document(
    doc: &Value,
    expected_service_url: &str,
    expected_signing_pubkey_did: &str,
) -> Result<(), ValidationError> {
    let services = doc
        .get("service")
        .ok_or(ValidationError::MissingServiceArray)?
        .as_array()
        .ok_or(ValidationError::ServiceNotArray)?;

    let labeler_entry = services
        .iter()
        .find(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| matches_fragment(id, LABELER_SERVICE_ID))
        })
        .ok_or(ValidationError::MissingLabelerService)?;

    let entry_type = labeler_entry
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if entry_type != LABELER_SERVICE_TYPE {
        return Err(ValidationError::WrongLabelerType(entry_type.to_string()));
    }

    let actual_endpoint = labeler_entry
        .get("serviceEndpoint")
        .and_then(Value::as_str)
        .unwrap_or("");
    if actual_endpoint != expected_service_url {
        return Err(ValidationError::LabelerEndpointMismatch {
            expected: expected_service_url.to_string(),
            actual: actual_endpoint.to_string(),
        });
    }

    let verification_methods = doc
        .get("verificationMethod")
        .ok_or(ValidationError::MissingVerificationMethodArray)?
        .as_array()
        .ok_or(ValidationError::VerificationMethodNotArray)?;

    let expected_multikey = expected_signing_pubkey_did
        .strip_prefix("did:key:")
        .unwrap_or(expected_signing_pubkey_did);

    let has_signing_key = verification_methods.iter().any(|vm| {
        let multibase = vm
            .get("publicKeyMultibase")
            .and_then(Value::as_str)
            .unwrap_or("");
        multibase == expected_multikey
    });
    if !has_signing_key {
        return Err(ValidationError::MissingSigningKey {
            expected_did_key: expected_signing_pubkey_did.to_string(),
        });
    }

    Ok(())
}

/// Extract the `service` array from a built DID document for use in
/// `sign_plc_operation::Input.services`.
///
/// The atproto `com.atproto.identity.signPlcOperation` lexicon types its
/// `services` field as `unknown` JSON; the wire shape is therefore the
/// same array we already place under the `service` key of the built
/// DID document. Exposed at the library boundary (issue #85) so the
/// in-process backend caller (`polaris-backend/src/api/setup.rs`) can
/// re-use the same shape the CLI assembles without re-deriving the
/// payload by hand.
///
/// Returns `None` when `doc` has no top-level `service` field; callers
/// surface that as an internal error (the DID document this crate
/// builds always carries a `service` array).
#[must_use]
pub fn build_plc_services_payload(doc: &Value) -> Option<Value> {
    // PLC's `signPlcOperation` lexicon declares `services` as a
    // `Map<fragment_id, ServiceEntry>` where `ServiceEntry =
    // {type, endpoint}`. The DID-document `service` array uses the
    // W3C DID-Core shape `[{id, type, serviceEndpoint}]`. Translate
    // by stripping the leading `#` from each `id` to use as the map
    // key, and renaming `serviceEndpoint` → `endpoint`. A bad
    // (non-array, non-object) entry is skipped silently rather than
    // failing the whole call — the lexicon validator on the PDS will
    // surface a precise error if the remaining shape is wrong.
    let arr = doc.get("service")?.as_array()?;
    let mut out = serde_json::Map::new();
    for entry in arr {
        let Some(entry_obj) = entry.as_object() else {
            continue;
        };
        let Some(id) = entry_obj.get("id").and_then(Value::as_str) else {
            continue;
        };
        let fragment = id.rsplit_once('#').map_or(id, |(_, suffix)| suffix);
        let ty = entry_obj.get("type").cloned().unwrap_or(Value::Null);
        let endpoint = entry_obj
            .get("serviceEndpoint")
            .cloned()
            .unwrap_or(Value::Null);
        out.insert(
            fragment.to_owned(),
            serde_json::json!({ "type": ty, "endpoint": endpoint }),
        );
    }
    Some(Value::Object(out))
}

/// Build the PLC `verificationMethods` payload from a built DID document.
///
/// PLC's `signPlcOperation` declares `verificationMethods` as a
/// `Map<fragment_id, did_key_string>` — each value is a `did:key:z…`
/// reference, **not** an object. The DID-document `verificationMethod`
/// array uses the Multikey shape `{id, type, controller,
/// publicKeyMultibase}`. Translate by stripping the leading `#` from
/// each `id` to use as the map key, and reconstructing the
/// `did:key:` prefix in front of `publicKeyMultibase`. Entries that
/// don't have a `Multikey` type or are missing `publicKeyMultibase`
/// are skipped silently.
#[must_use]
pub fn build_plc_verification_methods_payload(doc: &Value) -> Option<Value> {
    let arr = doc.get("verificationMethod")?.as_array()?;
    let mut out = serde_json::Map::new();
    for entry in arr {
        let Some(entry_obj) = entry.as_object() else {
            continue;
        };
        let Some(id) = entry_obj.get("id").and_then(Value::as_str) else {
            continue;
        };
        let fragment = id.rsplit_once('#').map_or(id, |(_, suffix)| suffix);
        let Some(multibase) = entry_obj.get("publicKeyMultibase").and_then(Value::as_str) else {
            continue;
        };
        out.insert(
            fragment.to_owned(),
            Value::String(format!("did:key:{multibase}")),
        );
    }
    Some(Value::Object(out))
}

/// Compare two service-entry ids, treating absolute and relative
/// fragments as equivalent.
///
/// The atproto spec permits both `#atproto_labeler` and
/// `did:web:example.com#atproto_labeler`; we match on the fragment
/// portion so callers don't have to know which form their PLC
/// directory normalized to.
fn matches_fragment(actual: &str, expected_fragment: &str) -> bool {
    if actual == expected_fragment {
        return true;
    }
    // `expected_fragment` is itself `#...`; the actual id either matches
    // verbatim or contains the same suffix after a `#` separator.
    let expected_bare = expected_fragment.trim_start_matches('#');
    actual
        .rsplit_once('#')
        .is_some_and(|(_, suffix)| suffix == expected_bare)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "unit test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    const HANDLE: &str = "polaris.example.com";
    const SERVICE_URL: &str = "https://polaris.example.com";
    const PDS_URL: &str = "https://bsky.social";
    const SIGNING_PUBKEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";

    #[test]
    fn build_did_web_document_contains_labeler_service_entry() {
        let doc = build_did_web_document(HANDLE, PDS_URL, SIGNING_PUBKEY, SERVICE_URL)
            .expect("happy-path build should succeed");

        let services = doc["service"]
            .as_array()
            .expect("service should be an array");
        let labeler = services
            .iter()
            .find(|s| s["id"] == LABELER_SERVICE_ID)
            .expect("should have #atproto_labeler entry");
        assert_eq!(labeler["type"], LABELER_SERVICE_TYPE);
        assert_eq!(labeler["serviceEndpoint"], SERVICE_URL);
        assert_eq!(doc["id"], format!("did:web:{HANDLE}"));
    }

    #[test]
    fn build_did_web_document_rejects_invalid_did_key() {
        let err =
            build_did_web_document(HANDLE, PDS_URL, "did:key:NOT_A_REAL_MULTIKEY", SERVICE_URL)
                .expect_err("garbage did:key should be rejected");
        assert!(matches!(err, BuildError::InvalidDidKey(_)), "got {err:?}");
    }

    #[test]
    fn build_did_web_document_rejects_non_https_service_url() {
        let err = build_did_web_document(HANDLE, PDS_URL, SIGNING_PUBKEY, "http://example.com")
            .expect_err("plaintext URL should be rejected");
        assert!(
            matches!(err, BuildError::NonHttpsServiceUrl(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn build_did_web_document_rejects_url_shaped_handle() {
        let err = build_did_web_document(
            "https://polaris.example.com",
            PDS_URL,
            SIGNING_PUBKEY,
            SERVICE_URL,
        )
        .expect_err("URL-shaped handle should be rejected");
        assert!(matches!(err, BuildError::InvalidHandle(_)), "got {err:?}");
    }

    #[test]
    fn validate_did_document_accepts_self_built_document() {
        let doc = build_did_web_document(HANDLE, PDS_URL, SIGNING_PUBKEY, SERVICE_URL)
            .expect("build should succeed");
        validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
            .expect("self-built document should validate");
    }

    #[test]
    fn validate_did_document_rejects_missing_labeler_entry() {
        let doc = json!({
            "id": "did:web:polaris.example.com",
            "verificationMethod": [{
                "id": "#atproto",
                "type": "Multikey",
                "controller": "did:web:polaris.example.com",
                "publicKeyMultibase": "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social",
            }],
        });
        let err = validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
            .expect_err("doc without #atproto_labeler should fail");
        assert!(
            matches!(err, ValidationError::MissingLabelerService),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_did_document_rejects_wrong_service_url() {
        let doc = json!({
            "id": "did:web:polaris.example.com",
            "verificationMethod": [{
                "id": "#atproto",
                "type": "Multikey",
                "controller": "did:web:polaris.example.com",
                "publicKeyMultibase": "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            }],
            "service": [{
                "id": "#atproto_labeler",
                "type": "AtprotoLabeler",
                "serviceEndpoint": "https://wrong.example.com",
            }],
        });
        let err = validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
            .expect_err("wrong service URL should fail");
        assert!(
            matches!(err, ValidationError::LabelerEndpointMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_did_document_rejects_missing_signing_key() {
        let doc = json!({
            "id": "did:web:polaris.example.com",
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_labeler",
                "type": "AtprotoLabeler",
                "serviceEndpoint": SERVICE_URL,
            }],
        });
        let err = validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
            .expect_err("missing verification method should fail");
        assert!(
            matches!(err, ValidationError::MissingSigningKey { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn validate_did_document_accepts_absolute_fragment_id() {
        // PLC directories sometimes normalize ids to the absolute form
        // (`did:web:...#atproto_labeler`); the validator must accept both.
        let doc = json!({
            "id": "did:web:polaris.example.com",
            "verificationMethod": [{
                "id": "#atproto",
                "type": "Multikey",
                "controller": "did:web:polaris.example.com",
                "publicKeyMultibase": "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
            }],
            "service": [{
                "id": "did:web:polaris.example.com#atproto_labeler",
                "type": "AtprotoLabeler",
                "serviceEndpoint": SERVICE_URL,
            }],
        });
        validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
            .expect("absolute-fragment id should be accepted");
    }
}
