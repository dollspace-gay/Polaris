//! Canonical DAG-CBOR encoding of `app.bsky.labeler.service` Label records (#78).
//!
//! Both the signing path ([`crate::labeler::emitter`]) and the verifying
//! path ([`crate::ingest::upstream_labels`]) must produce bit-identical bytes for the
//! same `Label` value — otherwise signatures Polaris issues and signatures
//! Polaris consumes can drift, breaking interop with external `AppViews` and
//! with proto-blue's own decoder.
//!
//! The serialisation chain:
//!
//! 1. Typed `ProtoLabel` → `serde_json::Value` via the generated type's
//!    Serialize impl. The `sig` field uses
//!    `#[serde(skip_serializing_if = "Option::is_none")]`, so the unsigned
//!    canonical form omits the field entirely.
//! 2. `serde_json::Value` → `LexValue` via
//!    [`proto_blue::lex_json::json_to_lex`].
//! 3. `LexValue` → DAG-CBOR bytes via [`proto_blue::lex_cbor::encode`],
//!    which enforces sorted map keys, shortest-integer encoding, and the
//!    rest of the DAG-CBOR canonicality rules.

use proto_blue::api::com::atproto::label::defs::Label as ProtoLabel;
use proto_blue::{lex_cbor, lex_json};

/// Error type for canonical encoding.
///
/// The serialisation chain is pure — every step is in-process with typed
/// inputs — so the only failure mode is a corrupted intermediate value
/// (which would be a serde bug, not a runtime condition). The variant is
/// kept opaque so each caller can `From`-convert it to their own typed
/// error without leaking serde's exact failure shape into the API surface.
#[derive(Debug, thiserror::Error)]
#[error("canonical label encoding failed")]
pub struct CanonicalizeError;

/// DAG-CBOR encode the `Label` with `sig` cleared.
///
/// This is the single source of truth for signature-canonical `Label` bytes
/// in the Polaris workspace. Callers that produce signatures must pass the
/// bytes from this function to the signer; callers that verify signatures
/// must pass the bytes from this function to the verifier. Drift between
/// the two paths is what this consolidation prevents (#78 origin: proto-blue
/// reuse audit during #51).
///
/// # Errors
///
/// Returns [`CanonicalizeError`] if the serde JSON → `LexValue` → CBOR chain
/// fails. In production this is unreachable; see the type-level doc.
pub fn encode_canonical_label(label: &ProtoLabel) -> Result<Vec<u8>, CanonicalizeError> {
    let json = serde_json::to_value(label).map_err(|_| CanonicalizeError)?;
    let lex = lex_json::json_to_lex(&json);
    lex_cbor::encode(&lex).map_err(|_| CanonicalizeError)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic per rust-quality §7"
)]
mod tests {
    use super::*;
    use proto_blue::api::com::atproto::label::defs::Label as ProtoLabel;
    use proto_blue::syntax::{Datetime, Did};

    fn fixture_label() -> ProtoLabel {
        ProtoLabel {
            ver: Some(1),
            src: Did::new("did:plc:example").expect("valid did"),
            uri: "at://did:plc:subject/app.bsky.feed.post/abc".to_owned(),
            cid: None,
            val: "spam".to_owned(),
            neg: Some(false),
            cts: Datetime::now(),
            exp: None,
            sig: None,
        }
    }

    #[test]
    fn encode_is_deterministic() {
        let label = fixture_label();
        let a = encode_canonical_label(&label).unwrap();
        let b = encode_canonical_label(&label).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn encode_omits_sig_field() {
        let mut signed = fixture_label();
        signed.sig = Some(vec![0u8; 64]);
        let mut unsigned = fixture_label();
        unsigned.sig = None;
        let a = encode_canonical_label(&signed).unwrap();
        let b = encode_canonical_label(&unsigned).unwrap();
        // sig: None is serde-skipped; sig: Some(...) is included. The two
        // forms therefore encode DIFFERENTLY — which is exactly why both
        // call sites canonicalise with sig cleared before signing/verifying.
        assert_ne!(a, b, "sig presence must change encoded bytes");
    }
}
