//! Historical-label signature verification (issue #30, REQ-12, AC-15).
//!
//! Polaris labels are signed with the labeler's K-256 private key and
//! published with the labeler's `did:key:z…` public key in the
//! signature's `signing_did` slot. Rotation introduces a temporal twist:
//! a label signed at time `t1` under key K1 must still verify after a
//! rotation at time `t2` swaps the active key to K2. The "current"
//! signing key is the wrong key to verify a historical label.
//!
//! [`verify_label`] resolves this by consulting `signing_key_history`:
//! find the key whose active window contains the label's `signed_at`,
//! then verify the signature against that key. The active-window query
//! is the [`crate::labeler::rotation::active_key_at`] helper.
//!
//! # Why DID-based lookup, not direct `K256Verifier` construction
//!
//! `proto_blue::crypto::verify_signature(did_key, msg, sig)` parses the
//! did:key, decodes the multikey to its compressed pubkey form,
//! constructs a per-call `K256Verifier`, and runs the verification.
//! Polaris's call sites never need to hold a long-lived verifier
//! (rotation invalidates that anyway) so the per-call construction is
//! the right shape. The `allow_malleable = false` setting matches the
//! signing path: every signature Polaris emits is low-S-normalised
//! (RFC 6979 §3.2), and verifiers MUST reject the non-canonical S form
//! to defeat signature-malleability attacks (BIP-62).

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::labeler::rotation::active_key_at;
use crate::labeler::signer::Signature;

/// Errors raised by [`verify_label`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// No `signing_key_history` row was active at the label's
    /// `signed_at`. Either the label pre-dates the rotation flow's
    /// bootstrap or the table is corrupt; both indicate an operator
    /// problem, not a label-content problem.
    #[error("no signing key was active at signed_at={signed_at}")]
    NoKeyAtTime {
        /// The instant the label claims it was signed.
        signed_at: DateTime<Utc>,
    },

    /// The signature did NOT verify against the issuance-time key.
    /// Either the label CBOR was tampered with, the signature was
    /// tampered with, or the signature was produced under a key
    /// Polaris doesn't recognise.
    #[error("signature did not verify against issuance-time key did={did}")]
    BadSignature {
        /// The did:key the verifier looked up.
        did: String,
    },

    /// A database operation failed while looking up the issuance-time
    /// key.
    #[error("verify-label DB lookup failed")]
    Db(#[source] sqlx::Error),

    /// The proto-blue crypto layer rejected the did:key, the signature
    /// bytes, or the underlying primitive. Wraps the upstream error.
    #[error("crypto layer rejected the verification inputs")]
    Crypto(#[source] proto_blue::crypto::CryptoError),
}

/// Verify a labeler signature against the *issuance-time* active key.
///
/// 1. Look up the active key at `signed_at` from `signing_key_history`.
/// 2. Verify `sig` over `label_cbor` against that key's did:key form,
///    rejecting malleable (non-low-S) signatures.
///
/// # Errors
///
/// - [`VerifyError::NoKeyAtTime`] if no key window contains `signed_at`.
/// - [`VerifyError::BadSignature`] if the signature did not verify.
/// - [`VerifyError::Db`] on a DB error during lookup.
/// - [`VerifyError::Crypto`] on a primitive-level crypto error.
pub async fn verify_label(
    pool: &PgPool,
    label_cbor: &[u8],
    sig: &Signature,
    signed_at: DateTime<Utc>,
) -> Result<(), VerifyError> {
    let did = active_key_at(pool, signed_at)
        .await
        .map_err(VerifyError::Db)?
        .ok_or(VerifyError::NoKeyAtTime { signed_at })?;

    let ok = proto_blue::crypto::verify_signature(&did, label_cbor, sig.as_bytes(), false)
        .map_err(VerifyError::Crypto)?;
    if ok {
        Ok(())
    } else {
        Err(VerifyError::BadSignature { did })
    }
}
