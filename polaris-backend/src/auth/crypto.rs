//! AES-256-GCM AEAD primitives for refresh-token-at-rest encryption.
//!
//! # Why AES-256-GCM
//!
//! AES-GCM is an authenticated-encryption mode: any tampering with the
//! ciphertext or the associated nonce produces a decryption error rather than
//! silently-garbage plaintext. That property is non-negotiable for refresh
//! tokens, which are bearer credentials against the upstream OIDC provider —
//! a malleable ciphertext layer would let an attacker who can write to the
//! `sessions` table flip bits in the token without detection.
//!
//! Per `.crosslink/rules/rigor.md` §Cryptographic correctness:
//!
//! - Fresh `OsRng`-derived 96-bit nonce per [`Crypto::seal`] call. Never
//!   reused, never derived from message content.
//! - AES-256 (32-byte key from config). The cookie key MUST be the same
//!   wrapping key across the deployment lifetime — rotating it invalidates
//!   every persisted refresh token.
//! - `aes-gcm` 0.10.x — the `RustCrypto` implementation, audit history at
//!   <https://github.com/RustCrypto/AEADs>.
//! - Errors are intentionally **opaque**: a decryption failure does not tell
//!   the caller whether the nonce was tampered with, the ciphertext was
//!   tampered with, or the key is wrong. The original error is captured via
//!   `#[source]` for logs but the `Display` impl is a constant string.
//!
//! # Wire format of [`SealedBytes`]
//!
//! ```text
//! [ nonce (12 bytes) ][ ciphertext + 16-byte GCM tag (N bytes) ]
//! ```
//!
//! The whole struct round-trips through `serde` (CBOR via `serde_json` is
//! avoided because session DB rows store the raw concatenation as a `BYTEA`;
//! see [`SealedBytes::to_bytes`] / [`SealedBytes::from_bytes`]).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// AES-256-GCM nonce length, in bytes (96 bits, per NIST SP 800-38D).
pub const NONCE_LEN: usize = 12;

/// AES-256-GCM authentication tag length, in bytes (128 bits, per NIST
/// SP 800-38D §5.2.1.2). The `aes-gcm` crate appends this tag to the
/// ciphertext automatically.
pub const TAG_LEN: usize = 16;

/// Errors raised by [`Crypto`].
///
/// The `Display` strings are intentionally generic: a caller (or, worse, a
/// log scraper) MUST NOT be able to distinguish between "wrong key", "bad
/// nonce", and "tampered ciphertext" — that distinction is a side channel.
/// The underlying `aes_gcm::Error` is captured via `#[source]` so an operator
/// reading a structured-logged error chain can still see the root cause; it
/// is not surfaced in user-facing responses.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Encryption failed. The `aes_gcm::Error` is opaque by construction.
    #[error("encryption failure")]
    Encrypt {
        /// Underlying `aes-gcm` error. `aes_gcm::Error` does not implement
        /// `std::error::Error` directly, so we wrap its `Display`.
        #[source]
        source: AesGcmError,
    },

    /// Decryption failed — wrong key, bad nonce, or tampered ciphertext.
    /// The variant deliberately collapses all three; see module-level docs.
    #[error("decryption failure")]
    Decrypt {
        /// Underlying `aes-gcm` error.
        #[source]
        source: AesGcmError,
    },

    /// The on-wire encoded form of [`SealedBytes`] was shorter than the
    /// minimum size (12-byte nonce + 16-byte tag = 28 bytes).
    #[error("sealed-bytes payload truncated: {len} < {min}")]
    Truncated {
        /// Byte length of the payload we tried to decode.
        len: usize,
        /// Minimum legal payload length.
        min: usize,
    },
}

/// `aes_gcm::Error` does not implement `std::error::Error`. This newtype lets
/// us put it in the `#[source]` chain anyway.
#[derive(Debug)]
pub struct AesGcmError(aes_gcm::Error);

impl std::fmt::Display for AesGcmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // aes_gcm::Error itself only carries a unit variant in current
        // versions and prints as "aead::Error". We do not need to expose any
        // more detail than that — leaking which branch failed in an AEAD
        // check is exactly the side channel `CryptoError` is designed to
        // avoid.
        write!(f, "aead error")
    }
}

impl std::error::Error for AesGcmError {}

/// AES-256-GCM cipher handle.
///
/// Constructed once at process start from the 32-byte cookie key and reused
/// for every seal/open call. `Aes256Gcm` is `Send + Sync` (the underlying
/// AES round keys are immutable after construction), so a `Crypto` is safe to
/// clone and stash in handler state.
#[derive(Clone)]
pub struct Crypto {
    cipher: Aes256Gcm,
}

impl std::fmt::Debug for Crypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the cipher state — its `Debug` would reveal the
        // expanded round keys.
        f.debug_struct("Crypto").finish_non_exhaustive()
    }
}

impl Crypto {
    /// Construct a [`Crypto`] from a 32-byte AES-256 key.
    ///
    /// The byte array is moved by value rather than borrowed so the caller
    /// cannot accidentally hold a longer-lived reference to the key bytes;
    /// once the array is consumed it lives only inside the `Aes256Gcm`
    /// state and is wiped by `aes-gcm`'s `Drop` impl.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        let key_ref: &Key<Aes256Gcm> = (&key).into();
        let cipher = Aes256Gcm::new(key_ref);
        Self { cipher }
    }

    /// Encrypt `plaintext` with a fresh `OsRng`-derived nonce.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Encrypt`] if the underlying AES-GCM
    /// implementation rejects the operation. In practice this only happens
    /// when the plaintext exceeds `2^36 - 32` bytes, which is far larger than
    /// any refresh token we will ever encounter.
    pub fn seal(&self, plaintext: &[u8]) -> Result<SealedBytes, CryptoError> {
        // CORRECTNESS: 96-bit nonce drawn from `OsRng`, the OS CSPRNG, on
        // every call. Each call yields a fresh nonce, so the GCM uniqueness
        // invariant ("never reuse a (key, nonce) pair under the same key")
        // holds by construction. We deliberately avoid `Aes256Gcm::generate_nonce`
        // because aes-gcm 0.10.3's helper routes through generic-array 0.14
        // which now emits a deprecation warning; the underlying primitive is
        // identical — read 12 bytes from `OsRng` into a fixed-size buffer.
        let mut nonce_bytes = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce_bytes.into(), plaintext)
            .map_err(|source| CryptoError::Encrypt {
                source: AesGcmError(source),
            })?;

        Ok(SealedBytes {
            nonce: nonce_bytes,
            ciphertext,
        })
    }

    /// Decrypt and authenticate `sealed`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Decrypt`] for any of: wrong key, tampered
    /// ciphertext, tampered nonce. The error variant deliberately collapses
    /// these into one — distinguishing them at the API surface is a side
    /// channel.
    pub fn open(&self, sealed: &SealedBytes) -> Result<Vec<u8>, CryptoError> {
        // Same rationale as `seal`: feed the raw nonce-array through `Into`
        // rather than `Nonce::from_slice`, which routes through deprecated
        // generic-array 0.14 helpers.
        self.cipher
            .decrypt(&sealed.nonce.into(), sealed.ciphertext.as_slice())
            .map_err(|source| CryptoError::Decrypt {
                source: AesGcmError(source),
            })
    }
}

/// On-wire representation of an AES-256-GCM ciphertext.
///
/// Holds the 12-byte nonce alongside the ciphertext (which already includes
/// the 16-byte GCM tag at its tail). The two fields are kept separate in
/// memory but serialise together via [`SealedBytes::to_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedBytes {
    /// 96-bit nonce. Generated fresh per [`Crypto::seal`] call.
    pub nonce: [u8; NONCE_LEN],
    /// AES-GCM ciphertext, with the 16-byte authentication tag appended.
    pub ciphertext: Vec<u8>,
}

impl SealedBytes {
    /// Encode as `[nonce || ciphertext]`. The resulting `Vec<u8>` is what
    /// gets stored in the `sessions.refresh_token_enc` `BYTEA` column.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Decode from `[nonce || ciphertext]`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Truncated`] if `bytes` is shorter than the
    /// 12-byte nonce + 16-byte tag minimum. Any longer payload is accepted;
    /// the AES-GCM `decrypt` call is what ultimately authenticates it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let min = NONCE_LEN + TAG_LEN;
        if bytes.len() < min {
            return Err(CryptoError::Truncated {
                len: bytes.len(),
                min,
            });
        }
        let mut nonce = [0_u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[..NONCE_LEN]);
        let ciphertext = bytes[NONCE_LEN..].to_vec();
        Ok(Self { nonce, ciphertext })
    }
}

#[cfg(test)]
// Allow `unwrap()` / `unwrap_err()` / `expect()` in tests so the
// workspace-level `clippy::unwrap_used` / `expect_used` lints (which fire
// at `--all-targets` level) do not flag the idiomatic Rust unit-test pattern
// of asserting via `.unwrap()`. The architect's pre-flight permits this in
// test code only; the production code paths in this file are unwrap-free.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fixed_key() -> [u8; 32] {
        // Deterministic test key — NEVER used outside `#[cfg(test)]`.
        let mut k = [0_u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap_or(0);
        }
        k
    }

    #[test]
    fn seal_open_round_trip() {
        let crypto = Crypto::new(fixed_key());
        let pt = b"refresh-token-payload-AAAA-BBBB";
        let sealed = crypto.seal(pt).unwrap();
        let opened = crypto.open(&sealed).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn two_seals_produce_distinct_nonces() {
        let crypto = Crypto::new(fixed_key());
        let s1 = crypto.seal(b"same-plaintext").unwrap();
        let s2 = crypto.seal(b"same-plaintext").unwrap();
        // OsRng collision on a 96-bit value is cryptographically impossible
        // in any reasonable bound (birthday bound ~2^48 ops); if this ever
        // fires either the RNG is broken or someone hard-coded a nonce.
        assert_ne!(s1.nonce, s2.nonce, "nonces MUST be unique per seal call");
        assert_ne!(
            s1.ciphertext, s2.ciphertext,
            "ciphertexts MUST differ when nonces differ"
        );
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let crypto = Crypto::new(fixed_key());
        let mut sealed = crypto.seal(b"tamper-me").unwrap();
        // Flip a bit in the ciphertext (or the appended tag — either should
        // cause GCM authentication to fail).
        sealed.ciphertext[0] ^= 0x01;
        let err = crypto.open(&sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt { .. }));
    }

    #[test]
    fn wrong_key_fails_to_open() {
        let alice = Crypto::new(fixed_key());
        let mut other = fixed_key();
        other[0] ^= 0xFF;
        let bob = Crypto::new(other);
        let sealed = alice.seal(b"alice-only").unwrap();
        let err = bob.open(&sealed).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt { .. }));
    }

    #[test]
    fn to_bytes_from_bytes_round_trip() {
        let crypto = Crypto::new(fixed_key());
        let sealed = crypto.seal(b"wire-format").unwrap();
        let bytes = sealed.to_bytes();
        let restored = SealedBytes::from_bytes(&bytes).unwrap();
        assert_eq!(sealed, restored);
        let opened = crypto.open(&restored).unwrap();
        assert_eq!(opened, b"wire-format");
    }

    #[test]
    fn from_bytes_rejects_truncated_payload() {
        let too_short = vec![0_u8; NONCE_LEN + TAG_LEN - 1];
        let err = SealedBytes::from_bytes(&too_short).unwrap_err();
        assert!(matches!(err, CryptoError::Truncated { .. }));
    }
}
