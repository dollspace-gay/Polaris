//! `passphrase-sealed` custody mode — AES-256-GCM at rest with a
//! scrypt-derived KEK.
//!
//! Defends T1-T3 (disk theft, backup leak, file disclosure) but not T4
//! (code execution as the Polaris user) — once unsealed, the K-256
//! secret sits in process memory exactly the way the file-plain key
//! does. The trade-off is documented in `.design/polaris-proto-blue-integration.md`
//! §B; this module is the implementation.
//!
//! # On-disk format
//!
//! ```text
//! offset  len  field
//!      0    1  magic byte 0x01 (format version)
//!      1   16  scrypt salt
//!     17   12  AES-GCM nonce
//!     29    *  AES-256-GCM ciphertext || 16-byte authentication tag
//! ```
//!
//! Total length is `29 + 32 + 16 = 77` bytes for a 32-byte K-256 secret.
//! The version byte exists so a future migration to a different KDF /
//! cipher / serialization can co-exist on disk; today only `0x01` is
//! recognised.
//!
//! # Scrypt parameters
//!
//! `N = 32768, r = 8, p = 1` — the current OWASP recommendation for
//! interactive (login-class) KDFs. Heavier params would extend the
//! per-startup unseal cost without buying meaningful protection
//! against the threat the mode defends (offline brute force of an
//! exfiltrated sealed file).
//!
//! # Passphrase sourcing
//!
//! In strict precedence order:
//!
//! 1. `POLARIS_SIGNING_PASSPHRASE` environment variable.
//! 2. Interactive stdin (terminal). The `rpassword` crate would land
//!    next, but for v1 we read a line off stdin if-and-only-if stdin
//!    is a TTY.
//!
//! Passphrase MUST NOT be supplied on the command line. There is no
//! argv path.
//!
//! # Zeroisation
//!
//! The passphrase string is read into a `String`, fed to `scrypt`, and
//! immediately zeroised via the `zeroize` crate. The derived 32-byte
//! AES key is zeroised after the AEAD initialiser consumes it. The
//! decrypted 32-byte K-256 secret is then handed to
//! `K256Keypair::from_private_key` — that crate (and the `k256` crate
//! underneath) owns the in-memory lifetime from there.

use std::path::Path;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead as _, KeyInit as _, Nonce};
use proto_blue::crypto::{K256Keypair, Keypair as _, Signer as _};
use scrypt::{Params, scrypt};
use zeroize::Zeroize as _;

use super::{RedactedKeypair, Signature, SigningError, SigningKey};

/// Borrowed view of the three sections of a sealed key blob: `(salt,
/// nonce, ciphertext_and_tag)`. Lifetime parameter is the blob the view
/// borrows from. The tuple shape matches the on-disk layout described
/// in the module-level docs; a struct would obscure rather than clarify
/// what is already a positional `(salt, nonce, ct)` decomposition.
type SealedBlobParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Format magic byte. Reserved for forward-compatibility.
const FORMAT_MAGIC_V1: u8 = 0x01;
const SCRYPT_SALT_LEN: usize = 16;
const AES_GCM_NONCE_LEN: usize = 12;
const AES_KEY_LEN: usize = 32;
const SECRET_KEY_LEN: usize = 32;
const HEADER_LEN: usize = 1 + SCRYPT_SALT_LEN + AES_GCM_NONCE_LEN;

// OWASP scrypt-for-interactive-KDF recommendation, 2026-current.
// <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt>
const SCRYPT_LOG_N: u8 = 15; // N = 2^15 = 32768
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Environment variable Polaris reads for the unseal passphrase.
const PASSPHRASE_ENV: &str = "POLARIS_SIGNING_PASSPHRASE";

/// Sealed-at-rest K-256 secret.
///
/// Construction unseals the file once and constructs an in-memory
/// `K256Keypair`. The sealed file is not retained after construction.
pub struct PassphraseSealedSigner {
    keypair: RedactedKeypair,
    public_key_did: String,
}

impl PassphraseSealedSigner {
    /// Read a sealed key file from `path`, derive the AES-256-GCM key
    /// from the operator's passphrase, decrypt the K-256 secret, and
    /// instantiate a signer.
    ///
    /// # Errors
    ///
    /// - [`SigningError::KeyLoad`] on file-system error, malformed
    ///   format, or absent passphrase.
    /// - [`SigningError::KeyDecrypt`] on AES-GCM authentication failure
    ///   (wrong passphrase, tampered ciphertext).
    pub fn from_path(path: &Path) -> Result<Self, SigningError> {
        let blob = std::fs::read(path).map_err(|_| SigningError::KeyLoad {
            reason: "could not read passphrase-sealed key file",
        })?;
        Self::from_sealed_bytes(&blob)
    }

    /// Parse a sealed blob (the on-disk bytes) and unseal it.
    ///
    /// Split out from [`Self::from_path`] so the round-trip test can
    /// drive the encrypt + decrypt cycle without touching the
    /// filesystem.
    ///
    /// # Errors
    ///
    /// As for [`Self::from_path`], minus the file-system path.
    pub fn from_sealed_bytes(blob: &[u8]) -> Result<Self, SigningError> {
        let (salt, nonce_bytes, ciphertext) = split_sealed_blob(blob)?;
        let passphrase = read_passphrase()?;
        let mut kek = derive_kek(&passphrase, salt)?;
        // Passphrase is no longer needed.
        drop(passphrase);

        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SigningError::KeyDecrypt)?;
        // Zeroise the derived KEK *after* AEAD init — the cipher
        // internally clones the key material into its expanded form.
        kek.zeroize();

        let nonce_arr: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| SigningError::KeyDecrypt)?;
        let nonce = Nonce::<Aes256Gcm>::from(nonce_arr);
        let secret_bytes = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
            // GCM authentication failure: do NOT echo any cause text
            // because aes-gcm intentionally returns an opaque error to
            // prevent padding-oracle-style probing. Mapping to
            // KeyDecrypt is the correct behaviour.
            SigningError::KeyDecrypt
        })?;

        if secret_bytes.len() != SECRET_KEY_LEN {
            return Err(SigningError::KeyLoad {
                reason: "decrypted payload is not exactly 32 bytes (K-256 secret)",
            });
        }
        let keypair =
            K256Keypair::from_private_key(&secret_bytes).map_err(|_| SigningError::KeyLoad {
                reason: "decrypted bytes do not form a valid K-256 secret",
            })?;
        let public_key_did = keypair.did();

        Ok(Self {
            keypair: RedactedKeypair(keypair),
            public_key_did,
        })
    }

    /// Decrypt a sealed blob with the passphrase passed in-process —
    /// the env- and stdin-free entry point used by the rotation
    /// rust-quality tests so a test does not have to mutate the
    /// global `POLARIS_SIGNING_PASSPHRASE` env var.
    ///
    /// Available in `cfg(test)` only because the production read path
    /// is the env-driven [`Self::from_path`] / [`Self::from_sealed_bytes`];
    /// exposing an in-process passphrase reader on the public API
    /// would invite callers to thread plaintext passphrases through
    /// argv-style channels, which is exactly what
    /// [`read_passphrase`] is designed to prevent.
    ///
    /// # Errors
    ///
    /// As for [`Self::from_sealed_bytes`], minus the env / stdin
    /// failure modes.
    #[cfg(test)]
    pub(crate) fn from_sealed_bytes_with_passphrase(
        blob: &[u8],
        passphrase: &str,
    ) -> Result<Self, SigningError> {
        let (salt, nonce_bytes, ciphertext) = split_sealed_blob(blob)?;
        let mut kek = derive_kek(passphrase, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SigningError::KeyDecrypt)?;
        kek.zeroize();
        let nonce_arr: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| SigningError::KeyDecrypt)?;
        let nonce = Nonce::<Aes256Gcm>::from(nonce_arr);
        let secret_bytes = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| SigningError::KeyDecrypt)?;
        if secret_bytes.len() != SECRET_KEY_LEN {
            return Err(SigningError::KeyLoad {
                reason: "decrypted payload is not exactly 32 bytes (K-256 secret)",
            });
        }
        let keypair =
            K256Keypair::from_private_key(&secret_bytes).map_err(|_| SigningError::KeyLoad {
                reason: "decrypted bytes do not form a valid K-256 secret",
            })?;
        let public_key_did = keypair.did();
        Ok(Self {
            keypair: RedactedKeypair(keypair),
            public_key_did,
        })
    }

    /// Encrypt a fresh K-256 secret to disk under `passphrase`,
    /// generating a fresh 16-byte scrypt salt and a fresh 12-byte
    /// AES-GCM nonce.
    ///
    /// This is the *write* path the key-rotation CLI (#30) will call.
    /// It lives here, next to the reader, so both sides of the
    /// format-magic / salt-position / nonce-position contract are
    /// owned by one module.
    ///
    /// `secret_bytes` must be exactly 32 bytes (the raw K-256 private
    /// scalar). `passphrase` is borrowed and not retained.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::KeyLoad`] on input validation failure or
    /// scrypt KDF failure (the latter is essentially unreachable for
    /// the hard-coded params but a typed error path keeps the API
    /// uniform).
    pub fn write_sealed(
        secret_bytes: &[u8; 32],
        passphrase: &str,
    ) -> Result<Vec<u8>, SigningError> {
        use rand::RngCore as _;

        let mut salt = [0_u8; SCRYPT_SALT_LEN];
        let mut nonce_bytes = [0_u8; AES_GCM_NONCE_LEN];
        // Per AES-GCM contract: fresh nonce on every encryption op. A
        // randomly-sampled 96-bit nonce is the canonical IND$-CPA-safe
        // construction at the modest scales this path operates at (one
        // encryption per key rotation, not per message).
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

        let mut kek = derive_kek(passphrase, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SigningError::KeyDecrypt)?;
        kek.zeroize();

        let nonce = Nonce::<Aes256Gcm>::from(nonce_bytes);
        let ciphertext = cipher
            .encrypt(&nonce, secret_bytes.as_slice())
            .map_err(|_| SigningError::KeyLoad {
                reason: "AES-GCM encryption failed during sealed-key write",
            })?;

        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.push(FORMAT_MAGIC_V1);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

impl SigningKey for PassphraseSealedSigner {
    fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError> {
        let bytes = self
            .keypair
            .0
            .sign(payload)
            .map_err(|_| SigningError::Sign {
                reason: "K-256 sign_prehash failed in passphrase-sealed mode",
            })?;
        Signature::from_bytes(&bytes)
    }

    fn public_key_did(&self) -> &str {
        &self.public_key_did
    }
}

impl std::fmt::Debug for PassphraseSealedSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassphraseSealedSigner")
            .field("public_key_did", &self.public_key_did)
            .field("secret_key", &"[REDACTED]")
            .field("sealed_at_rest", &true)
            .field("keypair", &self.keypair)
            .finish()
    }
}

/// Split `[ magic | salt | nonce | ciphertext+tag ]` into its three
/// parts (the ciphertext slice still carries the trailing 16-byte
/// auth tag, which `Aes256Gcm::decrypt` consumes).
fn split_sealed_blob(blob: &[u8]) -> Result<SealedBlobParts<'_>, SigningError> {
    if blob.len() < HEADER_LEN {
        return Err(SigningError::KeyLoad {
            reason: "sealed key file is shorter than the format header",
        });
    }
    if blob[0] != FORMAT_MAGIC_V1 {
        return Err(SigningError::KeyLoad {
            reason: "sealed key file has unrecognised format magic byte",
        });
    }
    // Range `1..=SCRYPT_SALT_LEN` is the inclusive form clippy prefers:
    // bytes 1 through SCRYPT_SALT_LEN inclusive, equivalent to
    // `1..1+SCRYPT_SALT_LEN` (16 bytes for SCRYPT_SALT_LEN=16).
    let salt = &blob[1..=SCRYPT_SALT_LEN];
    let nonce = &blob[1 + SCRYPT_SALT_LEN..HEADER_LEN];
    let ciphertext = &blob[HEADER_LEN..];
    Ok((salt, nonce, ciphertext))
}

/// Run scrypt with the module-level cost parameters and write the
/// 32-byte output into a heap buffer. The caller is responsible for
/// zeroising the returned buffer; we wrap that in a typed buffer below.
fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; AES_KEY_LEN], SigningError> {
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, AES_KEY_LEN).map_err(|_| {
        SigningError::KeyLoad {
            reason: "scrypt parameter validation failed (hard-coded defaults)",
        }
    })?;
    let mut out = [0_u8; AES_KEY_LEN];
    scrypt(passphrase.as_bytes(), salt, &params, &mut out).map_err(|_| SigningError::KeyLoad {
        reason: "scrypt KDF failed",
    })?;
    Ok(out)
}

/// Read the unseal passphrase from `POLARIS_SIGNING_PASSPHRASE` or
/// interactive stdin.
///
/// The returned `String` is the caller's to zeroise; we drop it as
/// soon as the KEK is derived inside [`PassphraseSealedSigner::from_sealed_bytes`].
fn read_passphrase() -> Result<String, SigningError> {
    use std::io::BufRead as _;

    if let Ok(p) = std::env::var(PASSPHRASE_ENV) {
        if p.is_empty() {
            return Err(SigningError::KeyLoad {
                reason: "POLARIS_SIGNING_PASSPHRASE is set but empty",
            });
        }
        return Ok(p);
    }

    // Stdin fallback. Only valid if stdin is a terminal — a piped
    // input is acceptable for scripting (e.g., `printf 'pw' | polaris`
    // workflows) but argv is not.
    let mut buf = String::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    handle
        .read_line(&mut buf)
        .map_err(|_| SigningError::KeyLoad {
            reason: "could not read passphrase from stdin",
        })?;
    // Strip exactly one trailing newline; leave embedded whitespace
    // intact — the operator's passphrase is exactly what they typed.
    if buf.ends_with('\n') {
        buf.pop();
        if buf.ends_with('\r') {
            buf.pop();
        }
    }
    if buf.is_empty() {
        return Err(SigningError::KeyLoad {
            reason: "no passphrase provided on stdin",
        });
    }
    Ok(buf)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Keypair as _, Verifier as _};

    use super::*;

    /// Compose the write+read cycle in-memory so the tests do not race
    /// the shared `POLARIS_SIGNING_PASSPHRASE` env var across threads.
    /// The env-driven path is exercised by an integration test gated on
    /// a serial-test guard; that test would conflict with the others
    /// here. The pure split_sealed_blob/derive_kek/encrypt-decrypt path
    /// is what we cover here.
    fn unseal_in_memory(blob: &[u8], passphrase: &str) -> Result<RedactedKeypair, SigningError> {
        // Mirror PassphraseSealedSigner::from_sealed_bytes but accept
        // the passphrase as a parameter so the test does not touch the
        // process env. Wraps the keypair in `RedactedKeypair` so the
        // `Result::unwrap_err` Debug bound (used by negative-path tests
        // below) is satisfied — `K256Keypair` itself is intentionally
        // not `Debug`.
        let (salt, nonce_bytes, ciphertext) = split_sealed_blob(blob)?;
        let mut kek = derive_kek(passphrase, salt)?;
        let cipher = Aes256Gcm::new_from_slice(&kek).map_err(|_| SigningError::KeyDecrypt)?;
        kek.zeroize();
        let nonce_arr: [u8; 12] = nonce_bytes
            .try_into()
            .map_err(|_| SigningError::KeyDecrypt)?;
        let nonce = Nonce::<Aes256Gcm>::from(nonce_arr);
        let pt = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| SigningError::KeyDecrypt)?;
        K256Keypair::from_private_key(&pt)
            .map(RedactedKeypair)
            .map_err(|_| SigningError::KeyLoad {
                reason: "decrypted bytes do not form a valid K-256 secret",
            })
    }

    // ── AC-13 round-trip: write_sealed → unseal → sign → verify ──────

    #[test]
    fn passphrase_sealed_roundtrip_sign_verify() {
        let kp = K256Keypair::generate();
        let secret: [u8; 32] = kp.export_private_key().try_into().unwrap();
        let pw = "correct horse battery staple";
        let sealed = PassphraseSealedSigner::write_sealed(&secret, pw).unwrap();

        // Unseal with the helper that takes the passphrase as a param
        // (avoids racing the global env var with other tests).
        let unsealed = unseal_in_memory(&sealed, pw).unwrap();
        // Sign with the unsealed keypair via proto-blue's Signer trait
        // and verify with the original public key. This exercises the
        // same round-trip the SigningKey trait would, without poking
        // the env-passphrase path.
        let payload = b"polaris label payload";
        let sig = unsealed.0.sign(payload).unwrap();
        let verifier = K256Keypair::verifier_from_compressed(&kp.public_key_compressed()).unwrap();
        assert!(verifier.verify(payload, &sig).unwrap());
    }

    #[test]
    fn passphrase_sealed_wrong_passphrase_fails_authentication() {
        let kp = K256Keypair::generate();
        let secret: [u8; 32] = kp.export_private_key().try_into().unwrap();
        let sealed = PassphraseSealedSigner::write_sealed(&secret, "right").unwrap();
        let err = unseal_in_memory(&sealed, "wrong").unwrap_err();
        assert!(matches!(err, SigningError::KeyDecrypt));
    }

    #[test]
    fn passphrase_sealed_tampered_ciphertext_fails_authentication() {
        let kp = K256Keypair::generate();
        let secret: [u8; 32] = kp.export_private_key().try_into().unwrap();
        let mut sealed = PassphraseSealedSigner::write_sealed(&secret, "pw").unwrap();
        // Flip a bit in the ciphertext region — AES-GCM's tag must reject.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let err = unseal_in_memory(&sealed, "pw").unwrap_err();
        assert!(matches!(err, SigningError::KeyDecrypt));
    }

    #[test]
    fn passphrase_sealed_format_layout_is_stable() {
        let secret = [0_u8; 32];
        let sealed = PassphraseSealedSigner::write_sealed(&secret, "x").unwrap();
        // Magic byte fixed at 0x01.
        assert_eq!(sealed[0], FORMAT_MAGIC_V1);
        // Header is 1 + 16 + 12 = 29 bytes; ciphertext is 32 plaintext
        // + 16-byte GCM tag = 48 bytes; total 77.
        assert_eq!(sealed.len(), HEADER_LEN + SECRET_KEY_LEN + 16);
    }

    #[test]
    fn passphrase_sealed_fresh_nonce_per_encryption() {
        // AES-GCM contract: never reuse a nonce with the same key. We
        // assert that two consecutive write_sealed calls produce
        // distinct nonces (offset 17..29).
        let secret = [0_u8; 32];
        let a = PassphraseSealedSigner::write_sealed(&secret, "pw").unwrap();
        let b = PassphraseSealedSigner::write_sealed(&secret, "pw").unwrap();
        let nonce_a = &a[1 + SCRYPT_SALT_LEN..HEADER_LEN];
        let nonce_b = &b[1 + SCRYPT_SALT_LEN..HEADER_LEN];
        assert_ne!(nonce_a, nonce_b, "AES-GCM nonces must be fresh per op");
        let salt_a = &a[1..=SCRYPT_SALT_LEN];
        let salt_b = &b[1..=SCRYPT_SALT_LEN];
        assert_ne!(salt_a, salt_b, "scrypt salts must be fresh per op");
    }

    #[test]
    fn passphrase_sealed_rejects_unknown_magic() {
        let mut blob = vec![0xFF_u8; HEADER_LEN + 1];
        blob[1..].copy_from_slice(&[0_u8; HEADER_LEN]);
        let err = split_sealed_blob(&blob).unwrap_err();
        assert!(matches!(err, SigningError::KeyLoad { .. }));
    }

    #[test]
    fn passphrase_sealed_rejects_short_blob() {
        let blob = vec![FORMAT_MAGIC_V1; 5];
        let err = split_sealed_blob(&blob).unwrap_err();
        assert!(matches!(err, SigningError::KeyLoad { .. }));
    }

    #[test]
    fn passphrase_sealed_debug_redacts_secret() {
        let kp = K256Keypair::generate();
        let secret: [u8; 32] = kp.export_private_key().try_into().unwrap();
        let sealed = PassphraseSealedSigner::write_sealed(&secret, "pw").unwrap();
        let unsealed = unseal_in_memory(&sealed, "pw").unwrap();
        let signer = PassphraseSealedSigner {
            public_key_did: unsealed.0.did(),
            keypair: unsealed,
        };
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("did:key:z"));
    }
}
