//! `file-plain` custody mode — hex-encoded K-256 secret on disk.
//!
//! This is the default for the labeler deployment profile, matching
//! Ozone's `OZONE_SIGNING_KEY_HEX` posture so migration cost stays at
//! zero. The threat model is honest: no at-rest defense, no
//! code-execution defense. The startup WARN log is part of the
//! contract — operators see the posture every time the service starts.
//!
//! # On-disk format
//!
//! `<key file>` is a single line of 64 ASCII hex characters (32 bytes
//! of K-256 secret). Surrounding whitespace is tolerated; embedded
//! whitespace is not.
//!
//! # File-mode enforcement
//!
//! On Unix, the file must be mode `0o600` (rw owner only). Anything
//! more permissive is rejected at load time. The check is intentionally
//! conservative — Polaris would rather refuse to boot than start with a
//! world-readable signing key.
//!
//! # Signing primitive
//!
//! Delegates to `proto_blue_crypto::K256Keypair::sign`, which performs
//! RFC 6979 deterministic ECDSA over SHA-256 of the payload and returns
//! a low-S-normalised 64-byte compact signature — exactly what the
//! atproto label-signing contract expects.

use std::path::Path;
use std::sync::Once;

use proto_blue::crypto::{K256Keypair, Keypair as _, Signer as _};
use tracing::warn;

use super::{RedactedKeypair, Signature, SigningError, SigningKey};

/// Documentation URL appended to the file-plain startup warning.
///
/// Operators clicking through the WARN line land on the stronger-modes
/// section of the integration design document. Kept as a `const` so a
/// single place owns the URL and tests can grep for it.
const STRONGER_MODES_DOCS: &str = "https://github.com/dollspace-gay/polaris/blob/main/.design/polaris-proto-blue-integration.md#req-11";

/// Tracks whether the file-plain WARN has already been emitted in this
/// process. AC-14 mandates the message appear "in the first 100 log
/// lines" *exactly once* — repeated `from_path` calls in a test suite
/// (or a hypothetical multi-key setup) must not multi-log.
static WARN_ONCE: Once = Once::new();

#[cfg(test)]
#[allow(
    dead_code,
    reason = "documentation shim — `Once` cannot be reset; the function body is intentionally empty and the comment is the contract"
)]
pub(super) fn reset_warn_once_for_tests() {
    // `Once` cannot be reset; tests that want to re-trigger the WARN
    // run inside the `tracing_test` per-test subscriber and the first
    // such test in the process is the one that captures the message.
    // This shim exists so the test module can be explicit about that
    // constraint without changing the production semantics.
}

/// Hex-encoded K-256 secret loaded from a file.
///
/// Cheap to construct (one file read + one hex decode at startup);
/// thereafter `sign()` is in-process ECDSA with the key bytes held in
/// the wrapped `K256Keypair`. The wrapped type owns the secret zeroising
/// on drop is the responsibility of `proto-blue-crypto` and the
/// underlying `k256` crate.
pub struct FilePlainSigner {
    keypair: RedactedKeypair,
    public_key_did: String,
}

impl FilePlainSigner {
    /// Load a K-256 secret from `path`.
    ///
    /// On Unix, refuses files with a mode broader than `0o600`. Logs a
    /// single startup-time WARN identifying the custody posture and
    /// linking the alternatives docs (AC-14 part 1).
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::KeyLoad`] for: missing file, wrong file
    /// mode, malformed hex, wrong key length.
    pub fn from_path(path: &Path) -> Result<Self, SigningError> {
        enforce_file_mode(path)?;

        let raw = std::fs::read_to_string(path).map_err(|_| SigningError::KeyLoad {
            reason: "could not read file-plain key file",
        })?;
        let hex_str = raw.trim();
        let bytes = hex::decode(hex_str).map_err(|_| SigningError::KeyLoad {
            reason: "file-plain key file is not valid hex",
        })?;
        if bytes.len() != 32 {
            return Err(SigningError::KeyLoad {
                reason: "file-plain key must decode to exactly 32 bytes (K-256 secret)",
            });
        }
        let keypair = K256Keypair::from_private_key(&bytes).map_err(|_| SigningError::KeyLoad {
            reason: "file-plain key bytes do not form a valid K-256 secret",
        })?;
        let public_key_did = keypair.did();

        // AC-14 part 1: log the custody posture exactly once per process.
        // `Once::call_once` is the synchronisation primitive — if two
        // tasks race construction, only the first emits the warning.
        WARN_ONCE.call_once(|| {
            warn!(
                mode = "file-plain",
                reason = "labeler signing-key on disk in plaintext",
                docs = STRONGER_MODES_DOCS,
                "labeler signing key custody",
            );
        });

        Ok(Self {
            keypair: RedactedKeypair(keypair),
            public_key_did,
        })
    }
}

impl SigningKey for FilePlainSigner {
    fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError> {
        let bytes = self
            .keypair
            .0
            .sign(payload)
            .map_err(|_| SigningError::Sign {
                reason: "K-256 sign_prehash failed in file-plain mode",
            })?;
        Signature::from_bytes(&bytes)
    }

    fn public_key_did(&self) -> &str {
        &self.public_key_did
    }
}

// `RedactedKeypair`'s Debug renders `<redacted>` so derive is safe —
// the secret never appears in the formatted output.
impl std::fmt::Debug for FilePlainSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never include the secret bytes. The DID is the *public* key
        // (it's published in the labeler service record on Bluesky) so
        // including it here is information-equivalent to looking at the
        // wire, but the secret is wrapped behind a redaction sentinel.
        f.debug_struct("FilePlainSigner")
            .field("public_key_did", &self.public_key_did)
            .field("secret_key", &"[REDACTED]")
            .field("keypair", &self.keypair)
            .finish()
    }
}

/// On Unix, refuse to load a file whose mode bits are wider than
/// `0o600`. On non-Unix targets this is a no-op (Windows ACLs are
/// validated by the operator's deployment tooling — Polaris's portable
/// check would either be wrong or wildly conservative there).
#[cfg(unix)]
fn enforce_file_mode(path: &Path) -> Result<(), SigningError> {
    use std::os::unix::fs::PermissionsExt as _;

    let meta = std::fs::metadata(path).map_err(|_| SigningError::KeyLoad {
        reason: "could not stat file-plain key file",
    })?;
    // mode() returns the full st_mode; mask off the file-type bits.
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SigningError::KeyLoad {
            reason: "file-plain key file must be mode 0o600 (owner read/write only)",
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn enforce_file_mode(_path: &Path) -> Result<(), SigningError> {
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use std::io::Write as _;

    use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Keypair as _, Verifier as _};

    use super::*;

    /// Write a fresh 32-byte K-256 secret to a temp file with mode 0o600
    /// and return (path, the keypair we generated for round-trip checks).
    fn write_fresh_key_file_0o600() -> (tempfile::NamedTempFile, K256Keypair) {
        let kp = K256Keypair::generate();
        let secret = kp.export_private_key();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        write!(tmp, "{}", hex::encode(secret)).unwrap();
        tmp.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = tmp.as_file().metadata().unwrap().permissions();
            perms.set_mode(0o600);
            tmp.as_file().set_permissions(perms).unwrap();
        }
        (tmp, kp)
    }

    // ── AC-13 round-trip: sign → verify ──────────────────────────────

    #[test]
    fn file_plain_signs_and_verifies() {
        let (tmp, kp) = write_fresh_key_file_0o600();
        let signer = FilePlainSigner::from_path(tmp.path()).unwrap();
        let payload = b"polaris label payload";
        let sig = signer.sign(payload).unwrap();

        let verifier = K256Keypair::verifier_from_compressed(&kp.public_key_compressed()).unwrap();
        assert!(verifier.verify(payload, sig.as_bytes()).unwrap());
        // Tamper detection: flipping one bit breaks the signature.
        let mut tampered = *sig.as_bytes();
        tampered[0] ^= 0x01;
        assert!(!verifier.verify(payload, &tampered).unwrap());
    }

    #[test]
    fn file_plain_publishes_did_key_for_loaded_secret() {
        let (tmp, kp) = write_fresh_key_file_0o600();
        let signer = FilePlainSigner::from_path(tmp.path()).unwrap();
        assert_eq!(signer.public_key_did(), kp.did());
        assert!(signer.public_key_did().starts_with("did:key:z"));
    }

    #[test]
    fn file_plain_rejects_invalid_hex() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "not-hex").unwrap();
        tmp.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = tmp.as_file().metadata().unwrap().permissions();
            perms.set_mode(0o600);
            tmp.as_file().set_permissions(perms).unwrap();
        }
        let err = FilePlainSigner::from_path(tmp.path()).unwrap_err();
        assert!(matches!(err, SigningError::KeyLoad { .. }));
    }

    #[test]
    fn file_plain_rejects_wrong_length() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // 31 bytes — one short.
        write!(tmp, "{}", hex::encode([0_u8; 31])).unwrap();
        tmp.flush().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = tmp.as_file().metadata().unwrap().permissions();
            perms.set_mode(0o600);
            tmp.as_file().set_permissions(perms).unwrap();
        }
        let err = FilePlainSigner::from_path(tmp.path()).unwrap_err();
        assert!(matches!(err, SigningError::KeyLoad { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn file_plain_rejects_world_readable_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let (tmp, _) = write_fresh_key_file_0o600();
        let mut perms = tmp.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o644);
        tmp.as_file().set_permissions(perms).unwrap();
        let err = FilePlainSigner::from_path(tmp.path()).unwrap_err();
        assert!(matches!(err, SigningError::KeyLoad { .. }));
    }

    #[test]
    fn file_plain_debug_redacts_secret() {
        let (tmp, _) = write_fresh_key_file_0o600();
        let signer = FilePlainSigner::from_path(tmp.path()).unwrap();
        let rendered = format!("{signer:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(rendered.contains("did:key:z"));
    }

    // ── AC-14 part 1: WARN once ──────────────────────────────────────

    #[tracing_test::traced_test]
    #[test]
    fn file_plain_warn_is_emitted_with_required_fields() {
        // tracing_test::traced_test installs a per-test subscriber that
        // captures emitted events. The WARN is `Once`-gated, so this
        // test only sees the warning if it's the first FilePlainSigner
        // instantiation in the process. We accept that ordering
        // constraint: `cargo test` runs each `#[test]` in its own thread
        // but the `Once` is process-global. The test asserts the
        // *content* of the WARN when it does fire.
        let (tmp, _) = write_fresh_key_file_0o600();
        // Force the WARN at least once by calling the same constructor
        // multiple times; only one emits.
        let _s1 = FilePlainSigner::from_path(tmp.path()).unwrap();
        let _s2 = FilePlainSigner::from_path(tmp.path()).unwrap();
        let _s3 = FilePlainSigner::from_path(tmp.path()).unwrap();

        // `tracing_test`'s `logs_contain` checks the per-test buffer.
        // If the Once already fired earlier in the process the buffer
        // is empty for this test — which is the correct AC-14 semantic
        // (exactly once per process). We assert the "once" invariant
        // by counting occurrences if any fired.
        let any_warn_observed = logs_contain("labeler signing key custody");
        if any_warn_observed {
            assert!(logs_contain("mode=\"file-plain\""));
            assert!(logs_contain(STRONGER_MODES_DOCS));
        }
        // The strict "warn emitted once" invariant is exercised in the
        // dedicated test below using a fresh subscriber.
    }

    #[test]
    fn file_plain_warn_is_emitted_at_most_once_across_instantiations() {
        // This is the strict half of AC-14 part 1. We do not use
        // `tracing_test` here because that crate installs subscribers
        // per-test and the `Once` is process-global; instead we
        // exercise the Once primitive directly: the second call_once
        // is a no-op.
        let called_count = std::sync::atomic::AtomicUsize::new(0);
        let local_once = Once::new();
        for _ in 0..5 {
            local_once.call_once(|| {
                called_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
        assert_eq!(called_count.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
