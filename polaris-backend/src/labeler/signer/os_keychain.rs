//! `os-keychain` custody mode — wraps the `keyring` crate to fetch a
//! hex-encoded K-256 secret from the OS-native secret store.
//!
//! Platform mapping (delegated to `keyring`):
//!
//! - macOS → Keychain Services.
//! - Linux → freedesktop Secret Service (GNOME Keyring / `KWallet`).
//! - Windows → Credential Manager (DPAPI-backed).
//!
//! On platforms without a supported keychain backend (BSDs without
//! Secret Service, headless containers, CI sandboxes), construction
//! returns [`SigningError::KeyLoad`] with a message naming the
//! platform.
//!
//! # Service / account naming
//!
//! Service name is the constant `"polaris.labeler"`. Account name is
//! operator-configurable so a single host can host multiple labeler
//! identities (e.g., one per operator domain) without aliasing.
//!
//! # On-disk format inside the keychain
//!
//! 64 ASCII hex characters representing the 32-byte K-256 secret —
//! same encoding as `file-plain`. The `keyring` crate's `set_password`
//! / `get_password` API is a UTF-8 string round-trip; the hex encoding
//! survives the keychain backend's UTF-8-only contract on every
//! platform.

use proto_blue::crypto::{K256Keypair, Keypair as _, Signer as _};

use super::{RedactedKeypair, Signature, SigningError, SigningKey};

/// Keychain service identifier under which the secret is stored.
///
/// Kept as a `const` so all platforms agree on the lookup key. A
/// future migration to a per-environment service name (e.g.,
/// `"polaris.labeler.production"`) is a coordinated rename, not a
/// per-call decision.
const KEYRING_SERVICE: &str = "polaris.labeler";

/// Signer backed by an OS-native secret store.
pub struct OsKeychainSigner {
    keypair: RedactedKeypair,
    public_key_did: String,
    account: String,
}

impl OsKeychainSigner {
    /// Fetch the K-256 secret from the OS keychain under
    /// `(KEYRING_SERVICE, account)` and instantiate a signer.
    ///
    /// # Errors
    ///
    /// Returns [`SigningError::KeyLoad`] when:
    ///
    /// - the keychain backend is not available on this platform,
    /// - no entry exists for `(service, account)`,
    /// - the stored value is not valid hex or wrong length,
    /// - the keychain returns a transport-level error (locked vault,
    ///   user denied prompt, …).
    pub fn from_account(account: &str) -> Result<Self, SigningError> {
        let entry = keyring::Entry::new(KEYRING_SERVICE, account)
            .map_err(|e| map_keyring_construct_err(&e))?;
        let stored = entry
            .get_password()
            .map_err(|e| map_keyring_lookup_err(&e))?;
        let bytes = hex::decode(stored.trim()).map_err(|_| SigningError::KeyLoad {
            reason: "os-keychain entry is not valid hex",
        })?;
        if bytes.len() != 32 {
            return Err(SigningError::KeyLoad {
                reason: "os-keychain secret must decode to exactly 32 bytes (K-256 secret)",
            });
        }
        let keypair = K256Keypair::from_private_key(&bytes).map_err(|_| SigningError::KeyLoad {
            reason: "os-keychain secret bytes do not form a valid K-256 secret",
        })?;
        let public_key_did = keypair.did();
        Ok(Self {
            keypair: RedactedKeypair(keypair),
            public_key_did,
            account: account.to_owned(),
        })
    }
}

impl SigningKey for OsKeychainSigner {
    fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError> {
        let bytes = self
            .keypair
            .0
            .sign(payload)
            .map_err(|_| SigningError::Sign {
                reason: "K-256 sign_prehash failed in os-keychain mode",
            })?;
        Signature::from_bytes(&bytes)
    }

    fn public_key_did(&self) -> &str {
        &self.public_key_did
    }
}

impl std::fmt::Debug for OsKeychainSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsKeychainSigner")
            .field("service", &KEYRING_SERVICE)
            .field("account", &self.account)
            .field("public_key_did", &self.public_key_did)
            .field("secret_key", &"[REDACTED]")
            .field("keypair", &self.keypair)
            .finish()
    }
}

/// Map a `keyring::Error` at the *constructor* stage (`Entry::new`)
/// onto [`SigningError::KeyLoad`] with a category-only message.
///
/// The category strings name the platform when the backend is missing
/// so an operator running on (e.g.) a BSD without Secret Service sees
/// an actionable error.
fn map_keyring_construct_err(err: &keyring::Error) -> SigningError {
    match err {
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_) => {
            SigningError::KeyLoad {
                reason: platform_unsupported_message(),
            }
        }
        _ => SigningError::KeyLoad {
            reason: "could not address os-keychain entry",
        },
    }
}

/// Map a `keyring::Error` at the *lookup* stage
/// (`Entry::get_password`) onto [`SigningError::KeyLoad`] with a
/// category-only message.
fn map_keyring_lookup_err(err: &keyring::Error) -> SigningError {
    match err {
        keyring::Error::NoEntry => SigningError::KeyLoad {
            reason: "no os-keychain entry found for (polaris.labeler, account)",
        },
        keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_) => {
            SigningError::KeyLoad {
                reason: platform_unsupported_message(),
            }
        }
        _ => SigningError::KeyLoad {
            reason: "could not read os-keychain entry",
        },
    }
}

/// Platform-named "no keychain backend here" message.
const fn platform_unsupported_message() -> &'static str {
    if cfg!(target_os = "macos") {
        "os-keychain: macOS Keychain Services unavailable"
    } else if cfg!(target_os = "linux") {
        "os-keychain: freedesktop Secret Service unavailable"
    } else if cfg!(target_os = "windows") {
        "os-keychain: Windows Credential Manager unavailable"
    } else {
        "os-keychain: no keychain backend on this platform"
    }
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

    /// AC-13 round-trip for the os-keychain mode.
    ///
    /// Ignored by default because it mutates real OS credential store
    /// state (would pollute the developer's keychain) and the keychain
    /// daemons (Secret Service, macOS Keychain) are not available in a
    /// stock CI sandbox. To exercise locally on macOS / Linux /
    /// Windows:
    ///
    /// ```bash
    /// cargo test -p polaris-backend signer::os_keychain::tests:: -- --ignored
    /// ```
    ///
    /// On Linux additionally requires a running Secret Service daemon
    /// (`gnome-keyring-daemon` or `kwalletd`).
    #[ignore = "requires a real OS keychain daemon — see test docstring"]
    #[test]
    fn os_keychain_roundtrip_sign_verify() {
        use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Verifier as _};

        let account = format!("test-{}", uuid::Uuid::new_v4());
        let kp = K256Keypair::generate();
        let secret_hex = hex::encode(kp.export_private_key());

        let entry = keyring::Entry::new(KEYRING_SERVICE, &account).unwrap();
        entry.set_password(&secret_hex).unwrap();

        let result = (|| -> Result<(), Box<dyn std::error::Error>> {
            let signer = OsKeychainSigner::from_account(&account)?;
            let payload = b"polaris label payload";
            let sig = signer.sign(payload)?;
            let verifier = K256Keypair::verifier_from_compressed(&kp.public_key_compressed())?;
            assert!(verifier.verify(payload, sig.as_bytes())?);
            assert_eq!(signer.public_key_did(), kp.did());
            Ok(())
        })();

        // Always tidy up the keychain entry, even if the test failed.
        let _ = entry.delete_credential();
        result.unwrap();
    }

    #[test]
    fn os_keychain_missing_entry_returns_keyload_not_panic() {
        // Use a UUID-prefixed account name so we are vanishingly likely
        // to collide with a real entry on a developer's machine.
        let account = format!("missing-{}", uuid::Uuid::new_v4());
        let err = OsKeychainSigner::from_account(&account).unwrap_err();
        // We do not assert *which* KeyLoad reason: a CI sandbox without
        // a keychain daemon hits PlatformFailure; a dev box with a
        // daemon and no entry hits NoEntry. Both must funnel through
        // KeyLoad — that's the contract.
        assert!(matches!(err, SigningError::KeyLoad { .. }));
    }
}
