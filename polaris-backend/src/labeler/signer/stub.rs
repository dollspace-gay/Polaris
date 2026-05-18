//! `StubSigner` — placeholder [`SigningKey`] returned by the factory
//! when the configured key file does not yet exist (REQ-A1).
//!
//! # Why a stub exists
//!
//! Polaris boots from a zero-state install: the operator launches the
//! binary against a fresh, empty database with no key material on
//! disk yet. The setup wizard's `POST /api/setup/generate-key`
//! endpoint is what mints the K-256 secret and writes it to the
//! configured path. Before the wizard runs, the labeler subsystem has
//! no real key — but the rest of the process (HTTP routing, the
//! frontend bundle at `/setup`, `/healthz`, `/oauth/client-metadata.json`)
//! must still come up so the operator can reach the wizard in the
//! first place. The stub closes the chicken-and-egg loop: it satisfies
//! the `Arc<dyn SigningKey>` storage slot on `ApiState` without
//! claiming to hold a real key.
//!
//! # Semantics
//!
//! - [`StubSigner::sign`] unconditionally returns
//!   [`SigningError::Sign`] with the static reason
//!   `"labeler signing key not yet provisioned"`. The error category is
//!   the same one the file-plain backend uses for primitive-level
//!   signing failures so the caller's match arms stay uniform.
//! - [`StubSigner::public_key_did`] returns the empty string. Callers
//!   that want to detect "stub vs real" can check
//!   `public_key_did().is_empty()`; the trait surface itself stays
//!   unchanged (no new `is_provisioned()` predicate — see the design
//!   doc's Architecture §A for the rationale).
//!
//! # Replacement
//!
//! The stub is replaced atomically by [`setup::generate_key`] after
//! it writes the key file: the handler loads a real
//! [`super::file_plain::FilePlainSigner`] and pushes the new
//! `Arc<dyn SigningKey>` through the
//! [`tokio::sync::watch::Sender<Arc<dyn SigningKey>>`] held on
//! [`crate::api::state::ApiState`]. The next emit sees the real
//! signer; no process restart is needed.

use std::path::{Path, PathBuf};

use super::{Signature, SigningError, SigningKey};

/// Placeholder [`SigningKey`] used before the labeler is provisioned.
///
/// Held in the `Arc<dyn SigningKey>` slot on `ApiState` from boot
/// until the setup wizard mints a real key. Every `sign` call returns
/// the same structured error so callers know the labeler is not yet
/// ready to emit labels. The configured `path` is stored only for
/// diagnostics (operators see it in `Debug` output) and for the
/// startup WARN — the stub never reads or writes it.
pub struct StubSigner {
    /// The configured signing-key path that did not yet exist when
    /// the factory built this stub. Carried so `Debug` impls and
    /// future diagnostics can render the path without re-parsing
    /// config.
    path: PathBuf,
}

impl StubSigner {
    /// Build a new stub against the configured (currently empty or
    /// missing) signing-key path.
    ///
    /// The path is captured for diagnostics only — the stub never
    /// touches the filesystem. The real key is written by
    /// `POST /api/setup/generate-key` and loaded into a
    /// [`super::file_plain::FilePlainSigner`] that replaces this
    /// stub in the active-signer slot via the watch channel.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Borrow the configured path the stub was built against.
    ///
    /// Used by `Debug` output and tests; the production hot path
    /// (the emitter's `sign` loop) never reads it.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SigningKey for StubSigner {
    fn sign(&self, _payload: &[u8]) -> Result<Signature, SigningError> {
        Err(SigningError::Sign {
            reason: "labeler signing key not yet provisioned",
        })
    }

    fn public_key_did(&self) -> &'static str {
        ""
    }
}

impl std::fmt::Debug for StubSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StubSigner")
            .field("path", &self.path)
            .field("public_key_did", &"<unprovisioned>")
            .finish()
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

    /// AC-A1: `StubSigner::sign` rejects with the structured
    /// `SigningError::Sign { reason: "labeler signing key not yet provisioned" }`
    /// variant; `public_key_did` returns the empty string.
    #[test]
    fn stub_signer_returns_structured_error() {
        let stub = StubSigner::new(PathBuf::from("/tmp/does/not/exist.key"));
        assert_eq!(stub.public_key_did(), "");
        let err = stub
            .sign(b"any payload")
            .expect_err("StubSigner::sign must always return an error");
        match err {
            SigningError::Sign { reason } => {
                assert_eq!(reason, "labeler signing key not yet provisioned");
            }
            other => panic!("expected SigningError::Sign, got {other:?}"),
        }
    }

    #[test]
    fn stub_signer_debug_redacts_unprovisioned_state() {
        let stub = StubSigner::new(PathBuf::from("/tmp/polaris/labeler.key"));
        let rendered = format!("{stub:?}");
        assert!(
            rendered.contains("<unprovisioned>"),
            "Debug output must mark the signer as unprovisioned; got {rendered}",
        );
        assert!(
            rendered.contains("labeler.key"),
            "Debug output must preserve the path for operator diagnostics; got {rendered}",
        );
    }

    #[test]
    fn stub_signer_path_accessor_returns_configured_path() {
        let path = PathBuf::from("/tmp/some/path.key");
        let stub = StubSigner::new(path.clone());
        assert_eq!(stub.path(), path);
    }
}
