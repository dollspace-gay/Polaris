//! Shared OAuth client-metadata loader for the ATProto OAuth flow.
//!
//! Issue #61. Consumed by `polaris-backend::auth::atproto` (the moderator
//! ATProto OAuth verifier, #31) and `polaris-publish-labeler-record`'s
//! `--oauth` CLI flow (#27). One canonical loader, one error type, one set
//! of tests — both consumers re-export or wrap this module rather than
//! duplicating the read-and-parse logic.
//!
//! # Why this lives in polaris-types
//!
//! The loader is purely "read JSON from disk, decode into
//! `proto_blue::oauth::ClientMetadata`". It carries no Polaris-business
//! logic: it doesn't talk to the database, doesn't seal anything at rest,
//! and doesn't drive a flow. That makes it a typed-input adapter — the
//! same category as the rest of `polaris-types` — and the natural home
//! for the one shared piece.
//!
//! See the crate-level `Cargo.toml` for the dependency-policy carve-out
//! that lets this module name a proto-blue type while the domain modules
//! (`subject`, `incident`, …) stay plain-serde.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use polaris_types::oauth_config::load_client_metadata;
//!
//! let metadata = load_client_metadata(Path::new("./client-metadata.json"))?;
//! assert!(!metadata.client_id.is_empty());
//! # Ok::<(), polaris_types::oauth_config::OauthConfigError>(())
//! ```

use std::path::Path;

use thiserror::Error;

/// Re-export so consumers can name the loaded type without reaching into
/// `proto_blue::oauth` themselves. Keeps the upstream surface area
/// grep-able from a single module.
pub use proto_blue::oauth::OAuthClientMetadata as ClientMetadata;

/// Errors that [`load_client_metadata`] can surface.
///
/// Two distinct variants because the failure mode dictates the operator's
/// next action: a `Read` error means "check the path / permissions", a
/// `Parse` error means "the JSON shape is wrong — diff against the
/// proto-blue example".
#[derive(Debug, Error)]
pub enum OauthConfigError {
    /// `std::fs::read` failed.
    ///
    /// `path` is the lossy-string form of the path the caller passed; it
    /// is stored as `String` (not `PathBuf`) so the `Display` impl can
    /// echo a stable rendering across platforms without re-running
    /// `path.display()`.
    #[error("read client_metadata at {path}: {source}")]
    Read {
        /// The path the loader was asked to read.
        path: String,
        /// The underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// `serde_json::from_slice` rejected the file's bytes.
    #[error("parse client_metadata at {path}: {source}")]
    Parse {
        /// The path the loader was asked to read.
        path: String,
        /// The underlying decode error.
        #[source]
        source: serde_json::Error,
    },
}

/// Read an OAuth client-metadata JSON document from disk and decode it
/// into the proto-blue typed [`ClientMetadata`].
///
/// The function performs only the read + decode steps. **Profile
/// validation** (atproto-specific shape: `dpop_bound_access_tokens`,
/// allowed `token_endpoint_auth_method` values, `redirect_uris`
/// well-formedness) is the caller's responsibility — they hold the
/// proto-blue context (`OAuthClient::new` plus
/// `proto_blue::oauth::validate_client_metadata`) and surface the
/// validation error in whichever error type their flow uses.
///
/// # Errors
///
/// - [`OauthConfigError::Read`] when the file is missing, unreadable,
///   or `std::fs::read` otherwise fails.
/// - [`OauthConfigError::Parse`] when the bytes are not valid JSON or
///   the JSON shape does not match the proto-blue
///   [`OAuthClientMetadata`] schema.
///
/// [`OAuthClientMetadata`]: proto_blue::oauth::OAuthClientMetadata
pub fn load_client_metadata(path: &Path) -> Result<ClientMetadata, OauthConfigError> {
    let bytes = std::fs::read(path).map_err(|source| OauthConfigError::Read {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| OauthConfigError::Parse {
        path: path.display().to_string(),
        source,
    })
}

#[cfg(test)]
// Tests are allowed to panic per rust-quality §7. The workspace lints
// otherwise flag `.unwrap()` / `.expect()` / `panic!()` even inside
// `#[cfg(test)]`.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "rust-quality §7: tests use the panic-on-failure pattern"
)]
mod tests {
    use super::*;

    fn fixture_metadata() -> ClientMetadata {
        ClientMetadata {
            client_id: "https://example.com/client-metadata.json".into(),
            redirect_uris: vec!["http://127.0.0.1:8421/callback".into()],
            response_types: Some(vec!["code".into()]),
            grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
            scope: Some("atproto transition:generic".into()),
            token_endpoint_auth_method: Some("none".into()),
            token_endpoint_auth_signing_alg: None,
            application_type: Some("web".into()),
            dpop_bound_access_tokens: Some(true),
            client_name: Some("Polaris".into()),
            client_uri: None,
            logo_uri: None,
        }
    }

    #[test]
    fn load_client_metadata_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        let metadata = fixture_metadata();
        let bytes = serde_json::to_vec(&metadata).unwrap();
        std::fs::write(&path, bytes).unwrap();

        let loaded = load_client_metadata(&path).unwrap();
        assert_eq!(loaded.client_id, metadata.client_id);
        assert_eq!(loaded.redirect_uris, metadata.redirect_uris);
        assert_eq!(
            loaded.dpop_bound_access_tokens,
            metadata.dpop_bound_access_tokens
        );
    }

    #[test]
    fn load_client_metadata_missing_file_yields_read_error() {
        let err = load_client_metadata(Path::new("/nonexistent/path/x.json")).unwrap_err();
        assert!(
            matches!(err, OauthConfigError::Read { .. }),
            "expected Read, got {err:?}"
        );
    }

    #[test]
    fn load_client_metadata_bad_json_yields_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(&path, b"not valid json").unwrap();
        let err = load_client_metadata(&path).unwrap_err();
        assert!(
            matches!(err, OauthConfigError::Parse { .. }),
            "expected Parse, got {err:?}"
        );
    }

    #[test]
    fn read_error_path_string_matches_input_path() {
        let path = Path::new("/nonexistent/path/x.json");
        let err = load_client_metadata(path).unwrap_err();
        match err {
            OauthConfigError::Read { path: p, .. } => assert_eq!(p, path.display().to_string()),
            OauthConfigError::Parse { .. } => panic!("expected Read variant"),
        }
    }

    #[test]
    fn parse_error_path_string_matches_input_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/dir/client.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{").unwrap();
        let err = load_client_metadata(&path).unwrap_err();
        match err {
            OauthConfigError::Parse { path: p, .. } => assert_eq!(p, path.display().to_string()),
            OauthConfigError::Read { .. } => panic!("expected Parse variant"),
        }
    }
}
