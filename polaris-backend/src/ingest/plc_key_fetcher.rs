//! Live `UpstreamKeyFetcher` for ATProto labelers.
//!
//! Resolves the `did:key:z…` signing key the labeler emits with each
//! `subscribeLabels` frame by fetching the labeler's DID document and
//! extracting the `#atproto_label` verification method.
//!
//! Two DID methods are supported, mirroring the AT Protocol DID
//! resolution spec:
//!
//! * **`did:plc:…`** → HTTP `GET {plc_base}/{did}` against the PLC
//!   directory (default <https://plc.directory>).
//! * **`did:web:host[:path]`** → HTTP `GET https://{host}/{path}/did.json`
//!   (no path → `/.well-known/did.json`).
//!
//! The returned document is parsed for a
//! `verificationMethod[]` entry whose `id` ends in `#atproto_label`, and
//! the entry's `publicKeyMultibase` (already a `z…` multikey form) is
//! reassembled into the canonical `did:key:z…` shape that
//! `proto_blue::crypto::verify_signature` consumes.
//!
//! Failures collapse into [`upstream_labels::CacheError::Fetch`] with a
//! cause-pinned message — the cache layer above this fetcher logs that
//! string verbatim against the offending upstream DID, so each error
//! variant must be specific enough for an operator to diagnose without
//! attaching a debugger.

use std::time::Duration;

use serde_json::Value;
use tracing::{debug, warn};

use crate::ingest::upstream_labels::{CacheError, UpstreamKeyFetcher};

/// Default base URL of the PLC directory. The `did:plc:…` method
/// resolves via this directory; the constant is exposed for tests that
/// want to assert the production default without re-typing the literal.
pub const DEFAULT_PLC_BASE_URL: &str = "https://plc.directory";

/// Connect timeout — capped low so a stuck DNS / TLS handshake never
/// wedges the verify-or-drop boundary. The label consumer is happy to
/// drop one frame and move on; it is not happy to block forever.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total request timeout. Read budget once a connection is up.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Verification-method id suffix that marks the labeler signing key.
/// The PLC operation builder in `polaris-backend/src/api/setup.rs`
/// emits this exact suffix.
const ATPROTO_LABEL_SUFFIX: &str = "#atproto_label";

/// Production [`UpstreamKeyFetcher`].
///
/// Holds a long-lived `reqwest::Client` so successive fetches reuse a
/// TLS session pool — the cache invokes this once per upstream per TTL
/// (24h), so the connection pool stays warm enough to satisfy the
/// occasional cold-cache miss without re-handshaking.
#[derive(Debug, Clone)]
pub struct PlcKeyFetcher {
    client: reqwest::Client,
    plc_base_url: String,
}

impl PlcKeyFetcher {
    /// Build a fetcher pointed at the public PLC directory.
    ///
    /// Construction can fail only if `reqwest` cannot build its
    /// internal client — typically a TLS-stack misconfiguration. The
    /// error string preserves the underlying cause so the operator
    /// gets actionable output in startup logs rather than a generic
    /// "client init failed".
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Fetch`] if the HTTP client cannot be built.
    pub fn new() -> Result<Self, CacheError> {
        Self::with_base_url(DEFAULT_PLC_BASE_URL)
    }

    /// Build a fetcher pointed at a custom PLC base URL.
    ///
    /// Test-only path. Production should always use [`Self::new`].
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Fetch`] if the HTTP client cannot be built.
    pub fn with_base_url(plc_base_url: &str) -> Result<Self, CacheError> {
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent("polaris-labeler/1.0 (+https://github.com/anthropics/polaris)")
            .build()
            .map_err(|e| CacheError::Fetch {
                message: format!("reqwest::Client::build: {e}"),
            })?;
        Ok(Self {
            client,
            plc_base_url: plc_base_url.trim_end_matches('/').to_owned(),
        })
    }

    /// Internal worker: fetch + parse + format. Split out from the
    /// trait `fetch` boxed-future shell so the body is testable with
    /// plain `.await`.
    async fn resolve(&self, upstream_did: &str) -> Result<String, CacheError> {
        let url = resolve_did_doc_url(upstream_did, &self.plc_base_url)?;
        debug!(target: "plc_key_fetcher", did = %upstream_did, %url, "fetching DID doc");

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| CacheError::Fetch {
                message: format!("GET {url} failed: {e}"),
            })?;

        let status = resp.status();
        if !status.is_success() {
            // PLC returns 404 for unknown DIDs and 410 for tombstoned
            // ones; either way the operator's `upstream_labelers` row
            // is bad data and the loud surface is correct.
            return Err(CacheError::Fetch {
                message: format!("GET {url} returned HTTP {status}"),
            });
        }

        let doc: Value = resp.json().await.map_err(|e| CacheError::Fetch {
            message: format!("GET {url} JSON parse failed: {e}"),
        })?;

        let multibase = extract_atproto_label_multibase(&doc, upstream_did)?;
        let did_key = format!("did:key:{multibase}");
        debug!(target: "plc_key_fetcher", did = %upstream_did, %did_key, "resolved signing key");
        Ok(did_key)
    }
}

impl UpstreamKeyFetcher for PlcKeyFetcher {
    fn fetch(
        &self,
        upstream_did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, CacheError>> + Send + '_>>
    {
        let did = upstream_did.to_owned();
        let me = self.clone();
        Box::pin(async move {
            let result = me.resolve(&did).await;
            if let Err(ref e) = result {
                // `Display` on `CacheError` already includes the inner
                // `Fetch.message` (or sqlx error). We log via `%e` rather
                // than hand-decomposing the variant — both shapes carry
                // a human-meaningful causal chain.
                warn!(
                    target: "plc_key_fetcher",
                    upstream_did = %did,
                    error = %e,
                    "PLC key fetch failed"
                );
            }
            result
        })
    }
}

/// Resolve the DID document URL for either `did:plc:…` or `did:web:…`.
///
/// `did:plc:LIDNUM` → `{base}/did:plc:LIDNUM`.
///
/// `did:web:example.com` → `https://example.com/.well-known/did.json`.
/// `did:web:example.com:foo:bar` → `https://example.com/foo/bar/did.json`.
///
/// The `did:web` decoding mirrors the W3C did:web method spec: colons
/// after the host segment are path separators; the implicit root case
/// (no extra segments) substitutes `/.well-known/did.json`.
///
/// # Errors
///
/// Returns [`CacheError::Fetch`] if the DID is malformed or uses an
/// unsupported method.
fn resolve_did_doc_url(upstream_did: &str, plc_base: &str) -> Result<String, CacheError> {
    if let Some(_plc_id) = upstream_did.strip_prefix("did:plc:") {
        // Pass the full DID through — the PLC directory keys are the
        // canonical `did:plc:…` form, not the bare identifier.
        return Ok(format!("{plc_base}/{upstream_did}"));
    }

    if let Some(web_rest) = upstream_did.strip_prefix("did:web:") {
        // did:web identifier is colon-joined; the first segment is the
        // host (with optional `%3A`-encoded port), the remainder is the
        // path. Per the spec, no path → `.well-known/did.json`.
        let mut segments = web_rest.split(':');
        let host_raw =
            segments
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| CacheError::Fetch {
                    message: format!("did:web identifier missing host segment: {upstream_did}"),
                })?;
        // The spec allows percent-encoded colons in the host (for ports).
        // Decode them so the resulting URL is well-formed.
        let host = host_raw.replace("%3A", ":").replace("%3a", ":");

        let path_segments: Vec<&str> = segments.collect();
        let path = if path_segments.is_empty() {
            "/.well-known/did.json".to_owned()
        } else {
            format!("/{}/did.json", path_segments.join("/"))
        };

        return Ok(format!("https://{host}{path}"));
    }

    Err(CacheError::Fetch {
        message: format!("unsupported DID method (only did:plc and did:web): {upstream_did}"),
    })
}

/// Parse a DID document and pull the `#atproto_label` verification
/// method's `publicKeyMultibase` field.
///
/// The DID document shape per W3C DID Core / ATProto: top-level
/// `verificationMethod` is an array of objects, each with `id`,
/// `type`, `controller`, `publicKeyMultibase`. The labeler signing
/// key lives in the entry whose `id` ends in `#atproto_label` — this
/// suffix is owned by ATProto's identity convention, not arbitrary.
///
/// # Errors
///
/// Returns [`CacheError::Fetch`] with a specific cause if the document
/// is missing the array, missing the `#atproto_label` entry, missing
/// the multibase field, or has a non-string multibase.
fn extract_atproto_label_multibase(doc: &Value, upstream_did: &str) -> Result<String, CacheError> {
    let methods = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| CacheError::Fetch {
            message: format!("DID doc for {upstream_did} missing `verificationMethod` array"),
        })?;

    let label_method = methods
        .iter()
        .find(|entry| {
            entry
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|id| id.ends_with(ATPROTO_LABEL_SUFFIX))
        })
        .ok_or_else(|| CacheError::Fetch {
            message: format!(
                "DID doc for {upstream_did} has no `#atproto_label` verification method (labeler not configured for label signing?)"
            ),
        })?;

    let multibase = label_method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| CacheError::Fetch {
            message: format!(
                "DID doc for {upstream_did} has `#atproto_label` entry without `publicKeyMultibase` string"
            ),
        })?;

    if !multibase.starts_with('z') {
        return Err(CacheError::Fetch {
            message: format!(
                "DID doc for {upstream_did} has malformed `publicKeyMultibase` (expected base58btc `z…` prefix, got `{multibase}`)"
            ),
        });
    }

    Ok(multibase.to_owned())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code — rust-quality §7"
)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── URL-resolution tests ─────────────────────────────────────────

    #[test]
    fn did_plc_resolves_to_base_url_path() {
        let url = resolve_did_doc_url("did:plc:ar7c4by46qjdydhdevvrndac", "https://plc.directory")
            .expect("did:plc URL");
        assert_eq!(
            url,
            "https://plc.directory/did:plc:ar7c4by46qjdydhdevvrndac"
        );
    }

    #[test]
    fn did_plc_trims_trailing_slash_in_base() {
        // Constructor normalises this, but the helper itself should
        // handle a raw base too.
        let url = resolve_did_doc_url("did:plc:abc", "https://plc.directory").unwrap();
        assert_eq!(url, "https://plc.directory/did:plc:abc");
    }

    #[test]
    fn did_web_host_only_uses_well_known() {
        let url = resolve_did_doc_url("did:web:example.com", "ignored").unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn did_web_with_path_segments_uses_explicit_path() {
        let url = resolve_did_doc_url("did:web:example.com:foo:bar", "ignored").unwrap();
        assert_eq!(url, "https://example.com/foo/bar/did.json");
    }

    #[test]
    fn did_web_with_percent_encoded_port_decodes_host() {
        let url = resolve_did_doc_url("did:web:example.com%3A8443", "ignored").unwrap();
        assert_eq!(url, "https://example.com:8443/.well-known/did.json");
    }

    #[test]
    fn did_web_missing_host_rejected() {
        let err = resolve_did_doc_url("did:web:", "ignored").unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch variant");
        };
        assert!(message.contains("missing host segment"), "got: {message}");
    }

    #[test]
    fn unsupported_did_method_rejected() {
        let err = resolve_did_doc_url("did:example:abc", "ignored").unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch variant");
        };
        assert!(message.contains("unsupported DID method"), "got: {message}");
    }

    // ── DID-doc-parser tests ──────────────────────────────────────────

    /// The fixture mirrors the real labeler doc captured live from
    /// `did:plc:ar7c4by46qjdydhdevvrndac` (moderation.bsky.app):
    /// two verification methods, one `#atproto`, one `#atproto_label`,
    /// both `Multikey` typed.
    fn canonical_labeler_did_doc() -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ],
            "id": "did:plc:ar7c4by46qjdydhdevvrndac",
            "verificationMethod": [
                {
                    "id": "did:plc:ar7c4by46qjdydhdevvrndac#atproto",
                    "type": "Multikey",
                    "controller": "did:plc:ar7c4by46qjdydhdevvrndac",
                    "publicKeyMultibase": "zQ3shoG4QW9B3zvKSSiRwwc1De7MFQLNBT9A71gr12GKwMgHu",
                },
                {
                    "id": "did:plc:ar7c4by46qjdydhdevvrndac#atproto_label",
                    "type": "Multikey",
                    "controller": "did:plc:ar7c4by46qjdydhdevvrndac",
                    "publicKeyMultibase": "zQ3shmV1BNcX17coaDbfen6zArEad6SCLT3jVWCbC6Y9iinTa",
                },
            ],
            "service": [],
        })
    }

    #[test]
    fn extracts_atproto_label_multibase_from_real_shape() {
        let doc = canonical_labeler_did_doc();
        let mb = extract_atproto_label_multibase(&doc, "did:plc:ar7c4by46qjdydhdevvrndac")
            .expect("extract succeeds");
        assert_eq!(mb, "zQ3shmV1BNcX17coaDbfen6zArEad6SCLT3jVWCbC6Y9iinTa");
    }

    #[test]
    fn rejects_doc_with_no_verification_method_array() {
        let doc = json!({"id": "did:plc:abc"});
        let err = extract_atproto_label_multibase(&doc, "did:plc:abc").unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch");
        };
        assert!(
            message.contains("missing `verificationMethod`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_doc_with_no_atproto_label_entry() {
        // A doc with only `#atproto` (rotation key) but no labeler key.
        let doc = json!({
            "id": "did:plc:abc",
            "verificationMethod": [{
                "id": "did:plc:abc#atproto",
                "type": "Multikey",
                "publicKeyMultibase": "zQ3sh...",
            }],
        });
        let err = extract_atproto_label_multibase(&doc, "did:plc:abc").unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch");
        };
        assert!(message.contains("no `#atproto_label`"), "got: {message}");
    }

    #[test]
    fn rejects_atproto_label_entry_missing_multibase() {
        let doc = json!({
            "id": "did:plc:abc",
            "verificationMethod": [{
                "id": "did:plc:abc#atproto_label",
                "type": "Multikey",
            }],
        });
        let err = extract_atproto_label_multibase(&doc, "did:plc:abc").unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch");
        };
        assert!(
            message.contains("without `publicKeyMultibase`"),
            "got: {message}"
        );
    }

    #[test]
    fn rejects_multibase_with_wrong_prefix() {
        // Public key encoded without the `z` (base58btc) multibase prefix.
        let doc = json!({
            "id": "did:plc:abc",
            "verificationMethod": [{
                "id": "did:plc:abc#atproto_label",
                "type": "Multikey",
                "publicKeyMultibase": "QQ3shmV1",
            }],
        });
        let err = extract_atproto_label_multibase(&doc, "did:plc:abc").unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch");
        };
        assert!(message.contains("expected base58btc"), "got: {message}");
    }

    #[test]
    fn atproto_label_match_uses_id_suffix_not_substring() {
        // Verify the matcher is suffix-based (not contains-based) so
        // an entry whose id happens to contain `atproto_label` mid-string
        // doesn't false-positive.
        let doc = json!({
            "id": "did:plc:abc",
            "verificationMethod": [
                {
                    "id": "did:plc:abc#atproto_label_decoy",
                    "type": "Multikey",
                    "publicKeyMultibase": "zNOTITS",
                },
                {
                    "id": "did:plc:abc#atproto_label",
                    "type": "Multikey",
                    "publicKeyMultibase": "zCORRECT",
                },
            ],
        });
        let mb = extract_atproto_label_multibase(&doc, "did:plc:abc").unwrap();
        assert_eq!(mb, "zCORRECT");
    }

    // ── End-to-end via wiremock ──────────────────────────────────────

    /// Drives the full resolver against a `wiremock` HTTP server that
    /// returns a fixture DID doc, asserting the fetcher's output is the
    /// canonical `did:key:zQ3sh…` form the verify path consumes.
    #[tokio::test]
    async fn live_http_path_returns_canonical_did_key() {
        let server = wiremock::MockServer::start().await;
        let did = "did:plc:ar7c4by46qjdydhdevvrndac";

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/{did}")))
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_json(canonical_labeler_did_doc()),
            )
            .mount(&server)
            .await;

        let fetcher = PlcKeyFetcher::with_base_url(&server.uri()).expect("client builds");
        let did_key = fetcher.resolve(did).await.expect("fetch resolves");
        assert_eq!(
            did_key,
            "did:key:zQ3shmV1BNcX17coaDbfen6zArEad6SCLT3jVWCbC6Y9iinTa"
        );
    }

    #[tokio::test]
    async fn live_http_404_surfaces_as_fetch_error() {
        let server = wiremock::MockServer::start().await;
        let did = "did:plc:doesnotexist";

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/{did}")))
            .respond_with(wiremock::ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let fetcher = PlcKeyFetcher::with_base_url(&server.uri()).unwrap();
        let err = fetcher.resolve(did).await.unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch");
        };
        assert!(message.contains("404"), "got: {message}");
    }

    #[tokio::test]
    async fn live_http_malformed_json_surfaces_as_fetch_error() {
        let server = wiremock::MockServer::start().await;
        let did = "did:plc:malformed";

        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path(format!("/{did}")))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_string("not actually json")
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let fetcher = PlcKeyFetcher::with_base_url(&server.uri()).unwrap();
        let err = fetcher.resolve(did).await.unwrap_err();
        let CacheError::Fetch { message } = err else {
            panic!("expected Fetch");
        };
        assert!(message.contains("JSON parse"), "got: {message}");
    }
}
