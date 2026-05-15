//! Live ATProto XRPC evidence fetcher (#70).
//!
//! The live [`EvidenceFetcher`] backing the
//! [`crate::evidence::EvidenceWorker`]; replaces the not-wired stub
//! that previously lived in `main.rs`. Given an AT-URI
//! `at://<did>/<collection>/<rkey>`, the fetcher:
//!
//! 1. Parses the URI into `(did, collection, rkey)` via
//!    [`crate::evidence::worker::parse_subject_uri`].
//! 2. Resolves the DID's PDS endpoint by walking the DID document
//!    through [`proto_blue::identity::IdResolver::did`] →
//!    `ensure_resolve` → [`proto_blue::common::get_pds_endpoint`].
//! 3. Builds an [`proto_blue::xrpc::XrpcClient`] pointed at that PDS
//!    (sharing the verifier's `Arc<dyn FetchHandler>` so the same
//!    `reqwest::Client` connection pool is reused).
//! 4. Calls `com.atproto.sync.getRecord` against the PDS via the
//!    typed binding [`proto_blue::api::com::atproto::sync::get_record`].
//!    The endpoint returns a CAR file whose header carries the
//!    repo's signed-commit root CID and whose body carries the
//!    record block plus the MST proof-path blocks needed to
//!    reproduce the inclusion proof.
//! 5. Extracts the CAR bytes from the XRPC response's `$bytes`
//!    base64-wrapper, decodes the CAR via
//!    [`proto_blue::repo::read_car_with_root`], and returns the
//!    `(root_cid, BlockMap)` as a [`FetchedEvidence`].
//!
//! # Why a single `getRecord` call instead of `describeRepo` + `getRecord`
//!
//! The `com.atproto.sync.getRecord` XRPC method's lexicon explicitly
//! returns a CAR file whose roots are the repo's current commit root
//! and whose blocks are the record + the MST proof path. Calling
//! `describeRepo` first would only duplicate work — the root CID is
//! already in the CAR header. `getRecord` is the single primitive
//! required to assemble a `FetchedEvidence`.
//!
//! # Forbidden patterns
//!
//! - No raw HTTP — every network call goes through the typed
//!   `proto_blue::api::com::atproto::sync::get_record::call` binding
//!   over an [`XrpcClient`].
//! - No `unwrap` / `expect` on production paths — every error path
//!   maps to a typed [`EvidenceFetcherError`] variant.
//! - No silent base64 / CAR failures — `Decode` is the dedicated
//!   variant for malformed wire-format payloads.

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use proto_blue::api::com::atproto::sync::get_record;
use proto_blue::common::fetch::FetchHandler;
use proto_blue::common::get_pds_endpoint;
use proto_blue::identity::IdResolver;
use proto_blue::repo::read_car_with_root;
use proto_blue::syntax::{Did, Nsid, RecordKey};
use proto_blue::xrpc::XrpcClient;

use crate::evidence::worker::{
    EvidenceFetcher, EvidenceFetcherError, FetchedEvidence, parse_subject_uri,
};

/// Live ATProto XRPC fetcher backed by proto-blue's typed bindings.
///
/// Constructed once in `main.rs` and held behind
/// `Arc<dyn EvidenceFetcher>` by the [`EvidenceWorker`]. Each
/// `fetch_record_with_proof` call resolves the subject DID to a PDS
/// endpoint via `id_resolver`, builds a per-PDS [`XrpcClient`] on the
/// shared `fetcher` transport, and dispatches `com.atproto.sync.getRecord`.
///
/// [`EvidenceWorker`]: crate::evidence::worker::EvidenceWorker
pub struct LiveEvidenceFetcher {
    /// Identity resolver. The `did` sub-resolver is the only piece we
    /// consult here — handle → DID resolution is not on this code
    /// path because the AT-URI we receive is already DID-prefixed.
    id_resolver: Arc<IdResolver>,
    /// Shared HTTP transport. Threaded into every per-call
    /// [`XrpcClient`] so PDS endpoints reuse the same connection pool
    /// the `id_resolver`'s DID resolver already opened against the PLC
    /// directory.
    fetcher: Arc<dyn FetchHandler>,
}

impl std::fmt::Debug for LiveEvidenceFetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Keep the formatted form minimal — the resolver's internal
        // PLC URL and the fetcher's transport identity are operator
        // details, not user-facing diagnostics.
        f.debug_struct("LiveEvidenceFetcher")
            .finish_non_exhaustive()
    }
}

impl LiveEvidenceFetcher {
    /// Construct a fetcher from a pre-built [`IdResolver`] and shared
    /// [`FetchHandler`]. The same transport handle should be used for
    /// every proto-blue component that talks to the upstream — the
    /// existing `AtprotoOauthAuthVerifier` follows the same pattern.
    #[must_use]
    pub fn new(id_resolver: Arc<IdResolver>, fetcher: Arc<dyn FetchHandler>) -> Self {
        Self {
            id_resolver,
            fetcher,
        }
    }

    /// Build a fetcher using the default native `reqwest` transport.
    ///
    /// Convenience constructor for `main.rs` when no upstream
    /// auth-verifier is sharing its transport (e.g. an OIDC-backed
    /// auth deployment that still wants live evidence). Production
    /// deployments that already build a shared [`FetchHandler`] for
    /// the OAuth path should call [`Self::new`] instead so the
    /// transport is shared end-to-end.
    #[must_use]
    pub fn with_default_transport() -> Self {
        let fetcher: Arc<dyn FetchHandler> =
            Arc::new(proto_blue::common::fetch::ReqwestFetcher::new());
        let id_resolver = Arc::new(IdResolver::with_fetch_handler(
            proto_blue::identity::IdentityResolverOpts::default(),
            None,
            Arc::clone(&fetcher),
        ));
        Self::new(id_resolver, fetcher)
    }

    /// Resolve `did` to its PDS endpoint URL.
    ///
    /// Walks `IdResolver::did::ensure_resolve` → DID document →
    /// `get_pds_endpoint`. A DID that resolves but advertises no
    /// `#atproto_pds` service is treated as `EvidenceFetcherError::Upstream`
    /// — there is no record to fetch from a repo without a PDS.
    async fn resolve_pds(&self, did: &str) -> Result<String, EvidenceFetcherError> {
        let doc = self
            .id_resolver
            .did
            .ensure_resolve(did, /*force_refresh=*/ false)
            .await
            .map_err(|e| EvidenceFetcherError::Upstream {
                message: format!("did resolution failed for {did}: {e}"),
            })?;
        get_pds_endpoint(&doc).ok_or_else(|| EvidenceFetcherError::Upstream {
            message: format!("did document for {did} has no #atproto_pds service endpoint"),
        })
    }

    /// Internal fetch path; the trait impl below is a thin async
    /// adapter around this. Splitting the method out keeps the trait
    /// impl free of the `?` ladder noise and lets the unit test below
    /// drive the helpers in isolation.
    async fn fetch_record_with_proof_impl(
        &self,
        subject_uri: &str,
    ) -> Result<FetchedEvidence, EvidenceFetcherError> {
        let (did_str, collection_str, rkey_str) = parse_subject_uri(subject_uri)?;

        // Step 1: validate the parsed components against the lexicon
        // syntax types proto-blue's getRecord binding requires. A
        // malformed DID / NSID / record key would otherwise surface
        // as a network error on the upstream; surfacing it here as
        // BadAtUri keeps the error chain honest.
        let did = Did::new(&did_str).map_err(|e| EvidenceFetcherError::BadAtUri {
            message: format!("invalid did {did_str:?}: {e}"),
        })?;
        let collection =
            Nsid::new(&collection_str).map_err(|e| EvidenceFetcherError::BadAtUri {
                message: format!("invalid collection {collection_str:?}: {e}"),
            })?;
        let rkey = RecordKey::new(&rkey_str).map_err(|e| EvidenceFetcherError::BadAtUri {
            message: format!("invalid rkey {rkey_str:?}: {e}"),
        })?;

        // Step 2: resolve the PDS endpoint.
        let pds_url = self.resolve_pds(&did_str).await?;

        // Step 3: build a per-PDS XrpcClient over the shared transport
        // and dispatch the typed query.
        let client =
            XrpcClient::with_fetch_handler(&pds_url, Arc::clone(&self.fetcher)).map_err(|e| {
                EvidenceFetcherError::Upstream {
                    message: format!("invalid PDS URL {pds_url:?}: {e}"),
                }
            })?;
        let params = get_record::Params {
            collection,
            did,
            rkey,
        };
        let response = get_record::call(&client, Some(&params), None)
            .await
            .map_err(|e| EvidenceFetcherError::Upstream {
                message: format!("getRecord({did_str}/{collection_str}/{rkey_str}): {e}"),
            })?;

        // Step 4: the XRPC client wraps non-JSON response bodies as
        // `{"$bytes": "<base64>"}`. CAR bytes always arrive that way
        // because the content-type is `application/vnd.ipld.car`.
        let car_bytes = extract_car_bytes(&response)?;

        // Step 5: parse the CAR, verifying each block's CID-for-bytes
        // (the default for `read_car`). `read_car_with_root` rejects
        // CARs with anything other than exactly one root — the
        // sync.getRecord lexicon mandates a single repo-commit root,
        // so a multi-root CAR from the upstream is a contract
        // violation worth refusing.
        let (root_cid, blocks) =
            read_car_with_root(&car_bytes).map_err(|e| EvidenceFetcherError::Decode {
                message: format!("CAR decode failed: {e}"),
            })?;

        Ok(FetchedEvidence { root_cid, blocks })
    }
}

impl EvidenceFetcher for LiveEvidenceFetcher {
    fn fetch_record_with_proof<'a>(
        &'a self,
        subject_uri: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<FetchedEvidence, EvidenceFetcherError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(self.fetch_record_with_proof_impl(subject_uri))
    }
}

/// Extract CAR bytes from an XRPC response.
///
/// The XRPC client parses unknown content-types as
/// `{"$bytes": "<base64-standard>"}`. We expect that exact shape for
/// `application/vnd.ipld.car` responses; any other shape — a JSON
/// error payload that slipped through the 200 path, an empty body,
/// a different wrapper — surfaces as
/// [`EvidenceFetcherError::Decode`].
fn extract_car_bytes(value: &serde_json::Value) -> Result<Vec<u8>, EvidenceFetcherError> {
    let bytes_field = value
        .get("$bytes")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| EvidenceFetcherError::Decode {
            message: format!(
                "getRecord response missing `$bytes` wrapper; got JSON keys {:?}",
                value
                    .as_object()
                    .map(|m| m.keys().cloned().collect::<Vec<_>>())
                    .unwrap_or_default(),
            ),
        })?;
    BASE64_STANDARD
        .decode(bytes_field)
        .map_err(|e| EvidenceFetcherError::Decode {
            message: format!("getRecord `$bytes` payload not valid base64: {e}"),
        })
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
    use proto_blue::lex_data::LexValue;
    use proto_blue::repo::{BlockMap, blocks_to_car};
    use serde_json::json;

    #[test]
    fn extract_car_bytes_round_trips_through_dollar_bytes_wrapper() {
        // Build a real CAR so the bytes decode end-to-end — proves the
        // base64 path and the CAR-parse path compose.
        let mut blocks = BlockMap::new();
        let root = blocks
            .add_value(&LexValue::String("commit-root".into()))
            .unwrap();
        let _proof = blocks
            .add_value(&LexValue::String("mst-proof".into()))
            .unwrap();
        let _record = blocks
            .add_value(&LexValue::String("record".into()))
            .unwrap();
        let car_bytes = blocks_to_car(Some(&root), &blocks).unwrap();

        let encoded = BASE64_STANDARD.encode(&car_bytes);
        let response = json!({ "$bytes": encoded });

        let extracted = extract_car_bytes(&response).unwrap();
        assert_eq!(extracted, car_bytes);
        let (decoded_root, decoded_blocks) = read_car_with_root(&extracted).unwrap();
        assert_eq!(decoded_root.to_string_base32(), root.to_string_base32());
        assert_eq!(decoded_blocks.len(), blocks.len());
    }

    #[test]
    fn extract_car_bytes_rejects_missing_wrapper() {
        let response = json!({ "data": "not-a-bytes-wrapper" });
        let err = extract_car_bytes(&response).unwrap_err();
        assert!(
            matches!(err, EvidenceFetcherError::Decode { .. }),
            "expected Decode, got {err:?}",
        );
    }

    #[test]
    fn extract_car_bytes_rejects_non_base64_payload() {
        let response = json!({ "$bytes": "not valid base64!!!" });
        let err = extract_car_bytes(&response).unwrap_err();
        assert!(
            matches!(err, EvidenceFetcherError::Decode { .. }),
            "expected Decode, got {err:?}",
        );
    }

    #[test]
    fn live_fetcher_constructs_with_default_transport() {
        // Smoke test: the constructor must produce a fetcher without
        // touching the network. The IdResolver is configured but no
        // resolution happens until fetch_record_with_proof is called.
        let fetcher = LiveEvidenceFetcher::with_default_transport();
        // Debug shape is intentionally minimal — assert it stays so.
        let dbg = format!("{fetcher:?}");
        assert!(dbg.contains("LiveEvidenceFetcher"), "got {dbg:?}");
    }
}
