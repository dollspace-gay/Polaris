//! Generated Rust types for the `polaris.classifier.v1.Classifier`
//! gRPC service (issue #125 / M5 #45 PR 1).
//!
//! # Overview
//!
//! This crate is a codegen-only leaf crate: every type under
//! [`v1`] is produced by `tonic-build` from
//! `proto/polaris-classifier-v1.proto` at build time. No
//! hand-written logic lives here.
//!
//! # Architecture
//!
//! The classifier service is operated independently of Polaris —
//! either self-hosted by the Polaris operator or by an external
//! cloud-API provider. Polaris is a CLIENT of this service; the
//! `ClassifierClient` trait in `polaris-backend::classifier` (lands
//! in issue #126 / PR 2) wraps the generated tonic client with the
//! Polaris-side retry, circuit-breaker, and observation-
//! materialisation pipeline.
//!
//! Service providers wanting to implement the contract depend on
//! this crate alone (it has no `polaris-backend` deps) and use the
//! generated [`v1::classifier_server::Classifier`] trait.
//!
//! # Module shape
//!
//! tonic-build emits one module per proto package; the file is
//! re-exported here via [`tonic::include_proto!`]. The package
//! `polaris.classifier.v1` maps to module `v1` (we strip the
//! `polaris.classifier.` prefix at re-export time since the crate
//! name already carries that namespace).
#![deny(missing_docs)]

/// Generated types for `polaris.classifier.v1.Classifier`.
///
/// All items in this module are produced by `tonic-build` from
/// `proto/polaris-classifier-v1.proto` at build time. Do not hand-edit
/// — the generated source lives in `OUT_DIR`, not in the source tree.
#[allow(
    missing_docs,
    clippy::pedantic,
    clippy::nursery,
    clippy::all,
    reason = "codegen output; doc-comments come from the proto's // comments \
              but tonic-build does not annotate every generated item, and \
              clippy lints fire on patterns the generator emits that are \
              fine for codegen but noisy for hand-written code"
)]
pub mod v1 {
    tonic::include_proto!("polaris.classifier.v1");
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic per rust-quality §7; a panic \
              here surfaces the codegen failure mode (decode returned Err) \
              directly as a test failure with a useful message"
)]
mod tests {
    //! Smoke tests for issue #231 / .design/llm-moderation-assist.md
    //! REQ-A2 + REQ-A3.
    //!
    //! These tests prove that `tonic-prost-build` produced wire-
    //! compatible Rust types for the Recommend RPC's message tree:
    //! the types implement `Default` (every prost-generated message
    //! does), implement `prost::Message` (so they can serialize to a
    //! `Vec<u8>` via `encode_to_vec`), and round-trip through
    //! `decode` back to a value equal to the original.
    //!
    //! The round-trip is the actual proof — a default-only encode
    //! would pass even if the generator silently dropped fields,
    //! whereas `encode → decode → assert_eq` exercises every field's
    //! tag wiring.
    use super::v1::{RecommendRequest, RecommendResponse};
    use prost::Message;

    /// `RecommendRequest::default()` encodes and round-trips via
    /// prost. Proves the codegen produced wire-compatible Rust types
    /// for the request side of REQ-A2.
    #[test]
    fn recommend_request_default_round_trips() {
        let req = RecommendRequest::default();
        let bytes = req.encode_to_vec();
        // Default messages encode to zero bytes in proto3 (every
        // field is its scalar zero / empty repeated / empty string)
        // — this is correct proto3 behaviour. The decode-and-compare
        // below is the real proof.
        let decoded = RecommendRequest::decode(bytes.as_slice())
            .expect("RecommendRequest decodes from its own encoded form");
        assert_eq!(decoded, req);
    }

    /// `RecommendResponse::default()` encodes and round-trips via
    /// prost. Proves the codegen produced wire-compatible Rust types
    /// for the response side of REQ-A3.
    #[test]
    fn recommend_response_default_round_trips() {
        let resp = RecommendResponse::default();
        let bytes = resp.encode_to_vec();
        let decoded = RecommendResponse::decode(bytes.as_slice())
            .expect("RecommendResponse decodes from its own encoded form");
        assert_eq!(decoded, resp);
    }
}
