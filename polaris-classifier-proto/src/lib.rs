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
