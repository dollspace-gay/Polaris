//! Generated Rust types for the `gay.dollspace.polaris.*` AT Protocol Lexicons.
//!
//! # Overview
//!
//! This crate is a codegen-only leaf crate: every type under [`generated`]
//! is produced by `proto-blue-codegen` from the Lexicon JSON sources in
//! `lexicons/polaris/`. No hand-written logic lives here.
//!
//! Re-run codegen with:
//!
//! ```text
//! cargo xtask gen-lexicons
//! ```
//!
//! See `lexicons/README.md` for the wire-format policy and the privacy
//! boundary rules that govern which Lexicon fields may cross instance
//! boundaries.
//!
//! # Wasm compatibility
//!
//! This crate builds for `wasm32-unknown-unknown`. It carries no `tokio`,
//! no `reqwest`, and no other async-runtime or HTTP dependency.
#![deny(missing_docs)]

/// Generated types from the `gay.dollspace.polaris.*` Lexicon namespace.
///
/// All items in this module are produced by `proto-blue-codegen`.
/// Do not edit anything under `generated/` by hand — the CI diff gate
/// (`cargo xtask gen-lexicons && git diff --exit-code polaris-lexicons/src/generated`)
/// will reject any manual edits.
#[allow(missing_docs)]
pub mod generated;

// Re-export the top-level NSID namespace at crate root so the generated
// tree's internal cross-references (`crate::gay::dollspace::polaris::…`)
// resolve correctly. proto-blue-codegen emits absolute `crate::…` paths
// rooted at the top-level NSID segment (matches proto-blue-api's
// convention: `pub use generated::com;` etc.), so consumers can import
// either `polaris_lexicons::gay::…` or `polaris_lexicons::generated::gay::…`
// — both resolve to the same items.
pub use generated::gay;
