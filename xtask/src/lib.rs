//! Polaris workspace automation — library surface.
//!
//! The `xtask` package ships as both a binary (`cargo xtask <subcommand>`)
//! and a thin library. The library exists exclusively so the boundary
//! scanner in [`check_frontend_boundary`] can be driven by integration
//! tests in `tests/`; production code paths go through `main.rs`.
//!
//! Adding a module here that is *not* part of an integration-test surface
//! is a smell — keep the binary's internals private to `main.rs` and only
//! re-export what the tests need.

pub mod audit_verify;
pub mod check_frontend_boundary;
pub mod check_wasm_budget;
pub mod check_wasm_symbols;
