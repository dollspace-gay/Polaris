#![allow(
    unsafe_code,
    reason = "build.rs sets PROTOC=<path> via std::env::set_var before \
              tonic-prost-build shells out to protoc. No threads exist in \
              the build-script process at that point, so the set_var call \
              is sound. Scope is limited to this build script — the lib \
              crate retains the workspace-default unsafe_code = deny."
)]

//! Build-time codegen for the `polaris.classifier.v1.Classifier`
//! gRPC service (issue #125 / M5 #45 PR 1).
//!
//! Reads `../proto/polaris-classifier-v1.proto` and writes Rust
//! source into `OUT_DIR`. The crate's `lib.rs` then re-exports the
//! generated tree via `tonic::include_proto!`.
//!
//! # Reproducibility
//!
//! tonic-build produces deterministic output for a given input — same
//! .proto + same tonic-build version → byte-identical generated code.
//! This is what makes codegen-on-build (vs. the
//! `cargo xtask gen-lexicons` checked-in-tree pattern used by
//! `polaris-lexicons`) acceptable here: there's nothing to drift
//! against because nothing is checked in.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto = "../proto/polaris-classifier-v1.proto";

    // Rerun-if-changed: stay out of the way of incremental builds
    // unless the .proto actually changes.
    println!("cargo:rerun-if-changed={proto}");
    println!("cargo:rerun-if-changed=build.rs");

    // Use the vendored `protoc` binary so the build is hermetic. Without
    // this, operators have to install `protobuf-compiler` system-wide
    // (apt-get install protobuf-compiler / brew install protobuf / etc.),
    // which is friction we can avoid for one-off codegen.
    let protoc_path = protoc_bin_vendored::protoc_bin_path()
        .map_err(|e| format!("protoc-bin-vendored could not resolve protoc binary: {e}"))?;
    // SAFETY: setting an env var on the build script's own process is
    // safe pre-spawn; tonic-prost-build reads PROTOC from env when it
    // shells out to protoc below. No threads exist yet in build.rs.
    unsafe {
        std::env::set_var("PROTOC", protoc_path);
    }

    // tonic 0.14 split the prost-driven entrypoint out of tonic-build
    // into tonic-prost-build. Use the new crate's `configure()`.
    tonic_prost_build::configure()
        // Emit both client and server stubs. The classifier service
        // provider implements the server side; Polaris implements the
        // client side. Shipping both lets the same crate satisfy
        // both consumers.
        .build_client(true)
        .build_server(true)
        // Add documentation links from the proto comments into the
        // generated Rust doc-comments (rust-quality §8: every public
        // item gets a doc-comment; tonic's output preserves them).
        .compile_protos(&[proto], &["../proto"])?;

    Ok(())
}
