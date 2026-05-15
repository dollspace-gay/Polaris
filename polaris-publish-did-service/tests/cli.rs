//! Integration tests for `polaris-publish-did-service` (issue #60).
//!
//! Covers the lib half plus the CLI smoke test. Authentication, the
//! PLC operation flow, and any actual PLC submission are out of scope
//! here — those are surfaced via `--help` and exit-code documentation.

// Integration tests are allowed to panic per `rust-quality §7` —
// `assert*!` and the test runner's panic→fail path are the canonical
// failure surface, not `Result::Err`. Mirrors the header on
// `polaris-publish-labeler-record/tests/cli.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_publish_did_service::{
    BuildError, LABELER_SERVICE_ID, LABELER_SERVICE_TYPE, ValidationError, build_did_web_document,
    validate_did_document,
};

const HANDLE: &str = "polaris.example.com";
const SERVICE_URL: &str = "https://polaris.example.com";
const PDS_URL: &str = "https://bsky.social";
const SIGNING_PUBKEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";

fn build_sample() -> serde_json::Value {
    build_did_web_document(HANDLE, PDS_URL, SIGNING_PUBKEY, SERVICE_URL)
        .expect("sample build should succeed")
}

#[test]
fn build_did_document_contains_atproto_labeler_service_entry() {
    let doc = build_sample();
    let services = doc["service"]
        .as_array()
        .expect("service should be an array");
    let labeler = services
        .iter()
        .find(|s| s["id"] == LABELER_SERVICE_ID)
        .expect("should contain #atproto_labeler entry");
    assert_eq!(labeler["type"], LABELER_SERVICE_TYPE);
    assert_eq!(labeler["serviceEndpoint"], SERVICE_URL);
}

#[test]
fn build_did_document_rejects_invalid_did_key() {
    let err = build_did_web_document(HANDLE, PDS_URL, "did:key:GARBAGE", SERVICE_URL)
        .expect_err("garbage did:key should be rejected");
    assert!(
        matches!(err, BuildError::InvalidDidKey(_)),
        "expected InvalidDidKey, got {err:?}"
    );
}

#[test]
fn validate_did_document_accepts_self_built_doc() {
    let doc = build_sample();
    validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
        .expect("self-built doc should validate");
}

#[test]
fn validate_did_document_rejects_doc_missing_labeler_entry() {
    let doc = serde_json::json!({
        "id": "did:web:polaris.example.com",
        "verificationMethod": [{
            "id": "#atproto",
            "type": "Multikey",
            "controller": "did:web:polaris.example.com",
            "publicKeyMultibase": "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://bsky.social",
        }],
    });
    let err = validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
        .expect_err("missing #atproto_labeler entry should fail");
    assert!(
        matches!(err, ValidationError::MissingLabelerService),
        "got {err:?}"
    );
}

#[test]
fn validate_did_document_rejects_wrong_service_url() {
    let doc = serde_json::json!({
        "id": "did:web:polaris.example.com",
        "verificationMethod": [{
            "id": "#atproto",
            "type": "Multikey",
            "controller": "did:web:polaris.example.com",
            "publicKeyMultibase": "zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        }],
        "service": [{
            "id": "#atproto_labeler",
            "type": "AtprotoLabeler",
            "serviceEndpoint": "https://wrong-host.example.com",
        }],
    });
    let err = validate_did_document(&doc, SERVICE_URL, SIGNING_PUBKEY)
        .expect_err("wrong serviceEndpoint should fail");
    assert!(
        matches!(err, ValidationError::LabelerEndpointMismatch { .. }),
        "got {err:?}"
    );
}

/// CLI `--help` exits 0 and documents the `--did-method` flag values.
#[test]
fn cli_help_exits_zero_and_documents_did_method_values() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-did-service");
    let output = Command::new(bin_path)
        .arg("--help")
        .output()
        .expect("running --help should not fail");

    assert!(
        output.status.success(),
        "--help exited non-zero: {:?}",
        output.status
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "--did-method",
        "plc",
        "web",
        "Exit codes:",
        "atproto_labeler",
    ] {
        assert!(
            stdout.contains(needle),
            "--help output missing `{needle}`; got:\n{stdout}"
        );
    }
}

/// `--oauth` without `--client-metadata` must not succeed. Clap's
/// `requires = "oauth"` constraint runs the other direction
/// (using `--client-metadata` without `--oauth` is rejected at parse
/// time); the missing-metadata-with-oauth case is enforced by
/// `select_auth_mode` and surfaces as `UserError::OauthMissingClientMetadata`
/// → exit 1. Either failure mode is acceptable here; the contract
/// pinned by this test is "the run must not succeed without metadata."
/// Mirrors `polaris-publish-labeler-record::cli_oauth_requires_client_metadata_flag`.
#[test]
fn cli_oauth_requires_client_metadata_flag() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-did-service");
    let output = Command::new(bin_path)
        .args([
            "--account",
            HANDLE,
            "--service-url",
            SERVICE_URL,
            "--signing-key",
            SIGNING_PUBKEY,
            "--did-method",
            "plc",
            "--oauth",
        ])
        .output()
        .expect("invocation should not fail");

    assert!(
        !output.status.success(),
        "--oauth without --client-metadata must not succeed; got success"
    );
}

/// `--oauth --client-metadata <missing-path>` lands the
/// `polaris_types::oauth_config::load_client_metadata` error on the
/// user-error exit path (exit code 1), not the remote/PDS path (exit
/// code 2). This pins the integration: the CLI surfaces the
/// polaris-types loader error (not a generic anyhow), and the exit
/// code matches `UserError`'s documented mapping.
/// Mirrors `polaris-publish-labeler-record::cli_oauth_missing_client_metadata_file_exits_user_error`.
#[test]
fn cli_oauth_missing_client_metadata_file_exits_user_error() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-did-service");
    let output = Command::new(bin_path)
        .args([
            "--account",
            HANDLE,
            "--service-url",
            SERVICE_URL,
            "--signing-key",
            SIGNING_PUBKEY,
            "--did-method",
            "plc",
            "--oauth",
            "--client-metadata",
            "/nonexistent/path/client-metadata.json",
        ])
        .output()
        .expect("invocation should not fail");

    let code = output.status.code().expect("process exited via signal");
    assert_eq!(
        code,
        1,
        "expected exit 1 (UserError); got {code}, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// CLI `--did-method=web` prints valid JSON containing the
/// `#atproto_labeler` service entry to stdout.
#[test]
fn cli_did_method_web_prints_did_document_json() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-did-service");
    let output = Command::new(bin_path)
        .args([
            "--account",
            HANDLE,
            "--service-url",
            SERVICE_URL,
            "--signing-key",
            SIGNING_PUBKEY,
            "--did-method",
            "web",
            "--pds",
            PDS_URL,
        ])
        .output()
        .expect("did-method=web invocation should not fail");

    assert!(
        output.status.success(),
        "did-method=web exited non-zero: status={:?}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout should be valid JSON");

    assert_eq!(parsed["id"], format!("did:web:{HANDLE}"));
    let services = parsed["service"]
        .as_array()
        .expect("service should be an array");
    assert!(
        services
            .iter()
            .any(|s| s["id"] == "#atproto_labeler" && s["serviceEndpoint"] == SERVICE_URL),
        "missing #atproto_labeler service entry in:\n{stdout}"
    );
}
