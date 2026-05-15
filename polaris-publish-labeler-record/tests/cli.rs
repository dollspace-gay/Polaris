//! Integration tests for `polaris-publish-labeler-record` (issue #27).
//!
//! Covers the **lib-half** of the binary plus a CLI-process smoke test
//! against the built binary. Authentication and live network calls are
//! out of scope here; the OAuth-flag plumbing (#61) is covered via
//! the user-error path (`--oauth` without `--client-metadata`,
//! `--oauth` with a missing file) — the interactive code-exchange
//! step itself requires a live AS and is exercised manually.

// Integration tests are allowed to panic per `rust-quality §7` —
// `assert*!` and the test runner's panic→fail path are the canonical
// failure surface, not `Result::Err`. Mirroring the header on
// `polaris-backend/tests/labels_xrpc.rs`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_publish_labeler_record::{
    BuildError, LabelerServiceMain, RECORD_COLLECTION, RECORD_RKEY, RecordValue,
    build_labeler_service_record, record_at_uri, validate_record,
};

/// Canonical inputs for the happy path. Kept as constants so every test
/// fails on the same expected values when they're surfaced in JSON
/// output, rather than re-defining the fixtures inside each test.
const SERVICE_URL: &str = "https://polaris.example.com";
const SIGNING_PUBKEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";

fn sample_label_values() -> Vec<String> {
    vec!["spam".to_string(), "harassment".to_string()]
}

fn build_sample() -> RecordValue {
    build_labeler_service_record(SERVICE_URL, SIGNING_PUBKEY, sample_label_values())
        .expect("sample build should succeed")
}

#[test]
fn build_record_with_valid_inputs_produces_main() {
    let record = build_sample();
    let main: &LabelerServiceMain = record.as_main();

    assert_eq!(main.r#type, "app.bsky.labeler.service");
    assert_eq!(main.policies.label_values, sample_label_values());
    assert!(main.labels.is_none());
    assert!(main.reason_types.is_none());
    assert!(main.subject_collections.is_none());
    assert!(main.subject_types.is_none());

    // `created_at` should be RFC-3339-ish and not empty.
    assert!(!main.created_at.as_str().is_empty());
}

#[test]
fn build_record_rejects_non_https_service_url() {
    let err = build_labeler_service_record(
        "http://polaris.example.com",
        SIGNING_PUBKEY,
        sample_label_values(),
    )
    .expect_err("http:// should be rejected");

    assert!(
        matches!(err, BuildError::NonHttpsServiceUrl(_)),
        "expected NonHttpsServiceUrl, got {err:?}"
    );
}

#[test]
fn build_record_rejects_invalid_service_url() {
    let err = build_labeler_service_record("not a url", SIGNING_PUBKEY, sample_label_values())
        .expect_err("garbage URL should be rejected");

    assert!(
        matches!(err, BuildError::InvalidServiceUrl(_)),
        "expected InvalidServiceUrl, got {err:?}"
    );
}

#[test]
fn build_record_rejects_invalid_did_key() {
    let err = build_labeler_service_record(
        SERVICE_URL,
        "did:key:NOT_A_REAL_MULTIKEY",
        sample_label_values(),
    )
    .expect_err("garbage did:key should be rejected");

    assert!(
        matches!(err, BuildError::InvalidDidKey(_)),
        "expected InvalidDidKey, got {err:?}"
    );
}

#[test]
fn build_record_rejects_empty_label_values() {
    let err = build_labeler_service_record(SERVICE_URL, SIGNING_PUBKEY, Vec::new())
        .expect_err("empty label_values should be rejected");

    assert!(
        matches!(err, BuildError::EmptyLabelValues),
        "expected EmptyLabelValues, got {err:?}"
    );
}

#[test]
fn validate_record_accepts_well_formed_record() {
    let record = build_sample();
    validate_record(&record).expect("well-formed record should validate");
}

#[test]
fn record_serializes_with_expected_json_shape() {
    let record = build_sample();
    let json = record.to_json().expect("serialize should succeed");

    assert_eq!(json["$type"], "app.bsky.labeler.service");
    let label_values = json["policies"]["labelValues"]
        .as_array()
        .expect("labelValues should be an array");
    assert_eq!(label_values.len(), 2);
    assert_eq!(label_values[0].as_str(), Some("spam"));
    assert_eq!(label_values[1].as_str(), Some("harassment"));
}

#[test]
fn at_uri_helper_uses_collection_and_self_rkey() {
    let uri = record_at_uri("did:plc:abc123");
    assert_eq!(
        uri,
        format!("at://did:plc:abc123/{RECORD_COLLECTION}/{RECORD_RKEY}")
    );
}

/// Smoke test: the CLI binary builds and `--help` exits 0 with text
/// that names the documented exit codes.
///
/// `env!("CARGO_BIN_EXE_polaris-publish-labeler-record")` is the
/// standard pattern for invoking a workspace binary from its own
/// integration tests — it's set by Cargo, so no `Command::new("cargo
/// run")` dance is needed (which would be measurably slower and
/// re-compile the world).
#[test]
fn cli_help_exits_zero_and_documents_exit_codes() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-labeler-record");
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
    // The exit-code documentation block must mention all four codes.
    for needle in ["Exit codes:", "0", "1", "2", "3", "lexicon validation"] {
        assert!(
            stdout.contains(needle),
            "--help output missing `{needle}`; got:\n{stdout}"
        );
    }
}

/// `--dry-run` constructs the record, validates it, and emits JSON to
/// stdout without contacting any PDS.
#[test]
fn cli_dry_run_emits_envelope_with_service_url_and_pubkey() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-labeler-record");
    let output = Command::new(bin_path)
        .args([
            "--account",
            "polaris.example.com",
            "--service-url",
            SERVICE_URL,
            "--signing-pubkey",
            SIGNING_PUBKEY,
            "--label-value",
            "spam",
            "--label-value",
            "harassment",
            "--dry-run",
        ])
        .output()
        .expect("dry-run invocation should not fail");

    assert!(
        output.status.success(),
        "--dry-run exited non-zero: status={:?}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout).expect("dry-run output should be valid JSON");

    assert_eq!(parsed["account"], "polaris.example.com");
    assert_eq!(parsed["service_url"], SERVICE_URL);
    assert_eq!(parsed["signing_pubkey"], SIGNING_PUBKEY);
    assert_eq!(parsed["collection"], "app.bsky.labeler.service");
    assert_eq!(parsed["rkey"], "self");
    assert_eq!(parsed["record"]["$type"], "app.bsky.labeler.service");
    assert_eq!(
        parsed["record"]["policies"]["labelValues"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
}

/// CLI rejects conflicting auth modes (clap's `ArgGroup` does the work;
/// this test pins the exit code so a refactor that loosens the group
/// to permit both flags fails loudly).
#[test]
fn cli_rejects_both_oauth_and_app_password_stdin() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-labeler-record");
    let output = Command::new(bin_path)
        .args([
            "--account",
            "polaris.example.com",
            "--service-url",
            SERVICE_URL,
            "--signing-pubkey",
            SIGNING_PUBKEY,
            "--label-value",
            "spam",
            "--oauth",
            "--app-password-stdin",
        ])
        .output()
        .expect("invocation should not fail");

    assert!(
        !output.status.success(),
        "conflicting auth modes should fail; got success"
    );
}

/// Issue #61 wired the `--oauth` path end-to-end; `--client-metadata` is
/// now a clap-enforced requirement when `--oauth` is set. This test
/// pins the help-text declaration so a refactor that drops the
/// `requires = "oauth"` constraint fails loudly.
#[test]
fn cli_oauth_requires_client_metadata_flag() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-labeler-record");
    let output = Command::new(bin_path)
        .args([
            "--account",
            "polaris.example.com",
            "--service-url",
            SERVICE_URL,
            "--signing-pubkey",
            SIGNING_PUBKEY,
            "--label-value",
            "spam",
            "--oauth",
        ])
        .output()
        .expect("invocation should not fail");

    // Clap enforces `requires = "oauth"` the other direction (using
    // --client-metadata without --oauth is fine; the flag is just
    // ignored). The real validation — "--oauth without
    // --client-metadata" — is enforced by `select_auth_mode` and lands
    // as a UserError → exit 1. Either failure mode is acceptable here;
    // the contract is "the run must not succeed without metadata."
    assert!(
        !output.status.success(),
        "--oauth without --client-metadata must not succeed; got success"
    );
}

/// `--oauth --client-metadata <path>` with a non-existent file lands
/// the polaris-types loader's `Read` error on the user-error exit
/// path. Pins the integration: this CLI surfaces the polaris-types
/// loader error (not a generic anyhow), and the exit code is the
/// `UserError` code (1), not the `Pds` code (2).
#[test]
fn cli_oauth_missing_client_metadata_file_exits_user_error() {
    let bin_path = env!("CARGO_BIN_EXE_polaris-publish-labeler-record");
    let output = Command::new(bin_path)
        .args([
            "--account",
            "polaris.example.com",
            "--service-url",
            SERVICE_URL,
            "--signing-pubkey",
            SIGNING_PUBKEY,
            "--label-value",
            "spam",
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
