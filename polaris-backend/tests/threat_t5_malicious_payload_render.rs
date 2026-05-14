//! Threat-model T5 — the tool itself becoming an attack surface
//! against moderators via malicious payloads in reported content
//! (`design.md` §9 #5; issue #39).
//!
//! # Mitigation under test
//!
//! Per design.md §9 #5: "all reported content rendered behind a
//! click-to-reveal with content warnings, no auto-loading of remote
//! resources, sandboxed iframe for any HTML preview, image rendering
//! through a sanitizing proxy."
//!
//! # Scope as of issue #39
//!
//! The click-to-reveal UX, iframe sandboxing, and proxied-image
//! rendering are all FRONTEND mitigations — the polaris-frontend
//! Leptos component for the case view owns them. See follow-up #76
//! ("Frontend test harness for T5 click-to-reveal sanitization").
//!
//! What we CAN test as a MUST-pass invariant on the BACKEND today:
//!
//! - **The API response body is JSON-encoded.** A `<script>` /
//!   `<iframe>` inside the report's `body` lands inside a JSON
//!   string literal, which by-definition does not execute as inline
//!   HTML when the frontend's renderer parses the response. JSON
//!   serialization is the smallest backend-side observable invariant
//!   for this threat.
//! - **The body round-trips byte-for-byte** through the storage
//!   layer. We do not silently strip / re-write the body on the
//!   server side; the frontend is the layer that applies sanitization
//!   (so the operator-side decision about HOW to render is in one
//!   place — frontend — not split across both halves).
//!
//! The frontend assertion (no auto-load, click-to-reveal, sandboxed
//! iframe) is the follow-up.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use polaris_backend::repo::{NewReport, PgReportRepo, ReportRepo as _};
use polaris_types::{Did, Report, ReportCategory, Severity};

#[path = "threats_common/mod.rs"]
mod common;

const SCRIPT_PAYLOAD: &str = "<script>alert('xss')</script>";
const IFRAME_PAYLOAD: &str = "<iframe src=\"http://evil.example/exfil\"></iframe>";
const IMG_PAYLOAD: &str = "<img src=\"http://evil.example/track.gif\" />";

/// T5 MUST-PASS: a report body containing `<script>` / `<iframe>` /
/// `<img>` round-trips through the DB byte-for-byte, and JSON
/// serialisation of the resulting `Report` puts the malicious bytes
/// inside a string literal. The frontend's response decoder
/// therefore receives the payload as data, not as inline HTML.
#[tokio::test]
async fn malicious_payload_round_trips_as_json_string_literal()
-> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t5_malicious_payload_render: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let subject_id = fixture.insert_account_subject("did:plc:t5subject").await?;
    let incident_id = fixture
        .insert_incident(subject_id, Severity::Medium)
        .await?;
    let reports = PgReportRepo::new(fixture.pool.clone());

    let malicious_body = format!("{SCRIPT_PAYLOAD}\n{IFRAME_PAYLOAD}\n{IMG_PAYLOAD}");

    let inserted = reports
        .insert(NewReport {
            subject_id,
            incident_id: Some(incident_id),
            reporter_did: Did::new("did:plc:t5reporter"),
            category: ReportCategory::new("harassment"),
            body: malicious_body.clone(),
        })
        .await?;

    // Invariant: round-trip is byte-identical. We do NOT silently
    // strip on the server.
    assert_eq!(
        inserted.body, malicious_body,
        "the report body must round-trip byte-for-byte through the DB \
         — sanitization is the frontend's job, not the server's",
    );
    let fetched: Option<Report> = reports.get(inserted.id).await?;
    let fetched = fetched.expect("just-inserted report must be retrievable");
    assert_eq!(fetched.body, malicious_body, "GET round-trip must match");

    // Invariant: JSON serialisation of the `Report` struct puts the
    // payload inside a string literal — escaped, not inline.
    let serialised = serde_json::to_string(&fetched).expect("Report must serialise to JSON");
    // The `<` character is OPTIONAL to escape in JSON-strict mode;
    // serde_json passes it through. What matters is that the bytes
    // appear inside the quoted `body` value, not at the top level.
    // We assert by parsing the JSON back and inspecting the typed
    // structure — the bytes-as-data invariant holds iff the parser
    // recovers `body` as a single string field carrying the exact
    // input.
    let parsed: serde_json::Value =
        serde_json::from_str(&serialised).expect("output must be valid JSON");
    let body_field = parsed
        .get("body")
        .and_then(serde_json::Value::as_str)
        .expect("Report JSON must have a `body` string field");
    assert_eq!(
        body_field, malicious_body,
        "malicious bytes must land inside the JSON string field `body`, \
         not at the top level — that is the bytes-as-data invariant",
    );

    // Stronger invariant: NO key on the JSON object equals the
    // malicious string. (A bug that flattened a payload to a top-
    // level key would be caught here.)
    if let serde_json::Value::Object(map) = &parsed {
        for key in map.keys() {
            assert!(
                !key.contains("<script>") && !key.contains("<iframe>") && !key.contains("<img"),
                "no JSON object key may contain HTML tags — got `{key}`",
            );
        }
    } else {
        panic!("serialised Report must be a JSON object");
    }

    Ok(())
}

/// T5 IGNORED-WITH-FOLLOWUP: the frontend rendering pipeline
/// honours click-to-reveal, sandboxed iframes, and proxied images.
///
/// The frontend is the mitigation surface — see follow-up #76. This
/// placeholder names the assertion shape so the follow-up has a
/// clear contract.
//
// Follow-up #76 owns un-ignoring this test once a polaris-frontend
// test harness exists. The mitigation surface needed is in
// `polaris-frontend/src/` (case-view component) plus a Leptos /
// wasm-bindgen test harness that can drive a render against a
// poisoned response.
#[tokio::test]
#[ignore = "T5 click-to-reveal / iframe-sandbox / image-proxy is a frontend concern — follow-up #76"]
async fn frontend_renders_malicious_payload_behind_click_to_reveal()
-> Result<(), Box<dyn std::error::Error>> {
    // Spec out the acceptance criterion the follow-up must satisfy:
    //
    //   given a GET /api/cases/:subject_id response whose Report
    //   body contains `<script>`, `<iframe src="http://evil/">`, and
    //   `<img src="http://evil/">`,
    //   the rendered DOM in the polaris-frontend case view must:
    //     (a) hide the report body behind a click-to-reveal toggle
    //         that defaults to closed,
    //     (b) not auto-fetch any of the cited URLs (network panel
    //         records zero outbound requests to evil.example before
    //         the moderator clicks),
    //     (c) render the iframe inside `sandbox="allow-same-origin"`
    //         (no `allow-scripts`, no `allow-top-navigation`),
    //     (d) rewrite the image's `src` through the operator's
    //         configured sanitizing proxy.
    //
    // Backend-side, `malicious_payload_round_trips_as_json_string_literal`
    // already pins the bytes-as-data invariant that protects the
    // frontend's renderer from inline-HTML execution.
    Ok(())
}
