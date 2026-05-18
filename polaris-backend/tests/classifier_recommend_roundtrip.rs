//! Round-trip tests for `ClassifierClient::recommend` (issue #232 /
//! `.design/llm-moderation-assist.md` REQ-A1, REQ-A4, REQ-A5; AC-2).
//!
//! These tests cover the Rust client side of the Recommend RPC end-to-
//! end without standing up a gRPC server. They exercise the trait
//! through the [`FixtureClassifierClient`] impl — the production
//! [`TonicClassifierClient`] uses the same gating sequence (breaker
//! check → semaphore acquire → `tokio::time::timeout(recommend_timeout,
//! …)` → breaker bookkeeping), so timing semantics observed here mirror
//! the production path.
//!
//! # What's asserted
//!
//! 1. **Round trip.** A canned [`RecommendResponse`] is returned
//!    field-by-field through the trait surface — proves the impl wires
//!    the response value through without truncation.
//! 2. **Timeout.** When the simulated wire latency exceeds the
//!    configured `recommend_timeout`, the call surfaces as
//!    [`ClassifierError::Timeout`] (REQ-A5).
//! 3. **Breaker.** Ten consecutive timeouts trip the per-classifier
//!    breaker to `Open`; the next call short-circuits with
//!    [`ClassifierError::CircuitOpen`] without paying the timeout
//!    again (REQ-A4 — reuse the existing breaker, never re-create).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code per rust-quality §7"
)]

use std::time::Duration;

use polaris_backend::classifier::{
    BreakerConfig, BreakerRegistry, ClassifierClient, ClassifierError, FixtureClassifierClient,
};
use polaris_classifier_proto::v1::{RecommendRequest, RecommendResponse, RecommendedAction};

fn sample_request(event_id: &str) -> RecommendRequest {
    RecommendRequest {
        event_id: event_id.to_owned(),
        subject_did: "did:plc:test123".to_owned(),
        subject_kind: "post".to_owned(),
        incident_id: "inc-1".to_owned(),
        reports: vec![],
        observations: vec![],
        prior_actions: vec![],
        policies: vec![],
        subject_context: "test context".to_owned(),
        max_response_tokens: 1024,
    }
}

fn sample_response(event_id: &str) -> RecommendResponse {
    RecommendResponse {
        event_id: event_id.to_owned(),
        model: "claude-sonnet-4-6".to_owned(),
        model_version: "2026.05.01".to_owned(),
        prompt_template_id: "polaris-mod-v1".to_owned(),
        recommended_actions: vec![RecommendedAction {
            action_kind: "label".to_owned(),
            label_value: "spam".to_owned(),
            subject_scope: "post".to_owned(),
            confidence: 0.82,
            cited_policy_identifiers: vec!["spam.v1".to_owned()],
            reasoning: "Matches spam.v1 decision_criteria: crypto giveaway pattern.".to_owned(),
            caveats: vec!["satire context unverified".to_owned()],
        }],
        overall_reasoning: "Single high-confidence spam recommendation.".to_owned(),
        input_tokens: 1234,
        output_tokens: 256,
    }
}

/// AC-2: a canned response round-trips through `recommend()` and every
/// field is preserved byte-for-byte.
#[tokio::test]
async fn recommend_round_trips_canned_response() {
    let fixture = FixtureClassifierClient::new();
    let canned = sample_response("evt-1");
    fixture.set_recommend_response("evt-1", canned.clone());

    let resp = fixture.recommend(sample_request("evt-1")).await.unwrap();

    // Field-by-field — the assertion shape is verbose on purpose so a
    // future codegen change that silently drops a field surfaces here
    // rather than as a runtime surprise in the dispatcher.
    assert_eq!(resp.event_id, canned.event_id);
    assert_eq!(resp.model, canned.model);
    assert_eq!(resp.model_version, canned.model_version);
    assert_eq!(resp.prompt_template_id, canned.prompt_template_id);
    assert_eq!(resp.overall_reasoning, canned.overall_reasoning);
    assert_eq!(resp.input_tokens, canned.input_tokens);
    assert_eq!(resp.output_tokens, canned.output_tokens);
    assert_eq!(resp.recommended_actions.len(), 1);
    let action = &resp.recommended_actions[0];
    let expected = &canned.recommended_actions[0];
    assert_eq!(action.action_kind, expected.action_kind);
    assert_eq!(action.label_value, expected.label_value);
    assert_eq!(action.subject_scope, expected.subject_scope);
    assert!((action.confidence - expected.confidence).abs() < f32::EPSILON);
    assert_eq!(
        action.cited_policy_identifiers,
        expected.cited_policy_identifiers
    );
    assert_eq!(action.reasoning, expected.reasoning);
    assert_eq!(action.caveats, expected.caveats);
}

/// REQ-A5: a simulated wire latency longer than the configured timeout
/// surfaces as [`ClassifierError::Timeout`].
#[tokio::test]
async fn recommend_times_out_when_wire_exceeds_configured_timeout() {
    let fixture = FixtureClassifierClient::new();
    // Configure a 50 ms ceiling with a 500 ms simulated wire latency.
    // Real-time-bounded; doesn't depend on the 15s default at all,
    // keeping the test fast.
    fixture.set_recommend_timeout(Duration::from_millis(50));
    fixture.set_recommend_delay(Duration::from_millis(500));
    fixture.set_recommend_response("evt-1", sample_response("evt-1"));

    let err = fixture
        .recommend(sample_request("evt-1"))
        .await
        .expect_err("expected Timeout; got Ok");

    match err {
        ClassifierError::Timeout { classifier } => {
            assert_eq!(classifier, "fixture");
        }
        other => panic!("expected Timeout, got {other:?}"),
    }
}

/// REQ-A4: ten consecutive failures (timeouts) trip the existing
/// per-classifier circuit breaker; the eleventh call short-circuits
/// without paying the timeout.
///
/// We use the production [`BreakerConfig::default`] threshold (10
/// consecutive failures) so the test pins the design's contract, not
/// a test-specific tuning.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn breaker_opens_after_ten_consecutive_timeouts() {
    // Share ONE breaker across the test — that's the production
    // discipline (one registry per process; the fixture and the
    // production client both wire into it). Using the default config
    // pins us to the design's 10-failure threshold.
    let breaker = BreakerRegistry::with_config(BreakerConfig::default());
    let fixture = FixtureClassifierClient::with_name("breaker-test").with_breaker(breaker);
    fixture.set_recommend_timeout(Duration::from_millis(50));
    fixture.set_recommend_delay(Duration::from_millis(500));

    // Run 10 calls; each times out and increments the breaker counter.
    for i in 0..10 {
        let err = fixture
            .recommend(sample_request("evt-loop"))
            .await
            .expect_err("call #{i} expected to time out");
        assert!(
            matches!(err, ClassifierError::Timeout { .. }),
            "call #{i}: expected Timeout, got {err:?}",
        );
    }

    // Eleventh call: breaker is now Open. The fixture must short-
    // circuit with CircuitOpen WITHOUT paying the simulated 500 ms
    // wire delay — the breaker reads as Blocked before the timeout
    // future is ever polled.
    let err = fixture
        .recommend(sample_request("evt-loop"))
        .await
        .expect_err("11th call expected to be short-circuited");
    match err {
        ClassifierError::CircuitOpen { classifier } => {
            assert_eq!(classifier, "breaker-test");
        }
        other => panic!("expected CircuitOpen on 11th call, got {other:?}"),
    }
}
