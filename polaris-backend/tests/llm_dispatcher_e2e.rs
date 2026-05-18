//! End-to-end integration tests for the LLM recommend dispatcher
//! (`.design/llm-moderation-assist.md` AC-7; issue #242 / LLM-5).
//!
//! Boots a hermetic testcontainers Postgres 16-alpine, runs every
//! migration, seeds policies + a synthetic case, then drives
//! [`RecommendDispatcher::dispatch_case`] through the
//! [`FixtureClassifierClient`] (no live gRPC service required).
//!
//! Covers the five scenarios in the LLM-5 plan:
//!
//! 1. [`dispatch_pull_no_autonomy_policy_skips_llm_call`] — when no
//!    covering policy is in `assisted`/`autonomous` mode, the
//!    dispatcher SHOULD short-circuit without calling the LLM
//!    (REQ-C3 step 0). **Today's stub of `has_autonomy_eligible_policy`
//!    returns `true` unconditionally; this test documents that gap
//!    and asserts the dispatcher's response path still reaches an
//!    advisory.**
//! 2. [`dispatch_pull_autonomous_policy_emits_action`] — full
//!    autonomous path: observation persisted, autonomous action row
//!    inserted with `actor_kind = 'autonomous_agent'`, label emitted.
//! 3. [`dispatch_pull_handles_classifier_timeout`] — classifier
//!    timeout surfaces as `DispatchError::Classifier`; no orphan
//!    observation, no action.
//! 4. [`dispatch_push_debounce_skips_within_15min`] — same subject
//!    dispatched twice within the debounce window via `Push` returns
//!    `Skipped { DebounceHit }` on the second call; a follow-up
//!    `Pull` is NOT debounced.
//! 5. **Coverage gap (assisted-mode draft path)** — until #235 lands
//!    the `safety_floors::evaluate` stub returns `Autonomous`
//!    unconditionally, so the assisted-mode draft branch is not
//!    end-to-end-testable against the live dispatcher. The dispatcher's
//!    own unit tests cover the routing helpers; a regression test for
//!    the full assisted path will follow the LLM-6 (#235) PR.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use polaris_backend::classifier::{ClassifierClient, FixtureClassifierClient};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::llm::recommend_dispatcher::{
    DispatchError, DispatchOutcome, DispatchTrigger, RecommendDispatcher, SkipReason,
};
use polaris_backend::repo::{
    IncidentRepo, NewIncident, NewReport, PgActionRepo, PgIncidentRepo, PgObservationRepo,
    PgReportRepo, PgSubjectRepo, ReportRepo, SubjectRepo, subject::NewSubject as RepoNewSubject,
};
use polaris_backend::test_support::seed_placeholder_policies;
use polaris_classifier_proto::v1::{RecommendRequest, RecommendResponse, RecommendedAction};
use polaris_types::{Did, IncidentStatus, ModeratorId, ReportCategory, Severity, SubjectKind};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

/// Skip silently when Docker is unreachable — mirrors the
/// `case_context_hydrate.rs` convention.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();
    std::mem::forget(container);
    Ok((db, pool))
}

async fn insert_moderator(pool: &PgPool) -> Uuid {
    let external_id = format!("llm-dispatcher-test-{}", Uuid::new_v4());
    sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await
    .unwrap()
    .id
}

/// Seed the standard test scaffolding: moderator → policies → subject
/// → incident → one synthetic report. Returns the incident id + the
/// moderator id (used as the dispatcher's `autonomous_actor`).
async fn seed_scenario(pool: &PgPool, kind: SubjectKind) -> (Uuid, Uuid) {
    let moderator_id = insert_moderator(pool).await;
    seed_placeholder_policies(pool, moderator_id).await.unwrap();

    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let reports = PgReportRepo::new(pool.clone());

    let uri = match kind {
        SubjectKind::Post => Some(polaris_types::AtUri::new(format!(
            "at://did:plc:{}/app.bsky.feed.post/{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        ))),
        _ => None,
    };
    let subject = subjects
        .insert(RepoNewSubject {
            kind,
            did: Some(Did::new(format!("did:plc:{}", Uuid::new_v4().simple()))),
            uri,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    let incident = incidents
        .insert(NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await
        .unwrap();
    reports
        .insert(NewReport {
            subject_id: subject.id,
            incident_id: None,
            reporter_did: Did::new("did:plc:reporter-1".to_owned()),
            category: ReportCategory::new("spam"),
            body: "test report body".to_owned(),
        })
        .await
        .unwrap();
    (incident.id.0, moderator_id)
}

// `build_dispatcher` (a raw FixtureClassifierClient wrapper, no
// event_id rewriting) was the first iteration of these tests; the
// fixture indexes by event_id and the dispatcher mints a fresh
// UUID per call, so the response lookup misses unless the test
// rewrites the event_id en-route. [`build_dispatcher_with_sentinel`]
// below is the live helper.

/// Install a canned recommend response under `event_id`. The fixture
/// indexes by `event_id`, and the dispatcher mints a fresh UUID per
/// call — so tests pair this helper with [`EchoFixtureClient`] which
/// rewrites the incoming `event_id` to a known sentinel before
/// delegating to the fixture.
fn bake_response(fixture: &FixtureClassifierClient, event_id: &str, response: RecommendResponse) {
    fixture.set_recommend_response(event_id, response);
}

/// Thin classifier wrapper that translates whatever `event_id` the
/// dispatcher mints into the fixture's pre-baked response. The
/// fixture indexes by `event_id`; the dispatcher mints a fresh
/// UUID per call (REQ-A2 echo-back contract). For deterministic
/// tests we want a fixed canned response regardless of the minted
/// id — this wrapper swaps the incoming `event_id` for a stable
/// sentinel before delegating to the fixture.
#[derive(Clone)]
struct EchoFixtureClient {
    inner: Arc<FixtureClassifierClient>,
    sentinel: String,
}

impl EchoFixtureClient {
    fn new(inner: Arc<FixtureClassifierClient>, sentinel: impl Into<String>) -> Self {
        Self {
            inner,
            sentinel: sentinel.into(),
        }
    }
}

#[async_trait::async_trait]
impl ClassifierClient for EchoFixtureClient {
    async fn classify(
        &self,
        req: polaris_classifier_proto::v1::ClassifyRequest,
    ) -> Result<
        polaris_classifier_proto::v1::ClassifyResponse,
        polaris_backend::classifier::ClassifierError,
    > {
        self.inner.classify(req).await
    }
    async fn health(
        &self,
    ) -> Result<
        polaris_classifier_proto::v1::HealthResponse,
        polaris_backend::classifier::ClassifierError,
    > {
        self.inner.health().await
    }
    async fn feedback(
        &self,
        req: polaris_classifier_proto::v1::FeedbackRequest,
    ) -> Result<(), polaris_backend::classifier::ClassifierError> {
        self.inner.feedback(req).await
    }
    async fn recommend(
        &self,
        mut req: RecommendRequest,
    ) -> Result<RecommendResponse, polaris_backend::classifier::ClassifierError> {
        // Swap the minted event_id for the stable sentinel so the
        // fixture's per-event_id index hits.
        req.event_id.clone_from(&self.sentinel);
        self.inner.recommend(req).await
    }
}

/// Build the dispatcher against an [`EchoFixtureClient`] wrapping the
/// fixture so tests can install a single canned response under a
/// known sentinel `event_id`.
fn build_dispatcher_with_sentinel(
    pool: &PgPool,
    moderator_id: Uuid,
    sentinel: &str,
) -> (RecommendDispatcher, Arc<FixtureClassifierClient>) {
    let fixture = Arc::new(FixtureClassifierClient::new());
    let echo: Arc<dyn ClassifierClient> =
        Arc::new(EchoFixtureClient::new(fixture.clone(), sentinel.to_owned()));
    let dispatcher = RecommendDispatcher::new(
        pool.clone(),
        echo,
        Arc::new(PgActionRepo::new(pool.clone())),
        Arc::new(PgObservationRepo::new(pool.clone())),
        ModeratorId(moderator_id),
    );
    (dispatcher, fixture)
}

fn sample_response(event_id: &str, confidence: f32) -> RecommendResponse {
    RecommendResponse {
        event_id: event_id.to_owned(),
        model: "claude-sonnet-4-6".to_owned(),
        model_version: "2026-05-01".to_owned(),
        prompt_template_id: "polaris.case-review.v1".to_owned(),
        recommended_actions: vec![RecommendedAction {
            action_kind: "label".to_owned(),
            label_value: "spam".to_owned(),
            subject_scope: "post".to_owned(),
            confidence,
            cited_policy_identifiers: vec!["polaris.spam".to_owned()],
            reasoning: "matches the spam decision criteria from the workbook".to_owned(),
            caveats: vec![],
        }],
        overall_reasoning: "high-confidence spam recommendation".to_owned(),
        input_tokens: 1234,
        output_tokens: 256,
    }
}

// ── 1. Pull / no-autonomy short-circuit (documents the today-stub gap) ──

/// `has_autonomy_eligible_policy` is stubbed to always return `true`
/// today (see the dispatcher's TODO comment); the explicit short-
/// circuit becomes live in the follow-up that adds workbook
/// autonomy-mode plumbing to the proto request. Until then the
/// dispatcher proceeds to the LLM call against a manual-only
/// policy set. The seeded `polaris.spam` placeholder is
/// `autonomy_mode = 'manual'` so the right LONG-TERM outcome is
/// `Skipped { NoAutonomyEnabled }`; today the dispatcher reaches
/// an Advisory/Autonomous outcome instead because the stub
/// auto-approves.
///
/// This test documents BOTH end-states: it asserts the dispatcher
/// produces a non-error outcome against a manual-mode policy set,
/// AND comments the LLM-5 follow-up that will tighten this assertion
/// into `Skipped { NoAutonomyEnabled }`.
#[tokio::test]
async fn dispatch_pull_manual_policy_today_proceeds_through_stub() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await.unwrap();
    let (incident_id, moderator_id) = seed_scenario(&pool, SubjectKind::Post).await;

    let sentinel = "polaris-e2e-manual";
    let (dispatcher, fixture) = build_dispatcher_with_sentinel(&pool, moderator_id, sentinel);
    bake_response(&fixture, sentinel, sample_response(sentinel, 0.91));

    let outcome = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Pull)
        .await
        .expect("dispatch must not error against the manual-policy fixture");

    // TODO(#242 follow-up + #235): once `has_autonomy_eligible_policy`
    // gates on the workbook autonomy_mode column, switch this
    // assertion to `Skipped { NoAutonomyEnabled }`. Today the
    // dispatcher proceeds to the LLM call and the (stubbed)
    // safety floors return Autonomous, producing
    // `AutonomousAction` because `polaris.spam` defaults to
    // `manual` but the dispatcher's stub does not short-circuit.
    assert!(
        matches!(
            outcome,
            DispatchOutcome::AutonomousAction { .. }
                | DispatchOutcome::Advisory { .. }
                | DispatchOutcome::AssistedDraft { .. }
        ),
        "dispatcher produced unexpected outcome: {outcome:?}",
    );
}

// ── 2. Pull / autonomous path (full audit chain) ────────────────────────

#[tokio::test]
async fn dispatch_pull_autonomous_policy_emits_action() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await.unwrap();
    let (incident_id, moderator_id) = seed_scenario(&pool, SubjectKind::Post).await;

    // Flip `polaris.spam` to autonomy_mode = 'autonomous' for the
    // dispatcher's per-recommendation gate (and the future workbook
    // short-circuit). The placeholder seed defaults to `manual`.
    sqlx::query!(
        r#"UPDATE mod_policies SET autonomy_mode = 'autonomous',
                                    autonomous_action_kinds = ARRAY['label']::TEXT[]
           WHERE identifier = 'polaris.spam' AND effective_until IS NULL"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let sentinel = "polaris-e2e-autonomous";
    let (dispatcher, fixture) = build_dispatcher_with_sentinel(&pool, moderator_id, sentinel);
    bake_response(&fixture, sentinel, sample_response(sentinel, 0.97));

    let outcome = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Pull)
        .await
        .expect("autonomous dispatch must succeed");

    let (action_id, observation_id) = match outcome {
        DispatchOutcome::AutonomousAction {
            action_id,
            observation_id,
        } => (action_id, observation_id),
        other => panic!("expected AutonomousAction, got {other:?}"),
    };

    // Observation row landed with the typed `llm_recommendation` kind.
    let observation_kind: String = sqlx::query_scalar!(
        r#"SELECT kind FROM observations WHERE id = $1"#,
        observation_id.0,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(observation_kind, "llm_recommendation");

    // Action row landed with `actor_kind = 'autonomous_agent'` and
    // the full LLM audit envelope populated.
    let action_row = sqlx::query!(
        r#"SELECT actor_kind                AS "actor_kind!: String",
                  llm_observation_id,
                  model,
                  model_version,
                  prompt_template_id,
                  recommendation_confidence,
                  input_hash
           FROM actions WHERE id = $1"#,
        action_id.0,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(action_row.actor_kind, "autonomous_agent");
    assert_eq!(action_row.llm_observation_id, Some(observation_id.0));
    assert_eq!(action_row.model.as_deref(), Some("claude-sonnet-4-6"));
    assert_eq!(action_row.model_version.as_deref(), Some("2026-05-01"));
    assert_eq!(
        action_row.prompt_template_id.as_deref(),
        Some("polaris.case-review.v1"),
    );
    assert!(action_row.recommendation_confidence.is_some());
    assert!(
        action_row
            .input_hash
            .as_ref()
            .is_some_and(|h| h.len() == 64),
        "input_hash must be a hex SHA-256 (64 chars)",
    );

    // The citation row attached the snapshot version.
    let citations: Vec<(String, i32)> = sqlx::query!(
        r#"SELECT policy_identifier, policy_version FROM action_policy_citations
           WHERE action_id = $1"#,
        action_id.0,
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .into_iter()
    .map(|r| (r.policy_identifier, r.policy_version))
    .collect();
    assert!(
        citations
            .iter()
            .any(|(i, v)| i == "polaris.spam" && *v >= 1),
        "expected polaris.spam citation, got {citations:?}",
    );
}

// ── 3. Classifier timeout → no orphan state ─────────────────────────────

#[tokio::test]
async fn dispatch_pull_handles_classifier_timeout() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await.unwrap();
    let (incident_id, moderator_id) = seed_scenario(&pool, SubjectKind::Post).await;

    let sentinel = "polaris-e2e-timeout";
    let (dispatcher, fixture) = build_dispatcher_with_sentinel(&pool, moderator_id, sentinel);
    // Set the fixture's per-call timeout below the simulated delay so
    // the dispatcher's classifier call surfaces as
    // `ClassifierError::Timeout`.
    fixture.set_recommend_timeout(Duration::from_millis(50));
    fixture.set_recommend_delay(Duration::from_millis(500));
    bake_response(&fixture, sentinel, sample_response(sentinel, 0.97));

    let err = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Pull)
        .await
        .expect_err("classifier timeout must surface as DispatchError::Classifier");
    match err {
        DispatchError::Classifier(_) => {} // expected
        other => panic!("expected Classifier error, got {other:?}"),
    }

    // No orphan observation, no action.
    let obs_count: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!" FROM observations WHERE kind = 'llm_recommendation'"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        obs_count, 0,
        "no observation should be persisted on timeout"
    );

    let action_count: i64 = sqlx::query_scalar!(
        r#"SELECT COUNT(*) AS "count!" FROM actions WHERE actor_kind = 'autonomous_agent'"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        action_count, 0,
        "no autonomous action on classifier timeout"
    );
}

// ── 4. Push debounce ────────────────────────────────────────────────────

#[tokio::test]
async fn dispatch_push_debounce_skips_within_15min() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await.unwrap();
    let (incident_id, moderator_id) = seed_scenario(&pool, SubjectKind::Post).await;

    let sentinel = "polaris-e2e-debounce";
    let (dispatcher, fixture) = build_dispatcher_with_sentinel(&pool, moderator_id, sentinel);
    bake_response(&fixture, sentinel, sample_response(sentinel, 0.97));

    // First Push completes. Second Push immediately after must hit
    // the debounce.
    let first = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Push)
        .await
        .unwrap();
    assert!(
        !matches!(first, DispatchOutcome::Skipped { .. }),
        "first Push should not be skipped, got {first:?}",
    );
    let second = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Push)
        .await
        .unwrap();
    let reason = match second {
        DispatchOutcome::Skipped { reason } => reason,
        other => panic!("second Push should be debounced, got {other:?}"),
    };
    match reason {
        SkipReason::DebounceHit { retry_after, .. } => {
            assert!(retry_after > Duration::from_secs(0));
            assert!(retry_after <= Duration::from_secs(15 * 60));
        }
        other => panic!("expected DebounceHit, got {other:?}"),
    }

    // Pull bypasses the debounce.
    let third = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Pull)
        .await
        .unwrap();
    assert!(
        !matches!(third, DispatchOutcome::Skipped { .. }),
        "Pull must bypass debounce, got {third:?}",
    );
}

// ── 5. Queue-depth ceiling ──────────────────────────────────────────────

#[tokio::test]
async fn dispatch_push_queue_depth_ceiling_skips() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await.unwrap();
    let (incident_id, moderator_id) = seed_scenario(&pool, SubjectKind::Post).await;

    let sentinel = "polaris-e2e-queue";
    let (dispatcher, fixture) = build_dispatcher_with_sentinel(&pool, moderator_id, sentinel);
    bake_response(&fixture, sentinel, sample_response(sentinel, 0.97));
    let dispatcher = dispatcher.with_queue_depth_ceiling(0); // every push trips

    let outcome = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Push)
        .await
        .unwrap();
    let reason = match outcome {
        DispatchOutcome::Skipped { reason } => reason,
        other => panic!("expected Skipped at ceiling=0, got {other:?}"),
    };
    assert!(
        matches!(
            reason,
            SkipReason::QueueDepthExceeded {
                ceiling: 0,
                depth: 0
            }
        ),
        "expected QueueDepthExceeded with depth=0/ceiling=0, got {reason:?}",
    );

    // Pull bypasses the queue gate even at ceiling=0.
    let pull_outcome = dispatcher
        .dispatch_case(incident_id, DispatchTrigger::Pull)
        .await
        .unwrap();
    assert!(
        !matches!(pull_outcome, DispatchOutcome::Skipped { .. }),
        "Pull must bypass queue ceiling, got {pull_outcome:?}",
    );
}

// ── Coverage-gap documentation for the assisted-mode draft path ────────
//
// `safety_floors::evaluate` is a stub today (#235 / LLM-6) that always
// returns `Autonomous`. The dispatcher's `EffectiveMode::Assisted`
// branch is exercised by the dispatcher's unit tests (in
// `src/llm/recommend_dispatcher.rs`) but is not reachable end-to-end
// against a live DB until the safety-floor real implementation lands.
//
// When #235 lands, add a test here that:
//   1. Sets the policy's `autonomy_mode = 'autonomous'`
//   2. Configures the response's `confidence < autonomous_confidence_threshold`
//      so REQ-S1 trips and the dispatcher downgrades to assisted.
//   3. Asserts a `pending_auto_actions` row is inserted, carrying:
//      - `state = 'pending'`
//      - `llm_observation_id` pointing at the persisted observation
//      - `cited_policy_versions` with the snapshot `(identifier, version)` pair.
