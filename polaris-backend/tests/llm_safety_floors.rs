//! LLM-6 (#235) safety-floor integration suite
//! (`.design/llm-moderation-assist.md` REQ-S1..S8; AC-6).
//!
//! One test per floor + the priority-order + all-pass sanity, fifteen
//! cases total per the issue plan. Every test spins a fresh Postgres
//! testcontainer, runs migrations, seeds the minimum subjects /
//! actions / policy rows the floor under test reads, and asserts
//! the [`EffectiveMode`] [`evaluate`] returns.
//!
//! Tests skip cleanly when Docker is unreachable — the same posture
//! the rest of `polaris-backend/tests/` uses for DB-bound suites.
//!
//! The fixture policy (`fixture_policy`) is `autonomy_mode =
//! 'autonomous'` with `autonomous_action_kinds = ['label', 'warn']`,
//! `autonomous_confidence_threshold = 0.95`,
//! `assisted_confidence_threshold = 0.7`,
//! `autonomous_rate_limit_per_hour = 60`,
//! `autonomous_reversal_breaker_threshold = 0.15`,
//! `human_required_always = false`. Per-test mutations target one
//! field so the failure mode is unambiguous.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use chrono::{Duration as ChronoDuration, Utc};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::llm::safety_floors::{EffectiveMode, evaluate};
use polaris_backend::repo::action::LlmAuditFields;
use polaris_backend::repo::mod_policies::{self, ModPolicy, NewModPolicy};
use polaris_backend::repo::{
    self, ActionRepo, IncidentRepo, PgActionRepo, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{
    ActionKind, Did, IncidentId, IncidentStatus, ObservationId, PolicyId, Severity, SubjectId,
    SubjectKind,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a fresh Postgres testcontainer, migrate, return `(db, pool)`.
async fn boot_db() -> (db::Db, PgPool) {
    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .unwrap();
    let host_port = pg.get_host_port_ipv4(5432).await.unwrap();
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.unwrap();
    let pool = database.pool().clone();
    std::mem::forget(pg);
    (database, pool)
}

async fn seed_moderator(pool: &PgPool, external_id: &str) -> Uuid {
    let row: (Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, pinned_admin)
          VALUES ($1, 'atproto', FALSE)
          RETURNING id",
    )
    .bind(external_id)
    .fetch_one(pool)
    .await
    .unwrap();
    row.0
}

async fn seed_policy(pool: &PgPool, moderator_id: Uuid, identifier: &str) -> ModPolicy {
    let mut tx = pool.begin().await.unwrap();
    let p = mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: identifier.to_owned(),
            name: format!("{identifier} title"),
            description: format!("LLM-6 fixture for {identifier}"),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "Apply this policy when the LLM-6 safety-floor test exercises it."
                .to_owned(),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "autonomous".to_owned(),
            autonomous_action_kinds: vec!["label".to_owned(), "warn".to_owned()],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            autonomous_rate_limit_per_hour: None,
            autonomous_reversal_breaker_threshold: None,
            change_summary: None,
        },
        moderator_id,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    p
}

async fn seed_subject_incident(pool: &PgPool, kind: SubjectKind) -> (SubjectId, IncidentId) {
    let subject_repo = PgSubjectRepo::new(pool.clone());
    let incident_repo = PgIncidentRepo::new(pool.clone());
    let did = Did::new(format!("did:plc:llm6-{}", Uuid::new_v4().simple()));
    let uri = match kind {
        SubjectKind::Account => None,
        _ => Some(polaris_types::AtUri::new(format!(
            "at://{did}/app.bsky.feed.post/3kabc{}",
            Uuid::new_v4().simple()
        ))),
    };
    let subject = subject_repo
        .insert(repo::NewSubject {
            kind,
            did: Some(did),
            uri,
            created_at: Utc::now(),
        })
        .await
        .unwrap();
    let incident = incident_repo
        .insert(repo::NewIncident {
            primary_subject: subject.id,
            severity: Severity::Medium,
            status: IncidentStatus::Open,
            assigned_to: None,
        })
        .await
        .unwrap();
    (subject.id, incident.id)
}

/// Insert a human action against `subject_id` with the given kind.
/// Used to fabricate the S4 cooldown precondition.
async fn insert_human_action(
    pool: &PgPool,
    moderator_id: Uuid,
    incident_id: IncidentId,
    subject_id: SubjectId,
    kind: ActionKind,
    policy_identifier: &str,
    policy_version: i32,
) {
    let action_repo = PgActionRepo::new(pool.clone());
    action_repo
        .insert(repo::NewAction {
            incident_id,
            subject_id,
            moderator_id: polaris_types::ModeratorId(moderator_id),
            kind,
            label: None,
            reasoning: "fixture human action for the LLM-6 floor regression".to_owned(),
            policy_refs: vec![PolicyId::new(format!(
                "{policy_identifier}@{policy_version}"
            ))],
            reversible_until: Utc::now() + ChronoDuration::days(7),
            reverses_action_id: None,
            llm_audit: None,
        })
        .await
        .unwrap();
}

/// Insert a placeholder `LlmRecommendation` observation row so the
/// autonomous-action FK (`actions.llm_observation_id`) can be
/// satisfied. The evidence JSONB carries the empty
/// `RecommendResponse`-shaped object — enough to make the row
/// readable; the safety-floor evaluator never reads observations
/// itself.
async fn insert_llm_observation(pool: &PgPool, subject_id: SubjectId) -> ObservationId {
    let id: Uuid = sqlx::query_scalar!(
        r#"
        INSERT INTO observations (subject_id, kind, confidence, evidence)
        VALUES ($1, 'llm_recommendation', 0.97,
                '{"model":"llm6-test","recommended_actions":[]}'::JSONB)
        RETURNING id
        "#,
        subject_id.0,
    )
    .fetch_one(pool)
    .await
    .unwrap();
    ObservationId(id)
}

/// Insert an autonomous action against `subject_id` cited at the
/// supplied policy. Used to fabricate the S5 rate-limit precondition
/// and the S6 reversal-rate breaker baseline.
async fn insert_autonomous_action(
    pool: &PgPool,
    moderator_id: Uuid,
    incident_id: IncidentId,
    subject_id: SubjectId,
    policy_identifier: &str,
    policy_version: i32,
) -> polaris_types::ActionId {
    let observation_id = insert_llm_observation(pool, subject_id).await;
    let action_repo = PgActionRepo::new(pool.clone());
    let action = action_repo
        .insert(repo::NewAction {
            incident_id,
            subject_id,
            moderator_id: polaris_types::ModeratorId(moderator_id),
            kind: ActionKind::Label,
            label: Some(polaris_types::LabelValue::new("spam")),
            reasoning: "fixture autonomous action for LLM-6 floor regression".to_owned(),
            policy_refs: vec![PolicyId::new(format!(
                "{policy_identifier}@{policy_version}"
            ))],
            reversible_until: Utc::now() + ChronoDuration::days(30),
            reverses_action_id: None,
            llm_audit: Some(LlmAuditFields {
                llm_observation_id: observation_id,
                model: "llm6-test".to_owned(),
                model_version: "2026-05".to_owned(),
                prompt_template_id: "llm6.fixture.v1".to_owned(),
                recommendation_confidence: 0.97,
                input_hash: "deadbeef".repeat(8),
            }),
        })
        .await
        .unwrap();
    // The action repo does NOT write `action_policy_citations` for
    // non-reversal actions; the cases::submit_action service writes
    // them. The S5 rate-limit + S6 reversal-breaker queries JOIN
    // through `action_policy_citations`, so the fixture has to
    // insert the citation row directly.
    sqlx::query!(
        r#"
        INSERT INTO action_policy_citations
            (action_id, policy_identifier, policy_version)
        VALUES ($1, $2, $3)
        "#,
        action.id.0,
        policy_identifier,
        policy_version,
    )
    .execute(pool)
    .await
    .unwrap();
    action.id
}

async fn insert_reversal(
    pool: &PgPool,
    moderator_id: Uuid,
    incident_id: IncidentId,
    subject_id: SubjectId,
    reverses: polaris_types::ActionId,
    policy_identifier: &str,
    policy_version: i32,
) {
    let action_repo = PgActionRepo::new(pool.clone());
    action_repo
        .insert(repo::NewAction {
            incident_id,
            subject_id,
            moderator_id: polaris_types::ModeratorId(moderator_id),
            kind: ActionKind::Reverse,
            label: None,
            reasoning: "fixture reversal for LLM-6 reversal-rate breaker test".to_owned(),
            policy_refs: vec![PolicyId::new(format!(
                "{policy_identifier}@{policy_version}"
            ))],
            reversible_until: Utc::now() + ChronoDuration::days(7),
            reverses_action_id: Some(reverses),
            llm_audit: None,
        })
        .await
        .unwrap();
}

// ── 1. S1: confidence below autonomous threshold → assisted ─────────

#[tokio::test]
async fn s1_below_autonomous_threshold_downgrades_to_assisted() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s1a").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s1a").await;
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    let mode = evaluate(&pool, &policy, "label", 0.80, subject.0, "post")
        .await
        .unwrap();

    assert!(
        matches!(mode, EffectiveMode::Assisted { .. }),
        "expected Assisted, got {mode:?}"
    );
}

// ── 2. S1: confidence below both thresholds → manual ────────────────

#[tokio::test]
async fn s1_below_both_thresholds_downgrades_to_manual() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s1b").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s1b").await;
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    let mode = evaluate(&pool, &policy, "label", 0.50, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);
}

// ── 3. S2: kind not in policy's autonomous_action_kinds → manual ────

#[tokio::test]
async fn s2_kind_not_in_autonomous_action_kinds_downgrades() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s2a").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s2a").await;
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    // Confidence high enough that S1 passes; kind "takedown" not in
    // fixture's allow-list ["label", "warn"].
    let mode = evaluate(&pool, &policy, "takedown", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);
}

// ── 4. S2: escalate is never autonomously eligible ──────────────────

#[tokio::test]
async fn s2_escalate_always_downgrades_even_if_in_list() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s2b").await;
    // Hand-seed a policy that DOES include "escalate" in its
    // autonomous_action_kinds (the admin API forbids this at write
    // time but the dispatcher must hold the floor too).
    let mut tx = pool.begin().await.unwrap();
    let policy = mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: "polaris.s2b".to_owned(),
            name: "s2b".to_owned(),
            description: "s2b fixture".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "x".repeat(64),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "autonomous".to_owned(),
            autonomous_action_kinds: vec!["escalate".to_owned()],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            autonomous_rate_limit_per_hour: None,
            autonomous_reversal_breaker_threshold: None,
            change_summary: None,
        },
        mod_id,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    let mode = evaluate(&pool, &policy, "escalate", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);
}

// ── 5. S3: account-takedown gate ────────────────────────────────────

#[tokio::test]
async fn s3_account_takedown_downgrades() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s3").await;
    // Allow takedown in the policy so S2 doesn't trip first.
    let mut tx = pool.begin().await.unwrap();
    let policy = mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: "polaris.s3".to_owned(),
            name: "s3".to_owned(),
            description: "s3 fixture".to_owned(),
            scope: "both".to_owned(),
            severity: "remove".to_owned(),
            decision_criteria: "x".repeat(64),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["takedown".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: false,
            autonomy_mode: "autonomous".to_owned(),
            autonomous_action_kinds: vec!["takedown".to_owned()],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            autonomous_rate_limit_per_hour: None,
            autonomous_reversal_breaker_threshold: None,
            change_summary: None,
        },
        mod_id,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Account).await;

    let mode = evaluate(&pool, &policy, "takedown", 0.99, subject.0, "account")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);
}

// ── 6. S4: recent human no_action blocks ────────────────────────────

#[tokio::test]
async fn s4_recent_human_no_action_blocks() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s4a").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s4a").await;
    let (subject, incident) = seed_subject_incident(&pool, SubjectKind::Post).await;
    insert_human_action(
        &pool,
        mod_id,
        incident,
        subject,
        ActionKind::NoAction,
        &policy.identifier,
        policy.version,
    )
    .await;

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert!(
        matches!(mode, EffectiveMode::Assisted { .. }),
        "expected Assisted (cooldown soft downgrade), got {mode:?}"
    );
}

// ── 7. S4: recent human reverse blocks ──────────────────────────────

#[tokio::test]
async fn s4_recent_human_reverse_blocks() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s4b").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s4b").await;
    let (subject, incident) = seed_subject_incident(&pool, SubjectKind::Post).await;
    // Need a target action for `reverses_action_id`; insert a prior
    // autonomous label first, then a human reverse against it.
    let target = insert_autonomous_action(
        &pool,
        mod_id,
        incident,
        subject,
        &policy.identifier,
        policy.version,
    )
    .await;
    insert_reversal(
        &pool,
        mod_id,
        incident,
        subject,
        target,
        &policy.identifier,
        policy.version,
    )
    .await;

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert!(
        matches!(mode, EffectiveMode::Assisted { .. }) || mode == EffectiveMode::Manual,
        "expected Assisted/Manual (cooldown), got {mode:?}"
    );
}

// ── 8. S4: outside cooldown window does not block ───────────────────

#[tokio::test]
async fn s4_outside_cooldown_window_does_not_block() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s4c").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s4c").await;
    let (subject, incident) = seed_subject_incident(&pool, SubjectKind::Post).await;
    // Insert a human no_action action directly via SQL with a
    // backdated `created_at` 100 days in the past. The repo's
    // PgActionRepo::insert always stamps `now()`; the actions table
    // is append-only (the BEFORE-UPDATE trigger from migration 4
    // rejects post-insert UPDATE on created_at). Direct SQL insert
    // at fixture time is the supported path for backdating.
    sqlx::query!(
        r#"
        INSERT INTO actions (
            incident_id, subject_id, moderator_id, kind,
            reasoning, policy_refs, reversible_until,
            actor_kind, created_at
        )
        VALUES ($1, $2, $3, 'no_action',
                'fixture backdated no_action for S4 cooldown-window test',
                ARRAY['polaris.s4c@1']::TEXT[],
                now() + INTERVAL '7 days',
                'human',
                now() - INTERVAL '100 days')
        "#,
        incident.0,
        subject.0,
        mod_id,
    )
    .execute(&pool)
    .await
    .unwrap();

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Autonomous);
}

// ── 9. S5: within rate limit passes ─────────────────────────────────

#[tokio::test]
async fn s5_within_rate_limit_passes() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s5a").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s5a").await;
    let (subject, incident) = seed_subject_incident(&pool, SubjectKind::Post).await;
    // Insert 5 autonomous actions (well below the default 60/hr).
    for _ in 0..5 {
        let (s, _) = seed_subject_incident(&pool, SubjectKind::Post).await;
        let _ = insert_autonomous_action(
            &pool,
            mod_id,
            incident,
            s,
            &policy.identifier,
            policy.version,
        )
        .await;
    }

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Autonomous);
}

// ── 10. S5: at rate limit downgrades ────────────────────────────────

#[tokio::test]
async fn s5_at_rate_limit_downgrades() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s5b").await;
    // Use a tight rate limit so the test doesn't have to insert 60+
    // actions to trip it. Amend the policy to limit = 2.
    let policy_v1 = seed_policy(&pool, mod_id, "polaris.s5b").await;
    let mut tx = pool.begin().await.unwrap();
    let policy = mod_policies::amend(
        &mut tx,
        &policy_v1.identifier,
        mod_policies::ModPolicyPatch {
            autonomous_rate_limit_per_hour: Some(2),
            ..Default::default()
        },
        mod_id,
        Some("tighten limit for s5 test".to_owned()),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let (subject, incident) = seed_subject_incident(&pool, SubjectKind::Post).await;
    for _ in 0..3 {
        let (s, _) = seed_subject_incident(&pool, SubjectKind::Post).await;
        let _ = insert_autonomous_action(
            &pool,
            mod_id,
            incident,
            s,
            &policy.identifier,
            policy.version,
        )
        .await;
    }

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert!(
        matches!(mode, EffectiveMode::Assisted { .. }),
        "expected Assisted (rate-limit soft downgrade), got {mode:?}"
    );
}

// ── 11. S6: reversal rate above threshold pauses + blocks ───────────

#[tokio::test]
async fn s6_reversal_rate_above_threshold_pauses_and_blocks() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s6").await;
    let policy_v1 = seed_policy(&pool, mod_id, "polaris.s6").await;

    // Insert 4 autonomous actions, reverse 3 of them = 75% reversal
    // rate (well above the 15% threshold). Each on a unique subject
    // so S4 cooldown doesn't shadow S6.
    let mut targets = Vec::new();
    for _ in 0..4 {
        let (s, inc) = seed_subject_incident(&pool, SubjectKind::Post).await;
        targets.push((
            s,
            inc,
            insert_autonomous_action(
                &pool,
                mod_id,
                inc,
                s,
                &policy_v1.identifier,
                policy_v1.version,
            )
            .await,
        ));
    }
    for (s, inc, target_id) in targets.iter().take(3) {
        insert_reversal(
            &pool,
            mod_id,
            *inc,
            *s,
            *target_id,
            &policy_v1.identifier,
            policy_v1.version,
        )
        .await;
    }

    // Subject for the recommendation under test — fresh, so no
    // S4 noise.
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    let mode = evaluate(&pool, &policy_v1, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);

    // The breaker side effect must have landed a new policy version
    // with autonomous_paused_until in the near future. Fetch the
    // current row by identifier to verify.
    let current = mod_policies::current_by_identifier(&pool, &policy_v1.identifier)
        .await
        .unwrap()
        .expect("policy still exists");
    assert!(
        current.version > policy_v1.version,
        "breaker should have written a successor version; got v{}",
        current.version,
    );
    assert!(
        current.autonomous_paused_until.is_some(),
        "successor version must carry autonomous_paused_until",
    );
}

// ── 12. S7: global pause blocks ─────────────────────────────────────

#[tokio::test]
async fn s7_global_pause_blocks() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s7").await;
    let policy = seed_policy(&pool, mod_id, "polaris.s7").await;
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    // Set the global kill switch to one hour in the future.
    sqlx::query!(
        r#"INSERT INTO polaris_setup_state (id, global_autonomous_pause_until)
           VALUES (TRUE, now() + INTERVAL '1 hour')
           ON CONFLICT (id) DO UPDATE
           SET global_autonomous_pause_until = EXCLUDED.global_autonomous_pause_until"#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);
}

// ── 13. S8: human_required blocks ───────────────────────────────────

#[tokio::test]
async fn s8_human_required_blocks() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "s8").await;
    // Seed a policy with human_required_always = true. Setting
    // autonomy_mode = manual is required because the admin API
    // would refuse autonomous+human_required pairs; the test
    // bypasses that layer by inserting directly through the repo.
    let mut tx = pool.begin().await.unwrap();
    let policy = mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: "polaris.s8".to_owned(),
            name: "s8".to_owned(),
            description: "s8 fixture".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "x".repeat(64),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: true,
            autonomy_mode: "manual".to_owned(),
            autonomous_action_kinds: vec![],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            autonomous_rate_limit_per_hour: None,
            autonomous_reversal_breaker_threshold: None,
            change_summary: None,
        },
        mod_id,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);
}

// ── 14. evaluate returns first trip in priority order ───────────────

/// When S8 (human_required) and S1 (confidence) would BOTH trip,
/// the evaluator's priority order means S8 wins — the returned
/// mode is Manual (hard block) not Assisted (soft S1 downgrade).
#[tokio::test]
async fn evaluate_returns_first_trip_in_priority_order() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "prio").await;
    let mut tx = pool.begin().await.unwrap();
    let policy = mod_policies::insert_initial(
        &mut tx,
        NewModPolicy {
            identifier: "polaris.prio".to_owned(),
            name: "prio".to_owned(),
            description: "prio fixture".to_owned(),
            scope: "post".to_owned(),
            severity: "alert".to_owned(),
            decision_criteria: "x".repeat(64),
            examples_positive: None,
            examples_negative: None,
            suggested_action_kinds: vec!["label".to_owned()],
            linked_label_value: None,
            exceptions: None,
            human_required_always: true,
            autonomy_mode: "manual".to_owned(),
            autonomous_action_kinds: vec![],
            autonomous_confidence_threshold: 0.95,
            assisted_confidence_threshold: 0.70,
            autonomous_rate_limit_per_hour: None,
            autonomous_reversal_breaker_threshold: None,
            change_summary: None,
        },
        mod_id,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    // confidence 0.80 would land S1 in the assisted bucket; S8
    // overrides and lands Manual.
    let mode = evaluate(&pool, &policy, "label", 0.80, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Manual);
}

// ── 15. all-pass → autonomous ───────────────────────────────────────

#[tokio::test]
async fn evaluate_all_passes_returns_autonomous() {
    if !docker_available() {
        eprintln!("skipping: docker unavailable");
        return;
    }
    let (_db, pool) = boot_db().await;
    let mod_id = seed_moderator(&pool, "pass").await;
    let policy = seed_policy(&pool, mod_id, "polaris.pass").await;
    let (subject, _) = seed_subject_incident(&pool, SubjectKind::Post).await;

    let mode = evaluate(&pool, &policy, "label", 0.99, subject.0, "post")
        .await
        .unwrap();

    assert_eq!(mode, EffectiveMode::Autonomous);
}
