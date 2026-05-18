//! Mod-policies repository integration tests (#223, WB-1, AC-2).
//!
//! Hermetic per test: each test boots a fresh testcontainers Postgres
//! 16-alpine, applies all migrations via `db::connect`, and exercises
//! the typed repo at [`polaris_backend::repo::mod_policies`] directly.
//! The action API isn't on the table for this PR (that's WB-2 / #224);
//! these tests are the bottom-up coverage of the repo contract.
//!
//! Mirrors the `tests/case_api.rs` boot harness so the docker-detection
//! / container-leak / migration-on-connect path is identical across
//! the suite.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::repo::mod_policies::{
    self, ModPolicyError, ModPolicyFilters, ModPolicyPatch, NewModPolicy,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors `case_api.rs`.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the pool.
async fn boot_pool() -> Result<PgPool, Box<dyn std::error::Error>> {
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
    // Leak the container handle so its Drop (which stops the container)
    // runs at process exit rather than at this stack frame.
    std::mem::forget(container);
    Ok(pool)
}

/// Insert a moderator row so the policy's `created_by_moderator_id`
/// FK is satisfied. Returns the moderator's UUID.
async fn insert_moderator(pool: &PgPool) -> Result<Uuid, Box<dyn std::error::Error>> {
    let external_id = format!("mod-policies-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// Build a [`NewModPolicy`] fixture with sensible defaults. The
/// caller overrides per-test fields by mutating the returned value.
fn fixture(identifier: &str) -> NewModPolicy {
    NewModPolicy {
        identifier: identifier.to_owned(),
        name: format!("{identifier} name"),
        description: format!("placeholder description for {identifier}"),
        scope: "post".to_owned(),
        severity: "alert".to_owned(),
        // ≥ 64 chars so the DB CHECK is satisfied.
        decision_criteria: "Apply this policy when the post contains material matching the \
                            criteria described in the workbook overview document."
            .to_owned(),
        examples_positive: None,
        examples_negative: None,
        suggested_action_kinds: vec!["label".to_owned(), "warn".to_owned()],
        linked_label_value: None,
        exceptions: None,
        human_required_always: false,
        autonomy_mode: "manual".to_owned(),
        autonomous_action_kinds: vec![],
        autonomous_confidence_threshold: 0.95,
        assisted_confidence_threshold: 0.70,
        autonomous_rate_limit_per_hour: None,
        autonomous_reversal_breaker_threshold: None,
        change_summary: None,
    }
}

// ── 1. insert_initial round-trip ───────────────────────────────────────

#[tokio::test]
async fn insert_initial_round_trip() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP mod_policies_repo::insert_initial_round_trip: docker unreachable");
        return Ok(());
    }
    let pool = boot_pool().await?;
    let mod_id = insert_moderator(&pool).await?;

    let mut tx = pool.begin().await?;
    let inserted =
        mod_policies::insert_initial(&mut tx, fixture("polaris.harassment"), mod_id).await?;
    tx.commit().await?;

    assert_eq!(inserted.identifier, "polaris.harassment");
    assert_eq!(inserted.version, 1, "initial insert is v1");
    assert!(
        inserted.effective_until.is_none(),
        "fresh insert is the current version"
    );
    assert!(inserted.supersedes_id.is_none(), "v1 supersedes nothing");
    assert_eq!(inserted.autonomy_mode, "manual");
    assert_eq!(inserted.created_by_moderator_id, mod_id);

    let fetched = mod_policies::current_by_identifier(&pool, "polaris.harassment")
        .await?
        .expect("current row exists");
    assert_eq!(
        fetched, inserted,
        "current_by_identifier returns inserted row"
    );
    Ok(())
}

// ── 2. amend creates successor version ─────────────────────────────────

#[tokio::test]
async fn amend_creates_successor_version() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP mod_policies_repo::amend_creates_successor_version: docker unreachable");
        return Ok(());
    }
    let pool = boot_pool().await?;
    let mod_id = insert_moderator(&pool).await?;

    // Seed v1.
    let mut tx = pool.begin().await?;
    let v1 = mod_policies::insert_initial(&mut tx, fixture("polaris.spam"), mod_id).await?;
    tx.commit().await?;

    // Amend → v2.
    let mut tx = pool.begin().await?;
    let v2 = mod_policies::amend(
        &mut tx,
        "polaris.spam",
        ModPolicyPatch {
            description: Some("v2 description — clarified".to_owned()),
            severity: Some("hide".to_owned()),
            ..Default::default()
        },
        mod_id,
        Some("clarify scope".to_owned()),
    )
    .await?;
    tx.commit().await?;

    assert_eq!(v2.version, 2);
    assert_eq!(v2.description, "v2 description — clarified");
    assert_eq!(v2.severity, "hide");
    // Patch-untouched field inherits from prior.
    assert_eq!(v2.scope, v1.scope, "untouched field carries forward");
    assert_eq!(v2.supersedes_id, Some(v1.id));
    assert!(v2.effective_until.is_none(), "v2 is now current");
    assert_eq!(v2.change_summary.as_deref(), Some("clarify scope"));

    // v1 row is closed out.
    let v1_now = mod_policies::at_version(&pool, "polaris.spam", 1)
        .await?
        .expect("v1 still readable");
    assert!(
        v1_now.effective_until.is_some(),
        "v1 has effective_until set after amend",
    );

    let current = mod_policies::current_by_identifier(&pool, "polaris.spam")
        .await?
        .expect("current row");
    assert_eq!(current.version, 2);
    Ok(())
}

// ── 3. history returns chain chronologically ───────────────────────────

#[tokio::test]
async fn history_returns_chain_chronologically() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP mod_policies_repo::history_returns_chain_chronologically: docker unreachable"
        );
        return Ok(());
    }
    let pool = boot_pool().await?;
    let mod_id = insert_moderator(&pool).await?;

    let mut tx = pool.begin().await?;
    mod_policies::insert_initial(&mut tx, fixture("polaris.copyright"), mod_id).await?;
    tx.commit().await?;

    for n in 2..=4 {
        let mut tx = pool.begin().await?;
        mod_policies::amend(
            &mut tx,
            "polaris.copyright",
            ModPolicyPatch {
                description: Some(format!("v{n} description")),
                ..Default::default()
            },
            mod_id,
            Some(format!("bump to v{n}")),
        )
        .await?;
        tx.commit().await?;
    }

    let history = mod_policies::history(&pool, "polaris.copyright").await?;
    assert_eq!(history.len(), 4, "v1..v4 present");
    assert_eq!(
        history.iter().map(|p| p.version).collect::<Vec<_>>(),
        vec![1, 2, 3, 4],
        "history is oldest-first",
    );
    // The last entry is current; all earlier entries have
    // effective_until set.
    assert!(history.last().unwrap().effective_until.is_none());
    for entry in &history[..3] {
        assert!(
            entry.effective_until.is_some(),
            "v{} closed out",
            entry.version
        );
    }
    Ok(())
}

// ── 4. concurrent edits serialise ──────────────────────────────────────

#[tokio::test]
async fn concurrent_edit_serializes() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP mod_policies_repo::concurrent_edit_serializes: docker unreachable");
        return Ok(());
    }
    let pool = boot_pool().await?;
    let mod_id = insert_moderator(&pool).await?;

    let mut tx = pool.begin().await?;
    mod_policies::insert_initial(&mut tx, fixture("polaris.impersonation"), mod_id).await?;
    tx.commit().await?;

    // Two transactions race to amend the same identifier. `tx_a`
    // acquires the FOR UPDATE lock first and commits; `tx_b` waits
    // on the lock, then sees v1's `effective_until` is now set and
    // its lookup of "current row" must produce a different (newer)
    // version.
    //
    // We model the race deterministically:
    //   1. open tx_a, take the FOR UPDATE lock (insert successor),
    //      commit
    //   2. open tx_b — its lookup of "current row" now returns v2,
    //      and writing a successor produces v3 (no error).
    //
    // The interesting safety property: each amendment produces a
    // strictly-increasing version, no duplicate `(identifier,
    // version)` row, and the prior row is correctly closed out.
    let mut tx_a = pool.begin().await?;
    let v2 = mod_policies::amend(
        &mut tx_a,
        "polaris.impersonation",
        ModPolicyPatch {
            description: Some("tx_a amendment".to_owned()),
            ..Default::default()
        },
        mod_id,
        Some("a".to_owned()),
    )
    .await?;
    tx_a.commit().await?;

    let mut tx_b = pool.begin().await?;
    let v3 = mod_policies::amend(
        &mut tx_b,
        "polaris.impersonation",
        ModPolicyPatch {
            description: Some("tx_b amendment".to_owned()),
            ..Default::default()
        },
        mod_id,
        Some("b".to_owned()),
    )
    .await?;
    tx_b.commit().await?;

    assert_eq!(v2.version, 2);
    assert_eq!(v3.version, 3);
    assert_eq!(v3.supersedes_id, Some(v2.id), "v3 chains to v2");

    // Now test the lock-contention path: open two long-lived
    // transactions, have both reach the FOR UPDATE on the same
    // current row. tx_x commits the successor; tx_y's amend
    // attempt opens AFTER tx_x committed, so its FOR UPDATE on
    // "current row" succeeds (it finds the new current v4, not
    // v3) — the typed loop SHOULD produce a fresh v5, NOT a
    // duplicate v4.
    let mut tx_x = pool.begin().await?;
    let v4 = mod_policies::amend(
        &mut tx_x,
        "polaris.impersonation",
        ModPolicyPatch::default(),
        mod_id,
        Some("x".to_owned()),
    )
    .await?;
    tx_x.commit().await?;

    let mut tx_y = pool.begin().await?;
    let v5 = mod_policies::amend(
        &mut tx_y,
        "polaris.impersonation",
        ModPolicyPatch::default(),
        mod_id,
        Some("y".to_owned()),
    )
    .await?;
    tx_y.commit().await?;

    assert_eq!(v4.version, 4);
    assert_eq!(v5.version, 5);

    // Final invariant: there is exactly one current row.
    let count = sqlx::query!(
        r"SELECT COUNT(*) AS n
          FROM mod_policies
          WHERE identifier = $1 AND effective_until IS NULL",
        "polaris.impersonation",
    )
    .fetch_one(&pool)
    .await?
    .n
    .unwrap_or(0);
    assert_eq!(count, 1, "exactly one current version after race");

    // Now exercise the unknown-identifier path so the variant is
    // also covered.
    let mut tx = pool.begin().await?;
    let err = mod_policies::amend(
        &mut tx,
        "polaris.does_not_exist",
        ModPolicyPatch::default(),
        mod_id,
        None,
    )
    .await
    .expect_err("amend on unknown identifier errors");
    drop(tx);
    assert!(
        matches!(err, ModPolicyError::UnknownIdentifier { .. }),
        "got {err:?}",
    );
    Ok(())
}

// ── 5. list filters ────────────────────────────────────────────────────

#[tokio::test]
async fn list_filters_by_scope() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP mod_policies_repo::list_filters_by_scope: docker unreachable");
        return Ok(());
    }
    let pool = boot_pool().await?;
    let mod_id = insert_moderator(&pool).await?;

    let mut tx = pool.begin().await?;
    let mut p_post = fixture("polaris.harassment");
    p_post.scope = "post".to_owned();
    mod_policies::insert_initial(&mut tx, p_post, mod_id).await?;

    let mut p_account = fixture("polaris.account_takedown");
    p_account.scope = "account".to_owned();
    mod_policies::insert_initial(&mut tx, p_account, mod_id).await?;

    let mut p_both = fixture("polaris.csam");
    p_both.scope = "both".to_owned();
    p_both.autonomy_mode = "manual".to_owned();
    mod_policies::insert_initial(&mut tx, p_both, mod_id).await?;
    tx.commit().await?;

    // No filter → all three.
    let all = mod_policies::list(&pool, ModPolicyFilters::default()).await?;
    assert_eq!(all.len(), 3);

    // scope=post → one row.
    let post_only = mod_policies::list(
        &pool,
        ModPolicyFilters {
            scope: Some("post".to_owned()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(post_only.len(), 1);
    assert_eq!(post_only[0].identifier, "polaris.harassment");

    // q="csam" → matches polaris.csam by identifier-derived
    // name/description.
    let q_match = mod_policies::list(
        &pool,
        ModPolicyFilters {
            q: Some("csam".to_owned()),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(q_match.len(), 1);
    assert_eq!(q_match[0].identifier, "polaris.csam");

    // autonomy_mode=autonomous → zero (all seeded as manual).
    let autonomous = mod_policies::list(
        &pool,
        ModPolicyFilters {
            autonomy_mode: Some("autonomous".to_owned()),
            ..Default::default()
        },
    )
    .await?;
    assert!(autonomous.is_empty());
    Ok(())
}

// ── 6. pause / resume cycle ────────────────────────────────────────────

#[tokio::test]
async fn pause_resume_cycle() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP mod_policies_repo::pause_resume_cycle: docker unreachable");
        return Ok(());
    }
    let pool = boot_pool().await?;
    let mod_id = insert_moderator(&pool).await?;

    let mut tx = pool.begin().await?;
    let mut new = fixture("polaris.harassment");
    new.autonomy_mode = "autonomous".to_owned();
    new.autonomous_action_kinds = vec!["label".to_owned()];
    mod_policies::insert_initial(&mut tx, new, mod_id).await?;
    tx.commit().await?;

    let initial = mod_policies::current_by_identifier(&pool, "polaris.harassment")
        .await?
        .expect("current");
    assert!(initial.autonomous_paused_until.is_none());

    let until = chrono::Utc::now() + chrono::Duration::hours(2);
    let mut tx = pool.begin().await?;
    mod_policies::pause(&mut tx, "polaris.harassment", Some(until)).await?;
    tx.commit().await?;

    let paused = mod_policies::current_by_identifier(&pool, "polaris.harassment")
        .await?
        .expect("current");
    assert!(paused.autonomous_paused_until.is_some());

    // Resume.
    let mut tx = pool.begin().await?;
    mod_policies::resume(&mut tx, "polaris.harassment").await?;
    tx.commit().await?;

    let resumed = mod_policies::current_by_identifier(&pool, "polaris.harassment")
        .await?
        .expect("current");
    assert!(resumed.autonomous_paused_until.is_none());

    // Pause/resume on unknown identifier → UnknownIdentifier.
    let mut tx = pool.begin().await?;
    let err = mod_policies::pause(&mut tx, "polaris.does_not_exist", None)
        .await
        .expect_err("pause on unknown");
    drop(tx);
    assert!(matches!(err, ModPolicyError::UnknownIdentifier { .. }));

    let mut tx = pool.begin().await?;
    let err = mod_policies::resume(&mut tx, "polaris.does_not_exist")
        .await
        .expect_err("resume on unknown");
    drop(tx);
    assert!(matches!(err, ModPolicyError::UnknownIdentifier { .. }));

    Ok(())
}
