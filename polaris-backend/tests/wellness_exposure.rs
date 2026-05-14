//! Wellness exposure integration tests (issue #23).
//!
//! Spins up Postgres 16 via testcontainers, applies every migration through
//! `db::connect`, then exercises the [`ExposureTracker`] across the four
//! scenarios mandated by the architect's dispatch:
//!
//! 1. **Record / count** — N events against a single category land as a
//!    single row whose `count` matches.
//! 2. **Cap + force-break** — once the moderator's total reaches
//!    `daily_cap * force_break_at_pct / 100`, `force_break_active = true`
//!    and `remaining_budget = 0`.
//! 3. **Consent-respecting aggregate** — `aggregate_for_manager` returns
//!    empty when consent is false and the breakdown when consent is true.
//!    The two calls are against the same data; the privacy gate is the
//!    only difference.
//! 4. **Routing integration** — `PgModeratorDirectory::list_eligible`
//!    reflects the live `remaining_budget`: before the force-break fires
//!    the per-moderator `exposure_budget_remaining` is positive, after
//!    it fires the value is `0`.
//!
//! Each test starts its own Postgres container so the cap / force-break
//! state is isolated between scenarios; container startup is ~3s and
//! parallelism between tests amortises the cost.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message and
//! returns successfully — same pattern as `tests/repo_roundtrip.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::routing::service::{ModeratorDirectory, PgModeratorDirectory};
use polaris_backend::wellness::exposure::ExposureTracker;
use polaris_types::{ModeratorId, RoutingCategory};
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

/// Boot Postgres + migrate + return the pool.
async fn boot_db() -> Result<PgPool, Box<dyn std::error::Error>> {
    // Postgres 16-alpine: migration 11 needs generated columns (PG ≥ 12).
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let pool = db::connect(&cfg).await?.pool().clone();
    // Keep the container alive for the rest of the test (same idiom as
    // `tests/pattern_actions.rs` — `Drop` on `ContainerAsync` stops the
    // container, so we `mem::forget` it).
    std::mem::forget(container);
    Ok(pool)
}

/// Insert a moderator row and return its id. The
/// `moderator_exposure(_settings)` FKs require this row to exist.
async fn insert_moderator(pool: &PgPool) -> Result<ModeratorId, Box<dyn std::error::Error>> {
    let external_id = format!("wellness-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(ModeratorId(row.id))
}

#[tokio::test]
async fn record_increments_per_moderator_day_category_counter()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP wellness_exposure::record_increments: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test."
        );
        return Ok(());
    }
    let pool = boot_db().await?;
    let tracker = ExposureTracker::new(pool.clone());
    let mod_id = insert_moderator(&pool).await?;

    // Record N events for the same category — the UPSERT must produce
    // a single row with `count = N`, not N rows.
    for _ in 0..7 {
        tracker.record(mod_id, "graphic").await?;
    }

    let row = sqlx::query!(
        r"SELECT count FROM moderator_exposure
          WHERE moderator_id = $1 AND day = current_date AND category = 'graphic'",
        mod_id.0,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.count, 7);
    Ok(())
}

#[tokio::test]
async fn force_break_fires_at_threshold_percentage() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP wellness_exposure::force_break_fires: docker daemon not reachable.");
        return Ok(());
    }
    let pool = boot_db().await?;
    let tracker = ExposureTracker::new(pool.clone());
    let mod_id = insert_moderator(&pool).await?;

    // Low cap + low threshold so the scenario stays fast: cap = 10, pct =
    // 50 — force-break fires at 5 events.
    tracker.set_daily_cap(mod_id, 10).await?;
    sqlx::query!(
        r"UPDATE moderator_exposure_settings SET force_break_at_pct = 50 WHERE moderator_id = $1",
        mod_id.0,
    )
    .execute(&pool)
    .await?;

    // Below threshold: 4 events -> still inactive.
    for _ in 0..4 {
        tracker.record(mod_id, "graphic").await?;
    }
    let status = tracker.status_for_me(mod_id).await?;
    assert_eq!(status.total, 4);
    assert_eq!(status.daily_cap, 10);
    assert_eq!(status.force_break_at_pct, 50);
    assert!(!status.force_break_active);
    assert_eq!(status.remaining_budget, 6);

    // At threshold: one more event -> 5 events -> force-break fires.
    tracker.record(mod_id, "graphic").await?;
    let status = tracker.status_for_me(mod_id).await?;
    assert_eq!(status.total, 5);
    assert!(status.force_break_active);
    assert_eq!(status.remaining_budget, 0);

    // `remaining_budget` accessor matches the status field.
    assert_eq!(tracker.remaining_budget(mod_id).await?, 0);
    Ok(())
}

#[tokio::test]
async fn aggregate_for_manager_respects_consent_flag() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP wellness_exposure::aggregate_respects_consent: docker daemon not reachable."
        );
        return Ok(());
    }
    let pool = boot_db().await?;
    let tracker = ExposureTracker::new(pool.clone());
    let mod_id = insert_moderator(&pool).await?;

    // Record two events in different categories so the aggregate has a
    // non-trivial breakdown when consent is granted.
    tracker.record(mod_id, "graphic").await?;
    tracker.record(mod_id, "graphic").await?;
    tracker.record(mod_id, "violence").await?;

    // Default consent is FALSE — aggregate must be empty regardless of
    // recorded events.
    let consent_off = tracker.aggregate_for_manager(mod_id, false).await?;
    assert!(
        consent_off.is_empty(),
        "consent=false MUST yield empty regardless of recorded events"
    );

    // Even after explicitly toggling the moderator's settings to share=true,
    // a caller that passes `consent=false` still gets empty: the function
    // is parameter-driven, not state-driven.
    tracker.set_share_with_manager(mod_id, true).await?;
    assert!(
        tracker
            .aggregate_for_manager(mod_id, false)
            .await?
            .is_empty()
    );

    // With consent=true, the breakdown surfaces with both categories.
    let mut breakdown = tracker.aggregate_for_manager(mod_id, true).await?;
    breakdown.sort_by(|a, b| a.category.cmp(&b.category));
    assert_eq!(breakdown.len(), 2);
    assert_eq!(breakdown[0].category, "graphic");
    assert_eq!(breakdown[0].count, 2);
    assert_eq!(breakdown[1].category, "violence");
    assert_eq!(breakdown[1].count, 1);

    // `share_with_manager` accessor reflects the toggle.
    assert!(tracker.share_with_manager(mod_id).await?);
    Ok(())
}

#[tokio::test]
async fn pg_moderator_directory_reflects_remaining_budget() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!("SKIP wellness_exposure::directory_reflects_budget: docker daemon not reachable.");
        return Ok(());
    }
    let pool = boot_db().await?;
    let tracker = ExposureTracker::new(pool.clone());
    let directory = PgModeratorDirectory::new(pool.clone());
    let mod_id = insert_moderator(&pool).await?;

    // Set cap = 4 and threshold = 50% so force-break fires at 2 events.
    tracker.set_daily_cap(mod_id, 4).await?;
    sqlx::query!(
        r"UPDATE moderator_exposure_settings SET force_break_at_pct = 50 WHERE moderator_id = $1",
        mod_id.0,
    )
    .execute(&pool)
    .await?;

    // Before any record: budget = 4.
    let pool_before = directory.list_eligible(RoutingCategory::Harassment).await?;
    let me = pool_before
        .iter()
        .find(|m| m.id == mod_id)
        .expect("moderator present");
    assert_eq!(me.exposure_budget_remaining, 4);
    assert_eq!(me.current_load, 0);

    // Record one event -> still below threshold -> budget = 3.
    tracker.record(mod_id, "graphic").await?;
    let pool_mid = directory.list_eligible(RoutingCategory::Harassment).await?;
    let me = pool_mid
        .iter()
        .find(|m| m.id == mod_id)
        .expect("moderator present");
    assert_eq!(me.exposure_budget_remaining, 3);

    // Trip the force-break: one more event -> 2 events -> threshold.
    tracker.record(mod_id, "graphic").await?;
    let pool_after = directory.list_eligible(RoutingCategory::Harassment).await?;
    let me = pool_after
        .iter()
        .find(|m| m.id == mod_id)
        .expect("moderator present");
    assert_eq!(
        me.exposure_budget_remaining, 0,
        "force-break must zero the routing-time budget so the cascade skips this moderator"
    );
    Ok(())
}
