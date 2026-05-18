//! WB-5 (#227) integration tests for the first-boot policy seed loader.
//!
//! Covers AC-6:
//!
//! * `first_boot_loads_five_policies` — empty DB + valid seed file
//!   loads all five placeholders; `polaris.csam` has
//!   `human_required_always = TRUE`.
//! * `second_boot_is_noop` — calling the loader twice short-circuits
//!   on the idempotency probe; no duplicate inserts.
//! * `corrupted_seed_file_does_not_partial_insert` — a bad YAML file
//!   surfaces `SeedError::YamlParseError`; zero rows committed.
//! * `missing_seed_file_returns_skipped` — non-existent path returns
//!   `Skipped { SeedFileMissing }`.
//! * `no_bootstrap_admin_returns_skipped` — empty `mod_policies` but
//!   no pinned admin: `run_first_boot_seed` refuses cleanly and
//!   inserts zero rows.
//!
//! Hermetic per test: each test boots its own testcontainers Postgres
//! 16-alpine, applies all migrations via `db::connect`, and drives the
//! seed loader directly. Mirrors `tests/policy_version_pinning.rs`
//! for the boot harness.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]
// The `no_bootstrap_admin_returns_skipped` test uses `unsafe std::env::set_var`
// per Rust 2024 / `unsafe_op_in_unsafe_fn`. The env mutation is isolated
// (one test, set + restore) and integration-test binaries serialise per
// crate so no other suite races on the variable.
#![allow(
    unsafe_code,
    reason = "single-test env-var mutation, isolated and restored on the same test"
)]

use std::path::PathBuf;
use std::process::Command;

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::seed::mod_policies::{
    SeedError, SeedOutcome, SkipReason, lookup_bootstrap_admin, maybe_seed_policies,
    run_first_boot_seed,
};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors `policy_version_pinning.rs`.
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
async fn boot_db() -> Result<PgPool, Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();
    std::mem::forget(container);
    Ok(pool)
}

/// Insert a fresh moderator and pin them as the bootstrap admin.
///
/// The migration-46 monotonic-pin trigger forbids clearing
/// `pinned_admin` once set, so the insert is the one and only path to
/// a pinned admin in these tests. We bypass the OAuth-callback flow
/// because the seed loader cares only about the pin, not how the row
/// got there.
async fn seed_pinned_admin(pool: &PgPool) -> Result<Uuid, Box<dyn std::error::Error>> {
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend, pinned_admin)
          VALUES ($1, 'oidc', TRUE)
          RETURNING id",
        format!("seed-admin-{}", Uuid::new_v4()),
    )
    .fetch_one(pool)
    .await?;
    sqlx::query!(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, 'admin')
          ON CONFLICT DO NOTHING",
        row.id,
    )
    .execute(pool)
    .await?;
    Ok(row.id)
}

/// Path to the workspace `deploy/seeds/mod-policies.yml`. Relative to
/// the integration-test crate root, which is `polaris-backend/`.
fn workspace_seed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../deploy/seeds/mod-policies.yml")
}

#[tokio::test]
async fn first_boot_loads_five_policies() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_seed_idempotent::first_boot_loads_five: docker unreachable");
        return Ok(());
    }
    let pool = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;
    let seed_path = workspace_seed_path();

    let outcome = maybe_seed_policies(&pool, admin, &seed_path).await?;
    assert_eq!(
        outcome,
        SeedOutcome::Loaded { count: 5 },
        "first boot must load exactly five placeholder policies",
    );

    // Every placeholder identifier landed.
    for identifier in [
        "polaris.harassment",
        "polaris.spam",
        "polaris.csam",
        "polaris.impersonation",
        "polaris.copyright",
    ] {
        let row = sqlx::query!(
            r"SELECT identifier, version, human_required_always, autonomy_mode
              FROM mod_policies
              WHERE identifier = $1",
            identifier,
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(row.identifier, identifier);
        assert_eq!(row.version, 1, "{identifier} must be at v1");
        assert_eq!(
            row.autonomy_mode, "manual",
            "{identifier} must default to manual autonomy"
        );
        // Only polaris.csam carries human_required_always=true.
        let expect_human_required = identifier == "polaris.csam";
        assert_eq!(
            row.human_required_always, expect_human_required,
            "{identifier}.human_required_always must be {expect_human_required}",
        );
    }

    // Author attribution: every row charged to the bootstrap admin.
    let attributed: i64 = sqlx::query_scalar!(
        r#"SELECT count(*) AS "c!"
          FROM mod_policies
          WHERE created_by_moderator_id = $1"#,
        admin,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(attributed, 5, "all five rows must attribute to admin");

    Ok(())
}

#[tokio::test]
async fn second_boot_is_noop() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_seed_idempotent::second_boot_is_noop: docker unreachable");
        return Ok(());
    }
    let pool = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;
    let seed_path = workspace_seed_path();

    let first = maybe_seed_policies(&pool, admin, &seed_path).await?;
    assert_eq!(first, SeedOutcome::Loaded { count: 5 });

    let second = maybe_seed_policies(&pool, admin, &seed_path).await?;
    assert_eq!(
        second,
        SeedOutcome::Skipped {
            reason: SkipReason::TableNotEmpty,
        },
        "second call must short-circuit on TableNotEmpty",
    );

    // Row count unchanged — no duplicates were inserted.
    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 5, "second call must not insert duplicates");

    Ok(())
}

#[tokio::test]
async fn corrupted_seed_file_does_not_partial_insert() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_seed_idempotent::corrupted_seed: docker unreachable");
        return Ok(());
    }
    let pool = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;

    // Write a temp seed file that is not parseable YAML.
    let tmp = std::env::temp_dir().join(format!("polaris-bad-seed-{}.yml", Uuid::new_v4()));
    std::fs::write(&tmp, "this: is: not: valid: yaml: [unclosed").unwrap();

    let result = maybe_seed_policies(&pool, admin, &tmp).await;
    assert!(
        matches!(result, Err(SeedError::YamlParseError(_))),
        "expected YamlParseError, got {result:?}",
    );

    // Zero rows committed.
    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 0, "bad YAML must not commit any rows");

    let _ = std::fs::remove_file(&tmp);
    Ok(())
}

#[tokio::test]
async fn missing_seed_file_returns_skipped() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_seed_idempotent::missing_seed_file: docker unreachable");
        return Ok(());
    }
    let pool = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;

    let nonexistent =
        PathBuf::from("/tmp/polaris-no-such-seed-file-").join(Uuid::new_v4().to_string());
    let outcome = maybe_seed_policies(&pool, admin, &nonexistent).await?;
    assert_eq!(
        outcome,
        SeedOutcome::Skipped {
            reason: SkipReason::SeedFileMissing,
        },
        "missing seed file must surface as Skipped/SeedFileMissing",
    );

    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 0, "missing file must commit zero rows");
    Ok(())
}

#[tokio::test]
async fn no_bootstrap_admin_returns_skipped() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP policy_seed_idempotent::no_admin: docker unreachable");
        return Ok(());
    }
    let pool = boot_db().await?;

    // Verify there is no pinned admin to begin with.
    let admin = lookup_bootstrap_admin(&pool).await?;
    assert!(admin.is_none(), "fresh DB must have no pinned admin");

    // run_first_boot_seed must skip cleanly rather than panic / error.
    // Use the env var to force the same workspace seed file the other
    // tests use, so we know the path resolution wouldn't be the cause
    // of a skip.
    // SAFETY: integration test sets a process-wide env var; we restore
    // it on exit. Other tests in this file do not depend on the env
    // var, and integration-test binaries serialise per crate so this
    // does not race other suites.
    unsafe {
        std::env::set_var("POLARIS_POLICY_SEED_PATH", workspace_seed_path());
    }
    let outcome = run_first_boot_seed(&pool).await?;
    unsafe {
        std::env::remove_var("POLARIS_POLICY_SEED_PATH");
    }
    // run_first_boot_seed reuses TableNotEmpty as the skip discriminator
    // when no admin is found; the contract is "outcome is Skipped, zero
    // rows committed", which is what we assert.
    assert!(
        matches!(outcome, SeedOutcome::Skipped { .. }),
        "no-admin path must surface Skipped, got {outcome:?}",
    );

    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 0, "no-admin path must commit zero rows");
    Ok(())
}
