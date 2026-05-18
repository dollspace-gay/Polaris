//! WB-6 (#228) integration tests for the `polaris-setup seed-policies`
//! subcommand. Implements REQ-E3 from `.design/mod-policy-workbook.md`:
//! the post-install YAML import path must
//!
//! * insert net-new identifiers as v1 attributed to the bootstrap admin,
//! * skip already-present identifiers without `--replace`,
//! * amend already-present identifiers with `--replace` (writing a
//!   successor version),
//! * refuse to import when an incoming `human_required_always = TRUE`
//!   entry collides with a live row in `autonomy_mode != 'manual'`,
//! * exit `1` on validation failure (YAML parse, hard-block) and `2`
//!   on IO failure (missing file, DB unreachable).
//!
//! Each test spawns the compiled binary via `std::process::Command`,
//! reading the resolved path from `env!("CARGO_BIN_EXE_polaris-setup")`
//! so the integration test runs the same code path the operator will.
//! Tests boot their own testcontainers Postgres 16-alpine so the DB
//! state is hermetic; the harness mirrors `tests/policy_seed_idempotent.rs`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::path::PathBuf;
use std::process::{Command, Stdio};

use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::seed::mod_policies::maybe_seed_policies;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

/// Path to the compiled `polaris-setup` binary. Cargo materialises
/// this env var for integration tests of any bin target in the same
/// crate, so we never have to hand-resolve `target/debug/...`.
const POLARIS_SETUP_BIN: &str = env!("CARGO_BIN_EXE_polaris-setup");

/// Probe for a working Docker daemon. Mirrors `case_api.rs`.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + return the (`url`, `pool`)
/// pair. The `url` is shaped for the binary's `DATABASE_URL` env so we
/// don't re-derive it inside each test.
async fn boot_db() -> Result<(String, PgPool), Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let url = format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres");
    let cfg = DbConfig {
        url: url.clone(),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();
    // Keep the container alive for the duration of the test process —
    // `std::mem::forget` is the testcontainers-recommended pattern for
    // integration tests that own a single container per test.
    std::mem::forget(container);
    Ok((url, pool))
}

/// Insert a fresh moderator and pin them as the bootstrap admin so
/// the seed-policies subcommand has an actor to attribute its
/// inserts / amendments to.
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

/// Path to the canonical seed file under the workspace.
fn workspace_seed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../deploy/seeds/mod-policies.yml")
}

/// Spawn `polaris-setup seed-policies` with the supplied arguments
/// and return the exit code + stdout + stderr. Always sets
/// `DATABASE_URL` so the binary can connect to the test DB.
fn run_seed_subcommand(
    database_url: &str,
    file: &PathBuf,
    replace: bool,
) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(POLARIS_SETUP_BIN);
    cmd.arg("seed-policies")
        .arg("--file")
        .arg(file)
        .env("DATABASE_URL", database_url);
    if replace {
        cmd.arg("--replace");
    }
    let out = cmd.output().expect("spawn polaris-setup binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out.status.code(), stdout, stderr)
}

#[tokio::test]
async fn import_into_fresh_db_inserts_all() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP seed_policies_subcommand::import_into_fresh_db: docker unreachable");
        return Ok(());
    }
    let (db_url, pool) = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;

    let seed = workspace_seed_path();
    let (code, _stdout, stderr) = run_seed_subcommand(&db_url, &seed, false);
    assert_eq!(
        code,
        Some(0),
        "expected exit 0, got {code:?}; stderr=\n{stderr}"
    );

    // Every placeholder identifier landed as v1.
    for identifier in [
        "polaris.harassment",
        "polaris.spam",
        "polaris.csam",
        "polaris.impersonation",
        "polaris.copyright",
    ] {
        let row = sqlx::query!(
            r"SELECT version, created_by_moderator_id
              FROM mod_policies
              WHERE identifier = $1 AND effective_until IS NULL",
            identifier,
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(row.version, 1, "{identifier} must be v1");
        assert_eq!(
            row.created_by_moderator_id, admin,
            "{identifier} must attribute to bootstrap admin",
        );
    }

    // Total row count == 5 (no duplicate inserts).
    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 5, "five rows total after fresh import");
    Ok(())
}

#[tokio::test]
async fn import_without_replace_skips_existing() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP seed_policies_subcommand::without_replace: docker unreachable");
        return Ok(());
    }
    let (db_url, pool) = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;

    // Pre-seed via the WB-5 first-boot loader so the table arrives at
    // the same state a freshly-deployed Polaris would have.
    let seed = workspace_seed_path();
    let outcome = maybe_seed_policies(&pool, admin, &seed).await?;
    assert!(
        matches!(
            outcome,
            polaris_backend::seed::mod_policies::SeedOutcome::Loaded { count: 5 }
        ),
        "pre-seed must load 5 rows, got {outcome:?}",
    );

    let total_before: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total_before, 5);

    // Run the subcommand without --replace. Every identifier should
    // be skipped; the row count must not change.
    let (code, _stdout, stderr) = run_seed_subcommand(&db_url, &seed, false);
    assert_eq!(code, Some(0), "expected exit 0; stderr=\n{stderr}");

    let total_after: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(
        total_after, total_before,
        "no-replace import must not add or amend rows",
    );

    // Every identifier should still be at v1 (no successor versions
    // created).
    for identifier in [
        "polaris.harassment",
        "polaris.spam",
        "polaris.csam",
        "polaris.impersonation",
        "polaris.copyright",
    ] {
        let row = sqlx::query!(
            r"SELECT version
              FROM mod_policies
              WHERE identifier = $1 AND effective_until IS NULL",
            identifier,
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(row.version, 1, "{identifier} must still be v1");
    }
    Ok(())
}

#[tokio::test]
async fn import_with_replace_amends_existing() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP seed_policies_subcommand::with_replace: docker unreachable");
        return Ok(());
    }
    let (db_url, pool) = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;

    let seed = workspace_seed_path();
    // Pre-seed via WB-5's first-boot path → five v1 rows.
    let _ = maybe_seed_policies(&pool, admin, &seed).await?;

    let (code, _stdout, stderr) = run_seed_subcommand(&db_url, &seed, true);
    assert_eq!(code, Some(0), "expected exit 0; stderr=\n{stderr}");

    // Every identifier should now have a v2 row that is current, and
    // a v1 row whose `effective_until` is set.
    for identifier in [
        "polaris.harassment",
        "polaris.spam",
        "polaris.csam",
        "polaris.impersonation",
        "polaris.copyright",
    ] {
        let current = sqlx::query!(
            r"SELECT version, change_summary
              FROM mod_policies
              WHERE identifier = $1 AND effective_until IS NULL",
            identifier,
        )
        .fetch_one(&pool)
        .await?;
        assert_eq!(
            current.version, 2,
            "{identifier} current must be v2 after --replace"
        );
        let summary = current
            .change_summary
            .as_deref()
            .expect("amend must set change_summary");
        assert!(
            summary.starts_with("Imported from "),
            "{identifier} change_summary must start with 'Imported from ', got {summary:?}",
        );

        let v1 = sqlx::query!(
            r#"SELECT effective_until AS "eu?"
               FROM mod_policies
               WHERE identifier = $1 AND version = 1"#,
            identifier,
        )
        .fetch_one(&pool)
        .await?;
        assert!(
            v1.eu.is_some(),
            "{identifier} v1 must have effective_until set after amend",
        );
    }

    // Total row count must now be exactly 10 (5 v1 tombstones + 5 v2
    // currents); the seed-policies path must not delete history.
    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 10, "amend path must preserve v1 rows as history");
    Ok(())
}

#[tokio::test]
async fn human_required_always_with_autonomous_live_state_aborts()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP seed_policies_subcommand::hard_block: docker unreachable");
        return Ok(());
    }
    let (db_url, pool) = boot_db().await?;
    let admin = seed_pinned_admin(&pool).await?;

    // Pre-seed via WB-5: polaris.csam lands with
    // human_required_always = TRUE, autonomy_mode = manual.
    let seed = workspace_seed_path();
    let _ = maybe_seed_policies(&pool, admin, &seed).await?;

    // Manually flip polaris.csam to autonomy_mode = autonomous via
    // raw SQL — this bypasses the WB-7 enforcement layer, which is
    // exactly the scenario the seed-policies safety scan defends
    // against. The DB-level CHECK does not forbid this directly
    // because the design layers the floor at the API surface; the
    // database stays a plain key/value store so the import-time
    // safety scan is the right place to catch it.
    sqlx::query!(
        r"UPDATE mod_policies
          SET autonomy_mode = 'autonomous'
          WHERE identifier = 'polaris.csam' AND effective_until IS NULL",
    )
    .execute(&pool)
    .await?;

    // Confirm the precondition: csam is now autonomous in the DB.
    let pre = sqlx::query!(
        r"SELECT autonomy_mode FROM mod_policies
          WHERE identifier = 'polaris.csam' AND effective_until IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(pre.autonomy_mode, "autonomous");

    // Run the subcommand with --replace. The seed file marks csam
    // human_required_always = TRUE; the live state is autonomous;
    // the hard-block scan must abort the import.
    let (code, _stdout, stderr) = run_seed_subcommand(&db_url, &seed, true);
    assert_eq!(
        code,
        Some(1),
        "hard-block must exit 1 (validation failure); stderr=\n{stderr}",
    );
    assert!(
        stderr.contains("polaris.csam"),
        "stderr must name the offending identifier; got {stderr}",
    );
    assert!(
        stderr.contains("human_required_always") || stderr.contains("autonomy_mode"),
        "stderr must explain the autonomy mismatch; got {stderr}",
    );

    // No rows mutated — the v2 amend must never have run.
    let csam_version: i32 = sqlx::query_scalar!(
        r"SELECT version FROM mod_policies
          WHERE identifier = 'polaris.csam' AND effective_until IS NULL",
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(
        csam_version, 1,
        "hard-block must not have written a v2 (current row still v1)",
    );

    // And no OTHER policies got mutated either (transactional rollback).
    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 5, "hard-block path must not insert any new rows");
    Ok(())
}

#[tokio::test]
async fn bad_yaml_file_exits_1() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP seed_policies_subcommand::bad_yaml: docker unreachable");
        return Ok(());
    }
    let (db_url, pool) = boot_db().await?;
    let _admin = seed_pinned_admin(&pool).await?;

    let bad = std::env::temp_dir().join(format!("polaris-bad-seed-{}.yml", Uuid::new_v4()));
    std::fs::write(&bad, "this: is: not: valid: yaml: [unclosed").unwrap();

    let (code, _stdout, stderr) = run_seed_subcommand(&db_url, &bad, false);
    assert_eq!(
        code,
        Some(1),
        "malformed YAML must exit 1 (validation failure); stderr=\n{stderr}",
    );

    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 0, "bad YAML must not commit any rows");

    let _ = std::fs::remove_file(&bad);
    Ok(())
}

#[tokio::test]
async fn missing_file_exits_2() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP seed_policies_subcommand::missing_file: docker unreachable");
        return Ok(());
    }
    let (db_url, pool) = boot_db().await?;
    let _admin = seed_pinned_admin(&pool).await?;

    let nonexistent = PathBuf::from(format!("/tmp/polaris-no-such-seed-{}.yml", Uuid::new_v4()));
    let (code, _stdout, stderr) = run_seed_subcommand(&db_url, &nonexistent, false);
    assert_eq!(
        code,
        Some(2),
        "missing file must exit 2 (IO failure); stderr=\n{stderr}",
    );

    let total: i64 = sqlx::query_scalar!(r#"SELECT count(*) AS "c!" FROM mod_policies"#)
        .fetch_one(&pool)
        .await?;
    assert_eq!(total, 0, "missing file must commit zero rows");
    Ok(())
}
