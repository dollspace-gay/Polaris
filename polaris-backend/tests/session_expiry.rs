//! Integration test — exercises [`SessionStore`] lifecycle behaviour against
//! a real Postgres.
//!
//! Test code uses `.unwrap()` / `.expect()` on `Result`s where a failure
//! is itself a test failure with a meaningful panic message. The workspace
//! `unwrap_used` / `expect_used` lints are denied at `--all-targets` level
//! so item-level allow is required here; this is the idiomatic Rust pattern
//! for integration tests (see Rust API Guidelines C-TEST-PANIC).
//!
//! `doc_markdown` and `too_many_lines` are pedantic-group lints; integration
//! tests written as a single linear scenario naturally exceed the 100-line
//! heuristic. Both allows are scoped to this test file and do not affect
//! library or binary code.
//!
//! Spins up a `testcontainers`-driven Postgres, runs migrations via
//! `db::connect`, then exercises three lifecycle paths on [`SessionStore`]:
//!
//! 1. **Expired**: `expires_at` in the past surfaces as
//!    [`SessionError::Expired`] on `lookup`.
//! 2. **Refresh**: a not-yet-expired session can be rotated; the old token
//!    is invalidated atomically and the new token's `expires_at` is bumped.
//! 3. **Revoke**: a revoked session resolves as
//!    [`SessionError::NotFound`] on the next `lookup`. `revoke` itself is
//!    idempotent — a second call on the same token does NOT error.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

use std::process::Command;
use std::time::Duration;

use chrono::{DateTime, Utc};
use polaris_backend::auth::ModeratorId;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::{SessionError, SessionStore};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors `db_smoke.rs` /
/// `oidc_login_flow.rs` so behaviour is consistent across the suite.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Insert a fresh moderator row directly (the OIDC `upsert_moderator` path
/// is exercised elsewhere; here we want a minimal, in-test fixture so the
/// test scope is the session store alone).
async fn seed_moderator(pool: &PgPool) -> ModeratorId {
    let mid = ModeratorId::new_v4();
    sqlx::query(
        r"INSERT INTO moderators (id, external_id, auth_backend, display_name, last_login_at)
          VALUES ($1, $2, 'oidc', $3, now())",
    )
    .bind(mid.0)
    .bind(format!("test-subject-{}", mid.0))
    .bind(Some("Test Moderator"))
    .execute(pool)
    .await
    .expect("seed moderator insert should succeed");
    mid
}

/// Helper: force a session's `expires_at` into the past by `delta`. Bypasses
/// the `SessionStore` API on purpose — the test needs to simulate the
/// post-TTL state without sleeping for hours.
async fn expire_session(pool: &PgPool, session_id: &str, delta: Duration) {
    let past = Utc::now()
        - chrono::Duration::from_std(delta).expect("delta within chrono::Duration range");
    sqlx::query(r"UPDATE sessions SET expires_at = $1 WHERE id = $2")
        .bind(past)
        .bind(session_id)
        .execute(pool)
        .await
        .expect("expire_session UPDATE should succeed");
}

/// Helper: read the current `expires_at` for a session row.
async fn read_expires_at(pool: &PgPool, session_id: &str) -> DateTime<Utc> {
    let row: (DateTime<Utc>,) = sqlx::query_as(r"SELECT expires_at FROM sessions WHERE id = $1")
        .bind(session_id)
        .fetch_one(pool)
        .await
        .expect("read_expires_at SELECT should succeed");
    row.0
}

#[tokio::test]
async fn expired_session_lookup_returns_expired_variant() {
    if !docker_available() {
        eprintln!("SKIP session_expiry::expired_session_lookup: docker daemon not reachable");
        return;
    }

    // Pin Postgres 16-alpine: testcontainers-modules 0.15 still defaults to
    // 11-alpine, which lacks the built-in `gen_random_uuid()` the auth
    // migration relies on. 16 ships with `gen_random_uuid()` in core (it
    // graduated out of `pgcrypto` in PG 13) and is a current LTS line.
    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("Postgres container should start");
    let host_port = pg
        .get_host_port_ipv4(5432)
        .await
        .expect("container port mapping should resolve");
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.expect("db::connect should succeed");
    let pool = database.pool().clone();

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let moderator_id = seed_moderator(&pool).await;

    let new_session = sessions
        .create(moderator_id, b"refresh-token-plain")
        .await
        .expect("sessions.create should succeed");
    let token = new_session.token.as_str().to_owned();

    // Move the row's expiry strictly into the past, then lookup.
    expire_session(&pool, &token, Duration::from_secs(60 * 60)).await;
    let err = sessions
        .lookup(&token)
        .await
        .expect_err("lookup on an expired session should return Err");
    assert!(
        matches!(err, SessionError::Expired),
        "expected SessionError::Expired, got {err:?}"
    );
}

#[tokio::test]
async fn refresh_rotates_token_and_bumps_expiry() {
    if !docker_available() {
        eprintln!("SKIP session_expiry::refresh_rotates_token: docker daemon not reachable");
        return;
    }

    // Pin Postgres 16-alpine: testcontainers-modules 0.15 still defaults to
    // 11-alpine, which lacks the built-in `gen_random_uuid()` the auth
    // migration relies on. 16 ships with `gen_random_uuid()` in core (it
    // graduated out of `pgcrypto` in PG 13) and is a current LTS line.
    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("Postgres container should start");
    let host_port = pg
        .get_host_port_ipv4(5432)
        .await
        .expect("container port mapping should resolve");
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.expect("db::connect should succeed");
    let pool = database.pool().clone();

    // 60-minute TTL: long enough we are well clear of the expiry window
    // during the test, but the helper still lets us reason about which row
    // is "fresh" vs. "old" by comparing absolute expires_at values.
    let crypto = Crypto::new([8_u8; 32]);
    let sessions = SessionStore::with_ttl(pool.clone(), crypto, Duration::from_secs(60 * 60));
    let moderator_id = seed_moderator(&pool).await;

    // Mint an initial session, capture its absolute expiry.
    let initial = sessions
        .create(moderator_id, b"initial-refresh-token-plain")
        .await
        .expect("initial sessions.create should succeed");
    let initial_token = initial.token.as_str().to_owned();
    let initial_expiry = initial.expires_at;
    // Sanity: row should be readable and not yet expired.
    let stored_initial = read_expires_at(&pool, &initial_token).await;
    assert_eq!(
        stored_initial.timestamp_millis(),
        initial_expiry.timestamp_millis(),
        "create() and the row's stored expires_at must agree",
    );

    // Force a measurable time gap so the post-refresh `expires_at` is
    // strictly greater than the initial one.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let refreshed = sessions
        .refresh(&initial_token)
        .await
        .expect("sessions.refresh should succeed on a non-expired token");
    let refreshed_token = refreshed.token.as_str().to_owned();

    // 1. The new token is distinct from the old (rotation is the point).
    assert_ne!(
        initial_token, refreshed_token,
        "refresh() must mint a fresh token",
    );

    // 2. The new expires_at is strictly later than the old one.
    assert!(
        refreshed.expires_at > initial_expiry,
        "refresh() must bump expires_at (was {initial_expiry}, now {})",
        refreshed.expires_at,
    );

    // 3. The OLD token row was deleted — lookup must report NotFound, not
    //    Expired (the row simply does not exist anymore).
    let old_err = sessions
        .lookup(&initial_token)
        .await
        .expect_err("old token must no longer resolve");
    assert!(
        matches!(old_err, SessionError::NotFound),
        "expected NotFound for the rotated-out token, got {old_err:?}",
    );

    // 4. The NEW token resolves to the same moderator.
    let ctx = sessions
        .lookup(&refreshed_token)
        .await
        .expect("new token must resolve");
    assert_eq!(ctx.moderator_id, moderator_id);
}

#[tokio::test]
async fn revoked_session_lookup_returns_not_found() {
    if !docker_available() {
        eprintln!("SKIP session_expiry::revoked_session_lookup: docker daemon not reachable");
        return;
    }

    // Pin Postgres 16-alpine: testcontainers-modules 0.15 still defaults to
    // 11-alpine, which lacks the built-in `gen_random_uuid()` the auth
    // migration relies on. 16 ships with `gen_random_uuid()` in core (it
    // graduated out of `pgcrypto` in PG 13) and is a current LTS line.
    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("Postgres container should start");
    let host_port = pg
        .get_host_port_ipv4(5432)
        .await
        .expect("container port mapping should resolve");
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.expect("db::connect should succeed");
    let pool = database.pool().clone();

    let crypto = Crypto::new([9_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let moderator_id = seed_moderator(&pool).await;

    let new_session = sessions
        .create(moderator_id, b"refresh-token-plain")
        .await
        .expect("sessions.create should succeed");
    let token = new_session.token.as_str().to_owned();

    // Sanity: lookup works before revocation.
    sessions
        .lookup(&token)
        .await
        .expect("lookup should succeed pre-revocation");

    sessions
        .revoke(&token)
        .await
        .expect("revoke should succeed");

    // Post-revoke lookup must surface NotFound, not Expired and not Database.
    let err = sessions
        .lookup(&token)
        .await
        .expect_err("revoked-session lookup should error");
    assert!(
        matches!(err, SessionError::NotFound),
        "expected SessionError::NotFound after revoke, got {err:?}",
    );

    // Idempotence: revoking again on the same (now-deleted) token must NOT
    // error — the cookie is already invalid, which is the desired end-state.
    sessions
        .revoke(&token)
        .await
        .expect("revoke must be idempotent on a missing row");
}

/// Compile-time use of `Uuid` to keep the import live even when the
/// `seed_moderator` helper is the only consumer — keeps `cargo clippy`
/// happy if the helper is ever inlined.
const _: fn() = || {
    let _: Option<Uuid> = None;
};
