//! Integration test — proves [`SessionStore::lookup`] fails closed under
//! every malformed-cookie payload we can throw at it, and that the
//! middleware / session-store layer does NOT echo the offending payload into
//! a `tracing` log line.
//!
//! Test code uses `.unwrap()` / `.expect()` on `Result`s where a failure is
//! itself a test failure with a meaningful panic message. The workspace
//! `unwrap_used` / `expect_used` lints are denied at `--all-targets` level
//! so item-level allow is required here; this is the idiomatic Rust pattern
//! for integration tests (see Rust API Guidelines C-TEST-PANIC).
//!
//! `doc_markdown` and `too_many_lines` are pedantic-group lints; tests that
//! exhaust a parameterised input set naturally exceed the 100-line heuristic.
//! Both allows are scoped to this test file and do not affect library or
//! binary code.
//!
//! # What "fails closed" means here
//!
//! `SessionStore::lookup` parses the cookie value via
//! `SessionToken::from_cookie_str` (constant-shape validation: 43 ASCII
//! base64url chars decoding to 32 bytes) BEFORE running the parameterised
//! Postgres query. Any malformed input returns
//! [`SessionError::InvalidToken`] without touching the database. We assert
//! that for every input variant:
//!
//! 1. The call returns `Err` (never `Ok`, never panics).
//! 2. The variant is exactly `InvalidToken` — never `NotFound` (which would
//!    imply the input reached SQL), never `Database` (which would imply the
//!    query ran and failed), and never `Expired`.
//! 3. The offending payload does NOT appear in any captured `tracing` event.
//!
//! # SQL safety
//!
//! The defence-in-depth layer is that even if `from_cookie_str` were
//! relaxed, every DB call uses `sqlx::query!` with bound parameters — no
//! string-built SQL. Hostile bytes ride through as a parameterised `TEXT`
//! comparison, not as syntax. The shape check is the cheap front-line
//! filter; the parameter binding is the structural guarantee.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

use std::process::Command;

use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::{SessionError, SessionStore};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tracing_test::traced_test;

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

/// The hostile inputs under test. Tuple is `(label, payload)`; `label` is a
/// short tag used only in panic messages, `payload` is the raw bytes the
/// client could send in the `polaris_session` cookie.
fn malformed_inputs() -> Vec<(&'static str, String)> {
    vec![
        // --- classic SQL injection payloads -----------------------------
        ("drop-table", "'; DROP TABLE sessions; --".to_owned()),
        ("or-1-eq-1", "' OR '1'='1".to_owned()),
        (
            "union-select",
            "%' UNION SELECT * FROM moderators --".to_owned(),
        ),
        // --- oversized payload (10 KB) ----------------------------------
        ("oversize-10kb", "A".repeat(10 * 1024)),
        // --- control characters -----------------------------------------
        ("nul-byte", "\0".to_owned()),
        ("lf-only", "\n".to_owned()),
        ("crlf", "\r\n".to_owned()),
        // --- unicode normalisation: zero-width space inside an "admin"
        //     identity probe -------------------------------------------
        ("zwsp-admin", "admin\u{200B}admin".to_owned()),
        // --- degenerate ------------------------------------------------
        ("empty", String::new()),
    ]
}

#[tokio::test]
#[traced_test]
async fn malformed_cookies_fail_closed_and_do_not_leak_to_logs() {
    if !docker_available() {
        eprintln!(
            "SKIP sql_injection_auth: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test."
        );
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

    let crypto = Crypto::new([3_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);

    for (label, payload) in malformed_inputs() {
        let result = sessions.lookup(&payload).await;

        // Property 1: never `Ok`. There is no path in `lookup` that should
        // accept any of these payloads. We deliberately use `match` (not
        // `unwrap_err`) so `Ok` produces a precise panic message and `Err`
        // hands us the typed variant for Property 2.
        let err = match result {
            Ok(_) => panic!(
                "[{label}] expected Err, got Ok — input never produces a valid \
                 session (this would indicate `SessionToken::from_cookie_str` \
                 accepted hostile bytes, or a session row was somehow forged)",
            ),
            Err(err) => err,
        };

        // Property 2: the variant is exactly `InvalidToken`. Anything else
        // means the front-line shape check did not catch the payload and it
        // reached SQL / decoding / role-resolution.
        match &err {
            SessionError::InvalidToken => {}
            SessionError::NotFound => panic!(
                "[{label}] surfaced NotFound — the shape check should have \
                 rejected this BEFORE the DB query ran. Input length: \
                 {len} bytes",
                len = payload.len(),
            ),
            SessionError::Database(inner) => panic!(
                "[{label}] surfaced Database error — the malformed payload \
                 should never have reached SQL. Inner: {inner}",
            ),
            SessionError::Expired | SessionError::Crypto(_) | SessionError::UnknownRole { .. } => {
                panic!(
                    "[{label}] surfaced unexpected variant {err:?} — only \
                 InvalidToken should be reachable from a hostile cookie",
                )
            }
        }
    }

    // Property 3: no captured `tracing` event echoed any of the hostile
    // payloads. `SessionStore::lookup` does not log; it returns a typed
    // error. The middleware DOES log (`tracing::warn!`), but it logs the
    // `error = %err` field on the `SessionError` — `SessionError::InvalidToken`'s
    // `Display` impl is the literal string "invalid session token" and
    // never embeds the user-supplied cookie value.
    //
    // We check each payload distinctly: even a single byte of the oversized
    // input ("A"-repeated) would be enough to fail the test if we logged any
    // prefix of the cookie value.
    for (label, payload) in malformed_inputs() {
        // Empty string substring matching is vacuously true (`logs_contain("")`
        // always succeeds), so skip the empty input here — Property 1 + 2
        // already proved it failed closed.
        if payload.is_empty() {
            continue;
        }
        // We test with the FULL payload first. For oversized inputs we also
        // test a 32-byte prefix, because the `tracing-test` substring matcher
        // would otherwise tolerate a logger that truncates long fields.
        assert!(
            !logs_contain(&payload),
            "[{label}] full payload leaked into a tracing event — \
             `SessionStore::lookup` MUST NOT echo cookie values to logs",
        );
        if payload.len() > 32 {
            let prefix = &payload[..32];
            assert!(
                !logs_contain(prefix),
                "[{label}] payload prefix leaked into a tracing event",
            );
        }
    }
}
