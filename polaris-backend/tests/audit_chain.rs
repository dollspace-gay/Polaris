//! Hash-chained audit-log integration tests (issue #35; design.md §6 + §9).
//!
//! Drives the full `audit_log` table through testcontainers Postgres
//! 16-alpine + the production migrations. Asserts the seven invariants
//! the chain depends on:
//!
//! 1. **Genesis row** — the first `record` inserts seq=1 with a 32-byte
//!    zero `prev_hash`.
//! 2. **Chain extension** — ten sequential `record` calls produce a
//!    cleanly-verifiable chain (`verify_chain` returns `Ok(10)`).
//! 3. **Tamper detection (row-level)** — direct `UPDATE` / `DELETE` on
//!    `audit_log` is rejected by the append-only trigger with SQLSTATE
//!    `P0001`.
//! 4. **Chain-break detection at INSERT** — a raw `INSERT` whose
//!    `prev_hash` disagrees with the committed head is rejected by the
//!    chain-check trigger with SQLSTATE `P0001`.
//! 5. **Long chain** — 1000 sequential records verify in <5s (and the
//!    test prints the actual wall time for evidence).
//! 6. **Caller-tx atomicity** — `record()` inside a caller transaction
//!    that ROLLBACKs leaves zero rows; no orphan audit rows.
//! 7. **Attestation worker** — one `attest_once` call writes a key
//!    under `audit-attestation/` to the configured [`BlobStore`] whose
//!    body is exactly `{seq}\n{this_hash_hex}\n`.
//!
//! All seven tests skip cleanly when the Docker daemon is not
//! reachable, matching the convention across the rest of `tests/`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use polaris_backend::audit::{AttestationWorker, AuditEvent, AuditLog, verify_chain};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::evidence::{BlobStore as _, InMemoryBlobStore};
use sqlx::Row as _;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build a fresh testcontainers Postgres 16-alpine + run every
/// production migration through the same `db::connect` path the
/// binary uses. Returns the migrated pool.
async fn fresh_pool() -> Result<
    (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        sqlx::PgPool,
    ),
    Box<dyn std::error::Error>,
> {
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
    Ok((container, pool))
}

fn sample_event(actor: &str, kind: &str, n: u32) -> AuditEvent {
    AuditEvent {
        actor: actor.to_owned(),
        kind: kind.to_owned(),
        payload: serde_json::json!({
            "seq_in_test": n,
            "action_id": "00000000-0000-0000-0000-000000000000",
            "kind": "label",
        }),
    }
}

// ── 1. Genesis row ──────────────────────────────────────────────────

#[tokio::test]
async fn genesis_row_has_zero_prev_hash() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP audit_chain genesis: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    let mut tx = pool.begin().await?;
    let seq = AuditLog::record(&mut tx, sample_event("system", "test.genesis", 1)).await?;
    tx.commit().await?;

    assert_eq!(seq, 1, "genesis row must have seq = 1");

    let row = sqlx::query("SELECT seq, prev_hash FROM audit_log WHERE seq = 1")
        .fetch_one(&pool)
        .await?;
    let prev_hash: Vec<u8> = row.try_get("prev_hash")?;
    assert_eq!(prev_hash.len(), 32, "prev_hash must be 32 bytes");
    assert!(
        prev_hash.iter().all(|&b| b == 0),
        "genesis prev_hash must be 32 zero bytes, got {prev_hash:?}",
    );

    // verify_chain on a one-row chain must report seq=1 clean.
    let head = verify_chain(&pool).await?;
    assert_eq!(head, 1);

    Ok(())
}

// ── 2. Chain extension (10 events) ──────────────────────────────────

#[tokio::test]
async fn chain_extension_ten_events_verify_clean() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP audit_chain extension: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    for i in 1..=10u32 {
        let mut tx = pool.begin().await?;
        let seq =
            AuditLog::record(&mut tx, sample_event("moderator-a", "action.commit", i)).await?;
        tx.commit().await?;
        assert_eq!(seq, i64::from(i), "seq must equal insert ordinal");
    }

    let head = verify_chain(&pool).await?;
    assert_eq!(head, 10);

    Ok(())
}

// ── 3. Tamper detection (row-level): UPDATE + DELETE rejected ───────

#[tokio::test]
async fn row_level_update_and_delete_rejected_by_trigger() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!("SKIP audit_chain row-level tamper: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    // Seed 6 rows so seq=5 is a real, non-edge row.
    for i in 1..=6u32 {
        let mut tx = pool.begin().await?;
        AuditLog::record(&mut tx, sample_event("system", "seed", i)).await?;
        tx.commit().await?;
    }

    // ── UPDATE rejected ──────────────────────────────────────────────
    let update_err = sqlx::query(
        "UPDATE audit_log SET this_hash = decode(repeat('00', 32), 'hex') WHERE seq = 5",
    )
    .execute(&pool)
    .await
    .expect_err("UPDATE on audit_log must be rejected by the trigger");

    match &update_err {
        sqlx::Error::Database(db_err) => {
            let code = db_err
                .code()
                .map(std::borrow::Cow::into_owned)
                .expect("trigger error must carry a SQLSTATE");
            assert_eq!(
                code, "P0001",
                "UPDATE rejection must surface as P0001, got {code}: {db_err}"
            );
            assert!(
                db_err.message().to_lowercase().contains("append-only"),
                "trigger message should mention append-only; got: {}",
                db_err.message()
            );
        }
        other => panic!("expected sqlx::Error::Database for UPDATE, got: {other:?}"),
    }

    // ── DELETE rejected ──────────────────────────────────────────────
    let delete_err = sqlx::query("DELETE FROM audit_log WHERE seq = 5")
        .execute(&pool)
        .await
        .expect_err("DELETE on audit_log must be rejected by the trigger");

    match &delete_err {
        sqlx::Error::Database(db_err) => {
            let code = db_err
                .code()
                .map(std::borrow::Cow::into_owned)
                .expect("trigger error must carry a SQLSTATE");
            assert_eq!(
                code, "P0001",
                "DELETE rejection must surface as P0001, got {code}: {db_err}"
            );
            assert!(
                db_err.message().to_lowercase().contains("append-only"),
                "trigger message should mention append-only; got: {}",
                db_err.message()
            );
        }
        other => panic!("expected sqlx::Error::Database for DELETE, got: {other:?}"),
    }

    // Chain is still clean — nothing actually changed.
    let head = verify_chain(&pool).await?;
    assert_eq!(head, 6);

    Ok(())
}

// ── 4. Chain-break detection at INSERT ──────────────────────────────

#[tokio::test]
async fn raw_insert_with_wrong_prev_hash_rejected_by_chain_check()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP audit_chain raw-insert: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    // Seed 10 rows so the next legitimate seq would be 11.
    for i in 1..=10u32 {
        let mut tx = pool.begin().await?;
        AuditLog::record(&mut tx, sample_event("system", "seed", i)).await?;
        tx.commit().await?;
    }

    // Construct a row whose prev_hash is 32 bytes of 0xFF — guaranteed
    // not to be the head's this_hash (the head's hash is SHA-256 of a
    // real preimage, never all-FF).
    let wrong_prev = vec![0xFFu8; 32];
    let some_this_hash = vec![0xAAu8; 32];

    let err = sqlx::query(
        "INSERT INTO audit_log (seq, ts, actor, kind, payload, prev_hash, this_hash) \
         VALUES (11, now(), 'attacker', 'forged', '{}'::jsonb, $1, $2)",
    )
    .bind(&wrong_prev)
    .bind(&some_this_hash)
    .execute(&pool)
    .await
    .expect_err("INSERT skipping AuditLog::record with wrong prev_hash must be rejected");

    match &err {
        sqlx::Error::Database(db_err) => {
            let code = db_err
                .code()
                .map(std::borrow::Cow::into_owned)
                .expect("chain-check error must carry a SQLSTATE");
            assert_eq!(
                code, "P0001",
                "chain-check rejection must surface as P0001, got {code}: {db_err}"
            );
            assert!(
                db_err.message().to_lowercase().contains("chain"),
                "trigger message should mention chain; got: {}",
                db_err.message()
            );
        }
        other => panic!("expected sqlx::Error::Database, got: {other:?}"),
    }

    // Chain is unchanged at 10.
    let head = verify_chain(&pool).await?;
    assert_eq!(head, 10);

    Ok(())
}

// ── 5. Long-chain (1000 events) ─────────────────────────────────────

#[tokio::test]
async fn long_chain_thousand_events_verify_within_five_seconds()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP audit_chain long-chain: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    // Insert 1000 sequential rows. We do not measure the insert phase —
    // the spec only requires the verify walk be under 5s.
    for i in 1..=1000u32 {
        let mut tx = pool.begin().await?;
        AuditLog::record(&mut tx, sample_event("system", "bulk", i)).await?;
        tx.commit().await?;
    }

    let started = Instant::now();
    let head = verify_chain(&pool).await?;
    let elapsed = started.elapsed();

    assert_eq!(head, 1000, "verify_chain must walk all 1000 rows");
    println!("audit_chain long-chain (1000 events) verify walk: {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "verify_chain over 1000 rows must finish in <5s, took {elapsed:?}",
    );

    Ok(())
}

// ── 5b. 100k-event perf test (gated behind `#[ignore]`) ─────────────

/// Stress the verifier on a 100 000-event chain.
///
/// Marked `#[ignore]` so it is excluded from default `cargo test`
/// runs; invoke with
/// `cargo test -p polaris-backend --test audit_chain -- --ignored
/// long_chain_hundred_thousand` to execute.
///
/// # Strategy
///
/// Inserting 100 000 audit rows naively (one transaction per row)
/// would issue 100 000 fsync barriers and dominate wall time. We batch
/// in chunks of 1000 records per transaction, which preserves the
/// chain-correctness contract (every `record` still reads the head and
/// computes a fresh hash; the chain-check trigger still fires inside
/// the batch) while amortising commit overhead. The assertion is on
/// the **verify** walk time, not the insert time — verification is
/// the latency-sensitive operation an auditor cares about.
#[tokio::test]
#[ignore = "perf test — run with --ignored. Takes ~30s wall."]
async fn long_chain_hundred_thousand_events_verify_within_thirty_seconds()
-> Result<(), Box<dyn std::error::Error>> {
    const TOTAL_EVENTS: u32 = 100_000;
    const BATCH_SIZE: u32 = 1_000;

    if !docker_available() {
        println!("SKIP audit_chain 100k: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    let insert_started = Instant::now();
    let mut next: u32 = 1;
    while next <= TOTAL_EVENTS {
        let batch_end = (next + BATCH_SIZE - 1).min(TOTAL_EVENTS);
        let mut tx = pool.begin().await?;
        for i in next..=batch_end {
            AuditLog::record(&mut tx, sample_event("system", "bulk100k", i)).await?;
        }
        tx.commit().await?;
        next = batch_end + 1;
    }
    let insert_elapsed = insert_started.elapsed();
    println!(
        "audit_chain 100k events inserted in {insert_elapsed:?} \
         (batched {BATCH_SIZE} per tx)"
    );

    let verify_started = Instant::now();
    let head = verify_chain(&pool).await?;
    let verify_elapsed = verify_started.elapsed();

    assert_eq!(
        head,
        i64::from(TOTAL_EVENTS),
        "verify_chain must walk all 100k rows"
    );
    println!("audit_chain 100k events verify walk: {verify_elapsed:?}");
    assert!(
        verify_elapsed < Duration::from_secs(30),
        "verify_chain over 100k rows must finish in <30s, took {verify_elapsed:?}",
    );

    Ok(())
}

// ── 6. Atomic with caller tx — ROLLBACK rolls back the audit row ────

#[tokio::test]
async fn record_inside_caller_tx_rolls_back_with_caller() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!("SKIP audit_chain rollback: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    {
        let mut tx = pool.begin().await?;
        let _seq = AuditLog::record(&mut tx, sample_event("system", "will.rollback", 1)).await?;
        // Explicit rollback — `tx` is dropped without `commit`.
        tx.rollback().await?;
    }

    let count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM audit_log")
        .fetch_one(&pool)
        .await?
        .try_get("cnt")?;
    assert_eq!(
        count, 0,
        "rolled-back caller transaction must leave audit_log empty (no orphans), got {count}",
    );

    // And verify_chain agrees the chain is empty.
    let head = verify_chain(&pool).await?;
    assert_eq!(head, 0, "verify_chain on empty chain must report head 0");

    Ok(())
}

// ── 7. Attestation worker single-tick ───────────────────────────────

#[tokio::test]
async fn attestation_worker_tick_writes_head_to_blob_store()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP audit_chain attestation: docker daemon not reachable.");
        return Ok(());
    }
    let (_container, pool) = fresh_pool().await?;

    // Seed 3 rows so the chain has a non-trivial head to attest.
    let mut last_seq: i64 = 0;
    for i in 1..=3u32 {
        let mut tx = pool.begin().await?;
        last_seq = AuditLog::record(&mut tx, sample_event("system", "to.attest", i)).await?;
        tx.commit().await?;
    }
    assert_eq!(last_seq, 3);

    let blob_store = Arc::new(InMemoryBlobStore::new());
    let worker = AttestationWorker::new(
        pool.clone(),
        blob_store.clone() as Arc<dyn polaris_backend::evidence::BlobStore>,
        Duration::from_secs(60), // irrelevant: we drive a single tick
    );

    let attested = worker
        .attest_once()
        .await?
        .expect("non-empty chain must yield an attestation tick");
    let (seq, hash_hex) = attested;
    assert_eq!(seq, 3);
    assert_eq!(hash_hex.len(), 64, "SHA-256 hex must be 64 chars");

    // Exactly one blob was written, and its key is under
    // `audit-attestation/`. The exact suffix is the worker's
    // `Utc::now()` at tick time at microsecond precision — we cannot
    // reproduce it without enumeration, so we issue a second
    // `attest_once` and assert that:
    //   (a) a *second* blob is now present (key strictly distinct),
    //   (b) both keys begin with `audit-attestation/` and end `.txt`,
    //   (c) the body of *each* blob is exactly
    //       `{seq}\n{this_hash_hex}\n` for the chain head at the
    //       moment of its write.
    //
    // To enumerate the keys we momentarily downcast through the
    // concrete `InMemoryBlobStore` we retained — the production trait
    // intentionally omits `list()`; the test reaches past the trait
    // only to enumerate inserted keys.
    assert_eq!(blob_store.len().await, 1);

    // Tick again; chain head still seq=3 so the body is identical, but
    // the key timestamp differs.
    let attested2 = worker
        .attest_once()
        .await?
        .expect("second tick must succeed");
    assert_eq!(attested2.0, 3);
    assert_eq!(attested2.1, hash_hex);
    assert_eq!(blob_store.len().await, 2, "two ticks must yield two keys");

    let keys = blob_store.snapshot_keys().await;
    assert_eq!(keys.len(), 2);
    for key in &keys {
        // Use `Path::extension` to satisfy clippy's case-sensitive
        // file-extension lint — equivalent to `key.ends_with(".txt")`
        // since we generate the keys ourselves.
        let key_path = std::path::Path::new(key);
        let has_txt_ext = key_path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("txt"));
        assert!(
            key.starts_with("audit-attestation/") && has_txt_ext,
            "every attested key must match the documented shape, got {key}",
        );
        let body = blob_store
            .get(key)
            .await?
            .expect("blob must exist at enumerated key");
        let body_str = std::str::from_utf8(&body).expect("attestation body must be UTF-8");
        let expected_body = format!("{seq}\n{hash_hex}\n");
        assert_eq!(
            body_str, expected_body,
            "attestation body must be exactly `{{seq}}\\n{{this_hash_hex}}\\n`",
        );
    }

    Ok(())
}
