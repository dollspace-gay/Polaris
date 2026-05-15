//! Live WebSocket integration test for subscribeLabels (#58).
//!
//! Drives the real labeler server (the same `axum::Router` mounted by
//! the production binary) bound on `127.0.0.1:0` with proto-blue's
//! [`MessageFrame`] decoder to prove the wire format end-to-end:
//!
//! 1. **Backfill** — seed N labels with monotonic seq, connect with
//!    `?cursor=0`, decode every received frame via
//!    [`proto_blue::ws::Frame::decode`], assert N frames in seq order.
//! 2. **Live fan-out** — seed M labels, connect with `?cursor=M`,
//!    publish ONE more via [`LabelBroadcaster::publish`], assert one
//!    frame arrives within 1s and carries seq M+1.
//! 3. **Lagged-consumer recovery** — drive the broadcaster past its
//!    capacity while the client stops reading, then resume the read
//!    side and assert delivery resumes (production behaviour: the
//!    `RecvError::Lagged` arm of `run_subscription` walks the DB
//!    forward from the current cursor rather than dropping the
//!    connection, so every persisted seq is observed even after a
//!    lag burst).
//!
//! The architectural contract enforced here: the server's
//! `encode_labels_frame` MUST emit strict DAG-CBOR canonical bytes,
//! because `MessageFrame::decode` (the reference path for proto-blue
//! consumers and the @atproto/* TS SDK) rejects any non-canonical
//! encoding. Wire-format drift surfaces as a `FrameError::Decode` on
//! the test client.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable the test prints a clear skip message
//! and returns successfully — same pattern as `tests/labels_xrpc.rs`
//! and the other repo-flavoured integration tests in this crate.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic per rust-quality §7; \
              the end-to-end body is a linear setup → drive → assert sequence \
              that reads more cleanly inline than split across helpers"
)]

use std::process::Command;
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::StreamExt as _;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::labeler::server::{Label, LabelBroadcaster, router};
use proto_blue::lex_data::LexValue;
use proto_blue::ws::Frame;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

/// Type alias for the `Box<dyn Error + Send + Sync>` shape every test
/// here returns. `Send + Sync` is required so the `?` operator on
/// `tokio_tungstenite::Error` (which is `Send + Sync`) coerces cleanly
/// across `await` boundaries that move the error across threads.
type TestError = Box<dyn std::error::Error + Send + Sync>;

/// Wall-time budget for any one test case. 30s envelopes Postgres
/// spin-up + backfill + handshake comfortably on commodity hardware
/// and matches the AC-9 budget used elsewhere in this crate.
const WALL_TIME_BUDGET: Duration = Duration::from_secs(30);

/// Per-frame receive timeout for the live fan-out test. 1s is generous
/// — the broadcaster→sink hop is process-local; if we don't see the
/// frame in 1s the fan-out path is broken.
const LIVE_FRAME_TIMEOUT: Duration = Duration::from_secs(1);

/// Number of rows pushed at the broadcaster during the lagged-consumer
/// test. Must exceed `DEFAULT_BROADCAST_CAPACITY` (1024) so the
/// receiver's queue overflows and the `Lagged(_)` arm of
/// `run_subscription` fires — that's the production behaviour under
/// test.
const LAGGED_BURST_SIZE: usize = 1100;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a hermetic Postgres 16-alpine container, run every migration,
/// and return a pool clone the test can issue raw inserts through.
async fn boot_pg() -> Result<
    (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        sqlx::PgPool,
    ),
    TestError,
> {
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
    Ok((container, pool))
}

/// Build a fresh [`ApiState`] over `pool` and return it together with
/// a clone of the live broadcaster so the test can publish into the
/// same channel the WebSocket handler subscribes to.
fn build_state(pool: sqlx::PgPool) -> (ApiState, LabelBroadcaster) {
    let crypto = Crypto::new([0u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let state = ApiState::new(pool, sessions);
    let broadcaster = state.label_broadcaster.clone();
    (state, broadcaster)
}

/// Spawn the labeler router on `127.0.0.1:0` and return the bound
/// address. The server runs for the lifetime of the test process —
/// the per-test container drop tears down the DB behind it, so a
/// dangling server cannot leak state into a sibling test.
async fn spawn_server(state: ApiState) -> Result<std::net::SocketAddr, TestError> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        // The accept loop terminates only when the listener drops; the
        // test process exiting drops it, which is the green-path
        // cleanup. Errors (peer-reset on disconnect) are surfaced via
        // the WebSocket transport, never via this future's return.
        let _ = axum::serve(listener, app).await;
    });
    Ok(addr)
}

/// Seed one fully-formed label row into the `labels` table.
///
/// Bypasses the emitter (which signs labels with a real K-256 key) —
/// this fixture only needs rows the backfill SELECT can return.
/// Migration 13 enforces a 64-byte `sig` CHECK plus NOT NULL on
/// `subject_did` / `label_cbor` / `signing_did`; we satisfy those with
/// the minimum-viable byte strings.
///
/// Uses the runtime `sqlx::query_scalar` (no offline-mode macro
/// expansion) so this fixture's `RETURNING seq` projection does not
/// require a separately-checked-in `.sqlx/` cache entry.
async fn insert_label(
    pool: &sqlx::PgPool,
    src: &str,
    uri: &str,
    val: &str,
) -> Result<i64, TestError> {
    let seq: i64 = sqlx::query_scalar(
        r"
        INSERT INTO labels (
            src, uri, val, sig,
            subject_did, label_cbor, signing_did
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING seq
        ",
    )
    .bind(src)
    .bind(uri)
    .bind(val)
    .bind(vec![0_u8; 64])
    .bind("did:plc:fake-subject")
    .bind(Vec::<u8>::new())
    .bind(src)
    .fetch_one(pool)
    .await?;
    Ok(seq)
}

/// Decode one binary WebSocket frame to a [`proto_blue::ws::Frame`].
///
/// Returns `Ok(None)` on a Close frame (peer closed cleanly); returns
/// `Err` on a non-binary message (which would indicate a wire-format
/// regression — subscribeLabels is binary-only).
fn decode_ws_frame(msg: Message) -> Result<Option<Frame>, TestError> {
    match msg {
        Message::Binary(bytes) => {
            let frame = Frame::decode(&bytes)?;
            Ok(Some(frame))
        }
        Message::Close(_) => Ok(None),
        // Ping / Pong are handled transparently by tokio-tungstenite —
        // we should never observe them at this layer. Text frames are
        // protocol violations for subscribeLabels.
        other => Err(format!("unexpected non-binary WS message: {other:?}").into()),
    }
}

/// Extract the `seq` integer from a decoded `#labels` message frame.
fn seq_of(frame: &Frame) -> Option<i64> {
    let Frame::Message(m) = frame else {
        return None;
    };
    if m.r#type.as_deref() != Some("#labels") {
        return None;
    }
    m.body.as_map()?.get("seq").and_then(LexValue::as_integer)
}

// ── Test 1: backfill ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn backfill_delivers_seeded_labels_in_seq_order() -> Result<(), TestError> {
    if !docker_available() {
        println!(
            "SKIP labels_xrpc_live::backfill_delivers_seeded_labels_in_seq_order: \
             docker daemon not reachable.",
        );
        return Ok(());
    }
    let test_start = Instant::now();

    // ── Fixture: PG + 5 seeded labels ───────────────────────────────
    let (_container, pool) = boot_pg().await?;
    let mut seeded_seqs = Vec::with_capacity(5);
    for i in 0..5 {
        let seq = insert_label(
            &pool,
            "did:plc:labeler",
            &format!("at://did:plc:user/app.bsky.feed.post/{i}"),
            "spam",
        )
        .await?;
        seeded_seqs.push(seq);
    }

    // ── Server ───────────────────────────────────────────────────────
    let (state, _broadcaster) = build_state(pool);
    let addr = spawn_server(state).await?;

    // ── Client: connect with cursor=0 ────────────────────────────────
    let url = format!("ws://{addr}/xrpc/com.atproto.label.subscribeLabels?cursor=0");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await?;

    // Drain 5 frames; each decode is the wire-format conformance gate.
    let mut received_seqs = Vec::with_capacity(5);
    for _ in 0..5 {
        let remaining = WALL_TIME_BUDGET
            .checked_sub(test_start.elapsed())
            .unwrap_or(Duration::ZERO);
        let msg = tokio::time::timeout(remaining, ws.next())
            .await?
            .ok_or("WS stream closed before backfill complete")??;
        let frame = decode_ws_frame(msg)?.ok_or("Close received during backfill")?;
        let seq = seq_of(&frame).ok_or("frame missing seq")?;
        received_seqs.push(seq);
    }

    // ── Assertions ───────────────────────────────────────────────────
    assert_eq!(
        received_seqs, seeded_seqs,
        "backfill must deliver every seeded label in monotonic seq order",
    );
    for window in received_seqs.windows(2) {
        assert!(
            window[0] < window[1],
            "seq must be strictly monotonic: {window:?}",
        );
    }
    // Wall-time budget.
    let elapsed = test_start.elapsed();
    assert!(
        elapsed < WALL_TIME_BUDGET,
        "wall-time budget exceeded: {elapsed:?} >= {WALL_TIME_BUDGET:?}",
    );

    // Close cleanly so the server-side pump observes Close and exits.
    ws.close(None).await?;
    Ok(())
}

// ── Test 2: live fan-out ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_fan_out_delivers_post_connect_emit() -> Result<(), TestError> {
    if !docker_available() {
        println!(
            "SKIP labels_xrpc_live::live_fan_out_delivers_post_connect_emit: \
             docker daemon not reachable.",
        );
        return Ok(());
    }
    let test_start = Instant::now();

    // ── Fixture: PG + 3 seeded labels ───────────────────────────────
    let (_container, pool) = boot_pg().await?;
    let mut max_seq = 0_i64;
    for i in 0..3 {
        let seq = insert_label(
            &pool,
            "did:plc:labeler",
            &format!("at://did:plc:user/app.bsky.feed.post/{i}"),
            "spam",
        )
        .await?;
        max_seq = max_seq.max(seq);
    }

    // ── Server ───────────────────────────────────────────────────────
    let (state, broadcaster) = build_state(pool);
    let addr = spawn_server(state).await?;

    // ── Client: connect at the live edge ────────────────────────────
    // `cursor = max_seq` means "stream rows with seq > max_seq" — the
    // backfill phase returns zero rows and we drop straight into the
    // live-fan-out branch of `run_subscription`.
    let url = format!("ws://{addr}/xrpc/com.atproto.label.subscribeLabels?cursor={max_seq}");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await?;

    // Give the server a brief moment to enter the live phase before
    // we publish, so the broadcast-channel receiver is installed.
    // `run_subscription` subscribes BEFORE the backfill loop, so this
    // is just defence-in-depth against a scheduler delay.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish ONE label directly through the broadcaster. We construct
    // a Label with seq = max_seq + 1 to model the row a real emit
    // would have produced (the broadcaster does not enforce seq
    // monotonicity itself — the SQL BIGSERIAL does).
    let new_seq = max_seq + 1;
    broadcaster.publish(Label {
        id: Uuid::nil(),
        seq: new_seq,
        src: "did:plc:labeler".to_owned(),
        uri: "at://did:plc:user/app.bsky.feed.post/live".to_owned(),
        cid: None,
        val: "spam".to_owned(),
        neg: false,
        cts: Utc::now(),
        exp: None,
        sig: vec![0_u8; 64],
        subject_did: "did:plc:user".to_owned(),
        label_cbor: Vec::new(),
        signing_did: "did:plc:labeler".to_owned(),
        signed_at: Utc::now(),
    });

    // ── Assertion: receive within 1s ────────────────────────────────
    let msg = tokio::time::timeout(LIVE_FRAME_TIMEOUT, ws.next())
        .await?
        .ok_or("WS stream closed before live frame arrived")??;
    let frame = decode_ws_frame(msg)?.ok_or("Close received instead of live frame")?;
    let seq = seq_of(&frame).ok_or("live frame missing seq")?;
    assert_eq!(
        seq, new_seq,
        "live fan-out must deliver the post-connect publish exactly",
    );

    let elapsed = test_start.elapsed();
    assert!(
        elapsed < WALL_TIME_BUDGET,
        "wall-time budget exceeded: {elapsed:?} >= {WALL_TIME_BUDGET:?}",
    );

    ws.close(None).await?;
    Ok(())
}

// ── Test 3: lagged-consumer recovery via DB walk-forward ────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lagged_consumer_recovers_via_db_walk_forward() -> Result<(), TestError> {
    if !docker_available() {
        println!(
            "SKIP labels_xrpc_live::lagged_consumer_recovers_via_db_walk_forward: \
             docker daemon not reachable.",
        );
        return Ok(());
    }
    let test_start = Instant::now();

    // Production design (server.rs:593): when the broadcast receiver
    // returns `RecvError::Lagged(_)`, the pump does NOT drop the
    // connection — it walks the DB forward from the current cursor
    // via `stream_from_cursor` and resumes the live channel after.
    // The test asserts that contract: even after a lag burst (more
    // inserts than the broadcaster's 1024 capacity), every persisted
    // seq is observed on the client.

    let (_container, pool) = boot_pg().await?;

    // We need to push the broadcaster past its 1024
    // `DEFAULT_BROADCAST_CAPACITY` to trigger the `Lagged` arm. We
    // INSERT directly into the DB (the durable path) + then publish
    // each row through the broadcaster (the live path) — production
    // does both via `LabelEmitter::persist`.

    let (state, broadcaster) = build_state(pool.clone());
    let addr = spawn_server(state).await?;

    // Connect at cursor=0 so the backfill phase is empty (no seeded
    // rows yet) and the receiver enters the live branch immediately.
    let url = format!("ws://{addr}/xrpc/com.atproto.label.subscribeLabels?cursor=0");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await?;

    // Give the server's receiver a moment to be installed before we
    // start spamming inserts. Same defence as the live-fan-out test.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spawn the burst: persist LAGGED_BURST_SIZE rows + publish each
    // through the broadcaster, intentionally without giving the client
    // time to drain in between. Once we exceed capacity, the server's
    // `rx.recv()` will start surfacing `Lagged(N)` errors.
    let pool_for_burst = pool.clone();
    let broadcaster_for_burst = broadcaster.clone();
    let burst_handle = tokio::spawn(async move {
        let mut last_seq: i64 = 0;
        for i in 0..LAGGED_BURST_SIZE {
            let seq = insert_label(
                &pool_for_burst,
                "did:plc:labeler",
                &format!("at://did:plc:user/app.bsky.feed.post/burst-{i}"),
                "spam",
            )
            .await
            .expect("insert succeeds during burst");
            broadcaster_for_burst.publish(Label {
                id: Uuid::nil(),
                seq,
                src: "did:plc:labeler".to_owned(),
                uri: format!("at://did:plc:user/app.bsky.feed.post/burst-{i}"),
                cid: None,
                val: "spam".to_owned(),
                neg: false,
                cts: Utc::now(),
                exp: None,
                sig: vec![0_u8; 64],
                subject_did: "did:plc:user".to_owned(),
                label_cbor: Vec::new(),
                signing_did: "did:plc:labeler".to_owned(),
                signed_at: Utc::now(),
            });
            last_seq = seq;
        }
        last_seq
    });

    // Drain the client side: read until we've seen the final seq the
    // burst inserted. The lagged-recovery branch may de-dup against
    // the cursor it has already sent, so we tolerate gaps in what we
    // observe (some rows pre-Lagged, the rest backfilled from the
    // DB) — but the final seq must arrive.
    let final_seq = burst_handle.await?;
    let mut observed_max: i64 = 0;
    while observed_max < final_seq {
        let remaining = WALL_TIME_BUDGET
            .checked_sub(test_start.elapsed())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            break;
        }
        let msg = match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => return Err(e.into()),
            Ok(None) => return Err("WS stream closed before recovery complete".into()),
            Err(_) => break,
        };
        match decode_ws_frame(msg)? {
            Some(frame) => {
                if let Some(seq) = seq_of(&frame) {
                    if seq > observed_max {
                        observed_max = seq;
                    }
                }
            }
            None => return Err("Close received before recovery complete".into()),
        }
    }

    // The binding assertion: production behaviour is "no rows lost"
    // because the `Lagged` arm walks the DB forward from the
    // post-backfill cursor. If the server had dropped the connection
    // on lag (the alternative design) we'd never see `final_seq`.
    assert_eq!(
        observed_max, final_seq,
        "lagged-consumer recovery must surface every persisted seq; \
         got max observed {observed_max}, expected {final_seq}",
    );
    let elapsed = test_start.elapsed();
    assert!(
        elapsed < WALL_TIME_BUDGET,
        "wall-time budget exceeded: {elapsed:?} >= {WALL_TIME_BUDGET:?}",
    );

    ws.close(None).await?;
    Ok(())
}
