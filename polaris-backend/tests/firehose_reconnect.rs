//! AC-9 binding: forced WebSocket close mid-stream → `FirehoseWorker`
//! resumes within 30s from persisted cursor with no event loss.
//!
//! Test fixture: an embedded `tokio-tungstenite` server that:
//!
//! 1. Accepts the first connection, parses `?cursor=K0` from the request
//!    URI. On first connect `K0 = 0` (worker has no persisted cursor).
//! 2. Sends frames `seq = K0+1 .. K0+K` (K frames).
//! 3. Sends a WebSocket Close frame with reconnect-eligible code
//!    (1001 Going Away).
//! 4. Drops the connection.
//! 5. Accepts the second connection. Parses `?cursor=K1`. Records `K1`
//!    so the test can assert `K1 = K0+K` — i.e. the worker persisted
//!    the disconnect-point seq before reconnecting.
//! 6. Sends frames `seq = K1+1 .. K1+(N-K)` (remaining `N-K` frames).
//! 7. Closes cleanly.
//!
//! `FirehoseWorker` is driven against the fixture URL. The test asserts:
//!
//! - Total events observed = N.
//! - Events are strictly monotonic in `seq` with no duplicates or gaps.
//! - Post-reconnect events (the last `N-K`) all have `seq > K` — the
//!   binding assertion that proves cursor-driven resume, not just
//!   frame-count parity.
//! - The fixture's recorded `last_seen_cursor` for the second connection
//!   equals `DISCONNECT_AFTER` — i.e. the worker sent `?cursor=K` on
//!   reconnect, which only happens if the cursor was persisted before
//!   the reconnect.
//! - End-state `firehose_cursor` row in Postgres = `TOTAL_FRAMES`.
//! - Wall time `< 30s` (AC-9 budget).
//!
//! ## Wire format
//!
//! The fixture emits real atproto `subscribeRepos` frames using
//! [`proto_blue::ws::Frame::encode`] — the same encoder
//! `proto_blue::repo::Firehose::next_event` decodes against. Events
//! are `#identity` variants because that lexicon shape is the smallest
//! that carries a `seq` field (no CIDs, no CAR bytes), which keeps the
//! fixture mechanical and the assertion surface narrow. The cursor
//! persistence and reconnect logic is independent of the event variant,
//! so this is sufficient for AC-9.
//!
//! ## Skip behaviour
//!
//! If Docker is unreachable the test prints a clear skip message and
//! returns `Ok(())`, matching the pattern in `tests/db_smoke.rs`.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "test code is allowed to panic; the integration test body is \
              a linear sequence of fixture setup → drive → assertions and \
              is more readable inline than split across helpers"
)]

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures::SinkExt as _;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::ingest::firehose::{self, FirehoseConfig, FirehoseWorker, NormalizedEvent};
use proto_blue::lex_data::LexValue;
use proto_blue::ws::{Frame, MessageFrame};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_util::sync::CancellationToken;

/// Total number of `#identity` frames the fixture will emit across both
/// connections. Sized to give the worker room to observe a clear
/// pre/post-reconnect partition without inflating the test budget.
const TOTAL_FRAMES: u64 = 20;

/// How many frames the fixture sends on the first connection before
/// closing. The remaining `TOTAL_FRAMES - DISCONNECT_AFTER` are sent on
/// the second connection — and must all carry `seq > DISCONNECT_AFTER`
/// to prove cursor-driven resume.
const DISCONNECT_AFTER: u64 = 8;

/// AC-9 budget. The end-to-end test (db spin-up + handshake + 20 frames
/// + reconnect) must complete inside this wall time.
const AC9_WALL_TIME_BUDGET: Duration = Duration::from_secs(30);

/// Mutable state observed by the fixture's accept loop. The test reads
/// `last_seen_cursor` after the run to confirm the reconnect attempt
/// carried `?cursor=K0+DISCONNECT_AFTER`.
#[derive(Debug, Default)]
struct FixtureState {
    /// Cursor query-param parsed from the most recent successful
    /// handshake. `None` until at least one client has connected.
    last_seen_cursor: Option<u64>,
    /// Cursor from the *first* handshake — recorded separately so we
    /// can assert `K0 == 0` without it being clobbered by the second
    /// connection's cursor.
    first_seen_cursor: Option<u64>,
    /// Number of successful WebSocket handshakes accepted.
    connection_count: u32,
}

/// Parse `cursor=<N>` out of an opaque query string like
/// `cursor=8&foo=bar`. Returns `0` if absent (matches the worker's
/// "no cursor yet" sentinel).
fn parse_cursor_param(query: &str) -> u64 {
    for pair in query.split('&') {
        if let Some(rest) = pair.strip_prefix("cursor=") {
            if let Ok(n) = rest.parse::<u64>() {
                return n;
            }
        }
    }
    0
}

/// Build a single CBOR-encoded `#identity` frame at `seq`. Identity is
/// the smallest variant that carries a seq: just `seq + did + time`.
fn encode_identity_frame(seq: u64) -> Vec<u8> {
    let mut body = BTreeMap::new();
    body.insert(
        "seq".to_owned(),
        LexValue::Integer(i64::try_from(seq).expect("test seq fits in i64")),
    );
    body.insert(
        "did".to_owned(),
        LexValue::String(format!("did:plc:test{seq:020}")),
    );
    body.insert(
        "time".to_owned(),
        LexValue::String("2025-01-01T00:00:00Z".to_owned()),
    );
    let frame = Frame::Message(MessageFrame {
        r#type: Some("#identity".to_owned()),
        body: LexValue::Map(body),
    });
    frame.encode().expect("test frame encodes")
}

/// Server-side state machine for one accepted connection. Returns the
/// cursor value parsed from the handshake, after streaming the
/// appropriate frame range and closing the socket.
async fn serve_one_connection(
    listener: &TcpListener,
    state: &Mutex<FixtureState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (stream, peer) = listener.accept().await?;
    eprintln!("fixture: accepted connection from {peer}");

    // Capture the request URI inside the handshake callback so we can
    // read the `?cursor=` query string before the WS upgrade completes.
    let cursor_slot: Arc<std::sync::Mutex<Option<u64>>> = Arc::new(std::sync::Mutex::new(None));
    let cursor_slot_cb = cursor_slot.clone();
    let mut ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
        let q = req.uri().query().unwrap_or("");
        let cursor = parse_cursor_param(q);
        *cursor_slot_cb
            .lock()
            .expect("cursor slot mutex not poisoned") = Some(cursor);
        Ok(resp)
    })
    .await?;

    let cursor = cursor_slot
        .lock()
        .expect("cursor slot mutex not poisoned")
        .unwrap_or(0);

    // Record the cursor + bump the connection count. Snapshot the
    // pre-bump count so we can decide which range of frames to send.
    let connection_index = {
        let mut s = state.lock().await;
        s.last_seen_cursor = Some(cursor);
        if s.first_seen_cursor.is_none() {
            s.first_seen_cursor = Some(cursor);
        }
        s.connection_count += 1;
        s.connection_count
    };

    // Frame range for this connection.
    //
    // - Connection 1 (`cursor=0`): send frames 1..=DISCONNECT_AFTER,
    //   then send a Close(1001 Away) and drop.
    // - Connection 2 (`cursor=DISCONNECT_AFTER`): send frames
    //   DISCONNECT_AFTER+1..=TOTAL_FRAMES, then close cleanly.
    // - Any further reconnect (shouldn't happen in a green run) is a
    //   no-op: send nothing, just close.
    let (start, end, close_with_away) = match connection_index {
        1 => (1, DISCONNECT_AFTER, true),
        2 => (DISCONNECT_AFTER + 1, TOTAL_FRAMES, false),
        _ => (1, 0, false),
    };

    for seq in start..=end {
        let frame_bytes = encode_identity_frame(seq);
        ws.send(Message::Binary(Bytes::from(frame_bytes))).await?;
    }

    if close_with_away {
        // 1001 Going Away — reconnect-eligible per
        // `proto_blue_ws::error::is_reconnectable`, so the worker's
        // keepalive layer surfaces `Ok(None)` to the
        // `next_event` consumer, which triggers the reconnect path
        // at `polaris-backend/src/ingest/firehose.rs:348`.
        ws.send(Message::Close(Some(CloseFrame {
            code: CloseCode::Away,
            reason: "fixture mid-stream close".into(),
        })))
        .await?;
    } else {
        ws.close(None).await?;
    }

    Ok(())
}

/// Spawn the fixture's accept loop. Returns the bound `SocketAddr`,
/// the join handle for the loop task, and a shared handle to the
/// observed state. The loop drains up to two connections (the
/// expected count for the AC-9 path) and then exits — extra
/// reconnect attempts caused by a real bug would surface as a hung
/// test rather than silently being absorbed.
fn spawn_fixture() -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<Mutex<FixtureState>>,
) {
    // Synchronously bind so the caller has a port before spawning the
    // worker — eliminates a connect-before-bind race window.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let addr = listener.local_addr().expect("listener has a local addr");
    let listener = TcpListener::from_std(listener).expect("convert to tokio listener");

    let state = Arc::new(Mutex::new(FixtureState::default()));
    let state_for_loop = state.clone();
    let handle = tokio::spawn(async move {
        // Cap the number of accept iterations. AC-9 needs exactly two
        // (initial connect + one reconnect); accept a third only so a
        // diagnostic from the worker (e.g. a malformed frame fault we
        // didn't anticipate) doesn't immediately hang the listener.
        // Anything past that surfaces as a test failure via the
        // wall-time budget rather than spinning forever.
        for _ in 0..3u32 {
            if let Err(e) = serve_one_connection(&listener, &state_for_loop).await {
                // Don't poison the test — a closed listener after
                // cancellation is expected. Log via eprintln so the
                // test harness surfaces it if something else is wrong.
                eprintln!("fixture: connection serve error: {e}");
                return;
            }
        }
    });

    (addr, handle, state)
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forced_disconnect_resumes_from_persisted_cursor() -> Result<(), Box<dyn std::error::Error>>
{
    // Surface worker `tracing` events through the test writer. `try_init`
    // (not `init`) keeps the call re-entry-safe when multiple tests in the
    // same binary share a tokio runtime. Level kept at INFO so green runs
    // stay quiet but a regression of AC-9 still produces actionable output
    // (worker startup, reconnect-from-cursor, etc.).
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_max_level(tracing::Level::INFO)
        .try_init();
    if !docker_available() {
        println!(
            "SKIP firehose_reconnect: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker \
             service to exercise this test.",
        );
        return Ok(());
    }

    let test_start = Instant::now();

    // ── Postgres ─────────────────────────────────────────────────
    // Same pattern as `tests/firehose_cursor_persistence.rs`:
    // testcontainers PG 16-alpine. The migrations create
    // `firehose_cursor`; no other table is needed because the worker
    // forwards events on an mpsc channel rather than persisting them.
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

    // ── Fixture ──────────────────────────────────────────────────
    let (addr, fixture_handle, fixture_state) = spawn_fixture();
    let relay_url = format!("ws://{addr}/xrpc/com.atproto.sync.subscribeRepos");

    // ── Worker ───────────────────────────────────────────────────
    // Aggressive flush cadence so the cursor is durable to Postgres
    // by the time the fixture closes the first connection. The
    // production defaults (every 100 events / every 5s) would also
    // satisfy AC-9, but tightening them keeps the test under budget.
    let worker_cfg = FirehoseConfig {
        relay_url,
        flush_every_n_events: 1,
        flush_every: Duration::from_millis(100),
        channel_capacity: 64,
    };
    let cancel = CancellationToken::new();
    let (worker, mut rx) = FirehoseWorker::new(worker_cfg, pool.clone(), cancel.clone());
    let worker_handle = tokio::spawn(worker.run());

    // ── Drain ────────────────────────────────────────────────────
    // Collect events until we've seen TOTAL_FRAMES or the wall-time
    // budget elapses. Bounded by the AC-9 budget — a stuck worker
    // surfaces here as a test timeout rather than a hang.
    let mut observed: Vec<i64> = Vec::with_capacity(usize::try_from(TOTAL_FRAMES)?);
    loop {
        let remaining = AC9_WALL_TIME_BUDGET
            .checked_sub(test_start.elapsed())
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(ev)) => {
                if let Some(seq) = ev.seq() {
                    observed.push(seq);
                }
                // `Info` / `Unknown` events have `None`; they would not
                // appear from this fixture, but we tolerate the case.
                if observed.len() == usize::try_from(TOTAL_FRAMES)? {
                    break;
                }
                // Stay generic about event kinds so the assertion
                // surface stays narrow to seq monotonicity.
                let _: &NormalizedEvent = &ev;
            }
            // `Ok(None)` (channel closed by worker) and `Err(_)` (recv
            // timed out) both mean "we're done draining" — fold them.
            Ok(None) | Err(_) => break,
        }
    }

    // Stop the worker cleanly so the cursor flush in the shutdown
    // path runs and we can assert against the persisted value.
    cancel.cancel();
    let worker_result = worker_handle.await?;
    assert!(
        worker_result.is_ok(),
        "worker returned an error: {worker_result:?}"
    );

    // Best-effort drain of the fixture task — if it's still running
    // (shouldn't be on a green run), don't block the test.
    fixture_handle.abort();
    let _ = fixture_handle.await;

    // ── Assertions ───────────────────────────────────────────────
    let total = u64::try_from(observed.len())?;
    assert_eq!(
        total, TOTAL_FRAMES,
        "expected {TOTAL_FRAMES} events end-to-end, got {total}: {observed:?}"
    );

    // Strict monotonicity + uniqueness + no-gaps. Encoded as one
    // assertion per property for diagnosability.
    for window in observed.windows(2) {
        assert!(
            window[0] < window[1],
            "events not strictly monotonic: {window:?}"
        );
    }
    let mut sorted = observed.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        observed.len(),
        "duplicate seqs observed: {observed:?}",
    );
    let min = *observed.first().expect("non-empty observed");
    let max = *observed.last().expect("non-empty observed");
    assert_eq!(min, 1, "expected min seq = 1, got {min}");
    assert_eq!(
        u64::try_from(max)?,
        TOTAL_FRAMES,
        "expected max seq = {TOTAL_FRAMES}, got {max}",
    );

    // The binding assertion: every event after the disconnect point
    // must carry a seq strictly greater than `DISCONNECT_AFTER`. If
    // the worker had reconnected with `?cursor=0` the relay would
    // (in production) resend seqs 1..=DISCONNECT_AFTER, the test
    // would see duplicates, and the previous dedup assertion would
    // fire. This one is the explicit positive statement.
    let post_reconnect = &observed[usize::try_from(DISCONNECT_AFTER)?..];
    for seq in post_reconnect {
        assert!(
            u64::try_from(*seq)? > DISCONNECT_AFTER,
            "post-reconnect event seq={seq} is not strictly > {DISCONNECT_AFTER}",
        );
    }

    // Fixture observed the cursor the worker actually sent.
    let state = fixture_state.lock().await;
    assert_eq!(
        state.first_seen_cursor,
        Some(0),
        "first connect should carry cursor=0; got {:?}",
        state.first_seen_cursor,
    );
    assert_eq!(
        state.last_seen_cursor,
        Some(DISCONNECT_AFTER),
        "reconnect should carry cursor={DISCONNECT_AFTER} (the disconnect point); \
         got {:?} — worker did not persist the cursor before reconnect",
        state.last_seen_cursor,
    );
    assert_eq!(
        state.connection_count, 2,
        "expected exactly 2 connections (initial + 1 reconnect), got {}",
        state.connection_count,
    );
    drop(state);

    // End-state cursor row matches the final seq.
    let final_cursor = firehose::load_cursor(&pool).await?;
    assert_eq!(
        u64::try_from(final_cursor)?,
        TOTAL_FRAMES,
        "expected persisted cursor = {TOTAL_FRAMES}, got {final_cursor}",
    );

    // Wall-time budget.
    let elapsed = test_start.elapsed();
    assert!(
        elapsed < AC9_WALL_TIME_BUDGET,
        "AC-9 wall-time budget exceeded: {elapsed:?} >= {AC9_WALL_TIME_BUDGET:?}",
    );

    Ok(())
}

// ── unit tests for fixture helpers ───────────────────────────────────

#[cfg(test)]
mod helper_tests {
    use super::*;

    #[test]
    fn parse_cursor_param_extracts_value() {
        assert_eq!(parse_cursor_param("cursor=8"), 8);
        assert_eq!(parse_cursor_param("cursor=0"), 0);
        assert_eq!(parse_cursor_param("foo=bar&cursor=42"), 42);
        assert_eq!(parse_cursor_param("cursor=12&extra=x"), 12);
    }

    #[test]
    fn parse_cursor_param_defaults_to_zero() {
        assert_eq!(parse_cursor_param(""), 0);
        assert_eq!(parse_cursor_param("foo=bar"), 0);
        assert_eq!(parse_cursor_param("cursor=not-a-number"), 0);
    }

    #[test]
    fn encode_identity_frame_round_trips() {
        // Confirm the fixture's wire format actually decodes through
        // the proto-blue stack the worker uses. If this regresses the
        // fixture would silently emit garbage and the integration
        // test would still hang on TOTAL_FRAMES rather than producing
        // a clear cause; this unit test gives that cause its own
        // failure mode.
        let bytes = encode_identity_frame(7);
        let decoded = Frame::decode(&bytes).expect("frame decodes");
        match decoded {
            Frame::Message(m) => {
                assert_eq!(m.r#type.as_deref(), Some("#identity"));
                let map = m.body.as_map().expect("body is map");
                match map.get("seq") {
                    Some(LexValue::Integer(7)) => {}
                    other => panic!("expected seq=7, got {other:?}"),
                }
            }
            Frame::Error(_) => panic!("expected Message frame"),
        }
    }
}
