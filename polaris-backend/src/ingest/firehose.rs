//! Firehose ingest worker.
//!
//! Subscribes to `com.atproto.sync.subscribeRepos` via
//! [`proto_blue::repo::Firehose`], decodes each frame into a typed
//! [`NormalizedEvent`], persists a cursor in Postgres so a process restart
//! resumes the stream without gaps, and forwards events onto a bounded
//! [`tokio::sync::mpsc`] channel. M2 (#16) replaces the channel consumer with
//! the event bus; until then the consumer is a logging stub.
//!
//! # Invariants
//!
//! - **Zero event loss across reconnect** (REQ-8 / AC-9). The cursor is
//!   flushed on a periodic interval AND on shutdown. On restart, the worker
//!   reads the persisted cursor and resumes the WebSocket subscription with
//!   `?cursor=<seq>` so no events are lost across the gap. Clean-close
//!   reconnects (server-side `Ok(None)` or server-issued error frame like
//!   `FutureCursor`) are handled in-flight: the worker rebuilds the
//!   [`proto_blue::repo::Firehose`] with the current cursor without losing
//!   the channel or restarting the task.
//! - **Bounded backpressure.** The outbound channel is sized from
//!   [`FirehoseConfig::channel_capacity`]; under backpressure, the worker
//!   awaits `Sender::send` rather than dropping events. A slow consumer
//!   therefore slows the upstream read, never drops a frame on the floor.
//! - **Single-writer cursor.** The worker task owns the cursor by value.
//!   No `Arc<Mutex<u64>>` — the only DB writer is [`flush_cursor`], and the
//!   in-process invariant (monotonic non-decreasing) is mirrored at the
//!   database via the `WHERE firehose_cursor.seq < EXCLUDED.seq` guard in
//!   the upsert. A stale writer can never rewind the persisted cursor.
//! - **Library-grade error handling.** No `unwrap()` / `expect()`; every
//!   fallible call returns through `?` into [`FirehoseError`]. Decode and
//!   transient server-error frames are non-fatal (logged + reconnect);
//!   cursor-persist and channel-closed failures are fatal so the
//!   supervisor (a future M1 task supervisor) can decide whether to retry
//!   or escalate.
//!
//! # M1 scope
//!
//! The worker is implemented but **not** wired into the binary — that
//! integration lands with the wider M1 task supervisor. Tests drive the
//! worker directly, both for cursor persistence and (where feasible) for
//! the reconnect path.

use std::time::Duration;

use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use proto_blue::repo::{
    AccountEvent, CommitEvent, FirehoseEvent, IdentityEvent, InfoEvent, RepoError, SyncEvent,
};

// ── public configuration ─────────────────────────────────────────────────

/// Default capacity of the outbound `(FirehoseWorker → consumer)` channel.
///
/// Sized for a moderate burst of firehose frames without forcing a slow
/// consumer to block immediately. The architect's pre-flight named 1024 as
/// the target; operators can override via [`FirehoseConfig::channel_capacity`].
pub const DEFAULT_CHANNEL_CAPACITY: usize = 1024;

/// Default `flush every N events` threshold.
///
/// A flush is `INSERT … ON CONFLICT DO UPDATE` against a one-row table —
/// fast, but not free. 100 frames per flush keeps the DB write rate in the
/// tens of Hz at firehose-peak (~1500 events/sec).
pub const DEFAULT_FLUSH_EVERY_N_EVENTS: usize = 100;

/// Default `flush every T` interval.
///
/// Bounds worst-case data loss at process kill: at most this many seconds
/// of events were observed since the last on-disk cursor write. Tuned for
/// the AC-9 "resume within 30s" criterion with margin.
pub const DEFAULT_FLUSH_EVERY: Duration = Duration::from_secs(5);

/// Configuration for a [`FirehoseWorker`].
///
/// All fields are public-by-value so configuration construction stays
/// data-oriented; the worker takes a `FirehoseConfig` by value at
/// [`FirehoseWorker::new`].
#[derive(Debug, Clone)]
pub struct FirehoseConfig {
    /// WebSocket URL to subscribe against, **without** any `?cursor=` query
    /// parameter — the worker appends it from the persisted cursor.
    ///
    /// For Bluesky the canonical value is
    /// `wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos`; for
    /// labeler-side deployments it points at the operator's own relay.
    pub relay_url: String,

    /// Flush the cursor every N decoded events with a `seq`. Defaults to
    /// [`DEFAULT_FLUSH_EVERY_N_EVENTS`].
    pub flush_every_n_events: usize,

    /// Flush the cursor on this interval regardless of event count.
    /// Defaults to [`DEFAULT_FLUSH_EVERY`].
    pub flush_every: Duration,

    /// Capacity of the outbound `mpsc` channel. Defaults to
    /// [`DEFAULT_CHANNEL_CAPACITY`].
    pub channel_capacity: usize,
}

impl Default for FirehoseConfig {
    fn default() -> Self {
        Self {
            relay_url: "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos".to_owned(),
            flush_every_n_events: DEFAULT_FLUSH_EVERY_N_EVENTS,
            flush_every: DEFAULT_FLUSH_EVERY,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }
}

// ── normalized event the worker emits ───────────────────────────────────

/// Normalized firehose event forwarded on the outbound channel.
///
/// The enum mirrors [`proto_blue::repo::FirehoseEvent`] one-for-one but
/// stays inside the Polaris crate so M2's event bus (#16) can serialise it
/// against a stable shape without leaking the upstream type. For M1 the
/// consumer is a logging stub; #13 will refine the typed payloads (e.g.
/// pulling out per-record mutations from `CommitEvent::ops`) once the
/// pattern engine's input contract is known.
#[derive(Debug, Clone)]
pub enum NormalizedEvent {
    /// A `#commit` event: repo state changed for `repo` (a DID).
    Commit(Box<CommitEvent>),
    /// A `#sync` event: full-state recovery message for `did`.
    Sync(Box<SyncEvent>),
    /// An `#identity` event: handle or DID-doc changed.
    Identity(Box<IdentityEvent>),
    /// An `#account` event: account activation / takedown.
    Account(Box<AccountEvent>),
    /// A server `#info` frame (e.g. `OutdatedCursor`). Carries no `seq`.
    Info(Box<InfoEvent>),
    /// A forward-compatible variant: a frame type the upstream client did
    /// not recognise. Forwarded verbatim so a consumer can choose to decode
    /// it; the worker itself logs at warn level and continues.
    Unknown {
        /// The unrecognised discriminator (e.g. `#futurism`).
        r#type: String,
    },
}

impl NormalizedEvent {
    /// Sequence number of this event, if any. Mirrors
    /// [`FirehoseEvent::seq`]: `Info` and `Unknown` carry `None`.
    #[must_use]
    pub const fn seq(&self) -> Option<i64> {
        match self {
            Self::Commit(e) => Some(e.seq),
            Self::Sync(e) => Some(e.seq),
            Self::Identity(e) => Some(e.seq),
            Self::Account(e) => Some(e.seq),
            Self::Info(_) | Self::Unknown { .. } => None,
        }
    }
}

impl From<FirehoseEvent> for NormalizedEvent {
    fn from(evt: FirehoseEvent) -> Self {
        match evt {
            FirehoseEvent::Commit(c) => Self::Commit(Box::new(c)),
            FirehoseEvent::Sync(s) => Self::Sync(Box::new(s)),
            FirehoseEvent::Identity(i) => Self::Identity(Box::new(i)),
            FirehoseEvent::Account(a) => Self::Account(Box::new(a)),
            FirehoseEvent::Info(i) => Self::Info(Box::new(i)),
            FirehoseEvent::Unknown { r#type, .. } => Self::Unknown { r#type },
        }
    }
}

// ── error type ──────────────────────────────────────────────────────────

/// Errors raised by the firehose ingest worker.
///
/// Variants are split into **fatal** (cursor persist / channel closed) and
/// **non-fatal** (decode / disconnected). Non-fatal errors are observed by
/// the worker internally and never bubble out of [`FirehoseWorker::run`];
/// the supervisor only sees a fatal cause or `Ok(())` after co-operative
/// shutdown.
#[derive(Debug, thiserror::Error)]
pub enum FirehoseError {
    /// Loading the cursor from Postgres at startup failed.
    #[error("failed to load firehose cursor from Postgres")]
    CursorLoad(#[source] sqlx::Error),

    /// Persisting the cursor to Postgres failed. Fatal because a missed
    /// flush turns into duplicated work on the next restart (the worker
    /// would re-read events the consumer already saw).
    #[error("failed to persist firehose cursor to Postgres")]
    CursorPersist(#[source] sqlx::Error),

    /// The outbound channel was closed by the consumer — the worker has
    /// nothing left to feed. Fatal: the supervisor must restart the
    /// pipeline (or shut down) before any further frames are read.
    #[error("outbound firehose channel closed (consumer dropped)")]
    ChannelClosed,
}

// ── worker ──────────────────────────────────────────────────────────────

/// A standalone firehose ingest worker.
///
/// Construct one with [`FirehoseWorker::new`], spawn its [`run`](Self::run)
/// future on `tokio::spawn`, and read decoded events from the
/// [`mpsc::Receiver`] returned by `new`. The worker exits when:
///
/// 1. The supplied [`CancellationToken`] is cancelled (the cursor is
///    flushed before return; the result is `Ok(())`).
/// 2. A fatal error occurs — see [`FirehoseError`].
#[derive(Debug)]
pub struct FirehoseWorker {
    cfg: FirehoseConfig,
    pool: PgPool,
    tx: mpsc::Sender<NormalizedEvent>,
    cancel: CancellationToken,
}

impl FirehoseWorker {
    /// Construct a worker and the matching receiver.
    ///
    /// The caller owns the [`mpsc::Receiver`] and drives the consumer; the
    /// worker holds only the `Sender`. Dropping the receiver therefore
    /// surfaces as [`FirehoseError::ChannelClosed`] on the next event the
    /// worker tries to forward, which is the supervisor's signal to
    /// either restart the consumer or cancel the worker.
    #[must_use]
    pub fn new(
        cfg: FirehoseConfig,
        pool: PgPool,
        cancel: CancellationToken,
    ) -> (Self, mpsc::Receiver<NormalizedEvent>) {
        let (tx, rx) = mpsc::channel(cfg.channel_capacity);
        (
            Self {
                cfg,
                pool,
                tx,
                cancel,
            },
            rx,
        )
    }

    /// Run the worker to completion.
    ///
    /// The future yields whenever it would block on (a) the upstream
    /// firehose, (b) the outbound channel's backpressure, (c) the
    /// flush interval, or (d) the cancellation token. It does not
    /// block-on any synchronous IO — every external call is `await`-ed.
    ///
    /// # Errors
    ///
    /// - [`FirehoseError::CursorLoad`] if the initial Postgres read fails.
    /// - [`FirehoseError::CursorPersist`] on any flush failure.
    /// - [`FirehoseError::ChannelClosed`] if the consumer dropped the
    ///   receiver while events were in-flight.
    ///
    /// Decode errors and transient firehose disconnects are absorbed
    /// internally: the worker logs at `warn` level via `tracing` and
    /// continues. The reconnect path rebuilds [`proto_blue::repo::Firehose`]
    /// with the current cursor so no events are lost across the gap.
    pub async fn run(self) -> Result<(), FirehoseError> {
        let Self {
            cfg,
            pool,
            tx,
            cancel,
        } = self;

        let mut cursor = load_cursor(&pool).await?;
        tracing::info!(
            cursor,
            relay_url = %cfg.relay_url,
            "firehose worker starting",
        );

        let mut firehose =
            proto_blue::repo::Firehose::new(build_subscribe_url(&cfg.relay_url, cursor));
        let mut flush_timer = tokio::time::interval(cfg.flush_every);
        // `MissedTickBehavior::Delay` keeps a stalled tick from generating a
        // burst of catch-up flushes after the worker is unparked.
        flush_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First tick fires immediately; consume it so the first real flush
        // is `flush_every` away from `run`-entry.
        let _ = flush_timer.tick().await;

        let mut since_flush: usize = 0;
        let mut last_flushed = cursor;

        loop {
            tokio::select! {
                // Co-operative shutdown. Race the firehose read so we can
                // exit promptly even if the upstream is silent.
                () = cancel.cancelled() => {
                    tracing::info!(cursor, "firehose worker received cancellation");
                    if cursor != last_flushed {
                        flush_cursor(&pool, cursor).await?;
                    }
                    tracing::info!(cursor, "firehose worker stopped");
                    return Ok(());
                }

                // Periodic flush. `tokio::time::Interval::tick` is
                // cancel-safe: dropping it mid-poll is a no-op.
                _ = flush_timer.tick() => {
                    if cursor != last_flushed {
                        flush_cursor(&pool, cursor).await?;
                        last_flushed = cursor;
                        since_flush = 0;
                    }
                }

                // Read one event from the firehose. `next_event` is
                // cancel-safe via `proto_blue_ws::WebSocketKeepAlive::recv`
                // — the underlying transport buffers atomic frames and
                // resumes from the next frame on the following poll. The
                // select macro will not lose a partially-decoded message.
                ev = firehose.next_event() => {
                    match ev {
                        Ok(Some(event)) => {
                            // Advance cursor *before* the send so a closed
                            // channel doesn't lose the seq we just read.
                            // The next on-flush write captures it.
                            if let Some(seq) = event.seq() {
                                if seq > cursor {
                                    cursor = seq;
                                }
                            }
                            let normalized = NormalizedEvent::from(event);
                            // Bounded send. Awaiting here is *correct* —
                            // it's how backpressure propagates upstream.
                            // Forbidden patterns #4 (unbounded) and #5
                            // (silent drop) are both addressed by this
                            // single line.
                            tx.send(normalized).await.map_err(|_| FirehoseError::ChannelClosed)?;
                            since_flush += 1;
                            if since_flush >= cfg.flush_every_n_events
                                && cursor != last_flushed
                            {
                                flush_cursor(&pool, cursor).await?;
                                last_flushed = cursor;
                                since_flush = 0;
                            }
                        }
                        Ok(None) => {
                            // Clean upstream close. Rebuild the Firehose
                            // with the current cursor so the next
                            // `?cursor=` resume picks up exactly where we
                            // left off.
                            tracing::warn!(
                                cursor,
                                "firehose stream closed cleanly; reconnecting from cursor",
                            );
                            firehose = proto_blue::repo::Firehose::new(
                                build_subscribe_url(&cfg.relay_url, cursor),
                            );
                        }
                        Err(RepoError::FirehoseError { error, message }) => {
                            // Server-sent error frame (e.g. `FutureCursor`,
                            // `ConsumerTooSlow`). Non-fatal: log and
                            // reconnect from the persisted cursor. For
                            // `FutureCursor` specifically the relay will
                            // accept a smaller cursor on the next attempt;
                            // we leave the cursor in place because the
                            // worker has not seen evidence to rewind it.
                            tracing::warn!(
                                cursor,
                                error = %error,
                                message = ?message,
                                "firehose server error frame; reconnecting",
                            );
                            firehose = proto_blue::repo::Firehose::new(
                                build_subscribe_url(&cfg.relay_url, cursor),
                            );
                        }
                        Err(err) => {
                            // Decode / transport error. The keep-alive
                            // layer already auto-reconnects on transport
                            // failure, so we surface the diagnostic and
                            // keep polling. Decode errors are bug-shaped
                            // (a malformed frame for a known type); we
                            // log and skip rather than crash the worker.
                            tracing::warn!(
                                cursor,
                                error = ?err,
                                "firehose decode/transport error; continuing",
                            );
                        }
                    }
                }
            }
        }
    }
}

// ── DB helpers ──────────────────────────────────────────────────────────

/// Load the persisted firehose cursor.
///
/// Returns `0` on a fresh database (no row yet) — the relay accepts
/// `?cursor=0` as "from the beginning".
///
/// # Visibility
///
/// Exposed as `pub` (rather than `pub(crate)`) so the integration tests in
/// `polaris-backend/tests/` can verify the durable-state contract without
/// standing up a full worker loop. The `#[doc(hidden)]` attribute keeps it
/// out of the rendered rustdoc surface — it is not part of the supported
/// API. The function is otherwise side-effect free and safe to call from
/// any consumer that wants to inspect the cursor.
///
/// # Errors
///
/// Returns [`FirehoseError::CursorLoad`] if the underlying `SELECT` fails.
#[doc(hidden)]
pub async fn load_cursor(pool: &PgPool) -> Result<i64, FirehoseError> {
    let row = sqlx::query!("SELECT seq FROM firehose_cursor WHERE id = 1")
        .fetch_optional(pool)
        .await
        .map_err(FirehoseError::CursorLoad)?;
    Ok(row.map_or(0, |r| r.seq))
}

/// Upsert the firehose cursor.
///
/// The `WHERE firehose_cursor.seq < EXCLUDED.seq` predicate enforces
/// monotonicity at the database: a stale writer that runs concurrently
/// can never rewind the persisted cursor.
///
/// # Visibility
///
/// Same `#[doc(hidden)] pub` shape as [`load_cursor`]: exposed for the
/// integration tests in `polaris-backend/tests/`, not part of the public
/// rustdoc API.
///
/// # Errors
///
/// Returns [`FirehoseError::CursorPersist`] if the upsert fails.
#[doc(hidden)]
pub async fn flush_cursor(pool: &PgPool, seq: i64) -> Result<(), FirehoseError> {
    sqlx::query!(
        r"
        INSERT INTO firehose_cursor (id, seq, updated_at)
        VALUES (1, $1, now())
        ON CONFLICT (id) DO UPDATE
        SET seq = EXCLUDED.seq,
            updated_at = EXCLUDED.updated_at
        WHERE firehose_cursor.seq < EXCLUDED.seq
        ",
        seq,
    )
    .execute(pool)
    .await
    .map_err(FirehoseError::CursorPersist)?;
    Ok(())
}

// ── URL helper ──────────────────────────────────────────────────────────

/// Build the `subscribeRepos` URL with the cursor query parameter.
///
/// `?cursor=0` is a valid "start from the beginning" sentinel, so we always
/// append rather than special-casing zero. If the caller's base URL already
/// carries a query string, we append with `&` instead.
pub(crate) fn build_subscribe_url(relay_url: &str, cursor: i64) -> String {
    let sep = if relay_url.contains('?') { '&' } else { '?' };
    format!("{relay_url}{sep}cursor={cursor}")
}

// ── unit tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_subscribe_url_appends_cursor() {
        let u = build_subscribe_url("wss://relay/xrpc/com.atproto.sync.subscribeRepos", 42);
        assert_eq!(
            u,
            "wss://relay/xrpc/com.atproto.sync.subscribeRepos?cursor=42"
        );
    }

    #[test]
    fn build_subscribe_url_preserves_existing_query() {
        let u = build_subscribe_url("wss://relay/xrpc/x?foo=bar", 7);
        assert_eq!(u, "wss://relay/xrpc/x?foo=bar&cursor=7");
    }

    #[test]
    fn build_subscribe_url_handles_zero() {
        let u = build_subscribe_url("wss://relay", 0);
        assert_eq!(u, "wss://relay?cursor=0");
    }

    #[test]
    fn firehose_config_default_is_documented_values() {
        let cfg = FirehoseConfig::default();
        assert_eq!(cfg.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
        assert_eq!(cfg.flush_every_n_events, DEFAULT_FLUSH_EVERY_N_EVENTS);
        assert_eq!(cfg.flush_every, DEFAULT_FLUSH_EVERY);
        assert!(cfg.relay_url.starts_with("wss://"));
    }

    #[test]
    fn normalized_event_seq_accessor_mirrors_firehose_event() {
        // The accessor is `const fn`; cover each variant once so a future
        // refactor can't accidentally drop a `seq` from a known variant.
        use proto_blue::repo::{AccountEvent, IdentityEvent, InfoEvent, SyncEvent};

        let sync = NormalizedEvent::Sync(Box::new(SyncEvent {
            seq: 11,
            did: "did:plc:x".to_owned(),
            blocks: Vec::new(),
            rev: String::new(),
            time: String::new(),
        }));
        assert_eq!(sync.seq(), Some(11));

        let id = NormalizedEvent::Identity(Box::new(IdentityEvent {
            seq: 12,
            did: "did:plc:x".to_owned(),
            time: String::new(),
            handle: None,
        }));
        assert_eq!(id.seq(), Some(12));

        let acct = NormalizedEvent::Account(Box::new(AccountEvent {
            seq: 13,
            did: "did:plc:x".to_owned(),
            time: String::new(),
            active: true,
            status: None,
        }));
        assert_eq!(acct.seq(), Some(13));

        let info = NormalizedEvent::Info(Box::new(InfoEvent {
            name: "n".to_owned(),
            message: None,
        }));
        assert_eq!(info.seq(), None);

        let unknown = NormalizedEvent::Unknown {
            r#type: "#future".to_owned(),
        };
        assert_eq!(unknown.seq(), None);
    }
}
