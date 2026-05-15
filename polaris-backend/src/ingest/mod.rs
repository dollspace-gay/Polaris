//! ATProto ingest workers.
//!
//! This module hosts the live subscribers that bring outside-world data
//! into Polaris. The first one — and the canonical worker shape that #32
//! (upstream-label consumer) and #33 (evidence worker) inherit — is the
//! firehose ingest (see [`firehose`]).
//!
//! Each worker follows the same pattern:
//!
//! 1. **Single-task ownership of all state.** No `Arc<Mutex<...>>` around
//!    a cursor or a session — the worker task owns it by value and
//!    flushes to durable storage on a tick.
//! 2. **Bounded outbound channel.** `tokio::sync::mpsc::channel` with
//!    capacity from config. Under backpressure, the worker awaits the
//!    `send` (slowing the upstream read) rather than dropping events.
//! 3. **Co-operative shutdown via [`tokio_util::sync::CancellationToken`].**
//!    A `tokio::select!` races the main loop against the cancellation
//!    future so the worker can flush any in-flight cursor before exit.
//! 4. **Typed errors.** Each worker exports a `thiserror`-derived enum;
//!    callers never see `anyhow::Error` cross the library boundary.

pub mod aggregator;
pub mod firehose;
pub mod upstream_labels;

pub use aggregator::{
    AggregatorConfig, AggregatorError, DEFAULT_BATCH_SIZE, DEFAULT_POLL_INTERVAL_SECS,
    DEFAULT_WINDOW_SECS, ReportAggregator,
};
pub use firehose::{FirehoseConfig, FirehoseError, FirehoseWorker, NormalizedEvent};
pub use upstream_labels::{
    CacheError, HandleError, UpstreamKeyCache, UpstreamKeyFetcher, UpstreamLabelerConfig,
    UpstreamLabelerConsumer,
};
