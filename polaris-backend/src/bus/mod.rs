//! Event bus abstraction.
//!
//! `EventBus` is the seam between event producers (the firehose ingest worker
//! from #12, the upstream-labeler consumer from #32) and consumers (the
//! pattern engine from #17/#18/#19, the evidence worker from #33). The
//! backend is Cargo-feature-selected per deployment profile (design.md
//! §3.1):
//!
//! - `bus-nats` (default) — labeler profile, single-binary, smaller footprint.
//! - `bus-kafka` — Bluesky first-party profile, sharded by event subject id.
//!
//! [`memory`] is always compiled and is used by tests; production code paths
//! never select it.
//!
//! # Invariants
//!
//! - **Bounded backpressure.** Producers `await` on send when the consumer
//!   lags; events are never silently dropped (the memory backend uses a
//!   bounded [`tokio::sync::broadcast`] whose error variants the producer
//!   translates into a typed [`BusError`] rather than swallowing).
//! - **Versioned wire format.** [`EventEnvelope`] carries an explicit
//!   `version: u32` so consumers can refuse forward-incompatible payloads.
//!   See [`WIRE_VERSION`].
//! - **Typed errors.** No `anyhow::Error` crosses the public surface; every
//!   fallible path returns through [`BusError`].
//!
//! # Module layout
//!
//! - [`memory`] — in-process [`tokio::sync::broadcast`]-backed implementation
//!   used by tests.
//! - `kafka` (behind `feature = "bus-kafka"`) — Bluesky-profile backend.
//! - `nats` (behind `feature = "bus-nats"`) — labeler-profile backend.

pub mod memory;

#[cfg(feature = "bus-kafka")]
pub mod kafka;

#[cfg(feature = "bus-nats")]
pub mod nats;

use futures::stream::BoxStream;

/// Wire-format version emitted by every Polaris producer.
///
/// Increment on any breaking schema change to [`EventEnvelope`] or the
/// payload type alias the bus carries. Consumers compare this against the
/// value on the wire and surface [`BusError::Decode`] when the producer is
/// forward-incompatible with the consumer's understanding.
pub const WIRE_VERSION: u32 = 1;

/// Errors raised by the event bus surface.
///
/// Each backend (`memory`, `kafka`, `nats`) folds its own per-backend error
/// type into one of these four variants via [`BusErrorInner`], so callers
/// can write a single `match` and recover the cause chain through
/// [`std::error::Error::source`].
#[derive(Debug, thiserror::Error)]
pub enum BusError {
    /// The producer could not deliver an envelope to the backend (network,
    /// serialisation, or backpressure-channel-closed).
    #[error("failed to publish event to bus")]
    Publish(#[source] BusErrorInner),

    /// The consumer could not establish a subscription against the backend
    /// (topic creation, connection, or auth).
    #[error("failed to subscribe to bus topic")]
    Subscribe(#[source] BusErrorInner),

    /// The consumer received bytes but could not decode them into an
    /// [`EventEnvelope`] of the expected payload type, or the on-wire
    /// `version` did not match the consumer's [`WIRE_VERSION`].
    #[error("failed to decode event envelope (version {version})")]
    Decode {
        /// The on-wire `version` field as observed by the consumer; `0` if
        /// the bytes could not even be parsed as an envelope.
        version: u32,
        /// Underlying decode error.
        #[source]
        source: BusErrorInner,
    },

    /// The backend reported a disconnect. The backend's own reconnect loop
    /// is in progress; the caller's stream will yield further envelopes
    /// once the connection is re-established. This is informational rather
    /// than fatal — consumers may choose to log and continue.
    #[error("bus disconnected; reconnect in progress")]
    Disconnected,
}

/// Inner error wrapper carrying a backend-specific cause as a `Display`
/// string.
///
/// Each backend's native error type is converted to a plain `String` so
/// [`BusError`] doesn't have to expose the union of every backend's error
/// type across Cargo features. The full cause is preserved in `Display`
/// (and via [`std::error::Error::source`] on [`BusError`]) for logging and
/// debugging; programmatic recovery is via the [`BusError`] variant.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BusErrorInner(String);

impl BusErrorInner {
    /// Build a [`BusErrorInner`] from any displayable cause.
    ///
    /// Backends call this at the boundary where their native error type
    /// (e.g. `async_nats::PublishError`, `rdkafka::error::KafkaError`,
    /// `tokio::sync::broadcast::error::SendError`) crosses the bus surface.
    pub fn new<E: std::fmt::Display>(cause: E) -> Self {
        Self(cause.to_string())
    }
}

/// Versioned envelope wrapping every event on the bus.
///
/// The envelope is what is serialised onto the wire (via `bincode` —
/// see [`memory`] for the in-process exception) and what [`EventBus`]
/// implementations carry. Generic over the payload type `T` so the bus
/// stays decoupled from the firehose's [`crate::ingest::NormalizedEvent`]:
/// any `T: Serialize + Deserialize + Send + Sync + 'static` can travel.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EventEnvelope<T> {
    /// Wire-format version. Increment on any breaking schema change. See
    /// [`WIRE_VERSION`] for the version emitted by every Polaris producer.
    pub version: u32,
    /// Producer-assigned monotonic sequence (firehose `seq` for the
    /// ingest worker, otherwise the producer's own counter). Consumers
    /// use this for ordering and dedup across reconnects.
    pub seq: i64,
    /// Producer identifier — used for fan-out routing and debugging
    /// (`"firehose"`, `"labeler-upstream:did:plc:..."`, etc.).
    pub source: String,
    /// The actual event payload.
    pub payload: T,
}

impl<T> EventEnvelope<T> {
    /// Build a new envelope stamped with the current [`WIRE_VERSION`].
    ///
    /// The common producer path: producers don't pick a version explicitly;
    /// they use this constructor and the bus carries the wire-version
    /// invariant for them.
    pub fn new(seq: i64, source: impl Into<String>, payload: T) -> Self {
        Self {
            version: WIRE_VERSION,
            seq,
            source: source.into(),
            payload,
        }
    }
}

/// Polaris event bus.
///
/// Implementations are Cargo-feature-selected at compile time:
///
/// - [`memory::MemoryBus`] — always available; used by tests.
/// - `kafka::KafkaBus` — behind `feature = "bus-kafka"`.
/// - `nats::NatsBus` — behind `feature = "bus-nats"`.
///
/// The trait is dyn-compatible (via `#[async_trait::async_trait]`) so M2
/// tests can swap a [`memory::MemoryBus`] for the live backend behind a
/// `Box<dyn EventBus<NormalizedEvent>>` without recompiling the pattern
/// engine.
///
/// # Type parameter
///
/// `T` is the payload type carried inside each [`EventEnvelope`]. The
/// firehose ingest worker produces [`crate::ingest::NormalizedEvent`], but
/// the bus is intentionally generic so the upstream-labeler consumer (#32)
/// and the evidence worker (#33) can carry their own payload types over
/// the same abstraction.
#[async_trait::async_trait]
pub trait EventBus<T>: Send + Sync
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
{
    /// Publish an envelope to `topic`.
    ///
    /// Returns once the backend has accepted the envelope (for the
    /// memory backend that is immediately after the send; for the Kafka
    /// and NATS backends that means the client has handed the bytes to
    /// its background I/O task). Producers therefore `await` on send
    /// under backpressure and never silently drop events.
    async fn publish(&self, topic: &str, envelope: EventEnvelope<T>) -> Result<(), BusError>;

    /// Subscribe to `topic` and return a [`BoxStream`] of envelopes.
    ///
    /// The stream is `'static` (no borrow from `self`) so consumers can
    /// move it into a `tokio::spawn`ed task without lifetime contortions.
    /// Backend-side reconnects are transparent: the stream continues
    /// yielding once the connection is re-established. A surfaced
    /// [`BusError::Disconnected`] item is informational, not terminal.
    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<BoxStream<'static, Result<EventEnvelope<T>, BusError>>, BusError>;
}
