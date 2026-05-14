//! In-process [`tokio::sync::broadcast`]-backed bus, used by tests.
//!
//! [`MemoryBus`] is always compiled — production code paths never select
//! it, but every unit and integration test that needs an [`EventBus`]
//! implementation goes through it. It exists so the pattern engine
//! (#17/#18/#19) and the evidence worker (#33) can be tested in isolation
//! from any external broker.
//!
//! # Invariants
//!
//! - **Bounded backpressure.** Each topic is backed by a
//!   [`tokio::sync::broadcast`] channel of fixed capacity; when a consumer
//!   lags past that capacity the next read surfaces a [`BusError::Decode`]
//!   (carrying the lag-and-recover signal from broadcast's
//!   `RecvError::Lagged`). The producer's `send` itself never blocks on
//!   the receiver — broadcast is a non-backpressured fan-out — so this
//!   backend is appropriate for tests but **not** for production: real
//!   backends carry true backpressure via the network's flow control.
//! - **No lock guard across `.await`.** The topic registry is a
//!   [`tokio::sync::RwLock`] over a `HashMap`, but the publish and
//!   subscribe paths clone the `Sender` and drop the guard before any
//!   `.await`.
//! - **Same payload type per bus.** Each [`MemoryBus`] is generic over
//!   `T`; topics route by string but the payload type is fixed at
//!   construction (mirroring the trait's shape).

use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use futures::stream::{self, BoxStream};
use tokio::sync::{RwLock, broadcast};

use crate::bus::{BusError, BusErrorInner, EventBus, EventEnvelope};

/// Default per-topic broadcast capacity for [`MemoryBus::new_default`].
///
/// Sized for typical tests (a handful of producers, a handful of
/// consumers); production-shaped tests should pass an explicit capacity
/// via [`MemoryBus::new`].
pub const DEFAULT_CAPACITY: usize = 1024;

/// In-process event bus backed by [`tokio::sync::broadcast`].
///
/// Each topic has its own broadcast channel; new topics are lazily
/// allocated on first `publish` or `subscribe`. Subscribers receive
/// envelopes published **after** their subscription was established — this
/// matches the production semantics of NATS and Kafka with default
/// consumer-group settings.
///
/// `T` is the payload type and must be `Clone` because broadcast fans out
/// by cloning to each receiver.
pub struct MemoryBus<T>
where
    T: Clone + Send + Sync + 'static,
{
    capacity: usize,
    topics: Arc<RwLock<HashMap<String, broadcast::Sender<EventEnvelope<T>>>>>,
}

impl<T> std::fmt::Debug for MemoryBus<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryBus")
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl<T> MemoryBus<T>
where
    T: Clone + Send + Sync + 'static,
{
    /// Build a new [`MemoryBus`] with explicit per-topic capacity.
    ///
    /// `capacity` is the broadcast channel buffer size — i.e. how many
    /// envelopes can be in flight to a slow subscriber before the
    /// subscriber starts receiving "lagged" errors. `0` panics inside
    /// broadcast; the constructor coerces it up to `1`.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            topics: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Build a [`MemoryBus`] at [`DEFAULT_CAPACITY`].
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Look up the [`broadcast::Sender`] for `topic`, creating it if absent.
    ///
    /// Holds the [`RwLock`] only across `HashMap` work — no `.await`
    /// happens while the guard is live, satisfying the
    /// "no-MutexGuard-across-await" invariant.
    async fn sender_for(&self, topic: &str) -> broadcast::Sender<EventEnvelope<T>> {
        // Fast path: read lock + clone (broadcast::Sender is Clone-cheap).
        {
            let guard = self.topics.read().await;
            if let Some(tx) = guard.get(topic) {
                return tx.clone();
            }
        }
        // Slow path: write lock + or_insert_with. Re-check inside the
        // exclusive guard in case a concurrent caller created the topic
        // between our read drop and our write acquire.
        let mut guard = self.topics.write().await;
        guard
            .entry(topic.to_owned())
            .or_insert_with(|| broadcast::channel(self.capacity).0)
            .clone()
    }
}

impl<T> Default for MemoryBus<T>
where
    T: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new_default()
    }
}

#[async_trait::async_trait]
impl<T> EventBus<T> for MemoryBus<T>
where
    T: Clone + serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
{
    async fn publish(&self, topic: &str, envelope: EventEnvelope<T>) -> Result<(), BusError> {
        let tx = self.sender_for(topic).await;
        // `broadcast::Sender::send` returns `Err` only when there are zero
        // receivers; that's not a publisher-side failure in the memory
        // backend (no subscriber yet means the test hasn't wired one up
        // and is just stashing events for a later subscribe-then-publish
        // ordering). We swallow it deliberately and document that here.
        let _ = tx.send(envelope);
        Ok(())
    }

    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<BoxStream<'static, Result<EventEnvelope<T>, BusError>>, BusError> {
        let tx = self.sender_for(topic).await;
        let rx = tx.subscribe();
        // `stream::unfold` keeps the `broadcast::Receiver` owned inside the
        // stream state, avoiding a separate `tokio-stream` dependency. The
        // closure returns `None` once the sender side has been dropped
        // (every topic has at least the `MemoryBus`-held `Sender` until
        // the bus itself is dropped, so this naturally tracks bus
        // lifetime); receiver-lag is surfaced as a typed `BusError::Decode`
        // rather than silently dropping the gap.
        let stream = stream::unfold(rx, |mut rx| async move {
            match rx.recv().await {
                Ok(env) => Some((Ok(env), rx)),
                Err(broadcast::error::RecvError::Closed) => None,
                Err(err @ broadcast::error::RecvError::Lagged(_)) => Some((
                    Err(BusError::Decode {
                        version: 0,
                        source: BusErrorInner::new(err),
                    }),
                    rx,
                )),
            }
        });
        Ok(stream.boxed())
    }
}

#[cfg(test)]
// Allow `unwrap()` / `expect()` / `panic!` in tests so the workspace-level
// restriction lints (denied at `--all-targets`) do not flag the idiomatic
// Rust unit-test pattern.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::bus::WIRE_VERSION;

    /// A minimal payload type for the in-process bus tests. Real consumers
    /// will use [`crate::ingest::NormalizedEvent`]; we use a simple struct
    /// here so the tests don't depend on the firehose module.
    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Ping {
        n: u32,
    }

    /// Round-trip: every envelope published lands on a subscriber that
    /// subscribed first, in publish order.
    #[tokio::test]
    async fn round_trip_in_order() {
        let bus = MemoryBus::<Ping>::new(16);
        let mut sub = bus.subscribe("t").await.expect("subscribe");

        for n in 0..4 {
            bus.publish("t", EventEnvelope::new(i64::from(n), "test", Ping { n }))
                .await
                .expect("publish");
        }

        for n in 0..4 {
            let got = sub.next().await.expect("stream end").expect("decode");
            assert_eq!(got.payload.n, n);
            assert_eq!(got.seq, i64::from(n));
            assert_eq!(got.version, WIRE_VERSION);
            assert_eq!(got.source, "test");
        }
    }

    /// Two subscribers each receive a copy of every event.
    #[tokio::test]
    async fn multi_subscriber_fanout() {
        let bus = MemoryBus::<Ping>::new(16);
        let mut s1 = bus.subscribe("t").await.expect("subscribe s1");
        let mut s2 = bus.subscribe("t").await.expect("subscribe s2");

        bus.publish("t", EventEnvelope::new(1, "test", Ping { n: 42 }))
            .await
            .expect("publish");

        let g1 = s1.next().await.expect("s1 end").expect("s1 decode");
        let g2 = s2.next().await.expect("s2 end").expect("s2 decode");
        assert_eq!(g1.payload.n, 42);
        assert_eq!(g2.payload.n, 42);
    }

    /// Lagged subscribers surface a typed [`BusError::Decode`] rather
    /// than silently dropping. The producer's `publish` itself does not
    /// block (broadcast is non-backpressured) — this is the test that
    /// pins the documented semantics.
    #[tokio::test]
    async fn lagging_subscriber_surfaces_decode_error() {
        let bus = MemoryBus::<Ping>::new(2);
        let mut sub = bus.subscribe("t").await.expect("subscribe");

        // Overrun the buffer by a wide margin.
        for n in 0..16u32 {
            bus.publish("t", EventEnvelope::new(i64::from(n), "test", Ping { n }))
                .await
                .expect("publish");
        }

        // First read should be the typed lag error — the buffer holds
        // capacity=2 envelopes, and we pushed 16, so the receiver is
        // behind by 14 and broadcast surfaces `RecvError::Lagged`.
        let first = sub.next().await.expect("stream end");
        match first {
            Err(BusError::Decode { .. }) => {}
            other => panic!("expected Decode lag error, got {other:?}"),
        }
    }

    /// Independent topics don't see each other's traffic.
    #[tokio::test]
    async fn topic_isolation() {
        let bus = MemoryBus::<Ping>::new(8);
        let mut a = bus.subscribe("alpha").await.expect("sub alpha");
        let mut b = bus.subscribe("beta").await.expect("sub beta");

        bus.publish("alpha", EventEnvelope::new(0, "test", Ping { n: 1 }))
            .await
            .expect("publish alpha");
        bus.publish("beta", EventEnvelope::new(0, "test", Ping { n: 2 }))
            .await
            .expect("publish beta");

        let ga = a.next().await.expect("alpha end").expect("alpha decode");
        let gb = b.next().await.expect("beta end").expect("beta decode");
        assert_eq!(ga.payload.n, 1);
        assert_eq!(gb.payload.n, 2);

        // No cross-talk: neither stream has anything more queued. We
        // can't easily prove emptiness without a timeout, so we
        // instead publish a second event on `alpha` and confirm it's
        // the next thing `a` sees (not the `beta` payload).
        bus.publish("alpha", EventEnvelope::new(1, "test", Ping { n: 3 }))
            .await
            .expect("publish alpha 2");
        let ga2 = a
            .next()
            .await
            .expect("alpha end 2")
            .expect("alpha decode 2");
        assert_eq!(ga2.payload.n, 3);
    }
}
