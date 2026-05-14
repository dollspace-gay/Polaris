//! NATS event-bus backend (labeler deployment profile, default).
//!
//! Behind `feature = "bus-nats"` and selected by the workspace default.
//! Backs the trait defined in [`crate::bus`] with an
//! [`async_nats::Client`]. Envelopes are serialised with [`bincode`]
//! under the same [`crate::bus::WIRE_VERSION`] the Kafka backend uses,
//! so cross-backend wire compatibility is preserved for operational
//! handovers.
//!
//! NATS' "core" subjects do not persist messages by default; consumers
//! receive only what is published while they are subscribed (matching
//! the [`crate::bus::memory::MemoryBus`] semantics). Operators wanting
//! durable replay should configure `JetStream` consumers at the NATS layer
//! — the abstraction is intentionally below that decision so durability
//! stays an operational toggle, not a code change.

use bytes::Bytes;
use futures::StreamExt;
use futures::stream::{self, BoxStream};

use crate::bus::{BusError, BusErrorInner, EventBus, EventEnvelope, WIRE_VERSION};

/// Configuration for a [`NatsBus`].
#[derive(Debug, Clone)]
pub struct NatsConfig {
    /// Server URL, e.g. `"nats://localhost:4222"`. Multiple URLs are
    /// comma-separated and forwarded to `async_nats::connect` as-is.
    pub url: String,
}

impl NatsConfig {
    /// Build a [`NatsConfig`] from a single URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

/// NATS-backed implementation of [`EventBus`].
///
/// Holds one [`async_nats::Client`] (an `Arc`-internal handle that is
/// `Clone`); a single [`NatsBus`] can be wrapped in an `Arc` and shared
/// across publish call sites without contention.
pub struct NatsBus<T> {
    client: async_nats::Client,
    _payload: std::marker::PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for NatsBus<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsBus").finish_non_exhaustive()
    }
}

impl<T> NatsBus<T>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
{
    /// Connect to NATS using `config`.
    ///
    /// Eagerly establishes the connection so a misconfigured server URL
    /// surfaces at startup rather than first publish.
    pub async fn connect(config: &NatsConfig) -> Result<Self, BusError> {
        let client = async_nats::connect(&config.url)
            .await
            .map_err(|err| BusError::Subscribe(BusErrorInner::new(err)))?;
        Ok(Self {
            client,
            _payload: std::marker::PhantomData,
        })
    }
}

#[async_trait::async_trait]
impl<T> EventBus<T> for NatsBus<T>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
{
    async fn publish(&self, topic: &str, envelope: EventEnvelope<T>) -> Result<(), BusError> {
        let bytes = bincode::serde::encode_to_vec(&envelope, bincode::config::standard())
            .map_err(|err| BusError::Publish(BusErrorInner::new(err)))?;
        self.client
            .publish(topic.to_owned(), Bytes::from(bytes))
            .await
            .map_err(|err| BusError::Publish(BusErrorInner::new(err)))?;
        Ok(())
    }

    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<BoxStream<'static, Result<EventEnvelope<T>, BusError>>, BusError> {
        let subscriber = self
            .client
            .subscribe(topic.to_owned())
            .await
            .map_err(|err| BusError::Subscribe(BusErrorInner::new(err)))?;

        // `stream::unfold` owns the `Subscriber` (which itself implements
        // `Stream<Item = Message>`); driving it via `unfold` lets us
        // translate each `Message` into our versioned envelope shape
        // without leaking the `async_nats::Message` type into the public
        // surface.
        let stream = stream::unfold(subscriber, |mut sub| async move {
            let msg = sub.next().await?;
            let decoded = bincode::serde::decode_from_slice::<EventEnvelope<T>, _>(
                &msg.payload,
                bincode::config::standard(),
            );
            let item = match decoded {
                Ok((env, _)) => {
                    if env.version == WIRE_VERSION {
                        Ok(env)
                    } else {
                        Err(BusError::Decode {
                            version: env.version,
                            source: BusErrorInner::new(format!(
                                "wire version {} not supported by consumer {}",
                                env.version, WIRE_VERSION
                            )),
                        })
                    }
                }
                Err(err) => Err(BusError::Decode {
                    version: 0,
                    source: BusErrorInner::new(err),
                }),
            };
            Some((item, sub))
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

    /// Compile-test: a `NatsBus<Ping>::connect` against an unreachable
    /// server returns a typed `BusError::Subscribe` (no panic, no
    /// `unwrap`), proving the feature-gated path compiles and the error
    /// translation is exhaustive.
    ///
    /// A testcontainers-driven NATS fixture lands as a follow-up.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct Ping {
        n: u32,
    }

    #[test]
    fn config_builds() {
        let cfg = NatsConfig::new("nats://example:4222");
        assert_eq!(cfg.url, "nats://example:4222");
    }

    #[tokio::test]
    async fn connect_returns_typed_error_on_bad_url() {
        // Port 1 is reserved and will refuse on every platform.
        let cfg = NatsConfig::new("nats://127.0.0.1:1");
        let res = NatsBus::<Ping>::connect(&cfg).await;
        assert!(matches!(res, Err(BusError::Subscribe(_))));
    }
}
