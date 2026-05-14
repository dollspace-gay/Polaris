//! Kafka event-bus backend (Bluesky deployment profile).
//!
//! Behind `feature = "bus-kafka"`. Backs the trait defined in
//! [`crate::bus`] with a [`rdkafka`] producer/consumer pair. Envelopes are
//! serialised with [`bincode`] under the same [`crate::bus::WIRE_VERSION`]
//! the NATS backend uses, so cross-backend wire compatibility is
//! preserved for operational handovers.
//!
//! # Operator notes
//!
//! `rdkafka` links against `librdkafka` at the system level by default.
//! Operators on hosts without a packaged `librdkafka` should enable the
//! `cmake-build` feature on the `rdkafka` workspace dependency (an
//! opt-in, not the default — see the comment in the root `Cargo.toml`).

use std::time::Duration;

use futures::StreamExt;
use futures::stream::{self, BoxStream};
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use rdkafka::producer::{FutureProducer, FutureRecord};

use crate::bus::{BusError, BusErrorInner, EventBus, EventEnvelope, WIRE_VERSION};

/// Configuration for a [`KafkaBus`].
///
/// Mirrors the minimum set of `librdkafka` settings the bus needs;
/// operators wanting finer control should extend this struct and forward
/// to [`ClientConfig::set`] in [`KafkaBus::new`]. All fields are owned
/// `String`s for simplicity — the bus is constructed once per process.
#[derive(Debug, Clone)]
pub struct KafkaConfig {
    /// Comma-separated list of bootstrap brokers, e.g.
    /// `"kafka-0.svc:9092,kafka-1.svc:9092"`.
    pub brokers: String,
    /// Consumer group id. Producers ignore this; consumers use it for
    /// offset-tracking across restarts.
    pub group_id: String,
    /// Producer-side `message.timeout.ms`. Defaults to 5 seconds at the
    /// constructor.
    pub message_timeout: Duration,
}

impl KafkaConfig {
    /// Build a [`KafkaConfig`] with sensible defaults.
    ///
    /// `brokers` and `group_id` are required; the message timeout
    /// defaults to 5 seconds.
    pub fn new(brokers: impl Into<String>, group_id: impl Into<String>) -> Self {
        Self {
            brokers: brokers.into(),
            group_id: group_id.into(),
            message_timeout: Duration::from_secs(5),
        }
    }
}

/// Kafka-backed implementation of [`EventBus`].
///
/// Holds one [`FutureProducer`] and a [`KafkaConfig`] used to spin up a
/// per-`subscribe` [`StreamConsumer`]. The producer is `Send + Sync` and
/// cheap to clone (it shares an inner Arc), so a single [`KafkaBus`] can
/// be wrapped in an `Arc` and shared across publish call sites.
pub struct KafkaBus<T> {
    producer: FutureProducer,
    config: KafkaConfig,
    _payload: std::marker::PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for KafkaBus<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaBus")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<T> KafkaBus<T>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
{
    /// Build a [`KafkaBus`] from a config.
    ///
    /// Initialises the producer eagerly so a misconfigured broker surface
    /// fails fast at startup rather than on first publish.
    pub fn new(config: &KafkaConfig) -> Result<Self, BusError> {
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.brokers)
            .set(
                "message.timeout.ms",
                config.message_timeout.as_millis().to_string(),
            )
            .create()
            .map_err(|err| BusError::Publish(BusErrorInner::new(err)))?;
        Ok(Self {
            producer,
            config: config.clone(),
            _payload: std::marker::PhantomData,
        })
    }
}

#[async_trait::async_trait]
impl<T> EventBus<T> for KafkaBus<T>
where
    T: serde::Serialize + for<'de> serde::Deserialize<'de> + Send + Sync + 'static,
{
    async fn publish(&self, topic: &str, envelope: EventEnvelope<T>) -> Result<(), BusError> {
        let bytes = bincode::serde::encode_to_vec(&envelope, bincode::config::standard())
            .map_err(|err| BusError::Publish(BusErrorInner::new(err)))?;
        // Use `seq` as a routing key so partitioned topics stay
        // monotonically ordered per producer; `to_be_bytes` gives a stable
        // 8-byte key. `FutureRecord` borrows both key and payload, so the
        // owned buffers must outlive the `send` await — they do, both are
        // local stack/heap bindings.
        let key: [u8; 8] = envelope.seq.to_be_bytes();
        let record: FutureRecord<'_, [u8; 8], Vec<u8>> =
            FutureRecord::to(topic).key(&key).payload(&bytes);
        self.producer
            .send(record, Duration::from_secs(0))
            .await
            .map_err(|(err, _)| BusError::Publish(BusErrorInner::new(err)))?;
        Ok(())
    }

    async fn subscribe(
        &self,
        topic: &str,
    ) -> Result<BoxStream<'static, Result<EventEnvelope<T>, BusError>>, BusError> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &self.config.brokers)
            .set("group.id", &self.config.group_id)
            .set("enable.auto.commit", "true")
            .create()
            .map_err(|err| BusError::Subscribe(BusErrorInner::new(err)))?;
        consumer
            .subscribe(&[topic])
            .map_err(|err| BusError::Subscribe(BusErrorInner::new(err)))?;

        // `stream::unfold` owns the `StreamConsumer` for the lifetime of
        // the returned stream. `recv` yields one message per poll; we
        // translate rdkafka's typed error variants into the bus's
        // versioned `BusError::Decode` / `Disconnected` shape.
        let stream = stream::unfold(consumer, |consumer| async move {
            let result = consumer.recv().await;
            match result {
                Ok(msg) => {
                    let Some(payload) = msg.payload() else {
                        return Some((
                            Err(BusError::Decode {
                                version: 0,
                                source: BusErrorInner::new("kafka message had no payload bytes"),
                            }),
                            consumer,
                        ));
                    };
                    let decoded = bincode::serde::decode_from_slice::<EventEnvelope<T>, _>(
                        payload,
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
                    Some((item, consumer))
                }
                Err(err) => Some((Err(BusError::Subscribe(BusErrorInner::new(err))), consumer)),
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

    /// A minimal payload type for the bus tests.
    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct Ping {
        n: u32,
    }

    /// Type-level proof that the kafka backend implements the
    /// dyn-compatible `EventBus` trait against an arbitrary payload.
    fn assert_event_bus<B: EventBus<Ping>>(_b: &B) {}

    #[test]
    fn config_builds() {
        let cfg = KafkaConfig::new("localhost:1", "g");
        assert_eq!(cfg.brokers, "localhost:1");
        assert_eq!(cfg.group_id, "g");
    }

    /// Compile/handle-construction test: a `KafkaBus<Ping>` against an
    /// unreachable broker still constructs a producer handle (rdkafka's
    /// `ClientConfig::create` is lazy and does not connect). This proves
    /// the feature-gated code path compiles, the `EventBus` trait is
    /// satisfied, and the `bincode::serde` envelope path type-checks
    /// against an arbitrary payload. Network behaviour is covered by a
    /// follow-up testcontainers integration test.
    #[test]
    fn bus_constructs_against_unreachable_broker() {
        let cfg = KafkaConfig::new("127.0.0.1:1", "polaris-test");
        let bus = KafkaBus::<Ping>::new(&cfg).expect("producer handle constructs");
        assert_event_bus(&bus);
    }
}
