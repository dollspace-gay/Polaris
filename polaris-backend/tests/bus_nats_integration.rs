//! NATS event-bus backend: testcontainers-driven integration test for
//! issue #56.
//!
//! Boots a NATS server via `testcontainers_modules::nats::Nats`,
//! constructs a [`polaris_backend::bus::nats::NatsBus`] pointing at the
//! container's `nats://<host>:<port>` URL, and exercises the full
//! publish → subscribe → bincode-decode round trip end-to-end. The
//! compile-only tests in `src/bus/nats.rs` already pin the trait shape
//! and the unreachable-server error translation; this file lands the
//! live-server contract that the architect's pre-flight pulled out of
//! the original #16 dispatch.
//!
//! # What this test proves
//!
//! 1. The NATS backend round-trips [`EventEnvelope`] payloads through a
//!    real server: 10 published envelopes arrive on the subscriber stream,
//!    in `seq` order, with byte-identical payloads.
//! 2. Backpressure / drop-before-subscribe invariant: NATS *core*
//!    subjects do not persist messages, so envelopes published BEFORE
//!    the subscription is established are dropped — the bus module's
//!    documentation calls this out explicitly (`src/bus/nats.rs`:
//!    "NATS' 'core' subjects do not persist messages by default;
//!    consumers receive only what is published while they are
//!    subscribed"). We pin that contract here so a regression that
//!    accidentally switches the backend to JetStream-replay semantics
//!    fails this test.
//!
//! # Skip behaviour
//!
//! If Docker is not reachable on the host, the test prints a clear
//! `SKIP` line and returns successfully — same convention as
//! `tests/db_smoke.rs`. The compile-time check (`cargo test --no-run`)
//! always passes; only the runtime is environment-dependent.
//!
//! # Wall-budget
//!
//! NATS starts in <5 s on a warm machine; per-step `tokio::time::timeout`
//! guards cap the receive loop at 30 s so a stuck server fails the test
//! rather than hanging CI indefinitely.
//!
//! # Feature gate
//!
//! Entire file is `#[cfg(feature = "bus-nats")]` — without the feature
//! the `polaris_backend::bus::nats` module is not compiled, so the test
//! correctly fails to build only when the user has not opted into the
//! NATS backend.

#![cfg(feature = "bus-nats")]
// Integration-test code is allowed to panic on the failure paths —
// the workspace-level restriction lints (`unwrap_used`, `expect_used`,
// `panic`) are denied at `--all-targets`, so opt out at the file level
// per the rust-quality §7 convention.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::process::Command;
use std::time::Duration;

use futures::StreamExt;
use polaris_backend::bus::EventBus;
use polaris_backend::bus::nats::{NatsBus, NatsConfig};
use polaris_backend::bus::{EventEnvelope, WIRE_VERSION};
use testcontainers_modules::nats::Nats;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// Probe for a working Docker daemon. Matches the `docker info` exit-code
/// check used by `tests/db_smoke.rs` so the skip convention is uniform
/// across the integration suite.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A minimal payload type for the bus tests. Real consumers will use
/// `polaris_backend::ingest::NormalizedEvent`; we use a simple struct here
/// so the test does not depend on the firehose module.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct Ping {
    n: u32,
}

/// Round-trip 10 envelopes through a live NATS server and assert
/// in-order delivery + byte-identical payload + version stamp; then
/// pin the "core NATS drops messages published before subscribe"
/// contract.
///
/// Wall-budget: 30 s for server boot + receive loop. A stuck server
/// fails the test (via `tokio::time::timeout`) rather than hanging CI.
#[tokio::test]
async fn nats_round_trip_and_backpressure() -> Result<(), Box<dyn std::error::Error>> {
    /// Number of envelopes in the round-trip batch.
    const N: u32 = 10;
    /// Number of envelopes in the backpressure-burst batch.
    const BURST: u32 = 50;

    if !docker_available() {
        println!(
            "SKIP bus_nats_integration: docker daemon not reachable. \
             Install docker or run in CI with the docker-in-docker service \
             to exercise this test."
        );
        return Ok(());
    }

    // Boot a fresh NATS server. The module image waits on the
    // `Server is ready` log line so `.start().await` returns only once
    // the server is listening for client connections.
    let container = Nats::default().start().await?;
    let host = container.get_host().await?;
    let host_port = container.get_host_port_ipv4(4222).await?;
    let url = format!("nats://{host}:{host_port}");

    let config = NatsConfig::new(&url);
    let bus = NatsBus::<Ping>::connect(&config)
        .await
        .expect("NatsBus connects");

    // One topic per test run keeps the per-test server hermetic.
    // NATS subjects do not require pre-creation; the random suffix
    // ensures concurrent test runs against a shared container do not
    // see each other's traffic.
    let topic = format!("polaris.bus.nats.{}", uuid::Uuid::new_v4().simple());

    // Drop-before-subscribe contract: publish 5 envelopes BEFORE
    // subscribing. Core NATS does not persist, so the consumer must NOT
    // receive these later. If a regression accidentally switches the
    // backend to JetStream-replay semantics this assertion fires.
    for i in 0..5_i64 {
        let envelope = EventEnvelope::new(-1 - i, "nats-integration-test-prelude", Ping { n: 999 });
        bus.publish(&topic, envelope)
            .await
            .expect("pre-subscribe publish");
    }

    let mut stream = bus.subscribe(&topic).await.expect("subscribe");

    // Give the NATS client's subscribe roundtrip time to reach the
    // server before publishing the round-trip batch. `async_nats`'
    // `subscribe()` awaits an internal SUB-ack frame, but a fresh
    // connection may still need a tick for the server to wire the
    // subscription into its routing table. 250 ms is generous on a
    // warm container; the outer 30 s receive timeout still bounds
    // the worst case.
    tokio::time::sleep(Duration::from_millis(250)).await;

    // Publish `N` envelopes with monotonically increasing `seq`.
    for i in 0..N {
        let envelope = EventEnvelope::new(i64::from(i), "nats-integration-test", Ping { n: i });
        bus.publish(&topic, envelope).await.expect("publish");
    }

    // Assert in-order delivery + byte-identical payload + version stamp.
    // Each `next()` is wrapped in a per-message timeout so a stuck
    // subscriber fails fast instead of hanging the test runner.
    for expected_n in 0..N {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("receive timeout")
            .expect("stream end")
            .expect("decode error");
        assert_eq!(
            item.seq,
            i64::from(expected_n),
            "envelope arrived out of order"
        );
        assert_eq!(item.version, WIRE_VERSION, "wire version mismatch");
        assert_eq!(item.source, "nats-integration-test");
        assert_eq!(item.payload, Ping { n: expected_n });
    }

    // Backpressure assertion: publish a second burst and verify all
    // envelopes still arrive on a (fast) consumer. NATS' per-subscription
    // mpsc channel has a default capacity of 64 KiB in `async_nats`
    // 0.48; the bus's `NatsBus::publish` awaits on `client.publish` so
    // the producer blocks on the connection's write buffer rather than
    // dropping. We publish 50 — far below subscriber capacity but
    // enough to exceed any single I/O batch — and assert all are
    // delivered. The "drop-on-slow-consumer" edge is the NATS server's
    // own posture (it disconnects slow consumers); proving the
    // non-edge case here pins the bus's "no silent drop on the fast
    // path" invariant. The drop-before-subscribe contract above
    // already pins the drop semantics for the documented edge.
    for i in 0..BURST {
        let n = N + i;
        let envelope = EventEnvelope::new(i64::from(n), "nats-integration-test", Ping { n });
        bus.publish(&topic, envelope).await.expect("publish burst");
    }

    for expected_n in N..(N + BURST) {
        let item = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await
            .expect("burst receive timeout")
            .expect("burst stream end")
            .expect("burst decode error");
        assert_eq!(
            item.seq,
            i64::from(expected_n),
            "burst envelope arrived out of order"
        );
        assert_eq!(item.payload, Ping { n: expected_n });
    }

    Ok(())
}
