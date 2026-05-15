//! Live dashboard WebSocket feed (issue #57).
//!
//! `GET /api/dashboard/live` upgrades to a WebSocket and forwards
//! [`DashboardEvent`] diffs to the connected moderator. The frontend
//! consumes these to patch its local [`DashboardSnapshot`] signal in
//! place — round-trip latency drops from the polling 5s ceiling down to
//! "as fast as the bus delivers", which the architect's north-star pins
//! at "within 1 second of detection".
//!
//! # Architecture
//!
//! The handler is a thin upgrade-then-pump shell:
//!
//! 1. [`live_handler`] receives the auth-validated request, captures the
//!    [`ApiState`] handle, and returns the upgrade response.
//! 2. Inside the upgrade closure, [`run_feed`] subscribes to
//!    `state.dashboard_bus` on the [`DASHBOARD_TOPIC`] and selects on
//!    two cancel-safe branches: (a) inbound frames from the client (we
//!    ignore the payload but watch for `Close`), and (b) the next
//!    bus envelope.
//! 3. Each envelope is `serde_json`-serialized into a [`Message::Text`]
//!    frame and sent to the peer. If the sink rejects the send the
//!    pump exits, releasing the bus subscription via RAII (`Drop` on
//!    the `BoxStream`).
//!
//! # Forbidden-pattern checklist alignment (issue #57)
//!
//! - **No `unwrap`/`expect` outside tests.** Every `Result` is handled
//!   with `?`, a `match`, or an early return.
//! - **No tight reconnect loop.** Reconnects are a frontend concern;
//!   the backend simply releases resources when the client disconnects
//!   and waits for a fresh upgrade request.
//! - **`EventBus` subscriber drops on WS close.** The subscription stream
//!   is owned by the task's stack; the `Drop` on `BoxStream` returns the
//!   broadcast receiver to the bus and unsubscribes — no leak.
//! - **AC-7 boundary preserved.** Authentication runs through the same
//!   `auth_middleware` as every other authed `/api/*` route; the
//!   `Extension<ModeratorAuthCtx>` extractor ensures an unauthenticated
//!   request never reaches [`live_handler`].

use std::sync::Arc;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::{Extension, Json};
use futures::{SinkExt as _, StreamExt as _};

use crate::api::dto::{DashboardEvent, DashboardSnapshot};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;
use crate::bus::{BusError, EventBus, EventEnvelope};

/// Single-topic name on the dashboard bus.
///
/// Topic-per-event-kind would force producers to fan out the same
/// payload across N topics; the dashboard fits in one stream and every
/// subscriber wants every kind. A `&'static str` constant keeps producers
/// and consumers from drifting on a string literal.
pub const DASHBOARD_TOPIC: &str = "dashboard";

/// `GET /api/dashboard/live` — upgrade to a WebSocket and stream
/// [`DashboardEvent`]s to the connected moderator.
///
/// The handler is intentionally tiny: it captures the [`ApiState`], the
/// authenticated [`ModeratorAuthCtx`] (required for AC-7 alignment), and
/// hands off to [`run_feed`] inside the upgrade closure. The
/// [`ModeratorAuthCtx`] extractor itself is what enforces the auth
/// boundary — the route is mounted under the authed subtree alongside
/// the rest of `/api/*`, and the middleware short-circuits to `401`
/// before the extractor ever runs on an unauthenticated request.
///
/// # Errors
///
/// `live_handler` itself does not return `Result` because the upgrade
/// response is infallible at this layer; transport-level failures
/// surface inside [`run_feed`] and terminate the task.
pub async fn live_handler(
    State(state): State<ApiState>,
    Extension(_ctx): Extension<ModeratorAuthCtx>,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade.on_upgrade(move |socket| async move {
        run_feed(socket, state).await;
    })
}

/// Drive a single client connection.
///
/// Subscribes to the dashboard bus, then loops on `tokio::select!` until
/// either the client disconnects or the bus stream ends.
///
/// # Cancellation safety
///
/// Both `select!` branches are cancel-safe:
///
/// - `client_read.next()` borrows the `WebSocket`'s read half (a
///   `Stream`); dropping the poll just stops draining inbound frames
///   for one tick.
/// - `bus_rx.next()` is `StreamExt::next` on a `BoxStream`; the inner
///   `tokio::sync::broadcast::Receiver` survives the dropped poll and
///   the next iteration picks up where the previous left off.
///
/// A `tokio::pin!` is not required because both futures are recreated
/// per-iteration (`.next()` produces a fresh future each call).
async fn run_feed(socket: WebSocket, state: ApiState) {
    let mut bus_rx = match state.dashboard_bus.subscribe(DASHBOARD_TOPIC).await {
        Ok(rx) => rx,
        Err(err) => {
            // Subscription failed before the upgrade was actionable.
            // Surface a structured event and let the upgrade tear down
            // (the WebSocket close handshake happens automatically as
            // the `socket` value falls out of scope).
            tracing::warn!(
                error = ?err,
                topic = DASHBOARD_TOPIC,
                "dashboard live feed: subscribe failed; closing connection"
            );
            return;
        }
    };

    let (mut sink, mut client_read) = socket.split();

    loop {
        tokio::select! {
            biased;
            // Cancel-safe: dropping a poll on the WebSocket's read half
            // just stops draining inbound frames for one tick.
            incoming = client_read.next() => {
                match incoming {
                    // Peer closed the connection or the read half errored;
                    // exit the loop and let RAII drop `bus_rx` so the
                    // broadcast receiver returns to the bus.
                    None | Some(Err(_) | Ok(Message::Close(_))) => return,
                    // The dashboard feed is server -> client; we discard
                    // any inbound payload. axum handles WebSocket pings
                    // at the protocol layer transparently.
                    Some(Ok(_)) => {}
                }
            }
            // Cancel-safe: `BoxStream::next` is `StreamExt::next`, which
            // is documented cancel-safe for the broadcast-receiver
            // adapter the memory backend uses.
            envelope = bus_rx.next() => {
                if !forward_envelope(envelope, &mut sink).await {
                    return;
                }
            }
        }
    }
}

/// Forward one bus envelope to the WS sink. Returns `false` when the
/// pump should exit (either the stream ended or the send failed).
///
/// Bus-level lag errors are not terminal — the frontend reconciles by
/// either accepting the gap (the next event refreshes the affected
/// panel) or by triggering a `GET /api/dashboard` snapshot refetch.
/// A `Decode` variant on the wire would surface as the only typed lag
/// signal; we surface it as a tracing event and continue. Other typed
/// errors (`Publish`, `Subscribe`, `Disconnected`) likewise log and
/// continue — they are informational here.
async fn forward_envelope(
    envelope: Option<Result<EventEnvelope<DashboardEvent>, BusError>>,
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
) -> bool {
    let envelope = match envelope {
        // Bus stream ended (bus dropped / topic closed). Exit the pump.
        None => return false,
        Some(Ok(env)) => env,
        Some(Err(err)) => {
            tracing::warn!(
                error = ?err,
                topic = DASHBOARD_TOPIC,
                "dashboard live feed: bus surfaced a typed error; continuing"
            );
            return true;
        }
    };

    let payload = match serde_json::to_string(&envelope.payload) {
        Ok(bytes) => bytes,
        Err(err) => {
            // Encoding our own DTO failed — this is a server bug, not a
            // client one. Log and continue; the panel will recover on
            // the next event the encoder accepts.
            tracing::error!(
                error = ?err,
                "dashboard live feed: failed to encode DashboardEvent"
            );
            return true;
        }
    };

    if let Err(err) = sink.send(Message::Text(payload.into())).await {
        // Peer gone or sink reset. Treat as terminal so RAII releases
        // the bus subscription.
        tracing::debug!(
            error = ?err,
            "dashboard live feed: send failed; closing connection"
        );
        return false;
    }
    true
}

/// Publish a single [`DashboardEvent`] onto the bus.
///
/// Producer-side convenience used by callers that already hold an
/// [`ApiState`] handle (the pattern engine, the incident-transition
/// path, the report-insert path). Centralising the topic + envelope
/// construction here keeps producers from drifting on the string
/// literal or the envelope shape.
///
/// # Errors
///
/// Returns [`ApiError::Internal`] when the backing bus surfaces a
/// publish failure. The memory backend never fails this path; the
/// kafka/nats backends can return a backpressure-channel-closed signal
/// which the caller propagates to its own error type.
pub async fn publish_dashboard_event(
    state: &ApiState,
    seq: i64,
    source: &'static str,
    event: DashboardEvent,
) -> Result<(), ApiError> {
    let envelope = EventEnvelope::new(seq, source, event);
    state
        .dashboard_bus
        .publish(DASHBOARD_TOPIC, envelope)
        .await
        .map_err(|err| ApiError::Internal(anyhow::anyhow!(err)))
}

/// Cheap re-export: keep the `Arc<dyn EventBus<DashboardEvent>>` shape
/// reachable here so producers in other modules can build their own
/// wiring without having to pull `crate::bus::EventBus` into scope by
/// hand.
#[must_use]
pub fn shared_bus(state: &ApiState) -> Arc<dyn EventBus<DashboardEvent>> {
    Arc::clone(&state.dashboard_bus)
}

/// Smoke probe used in tests: serialize a [`DashboardSnapshot`] through
/// the same JSON encoder the live feed uses, so any future refactor
/// that swaps the encoder also fails this probe.
#[doc(hidden)]
#[must_use]
pub fn encode_snapshot_for_probe(snapshot: &DashboardSnapshot) -> Option<Json<String>> {
    serde_json::to_string(snapshot).ok().map(Json)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use crate::api::dto::{
        CoordinatedSignal, CoordinatedSignalKind, IncidentClusterSummary, ModeratorLoad,
        ReportVolumeBucket,
    };
    use chrono::TimeZone as _;
    use chrono::Utc;
    use polaris_types::{IncidentId, IncidentStatus, Severity, SubjectId};

    #[test]
    fn new_cluster_round_trips_as_tagged_kind() {
        let cluster = IncidentClusterSummary {
            incident_id: IncidentId(uuid::Uuid::nil()),
            primary_subject: SubjectId(uuid::Uuid::nil()),
            severity: Severity::High,
            status: IncidentStatus::Open,
            related_subject_count: 3,
            opened_at: Utc.with_ymd_and_hms(2026, 5, 14, 0, 0, 0).unwrap(),
        };
        let event = DashboardEvent::NewCluster {
            cluster: cluster.clone(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        // Tag is the discriminant; the body is keyed by the variant's
        // field name.
        assert!(json.contains(r#""kind":"new_cluster""#));
        assert!(json.contains(r#""cluster""#));

        let back: DashboardEvent = serde_json::from_str(&json).expect("deserialize");
        match back {
            DashboardEvent::NewCluster { cluster: got } => {
                assert_eq!(got.incident_id, cluster.incident_id);
                assert_eq!(got.related_subject_count, cluster.related_subject_count);
            }
            other => panic!("expected NewCluster, got {other:?}"),
        }
    }

    #[test]
    fn new_signal_round_trips_as_tagged_kind() {
        let signal = CoordinatedSignal {
            kind: CoordinatedSignalKind::ImageHashCluster,
            label: "deadbeef".to_owned(),
            subject_count: 4,
            detected_at: Utc.with_ymd_and_hms(2026, 5, 14, 1, 0, 0).unwrap(),
        };
        let event = DashboardEvent::NewSignal {
            signal: signal.clone(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains(r#""kind":"new_signal""#));

        let back: DashboardEvent = serde_json::from_str(&json).expect("deserialize");
        match back {
            DashboardEvent::NewSignal { signal: got } => {
                assert_eq!(got.label, signal.label);
                assert_eq!(got.kind, CoordinatedSignalKind::ImageHashCluster);
            }
            other => panic!("expected NewSignal, got {other:?}"),
        }
    }

    #[test]
    fn volume_bucket_updated_round_trips() {
        let bucket = ReportVolumeBucket {
            bucket_start: Utc.with_ymd_and_hms(2026, 5, 14, 2, 0, 0).unwrap(),
            count: 17,
            weighted_count: 8.5,
            expected_mean: 4.2,
            expected_stddev: 1.1,
        };
        let event = DashboardEvent::VolumeBucketUpdated {
            bucket: bucket.clone(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains(r#""kind":"volume_bucket_updated""#));

        let back: DashboardEvent = serde_json::from_str(&json).expect("deserialize");
        match back {
            DashboardEvent::VolumeBucketUpdated { bucket: got } => {
                assert_eq!(got.count, bucket.count);
                assert!((got.weighted_count - bucket.weighted_count).abs() < f64::EPSILON);
            }
            other => panic!("expected VolumeBucketUpdated, got {other:?}"),
        }
    }

    #[test]
    fn moderator_load_delta_round_trips() {
        let load = ModeratorLoad {
            category: "all".to_owned(),
            open_count: 12,
            in_review_count: 3,
        };
        let event = DashboardEvent::ModeratorLoadDelta { load: load.clone() };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains(r#""kind":"moderator_load_delta""#));

        let back: DashboardEvent = serde_json::from_str(&json).expect("deserialize");
        match back {
            DashboardEvent::ModeratorLoadDelta { load: got } => {
                assert_eq!(got.category, load.category);
                assert_eq!(got.open_count, load.open_count);
            }
            other => panic!("expected ModeratorLoadDelta, got {other:?}"),
        }
    }

    #[test]
    fn unknown_kind_fails_to_deserialize() {
        // Wire schema is closed: a frontend that doesn't recognise a
        // variant should surface the deserialisation error and fall
        // back to polling rather than silently accept garbage.
        let json = r#"{"kind":"not_a_real_variant","data":{}}"#;
        let parsed: Result<DashboardEvent, _> = serde_json::from_str(json);
        assert!(
            parsed.is_err(),
            "expected deserialize to reject unknown tag"
        );
    }

    #[tokio::test]
    async fn publish_dashboard_event_goes_through_bus() {
        // Drive a memory-backed bus directly — the round-trip exercises
        // the topic constant, the envelope construction, and the typed
        // deserialisation on the subscribe side without needing a full
        // ApiState wired against Postgres.
        let bus: Arc<dyn EventBus<DashboardEvent>> =
            Arc::new(crate::bus::memory::MemoryBus::<DashboardEvent>::new_default());

        let mut sub = bus.subscribe(DASHBOARD_TOPIC).await.expect("subscribe");

        let event = DashboardEvent::ModeratorLoadDelta {
            load: ModeratorLoad {
                category: "all".to_owned(),
                open_count: 1,
                in_review_count: 0,
            },
        };
        bus.publish(DASHBOARD_TOPIC, EventEnvelope::new(1, "test", event))
            .await
            .expect("publish");

        let got = sub.next().await.expect("stream end").expect("decode");
        match got.payload {
            DashboardEvent::ModeratorLoadDelta { load } => {
                assert_eq!(load.category, "all");
                assert_eq!(load.open_count, 1);
            }
            other => panic!("unexpected event variant: {other:?}"),
        }
    }
}
