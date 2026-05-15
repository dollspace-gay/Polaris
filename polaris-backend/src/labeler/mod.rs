//! Polaris-as-labeler XRPC endpoints (issue #26).
//!
//! Hosts `com.atproto.label.subscribeLabels` (WebSocket) and
//! `com.atproto.label.queryLabels` (HTTP GET) against the same Axum router
//! the first-party `/api/*` surface lives on. These endpoints are the
//! downstream-facing contract REQ-1 / AC-1 of
//! `.design/polaris-proto-blue-integration.md` describes: external
//! `AppViews` and other labelers subscribe to Polaris without Polaris
//! credentials.
//!
//! # Architecture
//!
//! Per the architect's pre-flight, the implementation deliberately stays
//! lighter than mounting the full `proto_blue_xrpc::server::XrpcServer`
//! machinery for this single endpoint pair:
//!
//! - **Persistence** — every `Label` is a row in the `labels` table
//!   (migration `00000000000012_labels.sql`). `seq` is `BIGSERIAL`, the
//!   stable ordering primitive subscribers track.
//! - **Backfill** — the WebSocket handler first drains rows with
//!   `seq > cursor` ordered by `seq` from Postgres, so a reconnecting
//!   consumer never misses persisted labels.
//! - **Live fan-out** — a process-local `tokio::sync::broadcast` channel
//!   (`LabelBroadcaster`) carries fresh inserts to every connected
//!   subscriber. #28's signing-and-emit path is the only caller of
//!   `LabelBroadcaster::publish`.
//! - **Framing** — atproto's subscription protocol concatenates two
//!   DAG-CBOR values per binary WebSocket message: a header
//!   `{op: 1, t: "#labels"}` and a body `{seq, labels: [...]}`. We
//!   encode both via [`proto_blue::ws::Frame::encode`] so the resulting
//!   bytes are strict DAG-CBOR canonical (map keys ordered by byte-length
//!   then lexicographically, shortest integer encodings, `bytes`-typed
//!   `sig`). The reference decoder ATProto consumers reach for
//!   (`MessageFrame::decode`) rejects any non-canonical encoding, so
//!   #58's live WebSocket client harness uses it as the wire-format
//!   conformance gate.
//!
//! Label signing is **not** done here; this issue ships the consumer
//! endpoints and the persistence shape. The signed-bytes column (`sig`)
//! is populated by #28's signer.
//!
//! # Routing
//!
//! `server::router` returns a `Router<()>` mounted on the public subtree
//! by [`crate::api::router`]. The endpoints are intentionally NOT
//! auth-gated — downstream `AppViews` are the unauthenticated audience
//! for the labeler service.

pub mod canonicalize;
pub mod emitter;
pub mod rotation;
pub mod server;
pub mod signer;
pub mod verify;

/// Errors raised by the labeler subsystem.
///
/// The variant set is intentionally tight: a labeler endpoint should only
/// fail because of a database error, a request-parse error, or a
/// broadcast-channel error. Everything else is either a programming
/// invariant (handled by an upstream `Result` chain) or an HTTP-layer
/// concern Axum already maps cleanly.
#[derive(Debug, thiserror::Error)]
pub enum LabelerError {
    /// Underlying repo / Postgres error.
    #[error("database error")]
    Database(#[source] sqlx::Error),
    /// CBOR encoding of a subscription frame failed.
    ///
    /// This should be unreachable in practice — every `Label` field is
    /// serialisable — but a typed variant keeps the WebSocket pump from
    /// having to panic on a serializer surprise.
    #[error("failed to encode subscription frame")]
    FrameEncode,
    /// Request rejected at the validation layer (e.g. missing `uris`).
    #[error("bad request: {0}")]
    BadRequest(&'static str),
}

impl From<sqlx::Error> for LabelerError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}
