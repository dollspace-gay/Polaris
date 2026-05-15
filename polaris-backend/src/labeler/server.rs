//! Labeler subscription + query endpoints (issue #26).
//!
//! See the [module-level docs](crate::labeler) for the architectural
//! overview. This file contains:
//!
//! - The [`Label`] row shape and [`NewLabel`] insert input.
//! - The [`LabelRepo`] trait + [`PgLabelRepo`] Postgres impl (insert,
//!   `query_by_uris`, `stream_from_cursor` — all compile-time-checked SQL).
//! - The [`LabelBroadcaster`] process-local fan-out wrapper around
//!   `tokio::sync::broadcast`.
//! - The HTTP handler for `com.atproto.label.queryLabels`
//!   ([`query_labels`]).
//! - The WebSocket handler for `com.atproto.label.subscribeLabels`
//!   ([`subscribe_labels`]), with the backfill-then-live cursor pump.
//! - [`router`]: assembles both endpoints into a `Router<ApiState>`-style
//!   tree the API router merges into its public subtree.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
// `axum_extra::extract::Query` (vs. axum's built-in `axum::extract::Query`)
// decodes repeated query parameters into a `Vec<T>` via the `serde_html_form`
// backend. atproto's `queryLabels` lexicon specifies `uris` as a repeated
// parameter (`?uris=at://...&uris=at://...`); axum's stock `Query` uses
// `serde_urlencoded` which only keeps the LAST occurrence of a repeated key
// and refuses to decode into a `Vec`. axum-extra is workspace-pinned at 0.10
// with the `query` feature enabled at the root `Cargo.toml`.
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum_extra::extract::Query;
use chrono::{DateTime, Utc};
use futures::{SinkExt as _, StreamExt as _};
use proto_blue::lex_data::LexValue;
use proto_blue::ws::{Frame, MessageFrame};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::api::state::ApiState;
use crate::labeler::LabelerError;

// ── public types ────────────────────────────────────────────────────────

/// Default broadcaster capacity. 1024 is large enough that a transient
/// scheduler delay on a single slow subscriber will not lap the channel,
/// while bounded enough that a stuck subscriber surfaces as a `Lagged`
/// error rather than ballooning process memory.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 1024;

/// A persisted label, as stored in the `labels` table.
///
/// Field ordering and naming track `com.atproto.label.defs::Label` so the
/// JSON/CBOR serialisation can be wire-fed directly to subscribers and
/// queryLabels consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Label {
    /// Stable per-row identifier (UUID primary key).
    #[serde(skip)]
    pub id: Uuid,
    /// Monotonic per-row sequence number. The subscription cursor.
    pub seq: i64,
    /// DID of the labeler that issued this label.
    pub src: String,
    /// AT-URI or DID of the labeled subject.
    pub uri: String,
    /// Optional content CID — pins the label to a specific record
    /// revision when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// Label value (e.g. `spam`, `!hide`).
    pub val: String,
    /// Negation flag — `true` retracts a prior assertion of `val`.
    pub neg: bool,
    /// Server-assigned creation timestamp.
    pub cts: DateTime<Utc>,
    /// Optional expiration timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<DateTime<Utc>>,
    /// K-256 signature over the canonical DAG-CBOR encoding of the
    /// unsigned-`sig` Label payload. Exactly 64 bytes (compact `r || s`),
    /// enforced by the `labels_signature_len` CHECK in migration 13.
    ///
    /// Serialises as a JSON array of bytes via `serde_json` (the
    /// `queryLabels` response shape) and as DAG-CBOR `bytes` on the
    /// `subscribeLabels` frame body (see [`label_to_lex`]). The on-the-wire
    /// `label_cbor` column is the byte-identical canonical CBOR that
    /// produced this signature — see [`Self::label_cbor`].
    pub sig: Vec<u8>,
    /// The subject DID denormalised from `action -> incident -> subject`.
    /// `subscribeLabels`-side operator queries ("labels emitted for this
    /// did") read this column rather than join three tables.
    #[serde(skip)]
    pub subject_did: String,
    /// The full canonical DAG-CBOR encoding of the Label record exactly
    /// as it was signed. Re-distributing this byte-string on the wire
    /// lets downstream consumers verify [`Self::sig`] against bytes that
    /// never passed through a re-serialisation step.
    #[serde(skip)]
    pub label_cbor: Vec<u8>,
    /// `did:key:z…` form of the public key the signature was produced
    /// under. Pinned per row so post-rotation labels stay verifiable
    /// against the historical key (REQ-12).
    #[serde(skip)]
    pub signing_did: String,
    /// Emit-time server timestamp. Distinct from `cts` (which is the
    /// atproto-lexicon "created at" field embedded in the Label record);
    /// `signed_at` is Polaris's record of when this row's signature was
    /// generated.
    #[serde(skip)]
    pub signed_at: DateTime<Utc>,
}

/// Caller-supplied fields for inserting a new label.
///
/// `seq`, `id`, `cts`, and `signed_at` are server-assigned by the row
/// defaults; every other field is supplied explicitly because the emitter
/// (#28) is the only path that constructs valid signed rows.
#[derive(Debug, Clone)]
pub struct NewLabel {
    /// DID of the labeler that issued this label.
    pub src: String,
    /// AT-URI or DID of the labeled subject.
    pub uri: String,
    /// Optional content CID.
    pub cid: Option<String>,
    /// Label value.
    pub val: String,
    /// Negation flag.
    pub neg: bool,
    /// Optional expiration timestamp.
    pub exp: Option<DateTime<Utc>>,
    /// K-256 signature bytes — must be exactly 64 bytes (compact
    /// `r || s`). The `labels_signature_len` CHECK in migration 13
    /// rejects anything else at the storage layer.
    pub sig: Vec<u8>,
    /// Originating action id, when the label was produced through the
    /// moderator API. Migrated / imported labels leave this `None`.
    pub action_id: Option<Uuid>,
    /// Subject DID, denormalised from the originating action's subject.
    pub subject_did: String,
    /// Canonical DAG-CBOR encoding of the unsigned Label payload — the
    /// exact bytes [`Self::sig`] was produced over.
    pub label_cbor: Vec<u8>,
    /// `did:key:z…` form of the public key the signature was produced
    /// under.
    pub signing_did: String,
}

// ── repo trait + Postgres impl ──────────────────────────────────────────

/// Compile-time contract for the labels repository.
///
/// All three reads have hard `LIMIT` bounds at the caller — the repo never
/// imposes its own; callers (the subscription pump and queryLabels
/// handler) know their own backpressure budget.
pub trait LabelRepo: Send + Sync {
    /// Insert a new label and return the persisted row (with assigned
    /// `id`, `seq`, `cts`).
    fn insert(
        &self,
        new: NewLabel,
    ) -> impl std::future::Future<Output = Result<Label, LabelerError>> + Send;

    /// Return every label whose `uri` matches any entry in `uris`,
    /// ordered by `seq` ascending. Bounded by `limit` to keep a single
    /// request from monopolising the pool.
    fn query_by_uris(
        &self,
        uris: &[String],
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Label>, LabelerError>> + Send;

    /// Return up to `limit` labels with `seq > cursor`, ordered ascending.
    /// Used by the subscription pump for the backfill phase.
    fn stream_from_cursor(
        &self,
        cursor: i64,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Label>, LabelerError>> + Send;

    /// Return the most recent `limit` labels whose `subject_did` matches,
    /// ordered by `signed_at` descending (newest first). Used by operator
    /// "what have we said about this DID" queries; the `subject_did`
    /// column is denormalised from action -> incident -> subject by
    /// migration 13 so the query plan is a single index lookup.
    fn latest_for_subject(
        &self,
        subject_did: &str,
        limit: i64,
    ) -> impl std::future::Future<Output = Result<Vec<Label>, LabelerError>> + Send;
}

/// Postgres-backed [`LabelRepo`].
#[derive(Debug, Clone)]
pub struct PgLabelRepo {
    pool: PgPool,
}

impl PgLabelRepo {
    /// Build a [`PgLabelRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl LabelRepo for PgLabelRepo {
    async fn insert(&self, new: NewLabel) -> Result<Label, LabelerError> {
        let row = sqlx::query!(
            r#"
            INSERT INTO labels (
                src, uri, cid, val, neg, exp, sig, action_id,
                subject_did, label_cbor, signing_did
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id, seq, src, uri, cid, val, neg, cts, exp, sig,
                      subject_did, label_cbor, signing_did, signed_at
            "#,
            new.src,
            new.uri,
            new.cid,
            new.val,
            new.neg,
            new.exp,
            new.sig,
            new.action_id,
            new.subject_did,
            new.label_cbor,
            new.signing_did,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Label {
            id: row.id,
            seq: row.seq,
            src: row.src,
            uri: row.uri,
            cid: row.cid,
            val: row.val,
            neg: row.neg,
            cts: row.cts,
            exp: row.exp,
            sig: row.sig,
            subject_did: row.subject_did,
            label_cbor: row.label_cbor,
            signing_did: row.signing_did,
            signed_at: row.signed_at,
        })
    }

    async fn query_by_uris(&self, uris: &[String], limit: i64) -> Result<Vec<Label>, LabelerError> {
        // `uris` is bound as a Postgres `TEXT[]` via `ANY($1)` — sqlx
        // encodes `&[String]` to that array type natively, so the lookup
        // is a single round-trip rather than N `OR`-clauses.
        let rows = sqlx::query!(
            r#"
            SELECT id, seq, src, uri, cid, val, neg, cts, exp, sig,
                   subject_did, label_cbor, signing_did, signed_at
            FROM labels
            WHERE uri = ANY($1)
            ORDER BY seq ASC
            LIMIT $2
            "#,
            uris,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Label {
                id: r.id,
                seq: r.seq,
                src: r.src,
                uri: r.uri,
                cid: r.cid,
                val: r.val,
                neg: r.neg,
                cts: r.cts,
                exp: r.exp,
                sig: r.sig,
                subject_did: r.subject_did,
                label_cbor: r.label_cbor,
                signing_did: r.signing_did,
                signed_at: r.signed_at,
            })
            .collect())
    }

    async fn stream_from_cursor(
        &self,
        cursor: i64,
        limit: i64,
    ) -> Result<Vec<Label>, LabelerError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, seq, src, uri, cid, val, neg, cts, exp, sig,
                   subject_did, label_cbor, signing_did, signed_at
            FROM labels
            WHERE seq > $1
            ORDER BY seq ASC
            LIMIT $2
            "#,
            cursor,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Label {
                id: r.id,
                seq: r.seq,
                src: r.src,
                uri: r.uri,
                cid: r.cid,
                val: r.val,
                neg: r.neg,
                cts: r.cts,
                exp: r.exp,
                sig: r.sig,
                subject_did: r.subject_did,
                label_cbor: r.label_cbor,
                signing_did: r.signing_did,
                signed_at: r.signed_at,
            })
            .collect())
    }

    async fn latest_for_subject(
        &self,
        subject_did: &str,
        limit: i64,
    ) -> Result<Vec<Label>, LabelerError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, seq, src, uri, cid, val, neg, cts, exp, sig,
                   subject_did, label_cbor, signing_did, signed_at
            FROM labels
            WHERE subject_did = $1
            ORDER BY signed_at DESC
            LIMIT $2
            "#,
            subject_did,
            limit,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Label {
                id: r.id,
                seq: r.seq,
                src: r.src,
                uri: r.uri,
                cid: r.cid,
                val: r.val,
                neg: r.neg,
                cts: r.cts,
                exp: r.exp,
                sig: r.sig,
                subject_did: r.subject_did,
                label_cbor: r.label_cbor,
                signing_did: r.signing_did,
                signed_at: r.signed_at,
            })
            .collect())
    }
}

// ── broadcaster ─────────────────────────────────────────────────────────

/// Process-local fan-out wrapper around [`tokio::sync::broadcast`].
///
/// One `Sender` is held on [`ApiState`]; every subscribing WebSocket calls
/// [`LabelBroadcaster::subscribe`] for a fresh receiver. The signer
/// (#28) calls [`LabelBroadcaster::publish`] from the insert path so
/// connected subscribers see new labels without polling the DB.
///
/// `broadcast::Sender::send` returns `Err(SendError)` when no receivers
/// exist; we map that to `Ok(())` because the absence of subscribers is
/// not a producer-side failure — the row is already persisted; replay
/// from `seq > cursor` is the durable delivery path.
#[derive(Debug, Clone)]
pub struct LabelBroadcaster {
    tx: broadcast::Sender<Label>,
}

impl LabelBroadcaster {
    /// Build a broadcaster with the given channel capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Build a broadcaster at the [`DEFAULT_BROADCAST_CAPACITY`] default.
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_BROADCAST_CAPACITY)
    }

    /// Subscribe to live label inserts. Each call returns a fresh
    /// receiver — every active connection holds its own.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Label> {
        self.tx.subscribe()
    }

    /// Publish a label to every active subscriber.
    ///
    /// Silently absorbs `SendError` (no live receivers). The persisted
    /// row is the source of truth; live fan-out is a best-effort
    /// latency optimisation.
    pub fn publish(&self, label: Label) {
        let _ = self.tx.send(label);
    }
}

impl Default for LabelBroadcaster {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

// ── HTTP: queryLabels ───────────────────────────────────────────────────

/// Query-parameter shape for `GET /xrpc/com.atproto.label.queryLabels`.
///
/// `uris` is multi-valued in the atproto contract; axum's `Query`
/// decodes repeated `?uris=...&uris=...` parameters into a `Vec<String>`
/// via `serde_urlencoded` when the field type is `Vec<String>`. (We use
/// the `serde(default)` so a missing `uris` deserializes to an empty
/// vector and the handler can reject with `400 BadRequest`.)
#[derive(Debug, Default, Deserialize)]
pub struct QueryLabelsParams {
    /// AT-URIs / DIDs to fetch labels for.
    #[serde(default)]
    pub uris: Vec<String>,
    /// Maximum number of labels to return (default 50, hard cap 250 —
    /// matches the atproto lexicon's `maxLength: 250`).
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Hard cap on a single `queryLabels` response.
const QUERY_LABELS_MAX_LIMIT: i64 = 250;
/// Default response size when the caller doesn't pin `limit`.
const QUERY_LABELS_DEFAULT_LIMIT: i64 = 50;

/// Response body for `GET /xrpc/com.atproto.label.queryLabels`.
#[derive(Debug, Serialize)]
pub struct QueryLabelsResponse {
    /// The matched labels.
    pub labels: Vec<Label>,
    /// Optional pagination cursor for follow-up requests. The current
    /// implementation never paginates (returns all matches up to
    /// `limit`); the field is reserved by the atproto contract.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `axum`-shaped handler for `com.atproto.label.queryLabels`.
pub async fn query_labels(
    State(state): State<ApiState>,
    Query(params): Query<QueryLabelsParams>,
) -> Result<axum::Json<QueryLabelsResponse>, LabelerError> {
    if params.uris.is_empty() {
        return Err(LabelerError::BadRequest("uris must be non-empty"));
    }

    let limit = params
        .limit
        .unwrap_or(QUERY_LABELS_DEFAULT_LIMIT)
        .clamp(1, QUERY_LABELS_MAX_LIMIT);
    let labels = state.labels.query_by_uris(&params.uris, limit).await?;
    Ok(axum::Json(QueryLabelsResponse {
        labels,
        cursor: None,
    }))
}

// ── WebSocket: subscribeLabels ──────────────────────────────────────────

/// Query-parameter shape for the subscription handshake.
#[derive(Debug, Default, Deserialize)]
pub struct SubscribeLabelsParams {
    /// Resume cursor — stream rows with `seq > cursor`. Defaults to `0`
    /// which delivers every persisted label.
    #[serde(default)]
    pub cursor: Option<i64>,
}

/// Page size used by the backfill loop. Keeps each round-trip bounded so
/// a freshly-connecting subscriber with `cursor = 0` against a multi-million-
/// row table doesn't pull the whole set into memory at once.
const SUBSCRIBE_BACKFILL_PAGE_SIZE: i64 = 256;

/// axum WebSocket-upgrade entrypoint for
/// `com.atproto.label.subscribeLabels`.
pub async fn subscribe_labels(
    State(state): State<ApiState>,
    Query(params): Query<SubscribeLabelsParams>,
    upgrade: WebSocketUpgrade,
) -> Response {
    let cursor = params.cursor.unwrap_or(0);
    upgrade.on_upgrade(move |socket| async move {
        run_subscription(socket, state, cursor).await;
    })
}

/// Drive a single client connection: backfill from `cursor` then pump
/// live broadcasts until the peer disconnects.
async fn run_subscription(socket: WebSocket, state: ApiState, mut cursor: i64) {
    let (mut sink, mut client_read) = socket.split();
    let mut rx = state.label_broadcaster.subscribe();

    // ── Phase 1: drain persisted labels (`seq > cursor`). ───────────
    //
    // Each page is bounded by SUBSCRIBE_BACKFILL_PAGE_SIZE. We exit the
    // loop when a page returns fewer rows than we asked for — at that
    // point we've caught up to the live edge and Phase 2 takes over.
    loop {
        let Ok(page) = state
            .labels
            .stream_from_cursor(cursor, SUBSCRIBE_BACKFILL_PAGE_SIZE)
            .await
        else {
            return;
        };
        let page_len = page.len();
        for label in page {
            cursor = label.seq;
            if send_label_frame(&mut sink, &label).await.is_err() {
                return;
            }
        }
        if i64::try_from(page_len).unwrap_or(i64::MAX) < SUBSCRIBE_BACKFILL_PAGE_SIZE {
            break;
        }
    }

    // ── Phase 2: live fan-out via tokio::sync::broadcast. ───────────
    //
    // The `select!` race is cancel-safe on both branches: `client_read.next()`
    // borrows the read half (a Stream) and a dropped poll just stops yielding;
    // `rx.recv()` is documented cancel-safe by tokio (a dropped future leaves
    // the receiver intact for the next iteration).
    //
    // We deliberately do NOT add a periodic-ping branch here: axum/tungstenite
    // already responds to client-initiated pings transparently at the protocol
    // layer, and the subscription contract is one-way (server -> client) per
    // atproto's spec. Adding a server-initiated ping with a `tokio::time::interval`
    // would require justifying the interval cancel-safety against partial sends,
    // which is out of scope for #26. A follow-up issue can revisit if we
    // observe connection drops on idle subscriptions in production.
    loop {
        tokio::select! {
            biased;
            // Cancel-safe: dropping a poll on the WebSocket's read half
            // just stops draining inbound frames for one tick.
            incoming = client_read.next() => {
                match incoming {
                    None | Some(Err(_) | Ok(Message::Close(_))) => return,
                    Some(Ok(_)) => {
                        // Subscriptions are server -> client; we ignore
                        // any inbound payload. axum handles pings at the
                        // protocol layer.
                    }
                }
            }
            // Cancel-safe per tokio docs: `broadcast::Receiver::recv` may
            // be dropped at any await point without losing position.
            recv = rx.recv() => {
                match recv {
                    Ok(label) => {
                        // De-dup against the backfill: a label whose seq
                        // is <= the backfill watermark was already sent.
                        if label.seq <= cursor {
                            continue;
                        }
                        cursor = label.seq;
                        if send_label_frame(&mut sink, &label).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Slow consumer: rather than buffering unboundedly
                        // we walk the DB forward from the current cursor
                        // to recover, then resume on the broadcast.
                        let Ok(catch_up) = state
                            .labels
                            .stream_from_cursor(cursor, SUBSCRIBE_BACKFILL_PAGE_SIZE)
                            .await
                        else {
                            return;
                        };
                        for label in catch_up {
                            cursor = label.seq;
                            if send_label_frame(&mut sink, &label).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        }
    }
}

/// Encode a [`Label`] into the atproto subscription wire envelope
/// (`(header_cbor, body_cbor)` concatenated) and send it as a binary
/// WebSocket message.
///
/// Returns `Err(())` if the sink rejected the send (peer gone, connection
/// reset). The caller treats that as a terminal signal for the pump.
async fn send_label_frame(
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
    label: &Label,
) -> Result<(), ()> {
    let bytes = encode_labels_frame(label.seq, std::slice::from_ref(label)).map_err(|_| ())?;
    sink.send(Message::Binary(bytes.into()))
        .await
        .map_err(|_| ())
}

/// CBOR-encode the `(header, body)` pair for a `#labels` frame.
///
/// Header: `{ op: 1, t: "#labels" }` — the message-frame opcode plus the
/// atproto subscription type discriminator. Body: `{ seq, labels: [...] }`
/// per the `com.atproto.label.subscribeLabels` lexicon.
///
/// Encoded via [`proto_blue::ws::Frame::encode`] so the resulting bytes
/// are strict DAG-CBOR (canonical map-key ordering by byte-length then
/// lexicographic, shortest integer / string encodings, `bytes`-typed
/// `sig` not array-of-int). This is the same wire envelope ATProto
/// reference consumers decode via `MessageFrame::decode`; #58's live
/// WebSocket client harness exercises that decode against this encoder.
fn encode_labels_frame(seq: i64, labels: &[Label]) -> Result<Vec<u8>, LabelerError> {
    let mut body = BTreeMap::new();
    body.insert("seq".to_owned(), LexValue::Integer(seq));
    body.insert(
        "labels".to_owned(),
        LexValue::Array(labels.iter().map(label_to_lex).collect()),
    );

    let frame = Frame::Message(MessageFrame {
        r#type: Some("#labels".to_owned()),
        body: LexValue::Map(body),
    });
    frame.encode().map_err(|_| LabelerError::FrameEncode)
}

/// Project a persisted [`Label`] row into the on-the-wire
/// `com.atproto.label.defs::Label` shape as a [`LexValue`].
///
/// Mirrors the proto-blue `com::atproto::label::defs::Label` field set:
/// `cid?`, `cts`, `exp?`, `neg?`, `sig?`, `src`, `uri`, `val`. Fields
/// the server table carries for internal use only (`id`, `subject_did`,
/// `label_cbor`, `signing_did`, `signed_at`) are not part of the wire
/// shape and never appear in the encoded frame.
fn label_to_lex(label: &Label) -> LexValue {
    let mut m = BTreeMap::new();
    if let Some(cid) = &label.cid {
        m.insert("cid".to_owned(), LexValue::String(cid.clone()));
    }
    m.insert("cts".to_owned(), LexValue::String(label.cts.to_rfc3339()));
    if let Some(exp) = label.exp {
        m.insert("exp".to_owned(), LexValue::String(exp.to_rfc3339()));
    }
    m.insert("neg".to_owned(), LexValue::Bool(label.neg));
    // `sig` is bytes on the wire — `LexValue::Bytes` is the only shape
    // DAG-CBOR will round-trip cleanly. A `LexValue::Array<Integer>`
    // would technically encode but downstream verifiers (proto-blue's
    // Label codec, the TS SDK) typecheck against the `bytes` lexicon
    // and reject the array form.
    m.insert("sig".to_owned(), LexValue::Bytes(label.sig.clone()));
    m.insert("src".to_owned(), LexValue::String(label.src.clone()));
    m.insert("uri".to_owned(), LexValue::String(label.uri.clone()));
    m.insert("val".to_owned(), LexValue::String(label.val.clone()));
    LexValue::Map(m)
}

// ── error → HTTP response adapter ───────────────────────────────────────

impl IntoResponse for LabelerError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Self::Database(_) | Self::FrameEncode => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
            }
        }
    }
}

// ── router ──────────────────────────────────────────────────────────────

/// Build the labeler subtree of the public router. Returns a stateless
/// `Router` (state is bound at construction) so the caller can `merge` it
/// into the top-level router.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/xrpc/com.atproto.label.queryLabels", get(query_labels))
        .route(
            "/xrpc/com.atproto.label.subscribeLabels",
            get(subscribe_labels),
        )
        .with_state(state)
}

// Keep `Arc` reachable in this module so a future refactor that drops
// the explicit construction of `Arc<PgLabelRepo>` from `ApiState` doesn't
// silently break the import.
#[allow(dead_code)]
fn _arc_anchor<T>(_: Arc<T>) {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    fn sample_label(seq: i64) -> Label {
        Label {
            id: Uuid::new_v4(),
            seq,
            src: "did:plc:labeler".to_owned(),
            uri: "at://did:plc:user/app.bsky.feed.post/abc".to_owned(),
            cid: None,
            val: "spam".to_owned(),
            neg: false,
            cts: Utc::now(),
            exp: None,
            sig: vec![0_u8; 64],
            subject_did: "did:plc:user".to_owned(),
            label_cbor: Vec::new(),
            signing_did: "did:key:zSampleLabelerKey".to_owned(),
            signed_at: Utc::now(),
        }
    }

    #[test]
    fn encode_labels_frame_round_trips_through_proto_blue() {
        // The atproto subscription envelope is `header || body`, two
        // back-to-back DAG-CBOR values; `proto_blue::ws::Frame::decode`
        // is the reference decoder ATProto consumers reach for. A round
        // trip through it asserts both the framing layer (op=1,
        // t="#labels") and that the bytes are strict DAG-CBOR canonical
        // (the decoder rejects any non-canonical encoding).
        let bytes = encode_labels_frame(7, &[sample_label(7)]).unwrap();
        let decoded = Frame::decode(&bytes).expect("MessageFrame::decode accepts our bytes");

        let message = match decoded {
            Frame::Message(m) => m,
            Frame::Error(e) => panic!("expected Message frame, got error: {e:?}"),
        };
        assert_eq!(message.r#type.as_deref(), Some("#labels"));

        let body_map = message.body.as_map().expect("body is a CBOR map");
        let seq = body_map
            .get("seq")
            .and_then(LexValue::as_integer)
            .expect("body carries seq");
        assert_eq!(seq, 7);
        let labels = body_map
            .get("labels")
            .and_then(LexValue::as_array)
            .expect("body carries labels array");
        assert_eq!(labels.len(), 1);
        let label_map = labels[0].as_map().expect("label is a map");
        assert_eq!(
            label_map.get("val").and_then(LexValue::as_str),
            Some("spam"),
        );
        assert!(
            label_map
                .get("sig")
                .is_some_and(|v| matches!(v, LexValue::Bytes(_))),
            "sig must encode as DAG-CBOR bytes, not an array of integers",
        );
    }

    #[tokio::test]
    async fn broadcaster_publish_with_no_subscribers_does_not_panic() {
        let b = LabelBroadcaster::with_default_capacity();
        // No receivers; publish must be a no-op rather than a panic.
        b.publish(sample_label(1));
    }

    #[tokio::test]
    async fn broadcaster_delivers_to_subscriber() {
        let b = LabelBroadcaster::with_default_capacity();
        let mut rx = b.subscribe();
        let l = sample_label(2);
        b.publish(l.clone());
        let received = rx.recv().await.unwrap();
        assert_eq!(received.seq, 2);
        assert_eq!(received.uri, l.uri);
    }
}
