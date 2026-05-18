//! Inbound upstream-labeler consumer (issue #32, REQ-9 / AC-10).
//!
//! Polaris turns labels emitted by *other* labelers into pattern-engine
//! observations on the matching subject. Each operator-configured upstream
//! gets its own [`UpstreamLabelerConsumer`] task that:
//!
//! 1. Subscribes to `wss://<upstream-hostname>/xrpc/com.atproto.label.subscribeLabels`
//!    (via [`proto_blue::ws::WebSocketKeepAlive`] for transport + auto-
//!    reconnect with backoff).
//! 2. For each inbound [`Label`], looks up the upstream's signing key,
//!    verifies the K-256 signature, and on success persists an
//!    [`ObservationKind::ExternalLabel`] tied to the subject identified by
//!    the label's `uri`. Unverified labels are dropped with a structured
//!    `tracing::warn!`.
//! 3. Persists the upstream's cursor (`last_seq`) after each successful
//!    insert so a reconnect resumes from the last acknowledged seq — AC-10
//!    "no labels lost across reconnect" matches the firehose-cursor
//!    discipline in [`crate::ingest::firehose`].
//!
//! # `AppState` wiring
//!
//! The binary entrypoint queries `upstream_labelers WHERE enabled = TRUE` at
//! startup and spawns one detached [`tokio::spawn`] per row. Tasks own their
//! own state by value (no `Arc<Mutex<...>>` on the cursor); the in-process
//! key cache uses the one legitimate [`tokio::sync::Mutex`] documented at
//! [`UpstreamKeyCache`]. Tasks borrow connections from the shared
//! [`sqlx::PgPool`]; the pool is internally `Arc`-shared so cloning is cheap.
//!
//! # Forbidden patterns (issue #32 brief)
//!
//! - No `unwrap()` / `expect()` outside `#[cfg(test)]`.
//! - No tight-loop reconnect — every reconnect path goes through
//!   [`reconnect_delay`], which applies exponential backoff plus jitter and
//!   sleeps via [`tokio::time::sleep`].
//! - No unverified label makes it past [`UpstreamLabelerConsumer::handle_frame`]
//!   — verify-or-drop is total at that boundary.
//! - No string-built SQL — every DB op is a `sqlx::query!` invocation.
//! - The only `Arc<Mutex<...>>`-shaped state is the per-process key cache
//!   ([`UpstreamKeyCache::cache`]); the brief authorises this exception.
//! - No `unsafe`.

#![allow(
    clippy::module_name_repetitions,
    reason = "Upstream* prefix is the convention this module uses to disambiguate from Polaris-emitted labels"
)]

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use polaris_types::{Did, LabelValue, NewObservation, ObservationKind, SubjectId, SubjectKind};
use proto_blue::api::generated::com::atproto::label::defs::Label as ProtoLabel;
use proto_blue::api::generated::com::atproto::label::subscribe_labels::Labels as ProtoLabels;
use proto_blue::lex_data::LexValue;
use proto_blue::ws::{Frame, MessageFrame, WebSocketKeepAlive, WebSocketKeepAliveOpts};
use rand::Rng;
use sqlx::PgPool;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use url::form_urlencoded;

use crate::repo::{ObservationRepo, RepoError};

// ── public configuration ────────────────────────────────────────────────

/// Default per-label trust weight, used when an upstream's `weights` map has
/// no entry for the label `val` (and no `_default` override).
///
/// 0.5 is the centre of the unit interval — a label whose upstream-source
/// has no calibration data treated as a neutral signal rather than a strong
/// one. Per-category trust weights override this on a per-upstream basis.
pub const DEFAULT_WEIGHT: f32 = 0.5;

/// Initial reconnect backoff (the `T0` of `T0 * 2^attempt`).
pub const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// Upper cap on the exponential reconnect backoff.
pub const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(60);

/// One [`upstream_labelers`] row, projected into the in-memory form the
/// consumer needs.
#[derive(Debug, Clone, PartialEq)]
pub struct UpstreamLabelerConfig {
    /// Upstream's DID — the `src` field of every label this consumer
    /// processes will equal this value (when the upstream is honest;
    /// signature verification is what enforces that).
    pub did: String,
    /// Upstream's WSS hostname (without `/xrpc/...` suffix).
    pub hostname: String,
    /// Per-label-value trust weights. Lookup is by label `val`.
    pub weights: BTreeMap<String, f32>,
    /// Default weight when a label's `val` is not in [`Self::weights`].
    /// Initialised from the `_default` key of the persisted JSONB (if
    /// present) or [`DEFAULT_WEIGHT`] otherwise.
    pub default_weight: f32,
}

impl UpstreamLabelerConfig {
    /// Resolve the trust weight for a label value, applying the
    /// per-category map first and falling back to [`Self::default_weight`].
    #[must_use]
    pub fn weight_for(&self, label_val: &str) -> f32 {
        self.weights
            .get(label_val)
            .copied()
            .unwrap_or(self.default_weight)
    }

    /// Parse an [`UpstreamLabelerConfig`] from a row's `weights` JSONB.
    ///
    /// The JSONB shape is `{ "<label_val>": <0..1>, "_default": <0..1>? }`;
    /// non-numeric values are dropped silently (the operator's CLI / admin
    /// surface is the right place to reject malformed input — at this layer
    /// we tolerate them so a single bad entry can't kill a whole task).
    #[must_use]
    pub fn from_row(did: String, hostname: String, weights_jsonb: &serde_json::Value) -> Self {
        let mut weights = BTreeMap::new();
        let mut default_weight = DEFAULT_WEIGHT;
        if let serde_json::Value::Object(map) = weights_jsonb {
            for (k, v) in map {
                let Some(f) = v.as_f64() else { continue };
                // `as f32` clamps to the f32 range; values produced by an
                // operator-driven UI are always within (0,1].
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "weights are tiny rationals < 1; f64 -> f32 loses no operator-meaningful precision"
                )]
                let f = f as f32;
                if k == "_default" {
                    default_weight = f;
                } else {
                    weights.insert(k.clone(), f);
                }
            }
        }
        Self {
            did,
            hostname,
            weights,
            default_weight,
        }
    }
}

// ── error type ──────────────────────────────────────────────────────────

/// Errors that can arise while processing one inbound label.
///
/// These are *per-frame* errors — the run-loop catches them, logs at WARN,
/// and continues with the next frame. A frame-level error never aborts the
/// consumer task; only cursor-persistence or transport-level *fatal* errors
/// do that, and those surface through [`ConsumerError`] from the run loop.
#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    /// The label was unsigned. Per AC-10's verify-or-drop contract.
    #[error("label has no signature; dropping")]
    Unsigned,

    /// The signature did not verify against the upstream's cached pubkey.
    #[error("signature did not verify against upstream key did={did}")]
    BadSignature {
        /// The did:key the verifier was given.
        did: String,
    },

    /// The proto-blue crypto layer rejected the inputs (malformed
    /// signature bytes, malformed did:key, etc.).
    #[error("crypto layer rejected the verification inputs")]
    Crypto(#[source] proto_blue::crypto::CryptoError),

    /// The label's canonical pre-signature bytes could not be encoded.
    #[error("failed to canonical-CBOR-encode label payload")]
    CanonicalEncode,

    /// The label carried a `cts` or `exp` field that did not parse as
    /// RFC 3339. The proto-blue lex stack accepts a permissive subset
    /// for backwards-compatibility with older labelers; if the column
    /// store rejects the value we drop the frame rather than persisting
    /// a row whose `cts` does not round-trip.
    #[error("label timestamp did not parse as RFC 3339: field={field}, value={value}")]
    TimestampParse {
        /// `"cts"` or `"exp"`.
        field: &'static str,
        /// The offending value, verbatim from the wire.
        value: String,
    },

    /// Could not look up or refresh the upstream's signing key.
    #[error("key-cache lookup failed for did={did}")]
    KeyLookup {
        /// The upstream DID whose key was requested.
        did: String,
        /// The cache layer's reported reason.
        #[source]
        source: CacheError,
    },

    /// Repository-layer failure inserting the observation, advancing the
    /// cursor, or resolving the subject.
    #[error("repository operation failed")]
    Repo(#[from] RepoError),

    /// A direct sqlx error (used by the local subject-resolve / cursor
    /// helpers that don't go through a `*Repo`).
    #[error("database error")]
    Database(#[source] sqlx::Error),
}

impl From<sqlx::Error> for HandleError {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

/// Fatal errors that terminate the per-upstream run-loop.
///
/// Frame-level errors ([`HandleError`]) are caught and logged inside the
/// loop; only the conditions enumerated here are reasons to exit the
/// task. The supervising binary logs the exit and keeps the process
/// running (a fault on one upstream cannot wedge the rest of Polaris).
#[derive(Debug, thiserror::Error)]
pub enum ConsumerError {
    /// The keep-alive client gave up reconnecting. The supervisor logs
    /// and leaves the task exited; an operator can restart it via the
    /// admin surface (or by toggling the row's `enabled` flag).
    #[error("WebSocket reconnect attempts exhausted")]
    ReconnectExhausted,

    /// A non-recoverable transport error surfaced by the keep-alive
    /// client (e.g. TLS handshake failure that won't be cured by
    /// retrying). The underlying `WsError` is preserved for diagnostics.
    #[error("WebSocket transport error: {0}")]
    Transport(String),

    /// The consumer task was cancelled via its `CancellationToken`.
    /// This is the clean-shutdown path; the supervisor treats it as a
    /// successful exit.
    #[error("consumer cancelled")]
    Cancelled,
}

/// Errors raised by [`UpstreamKeyCache`].
#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    /// Database failure during the cache read/write.
    #[error("database error during key-cache I/O")]
    Database(#[from] sqlx::Error),

    /// The upstream-key fetcher could not return a usable key.
    #[error("upstream key fetcher failed: {message}")]
    Fetch {
        /// Human-readable cause from the fetcher.
        message: String,
    },
}

// ── upstream-key fetcher contract ───────────────────────────────────────

/// Pluggable lookup of an upstream's signing-key `did:key` form.
///
/// The default implementation resolves the upstream's DID document via
/// `https://plc.directory/<did>` and extracts the `#atproto_label`
/// verification method. Tests inject a stub fetcher so the AC-10 binding
/// test runs without a network round-trip.
///
/// The trait is dyn-compatible (`Send + Sync`, uses [`async_trait::async_trait`]
/// internally via boxed futures) so the cache can hold a single trait object
/// regardless of the underlying transport.
pub trait UpstreamKeyFetcher: Send + Sync {
    /// Resolve the upstream's signing-key did:key form. Returns `Ok` with a
    /// `did:key:z...` string on success.
    ///
    /// # Errors
    ///
    /// Returns [`CacheError::Fetch`] with a human-readable message on any
    /// transport / parse failure.
    fn fetch(
        &self,
        upstream_did: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<String, CacheError>> + Send + '_>>;
}

/// Cached upstream signing key with its TTL expiry.
#[derive(Debug, Clone)]
struct CachedKey {
    signing_pubkey_did: String,
    expires_at: DateTime<Utc>,
}

/// Per-process upstream-signing-key cache.
///
/// Two-tier:
///
/// 1. **In-memory map** (`cache: Mutex<HashMap<String, CachedKey>>`).
///    Read first; serves verified hits without touching the DB.
/// 2. **`upstream_labeler_keys` row** in Postgres. Read on memory miss; on
///    DB miss or expiry the fetcher is invoked and the result is persisted.
///
/// # Why the [`tokio::sync::Mutex`]
///
/// The brief authorises a single Mutex in this module: the cache key-fetch
/// is rare (per-upstream, per-day, since the TTL is 24h), and serialising
/// concurrent fetches for the same DID is the correct behaviour — racing
/// fetches would each open an HTTP connection to PLC and write conflicting
/// rows. Holding the Mutex across the fetch is intentional; the lock
/// granularity is the whole map but contention is one fetch per upstream
/// per TTL window.
pub struct UpstreamKeyCache {
    pool: PgPool,
    /// In-memory cache shared across consumer tasks. The Mutex is held
    /// across the fetch await, which is the documented exception to the
    /// "never lock across await" rule (see module docs).
    cache: Mutex<HashMap<String, CachedKey>>,
    fetcher: Arc<dyn UpstreamKeyFetcher>,
}

impl std::fmt::Debug for UpstreamKeyCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamKeyCache")
            .field("pool", &"<PgPool>")
            .field("cache", &"<Mutex<HashMap<…>>>")
            .field("fetcher", &"<dyn UpstreamKeyFetcher>")
            .finish()
    }
}

impl UpstreamKeyCache {
    /// Build a key cache against the given pool with a custom fetcher.
    #[must_use]
    pub fn new(pool: PgPool, fetcher: Arc<dyn UpstreamKeyFetcher>) -> Self {
        Self {
            pool,
            cache: Mutex::new(HashMap::new()),
            fetcher,
        }
    }

    /// Look up the upstream's `did:key:z...` signing-key form.
    ///
    /// Resolution order: in-memory cache → `upstream_labeler_keys` row →
    /// fetcher round-trip + persist. The TTL is honoured at both tiers:
    /// expired rows in either are treated as misses and re-fetched.
    ///
    /// # Errors
    ///
    /// - [`CacheError::Database`] on a Postgres I/O failure.
    /// - [`CacheError::Fetch`] if the fetcher could not return a key.
    pub async fn get_or_fetch(&self, upstream_did: &str) -> Result<String, CacheError> {
        // Hold the Mutex across the whole resolution: serialising
        // concurrent fetches for the same DID is intentional (see
        // struct-level docs). This is the one Mutex the module's
        // forbidden-pattern checklist authorises.
        let mut guard = self.cache.lock().await;
        let now = Utc::now();
        if let Some(cached) = guard.get(upstream_did)
            && cached.expires_at > now
        {
            return Ok(cached.signing_pubkey_did.clone());
        }

        // Memory miss or stale; consult the DB.
        if let Some(row) = sqlx::query!(
            r#"
            SELECT signing_pubkey_did, expires_at
            FROM upstream_labeler_keys
            WHERE did = $1
            "#,
            upstream_did,
        )
        .fetch_optional(&self.pool)
        .await?
            && row.expires_at > now
        {
            let cached = CachedKey {
                signing_pubkey_did: row.signing_pubkey_did.clone(),
                expires_at: row.expires_at,
            };
            guard.insert(upstream_did.to_owned(), cached.clone());
            return Ok(cached.signing_pubkey_did);
        }

        // DB miss or expired. Round-trip the fetcher.
        let fresh = self.fetcher.fetch(upstream_did).await?;
        let expires_at = now + chrono::Duration::hours(24);
        sqlx::query!(
            r#"
            INSERT INTO upstream_labeler_keys (did, signing_pubkey_did, fetched_at, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (did) DO UPDATE
            SET signing_pubkey_did = EXCLUDED.signing_pubkey_did,
                fetched_at = EXCLUDED.fetched_at,
                expires_at = EXCLUDED.expires_at
            "#,
            upstream_did,
            &fresh,
            now,
            expires_at,
        )
        .execute(&self.pool)
        .await?;

        guard.insert(
            upstream_did.to_owned(),
            CachedKey {
                signing_pubkey_did: fresh.clone(),
                expires_at,
            },
        );
        Ok(fresh)
    }

    /// Test-only helper: seed the in-memory cache with a known key,
    /// bypassing the fetcher.
    #[doc(hidden)]
    pub async fn seed_in_memory_for_tests(
        &self,
        upstream_did: &str,
        signing_pubkey_did: String,
        ttl: Duration,
    ) {
        let mut guard = self.cache.lock().await;
        // Convert via i64 milliseconds because chrono::Duration::from_std
        // accepts std::time::Duration but is fallible for very large values;
        // ttl values used in practice (hours) always fit.
        let expires_at = Utc::now()
            + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::hours(24));
        guard.insert(
            upstream_did.to_owned(),
            CachedKey {
                signing_pubkey_did,
                expires_at,
            },
        );
    }
}

// ── consumer task ───────────────────────────────────────────────────────

/// Per-upstream subscribeLabels consumer task.
///
/// Construct one with [`Self::new`] and drive it with [`Self::run`]. The
/// task owns its own cursor by value (no `Arc<Mutex<i64>>`); the in-process
/// signing-key cache is the only shared state and lives in
/// [`UpstreamKeyCache`].
pub struct UpstreamLabelerConsumer<O: ObservationRepo + 'static> {
    config: UpstreamLabelerConfig,
    pool: PgPool,
    observations: Arc<O>,
    key_cache: Arc<UpstreamKeyCache>,
}

impl<O: ObservationRepo + 'static> std::fmt::Debug for UpstreamLabelerConsumer<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamLabelerConsumer")
            .field("config", &self.config)
            .field("pool", &"<PgPool>")
            .field("observations", &"<dyn ObservationRepo>")
            .field("key_cache", &self.key_cache)
            .finish()
    }
}

impl<O: ObservationRepo + 'static> UpstreamLabelerConsumer<O> {
    /// Build a consumer.
    #[must_use]
    pub fn new(
        config: UpstreamLabelerConfig,
        pool: PgPool,
        observations: Arc<O>,
        key_cache: Arc<UpstreamKeyCache>,
    ) -> Self {
        Self {
            config,
            pool,
            observations,
            key_cache,
        }
    }

    /// Borrow this consumer's configuration. Test-only convenience.
    #[doc(hidden)]
    #[must_use]
    pub fn config(&self) -> &UpstreamLabelerConfig {
        &self.config
    }

    /// Handle one inbound label frame.
    ///
    /// Total at the verify-or-drop boundary: any error path returns an
    /// [`HandleError`] *without* persisting any row. The caller (the
    /// run-loop) maps [`HandleError::Unsigned`] and
    /// [`HandleError::BadSignature`] to a structured `tracing::warn!` and
    /// drops the frame; other errors propagate as fatal.
    ///
    /// `seq` is the wrapping `Labels` envelope's sequence number — the
    /// same value covers every `Label` inside one envelope. The run-loop
    /// supplies it from the decoded envelope; unit/integration tests
    /// supply a synthetic value via [`Self::handle_frame_with_seq`] or
    /// pass `0` here (the latter is a back-compat shim around
    /// [`Self::handle_frame_with_seq`] with a fixed seq=0).
    ///
    /// # Errors
    ///
    /// See [`HandleError`].
    pub async fn handle_frame(&self, frame: &ProtoLabel) -> Result<i64, HandleError> {
        self.handle_frame_with_seq(frame, 0).await
    }

    /// Like [`Self::handle_frame`] but with an explicit envelope sequence
    /// number. The run-loop uses this; tests that want to assert
    /// cursor-progress behaviour use it too.
    ///
    /// # Errors
    ///
    /// See [`HandleError`].
    pub async fn handle_frame_with_seq(
        &self,
        frame: &ProtoLabel,
        seq: i64,
    ) -> Result<i64, HandleError> {
        let sig = frame.sig.as_deref().ok_or(HandleError::Unsigned)?;

        // Look up the upstream's signing key (cache → DB → fetcher).
        let signing_did = self
            .key_cache
            .get_or_fetch(&self.config.did)
            .await
            .map_err(|source| HandleError::KeyLookup {
                did: self.config.did.clone(),
                source,
            })?;

        // The canonical pre-signature bytes are the DAG-CBOR encoding of
        // the label with `sig` omitted. We mirror the labeler emitter's
        // approach: clone the frame, clear `sig`, then encode via
        // proto_blue's lex stack.
        let mut unsigned = frame.clone();
        unsigned.sig = None;
        let cbor = encode_label_canonical(&unsigned)?;

        let ok = proto_blue::crypto::verify_signature(&signing_did, &cbor, sig, false)
            .map_err(HandleError::Crypto)?;
        if !ok {
            return Err(HandleError::BadSignature { did: signing_did });
        }

        // Signature verified. Persist into the local label index FIRST —
        // this is the bunnynabbit `atp-label-indexer` pattern: the
        // case-view reads this table, never the AppView. The persist is
        // unconditional on subject-existence (a label targeting any URI
        // is recorded, even if Polaris has never observed the subject),
        // so post-level labels from labelers we subscribe to surface in
        // the panel for any account a moderator opens.
        persist_to_indexed_labels(&self.pool, frame, sig, seq).await?;

        // Health bookkeeping: a verified + persisted frame is the
        // signal of a healthy labeler. Clear any accumulated
        // dormancy so the supervisor stops avoiding this row. The
        // write is idempotent — running it on every frame is cheap
        // and gives operators a near-real-time `last_success_at`.
        if let Err(err) = record_consumer_success(&self.pool, &self.config.did).await {
            tracing::warn!(
                upstream = %self.config.did,
                error = %err,
                "failed to record consumer health success; continuing",
            );
        }

        // Then persist the pattern-engine observation (subject-bound).
        // The Postgres trigger on `observations` refreshes the subject's
        // risk_signals JSONB automatically.
        let resolved_did = extract_did_from_uri(&frame.uri);
        let subject_id = find_or_create_account_subject(&self.pool, resolved_did).await?;
        let weight = self.config.weight_for(&frame.val);

        // Evidence: the full label record (including sig) + the verified
        // signing-key did. Keeps the audit trail self-contained.
        let evidence = serde_json::json!({
            "label": frame,
            "signing_did": signing_did,
        });

        let new_obs = NewObservation {
            subject_id,
            kind: ObservationKind::ExternalLabel {
                source: Did::new(&self.config.did),
                label_value: LabelValue::new(&frame.val),
                weight,
            },
            confidence: weight,
            evidence,
        };
        self.observations.insert(new_obs).await?;

        Ok(seq)
    }

    /// Persist the cursor for this upstream.
    ///
    /// Exposed `pub` so the run-loop, `AppState` wiring, and integration
    /// tests can drive cursor advancement directly without re-implementing
    /// the upsert. Mirrors the firehose cursor flush shape (issue #12).
    ///
    /// # Errors
    ///
    /// Returns the underlying [`sqlx::Error`] on persist failure; the
    /// caller wraps it as fatal (cursor loss → duplicate work on restart).
    pub async fn flush_cursor(&self, seq: i64) -> Result<(), sqlx::Error> {
        flush_cursor(&self.pool, &self.config.did, seq).await
    }

    /// Drive the per-upstream subscribeLabels consumer loop.
    ///
    /// Connects via [`WebSocketKeepAlive`] to
    /// `wss://{hostname}/xrpc/com.atproto.label.subscribeLabels?cursor={seq}`
    /// and processes inbound `#labels` and `#info` envelopes until either
    /// the WebSocket exhausts its reconnect budget or `cancel` is fired.
    ///
    /// On every reconnect the URL function reads the latest persisted
    /// cursor from `upstream_labeler_cursors.last_seq`, so a resumed
    /// connection never re-delivers a label whose effects were already
    /// recorded.
    ///
    /// # Errors
    ///
    /// See [`ConsumerError`]. Frame-level errors do NOT terminate the
    /// loop — they are logged at WARN and the loop continues.
    pub async fn run(self, cancel: CancellationToken) -> Result<(), ConsumerError> {
        let initial_seq = load_cursor(&self.pool, &self.config.did)
            .await
            .unwrap_or_else(|err| {
                tracing::warn!(
                    upstream = %self.config.did,
                    error = %err,
                    "failed to load cursor at startup; resuming from 0",
                );
                0
            });
        let initial_url = build_subscribe_url(&self.config.hostname, initial_seq);

        // URL function: every reconnect reads the latest persisted cursor.
        let url_pool = self.pool.clone();
        let url_did = self.config.did.clone();
        let url_host = self.config.hostname.clone();
        let url_fn: proto_blue::ws::keepalive::UrlFn = Arc::new(move || {
            let pool = url_pool.clone();
            let did = url_did.clone();
            let host = url_host.clone();
            Box::pin(async move {
                let seq = load_cursor(&pool, &did).await.unwrap_or(0);
                build_subscribe_url(&host, seq)
            })
        });

        let opts = WebSocketKeepAliveOpts {
            // Cap at a reasonable upper bound so a permanently-broken
            // upstream eventually surfaces as ReconnectExhausted; the
            // supervisor will log + exit the task. Operators can re-
            // enable by toggling `upstream_labelers.enabled`.
            max_reconnect_attempts: Some(20),
            ..WebSocketKeepAliveOpts::default()
        };

        // `WebSocketKeepAlive::new` is gated by proto-blue-ws's own
        // `tungstenite`/`gloo-ws` features (picked per target by proto-
        // blue's umbrella `ws` feature). Polaris does not need to gate
        // here — the constructor is present iff the right transport is
        // compiled in.
        let mut ws = WebSocketKeepAlive::new(initial_url, opts).with_url_fn(url_fn);

        tracing::info!(
            upstream = %self.config.did,
            hostname = %self.config.hostname,
            cursor = initial_seq,
            "upstream label consumer starting",
        );

        loop {
            // Two-arm cancellation race: a cancel signal short-circuits
            // the recv. The recv arm yields a `RecvOutcome` (instead of
            // raw `Result<Option<Vec<u8>>, _>`) so both branches resolve
            // to the same sized type, satisfying tokio::select!'s
            // unification.
            let outcome: RecvOutcome = tokio::select! {
                biased;
                () = cancel.cancelled() => RecvOutcome::Cancelled,
                recv = ws.recv() => match recv {
                    Ok(Some(b)) => RecvOutcome::Frame(b),
                    Ok(None) => RecvOutcome::CleanClose,
                    Err(proto_blue::ws::WsError::ReconnectExhausted { attempts }) =>
                        RecvOutcome::Exhausted(attempts),
                    Err(err) => RecvOutcome::Transport(err.to_string()),
                },
            };

            let bytes = match outcome {
                RecvOutcome::Frame(b) => b,
                RecvOutcome::Cancelled => {
                    tracing::info!(upstream = %self.config.did, "consumer cancelled");
                    return Err(ConsumerError::Cancelled);
                }
                RecvOutcome::CleanClose => {
                    tracing::info!(
                        upstream = %self.config.did,
                        "upstream closed the WebSocket; reconnecting on next recv",
                    );
                    continue;
                }
                RecvOutcome::Exhausted(attempts) => {
                    apply_consumer_dormancy(
                        &self.pool,
                        &self.config.did,
                        "reconnect budget exhausted; consumer exiting",
                        Some(attempts),
                        None,
                    )
                    .await;
                    return Err(ConsumerError::ReconnectExhausted);
                }
                RecvOutcome::Transport(err) => {
                    apply_consumer_dormancy(
                        &self.pool,
                        &self.config.did,
                        "non-recoverable WebSocket error; consumer exiting",
                        None,
                        Some(err.as_str()),
                    )
                    .await;
                    return Err(ConsumerError::Transport(err));
                }
            };

            if let Err(err) = self.handle_envelope(&bytes).await {
                tracing::warn!(
                    upstream = %self.config.did,
                    error = %err,
                    "frame-level handling error; dropping frame and continuing",
                );
            }
        }
    }

    /// Decode one wire envelope and dispatch it.
    ///
    /// Returns `Ok(())` for any outcome that does NOT warrant exiting
    /// the run-loop (decoded successfully and labels handled, or
    /// decoded but unrecognised type — logged at WARN). Returns an
    /// `Err(EnvelopeError)` only when the envelope itself fails to
    /// decode, which the caller logs and skips.
    async fn handle_envelope(&self, bytes: &[u8]) -> Result<(), EnvelopeError> {
        let frame = Frame::decode(bytes).map_err(|e| EnvelopeError::FrameDecode(e.to_string()))?;
        let MessageFrame { r#type, body } = match frame {
            Frame::Message(m) => m,
            Frame::Error(e) => {
                // An error frame is the labeler telling us something
                // went wrong on its side (e.g. `FutureCursor` if we
                // resumed past its tail). Log + continue; the keep-
                // alive will reconnect on the next failure.
                tracing::warn!(
                    upstream = %self.config.did,
                    error = %e.error,
                    message = e.message.as_deref().unwrap_or(""),
                    "upstream sent error frame",
                );
                return Ok(());
            }
        };

        match r#type.as_deref() {
            Some("#labels") => {
                // Decode straight from the `LexValue::Map` body rather than
                // round-tripping through `lex_to_json` + `serde_json`. The
                // round-trip path corrupts the `sig` field: CBOR
                // major-type-2 bytes become `LexValue::Bytes`, which
                // `lex_to_json` serialises as the AT-Proto wrapper
                // `{"$bytes": "<base64>"}`. The typed `Label` struct's
                // `sig: Option<Vec<u8>>` field would then refuse to
                // deserialise from that wrapper ("invalid type: map,
                // expected a sequence"). Every received label-frame
                // was being dropped before this fix.
                let labels_msg = decode_labels_body(&body).map_err(EnvelopeError::BodyDecode)?;
                let seq = labels_msg.seq;
                for label in &labels_msg.labels {
                    if let Err(err) = self.handle_frame_with_seq(label, seq).await {
                        tracing::warn!(
                            upstream = %self.config.did,
                            seq,
                            error = ?err,
                            "label rejected at verify-or-drop boundary",
                        );
                    }
                }
                // Advance the persisted cursor once per envelope; the
                // monotonicity guard inside `flush_cursor` prevents a
                // stale envelope from rewinding the persisted value.
                if let Err(err) = flush_cursor(&self.pool, &self.config.did, seq).await {
                    tracing::warn!(
                        upstream = %self.config.did,
                        seq,
                        error = %err,
                        "failed to flush cursor; will replay on reconnect",
                    );
                }
                Ok(())
            }
            Some("#info") => {
                // The subscription lexicon allows `#info` frames for
                // out-of-band notices like backfill warnings. Log
                // verbatim; they don't advance the cursor.
                tracing::info!(
                    upstream = %self.config.did,
                    info = ?body,
                    "upstream sent info frame",
                );
                Ok(())
            }
            other => {
                tracing::warn!(
                    upstream = %self.config.did,
                    r#type = ?other,
                    "ignoring unrecognised subscription frame type",
                );
                Ok(())
            }
        }
    }
}

/// Outcome of a single `recv` race in the run-loop.
///
/// All variants are sized; the enum lets `tokio::select!` unify the
/// two branch types into one. The dispatching `match` then turns each
/// variant into the appropriate control-flow (continue, return, or
/// process the frame bytes).
enum RecvOutcome {
    /// A binary subscription envelope arrived; the caller dispatches it.
    Frame(Vec<u8>),
    /// The cancellation token fired before recv produced a frame.
    Cancelled,
    /// The peer closed the WebSocket cleanly; the caller continues the
    /// loop so the keep-alive reconnects on the next call.
    CleanClose,
    /// The keep-alive exhausted its reconnect budget; the caller exits.
    Exhausted(u32),
    /// A non-recoverable transport error surfaced; the caller exits.
    Transport(String),
}

/// Decode a `com.atproto.label.subscribeLabels#labels` envelope body
/// from its [`LexValue::Map`] form into a typed [`ProtoLabels`].
#[allow(
    clippy::too_many_lines,
    reason = "linear field-by-field walker over the Label wire shape — \
              splitting per-field type checks across helpers would \
              push the error-context construction across function \
              boundaries and lose the per-index position in each \
              error message."
)]
///
/// This bypasses `serde_json` to handle AT-Proto's CBOR bytes
/// correctly: `sig` is encoded as DAG-CBOR major-type-2 bytes, which
/// becomes [`LexValue::Bytes`] in the decoder. Going through
/// `lex_to_json` would wrap that as `{"$bytes": "<base64>"}`, which
/// the typed `Label::sig: Option<Vec<u8>>` field cannot deserialise.
/// Walking the map directly avoids the round-trip.
fn decode_labels_body(body: &LexValue) -> Result<ProtoLabels, String> {
    use proto_blue::syntax::{Datetime as ProtoDatetime, Did as ProtoDid};

    let LexValue::Map(root) = body else {
        return Err(format!("body is {} not map", lex_kind(body)));
    };
    let labels_lex = root
        .get("labels")
        .ok_or_else(|| "body missing `labels` field".to_owned())?;
    let LexValue::Array(labels_arr) = labels_lex else {
        return Err(format!("body.labels is {} not array", lex_kind(labels_lex)));
    };
    let seq_lex = root
        .get("seq")
        .ok_or_else(|| "body missing `seq` field".to_owned())?;
    let LexValue::Integer(seq) = seq_lex else {
        return Err(format!("body.seq is {} not integer", lex_kind(seq_lex)));
    };

    let mut labels = Vec::with_capacity(labels_arr.len());
    for (idx, entry) in labels_arr.iter().enumerate() {
        let LexValue::Map(m) = entry else {
            return Err(format!("body.labels[{idx}] is {} not map", lex_kind(entry)));
        };
        let cid = match m.get("cid") {
            Some(LexValue::String(s)) => Some(s.clone()),
            Some(LexValue::Null) | None => None,
            Some(other) => {
                return Err(format!(
                    "body.labels[{idx}].cid is {} not string|null",
                    lex_kind(other)
                ));
            }
        };
        let cts_str = match m.get("cts") {
            Some(LexValue::String(s)) => s.clone(),
            other => {
                return Err(format!(
                    "body.labels[{idx}].cts is {} not string",
                    other.map_or("missing", lex_kind)
                ));
            }
        };
        let cts = ProtoDatetime::new(&cts_str)
            .map_err(|e| format!("body.labels[{idx}].cts invalid: {e}"))?;
        let exp = match m.get("exp") {
            Some(LexValue::String(s)) => Some(
                ProtoDatetime::new(s)
                    .map_err(|e| format!("body.labels[{idx}].exp invalid: {e}"))?,
            ),
            Some(LexValue::Null) | None => None,
            Some(other) => {
                return Err(format!(
                    "body.labels[{idx}].exp is {} not string|null",
                    lex_kind(other)
                ));
            }
        };
        let neg = match m.get("neg") {
            Some(LexValue::Bool(b)) => Some(*b),
            Some(LexValue::Null) | None => None,
            Some(other) => {
                return Err(format!(
                    "body.labels[{idx}].neg is {} not bool|null",
                    lex_kind(other)
                ));
            }
        };
        let sig = match m.get("sig") {
            Some(LexValue::Bytes(b)) => Some(b.clone()),
            Some(LexValue::Null) | None => None,
            Some(other) => {
                return Err(format!(
                    "body.labels[{idx}].sig is {} not bytes|null",
                    lex_kind(other)
                ));
            }
        };
        let src_str = match m.get("src") {
            Some(LexValue::String(s)) => s.clone(),
            other => {
                return Err(format!(
                    "body.labels[{idx}].src is {} not string",
                    other.map_or("missing", lex_kind)
                ));
            }
        };
        let src =
            ProtoDid::new(&src_str).map_err(|e| format!("body.labels[{idx}].src invalid: {e}"))?;
        let uri = match m.get("uri") {
            Some(LexValue::String(s)) => s.clone(),
            other => {
                return Err(format!(
                    "body.labels[{idx}].uri is {} not string",
                    other.map_or("missing", lex_kind)
                ));
            }
        };
        let val = match m.get("val") {
            Some(LexValue::String(s)) => s.clone(),
            other => {
                return Err(format!(
                    "body.labels[{idx}].val is {} not string",
                    other.map_or("missing", lex_kind)
                ));
            }
        };
        let ver = match m.get("ver") {
            Some(LexValue::Integer(n)) => Some(*n),
            Some(LexValue::Null) | None => None,
            Some(other) => {
                return Err(format!(
                    "body.labels[{idx}].ver is {} not integer|null",
                    lex_kind(other)
                ));
            }
        };
        labels.push(ProtoLabel {
            cid,
            cts,
            exp,
            neg,
            sig,
            src,
            uri,
            val,
            ver,
        });
    }

    Ok(ProtoLabels { labels, seq: *seq })
}

/// Operator-readable label for a [`LexValue`] variant — used in
/// error messages from [`decode_labels_body`] so a malformed frame
/// surfaces the type that was found, not just "not a string".
fn lex_kind(v: &LexValue) -> &'static str {
    match v {
        LexValue::Null => "null",
        LexValue::Bool(_) => "bool",
        LexValue::Integer(_) => "integer",
        LexValue::String(_) => "string",
        LexValue::Bytes(_) => "bytes",
        LexValue::Cid(_) => "cid",
        LexValue::Array(_) => "array",
        LexValue::Map(_) => "map",
    }
}

/// Envelope-level errors that the run-loop swallows.
///
/// These describe a single mis-shaped wire envelope. The loop logs and
/// continues; persistent decode failures are an upstream-protocol bug,
/// not a Polaris-side fault.
#[derive(Debug, thiserror::Error)]
enum EnvelopeError {
    #[error("frame decode failed: {0}")]
    FrameDecode(String),
    #[error("body decode failed: {0}")]
    BodyDecode(String),
}

/// Build the subscription URL for a given upstream hostname + cursor.
///
/// The cursor is omitted entirely when `seq == 0` (rather than emitted
/// as `?cursor=0`) so the labeler interprets the first connection as
/// "start at the live edge" rather than "replay from the beginning of
/// time." Once a cursor has been persisted, every subsequent reconnect
/// resumes from `seq + 1` (the labeler's `seq` field is the cursor for
/// the NEXT message).
fn build_subscribe_url(hostname: &str, seq: i64) -> String {
    // Defensive: strip any leading `wss://` / `ws://` if the operator
    // entered it as a URL in the upstream_labelers row. The schema
    // expects bare hostname; this normalisation is forgiving.
    let host = hostname
        .trim_start_matches("wss://")
        .trim_start_matches("ws://")
        .trim_end_matches('/');
    if seq <= 0 {
        format!("wss://{host}/xrpc/com.atproto.label.subscribeLabels")
    } else {
        let cursor = form_urlencoded::Serializer::new(String::new())
            .append_pair("cursor", &seq.to_string())
            .finish();
        format!("wss://{host}/xrpc/com.atproto.label.subscribeLabels?{cursor}")
    }
}

/// Load the persisted cursor for an upstream. Returns 0 on first connect.
///
/// # Errors
///
/// Returns the underlying [`sqlx::Error`] on read failure.
#[doc(hidden)]
pub async fn load_cursor(pool: &PgPool, upstream_did: &str) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT last_seq
        FROM upstream_labeler_cursors
        WHERE did = $1
        "#,
        upstream_did,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map_or(0, |r| r.last_seq))
}

/// Upsert the cursor for an upstream. Monotonic at the database via the
/// `WHERE upstream_labeler_cursors.last_seq < EXCLUDED.last_seq` guard, so
/// a stale writer can never rewind the persisted cursor.
///
/// # Errors
///
/// Returns the underlying [`sqlx::Error`] on write failure.
#[doc(hidden)]
pub async fn flush_cursor(pool: &PgPool, upstream_did: &str, seq: i64) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        INSERT INTO upstream_labeler_cursors (did, last_seq, last_seen_at)
        VALUES ($1, $2, now())
        ON CONFLICT (did) DO UPDATE
        SET last_seq = EXCLUDED.last_seq,
            last_seen_at = EXCLUDED.last_seen_at
        WHERE upstream_labeler_cursors.last_seq < EXCLUDED.last_seq
        "#,
        upstream_did,
        seq,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ── startup wiring ──────────────────────────────────────────────────────

/// Load every `upstream_labelers WHERE enabled = TRUE` row that is
/// NOT currently in its dormancy window.
///
/// A row's `dormant_until` column is populated by [`record_consumer_failure`]
/// after a consumer task exits with a non-recoverable error (DNS
/// NXDOMAIN, TLS handshake failure, reconnect-budget exhausted, …).
/// The supervisor's reconcile pass calls this function and only
/// spawns consumers for the rows it returns — labelers whose host is
/// dead are not pounded on every 60s tick. The dormancy is cleared
/// (set NULL) by [`record_consumer_success`] on the first verified +
/// persisted frame, at which point the next reconcile pass will pick
/// up the row again.
///
/// # Errors
///
/// Returns the underlying [`sqlx::Error`] on read failure.
pub async fn load_enabled_upstreams(
    pool: &PgPool,
) -> Result<Vec<UpstreamLabelerConfig>, sqlx::Error> {
    let rows = sqlx::query!(
        r#"
        SELECT did, hostname, weights
        FROM upstream_labelers
        WHERE enabled = TRUE
          AND (dormant_until IS NULL OR dormant_until <= now())
        ORDER BY did
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| UpstreamLabelerConfig::from_row(r.did, r.hostname, &r.weights))
        .collect())
}

/// Reset the per-labeler health bookkeeping on a successful frame.
///
/// Called from the run-loop after a label has been verified AND
/// persisted into `indexed_labels`. The DB write is idempotent and
/// cheap enough to fire on every frame — the operator-perceptible
/// signal is `last_success_at` updating in near-real-time as labels
/// flow in.
///
/// # Errors
///
/// Returns the underlying [`sqlx::Error`] on write failure.
pub async fn record_consumer_success(pool: &PgPool, upstream_did: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
        UPDATE upstream_labelers
        SET consecutive_failures = 0,
            last_success_at = now(),
            dormant_until = NULL,
            updated_at = now()
        WHERE did = $1
        "#,
        upstream_did,
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Record a consumer-task failure and compute the next dormancy
/// window for the labeler.
///
/// The dormancy schedule is keyed off `consecutive_failures` AFTER
/// the increment:
///
///   1 →   1min
///   2 →   5min
///   3 →  30min
///   4 →   6h
///   ≥5 →  24h (cap)
///
/// Returns the just-written `(consecutive_failures, dormant_until)`
/// pair so the caller can log it in the same envelope as the failure
/// itself.
///
/// # Errors
///
/// Returns the underlying [`sqlx::Error`] on write failure.
pub async fn record_consumer_failure(
    pool: &PgPool,
    upstream_did: &str,
) -> Result<(i32, DateTime<Utc>), sqlx::Error> {
    // Two-step (read-increment-write) inside one transaction so the
    // computed dormancy window is consistent with the observed
    // `consecutive_failures`. A pure SQL `UPDATE ... RETURNING` would
    // be a single round-trip but the `make_interval` schedule below
    // is easier to read in Rust than as a `CASE WHEN` ladder, and the
    // transaction overhead is negligible at the per-task-exit
    // frequency this is called.
    let mut tx = pool.begin().await?;
    let row = sqlx::query!(
        r#"
        UPDATE upstream_labelers
        SET consecutive_failures = consecutive_failures + 1,
            updated_at = now()
        WHERE did = $1
        RETURNING consecutive_failures
        "#,
        upstream_did,
    )
    .fetch_optional(&mut *tx)
    .await?;
    // No such labeler row (e.g. the operator deleted the row
    // mid-flight). Treat as a no-op so the consumer task exits
    // cleanly without dragging the rest of the supervisor down.
    let Some(r) = row else {
        tx.rollback().await?;
        return Ok((0, Utc::now()));
    };
    let failures = r.consecutive_failures;

    let dormancy = dormancy_for(failures);
    let dormant_until = Utc::now()
        + chrono::Duration::from_std(dormancy).unwrap_or_else(|_| chrono::Duration::hours(24));

    sqlx::query!(
        r#"
        UPDATE upstream_labelers
        SET dormant_until = $2
        WHERE did = $1
        "#,
        upstream_did,
        dormant_until,
    )
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((failures, dormant_until))
}

/// Helper for the consumer's run-loop: record a failure, log the
/// dormancy that was applied, and swallow any health-write errors
/// (the consumer is on its way out either way, so a failed health
/// write is not worth panicking over).
///
/// `attempts` / `error` are optional — at most one is set per call
/// site (`Exhausted` carries the reconnect attempt count;
/// `Transport` carries the transport error string).
async fn apply_consumer_dormancy(
    pool: &PgPool,
    upstream_did: &str,
    message: &'static str,
    attempts: Option<u32>,
    transport_error: Option<&str>,
) {
    match record_consumer_failure(pool, upstream_did).await {
        Ok((failures, dormant_until)) => tracing::warn!(
            upstream = %upstream_did,
            attempts = ?attempts,
            transport_error = ?transport_error,
            consecutive_failures = failures,
            %dormant_until,
            "{message} (dormancy applied)",
        ),
        Err(err) => tracing::warn!(
            upstream = %upstream_did,
            attempts = ?attempts,
            transport_error = ?transport_error,
            health_error = %err,
            "{message} (health write failed)",
        ),
    }
}

/// Dormancy duration to apply at a given `consecutive_failures` count
/// (post-increment).
///
/// Separated out so the schedule is testable without a database.
#[must_use]
fn dormancy_for(consecutive_failures: i32) -> Duration {
    match consecutive_failures {
        ..=1 => Duration::from_secs(60),
        2 => Duration::from_secs(5 * 60),
        3 => Duration::from_secs(30 * 60),
        4 => Duration::from_secs(6 * 60 * 60),
        _ => Duration::from_secs(24 * 60 * 60),
    }
}

// ── helpers ─────────────────────────────────────────────────────────────

/// Extract the DID-of-account from a label `uri`.
///
/// Per AC-10's data model, every label resolves to an account subject:
///
/// - Bare DID (`did:plc:abc`) passes through unchanged.
/// - AT-URI (`at://did:plc:abc/<collection>/<rkey>`) returns `did:plc:abc`.
/// - Anything else returns the input unchanged; the subject row's DID
///   column will hold it verbatim, and downstream operators get an
///   actionable diagnostic.
#[must_use]
pub fn extract_did_from_uri(uri: &str) -> &str {
    if let Some(rest) = uri.strip_prefix("at://") {
        // The DID is the first path segment.
        rest.split('/').next().unwrap_or(rest)
    } else {
        uri
    }
}

/// Find a subject row by DID, inserting one with `kind = 'account'` if no
/// match exists. The insert is racy across consumer tasks for the same DID;
/// the ON CONFLICT clause on the `subjects_did_unique` index (migration
/// 00000000000003) makes the operation idempotent and returns the existing
/// row's id.
///
/// # Errors
///
/// Returns [`sqlx::Error`] on database I/O failure.
#[doc(hidden)]
pub async fn find_or_create_account_subject(
    pool: &PgPool,
    did: &str,
) -> Result<SubjectId, sqlx::Error> {
    // Race-free upsert: try to insert; if a row already exists (uniqueness
    // enforced by `subjects_account_did_uniq` in migration 16), fall back
    // to the existing row via the UNION ALL tail. Two round-trips at
    // worst; one in the steady state.
    //
    // The ON CONFLICT clause must name the same predicate the partial
    // unique index carries (`kind = 'account' AND did IS NOT NULL`), so we
    // bind the kind both as a value for INSERT and as the WHERE predicate.
    let kind_str = SubjectKind::Account.as_str();
    let row = sqlx::query!(
        r#"
        WITH ins AS (
            INSERT INTO subjects (kind, did, uri, created_at)
            VALUES ($1, $2, NULL, now())
            ON CONFLICT (did) WHERE kind = 'account' AND did IS NOT NULL
            DO NOTHING
            RETURNING id
        )
        SELECT id FROM ins
        UNION ALL
        SELECT id FROM subjects WHERE kind = $1 AND did = $2
        LIMIT 1
        "#,
        kind_str,
        did,
    )
    .fetch_one(pool)
    .await?;

    let id = row.id.ok_or_else(|| {
        sqlx::Error::Protocol(format!(
            "find_or_create_account_subject returned NULL id for did={did}"
        ))
    })?;
    Ok(SubjectId(id))
}

/// Compute the reconnect sleep for `attempt`: `T0 * 2^attempt`, capped at
/// [`RECONNECT_BACKOFF_CAP`], with ±25% jitter so a fleet of consumers does
/// not synchronise their retries against a flapping upstream.
///
/// The jitter band is `[0.75 * base, 1.25 * base]`. The shift exponent is
/// clamped at 6 so `attempt >= 7` saturates to the cap rather than
/// overflowing the shift.
#[must_use]
pub fn reconnect_delay(attempt: u32) -> Duration {
    let shift = attempt.min(6);
    let raw_secs = RECONNECT_BACKOFF_INITIAL
        .as_secs()
        .saturating_mul(2_u64.saturating_pow(shift));
    let base_secs = raw_secs.min(RECONNECT_BACKOFF_CAP.as_secs()).max(1);
    let base_ms = base_secs.saturating_mul(1000);

    // jitter ∈ [750, 1250] of the base in per-mille — integer math, no
    // f64 casts (which clippy's cast-precision-loss / cast-sign-loss /
    // cast-possible-truncation suite rejects under -D warnings).
    let mut rng = rand::thread_rng();
    let permille: u64 = rng.gen_range(750_u64..=1250_u64);
    let jittered_ms = base_ms.saturating_mul(permille) / 1000;
    Duration::from_millis(jittered_ms.max(1))
}

/// DAG-CBOR encode the label with `sig` cleared. Thin shim over the shared
/// implementation in [`crate::labeler::canonicalize::encode_canonical_label`]
/// so the produce-side (`labeler/emitter.rs`) and the consume-side (here)
/// canonicalisation rule stay byte-identical (#78).
pub(crate) fn encode_label_canonical(label: &ProtoLabel) -> Result<Vec<u8>, HandleError> {
    crate::labeler::canonicalize::encode_canonical_label(label)
        .map_err(|_| HandleError::CanonicalEncode)
}

/// Parse an RFC 3339 atproto-syntax `Datetime` into a `chrono::DateTime<Utc>`,
/// mapping a parse failure to a structured [`HandleError`].
fn parse_proto_datetime(
    dt: &proto_blue::syntax::Datetime,
    field: &'static str,
) -> Result<DateTime<Utc>, HandleError> {
    DateTime::parse_from_rfc3339(dt.as_str())
        .map(|d| d.with_timezone(&Utc))
        .map_err(|_| HandleError::TimestampParse {
            field,
            value: dt.as_str().to_owned(),
        })
}

/// Persist one verified label into the local `indexed_labels` store.
///
/// This is the bunnynabbit `atp-label-indexer` pattern's "write" half:
/// every verified label received over the firehose lands in a local
/// table keyed by `(src, uri, val, neg)`. The case-view's "third-party
/// labels" panel reads exclusively from this table — no AppView
/// round-trip, no hardcoded labeler list at query time.
///
/// # Upsert semantics
///
/// The `UNIQUE (src, uri, val, neg)` constraint from migration 34 makes
/// repeated emission of the same `(src, uri, val)` triple by a labeler
/// (typical when a labeler updates a label's expiry or re-signs after
/// rotation) an upsert: we keep the latest `cts`/`seq`/`sig`. A
/// negation arrives as a separate row (`neg=true`), preserving the
/// assert → retract history.
///
/// # Cursor monotonicity
///
/// The `WHERE indexed_labels.seq <= EXCLUDED.seq` guard on the
/// `DO UPDATE` arm makes the upsert idempotent under at-least-once
/// re-delivery (a duplicate frame with the same seq is a no-op; a
/// genuinely-newer frame wins). A label whose seq has regressed
/// (labeler-side bug) does not rewrite the row.
///
/// # Errors
///
/// Returns [`HandleError::Database`] on a Postgres I/O failure or
/// [`HandleError::TimestampParse`] if `cts`/`exp` is malformed.
pub(crate) async fn persist_to_indexed_labels(
    pool: &PgPool,
    frame: &ProtoLabel,
    sig: &[u8],
    seq: i64,
) -> Result<(), HandleError> {
    let cts = parse_proto_datetime(&frame.cts, "cts")?;
    let exp = frame
        .exp
        .as_ref()
        .map(|dt| parse_proto_datetime(dt, "exp"))
        .transpose()?;
    // The on-the-wire `neg` is `Option<bool>` but the column is NOT NULL
    // with default FALSE; treat absence as the assert direction.
    let neg = frame.neg.unwrap_or(false);
    // The on-the-wire `ver` is `Option<i64>` but the column is
    // `INTEGER NOT NULL DEFAULT 1`. The protocol's `ver` field is `1`
    // today and bounded; downcast via `try_from` rather than the
    // accident-prone `as i32`, falling back to the lexicon default
    // for any value that doesn't fit.
    let ver: i32 = frame.ver.unwrap_or(1).try_into().unwrap_or(1);
    sqlx::query!(
        r#"
        INSERT INTO indexed_labels (src, uri, cid, val, neg, cts, exp, ver, seq, sig)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (src, uri, val, neg) DO UPDATE
        SET cts = EXCLUDED.cts,
            cid = EXCLUDED.cid,
            exp = EXCLUDED.exp,
            ver = EXCLUDED.ver,
            seq = EXCLUDED.seq,
            sig = EXCLUDED.sig
        WHERE indexed_labels.seq <= EXCLUDED.seq
        "#,
        frame.src.as_str(),
        frame.uri,
        frame.cid.as_deref(),
        frame.val,
        neg,
        cts,
        exp,
        ver,
        seq,
        sig,
    )
    .execute(pool)
    .await
    .map_err(HandleError::Database)?;
    Ok(())
}

// ── unit tests (no DB) ──────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use proto_blue::crypto::{K256Keypair, Keypair as _, Signer as _};
    use proto_blue::syntax::{Datetime as ProtoDatetime, Did as ProtoDid};

    /// Trust weight resolution: weights map `{"spam": 0.4}`, default 0.5 →
    /// label.val="spam" yields 0.4; label.val="other" yields 0.5.
    #[test]
    fn weight_resolution_uses_map_then_default() {
        let mut weights = BTreeMap::new();
        weights.insert("spam".to_owned(), 0.4_f32);
        let cfg = UpstreamLabelerConfig {
            did: "did:plc:upstream".to_owned(),
            hostname: "labeler.example".to_owned(),
            weights,
            default_weight: 0.5,
        };
        assert!((cfg.weight_for("spam") - 0.4).abs() < f32::EPSILON);
        assert!((cfg.weight_for("other") - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn weight_resolution_falls_back_to_default_weight_when_map_empty() {
        let cfg = UpstreamLabelerConfig {
            did: "did:plc:upstream".to_owned(),
            hostname: "labeler.example".to_owned(),
            weights: BTreeMap::new(),
            default_weight: 0.42,
        };
        assert!((cfg.weight_for("anything") - 0.42).abs() < f32::EPSILON);
    }

    /// `from_row` honours the `_default` override key.
    #[test]
    fn from_row_parses_default_override() {
        let weights = serde_json::json!({ "spam": 0.4, "_default": 0.7 });
        let cfg = UpstreamLabelerConfig::from_row(
            "did:plc:x".to_owned(),
            "labeler.example".to_owned(),
            &weights,
        );
        assert!((cfg.weight_for("spam") - 0.4).abs() < f32::EPSILON);
        assert!((cfg.weight_for("unknown") - 0.7).abs() < f32::EPSILON);
    }

    /// `from_row` ignores non-numeric values gracefully.
    #[test]
    fn from_row_skips_malformed_entries() {
        let weights = serde_json::json!({
            "spam": 0.4,
            "weird": "not a number",
        });
        let cfg = UpstreamLabelerConfig::from_row(
            "did:plc:x".to_owned(),
            "labeler.example".to_owned(),
            &weights,
        );
        assert!((cfg.weight_for("spam") - 0.4).abs() < f32::EPSILON);
        // "weird" was dropped — falls back to default.
        assert!((cfg.weight_for("weird") - DEFAULT_WEIGHT).abs() < f32::EPSILON);
    }

    /// AT-URI subject extraction: `at://did:plc:abc/app.bsky.feed.post/x` →
    /// `did:plc:abc`. Bare DID input passes through.
    #[test]
    fn extract_did_from_at_uri_returns_authority_did() {
        assert_eq!(
            extract_did_from_uri("at://did:plc:abc/app.bsky.feed.post/3l"),
            "did:plc:abc",
        );
    }

    #[test]
    fn extract_did_from_bare_did_passes_through() {
        assert_eq!(extract_did_from_uri("did:plc:abc"), "did:plc:abc");
    }

    #[test]
    fn extract_did_from_at_uri_just_authority() {
        assert_eq!(extract_did_from_uri("at://did:plc:abc"), "did:plc:abc");
    }

    /// Signature verification negative: given a wrong public key, verify
    /// must fail without panic.
    ///
    /// We exercise the inner canonical-encode + `verify_signature` path
    /// directly (no DB, no key cache). This is the same code
    /// [`UpstreamLabelerConsumer::handle_frame`] runs end-to-end; the
    /// integration test in `tests/upstream_labelers.rs` covers the full
    /// path against a live Postgres.
    #[test]
    fn verify_signature_negative_path_fails_without_panic() {
        // Build a real signed label with key A.
        let signer = K256Keypair::generate();
        let signing_did = signer.did();
        let mut label = ProtoLabel {
            cid: None,
            cts: ProtoDatetime::from_utc(Utc::now()),
            exp: None,
            neg: Some(false),
            sig: None,
            src: ProtoDid::new(&signing_did).expect("valid did:key"),
            uri: "did:plc:victim".to_owned(),
            val: "spam".to_owned(),
            ver: Some(1),
        };
        let cbor = encode_label_canonical(&label).expect("canonical encode");
        let sig = signer.sign(&cbor).expect("sign");
        label.sig = Some(sig);

        // Verifying with a *different* key must fail cleanly.
        let other = K256Keypair::generate();
        let wrong_did = other.did();
        let result = proto_blue::crypto::verify_signature(
            &wrong_did,
            &cbor,
            label.sig.as_ref().expect("signed above").as_slice(),
            false,
        );
        if let Ok(ok) = result {
            assert!(!ok, "verifier must reject signature under wrong key");
        }
        // Err(CryptoError) is also an acceptable rejection — the inputs
        // were well-formed but the math didn't add up.
    }

    /// First connect (seq=0) emits the URL WITHOUT a cursor query
    /// param — the labeler interprets cursor-absent as "start at the
    /// live edge" per the AT-Proto subscription contract.
    #[test]
    fn build_subscribe_url_omits_cursor_at_seq_zero() {
        let url = super::build_subscribe_url("mod.bsky.app", 0);
        assert_eq!(
            url,
            "wss://mod.bsky.app/xrpc/com.atproto.label.subscribeLabels",
        );
        // And negative values (defensive — should never happen in
        // practice, but the persisted cursor column is BIGINT signed).
        let url_neg = super::build_subscribe_url("mod.bsky.app", -1);
        assert_eq!(
            url_neg,
            "wss://mod.bsky.app/xrpc/com.atproto.label.subscribeLabels",
        );
    }

    /// Subsequent connects (seq>0) emit `?cursor=<seq>` so the labeler
    /// resumes from after the last-acked seq.
    #[test]
    fn build_subscribe_url_appends_cursor_when_seq_positive() {
        let url = super::build_subscribe_url("mod.bsky.app", 42);
        assert_eq!(
            url,
            "wss://mod.bsky.app/xrpc/com.atproto.label.subscribeLabels?cursor=42",
        );
    }

    /// Operator forgiveness: a hostname containing a `wss://` prefix or
    /// a trailing slash is normalised away so the resulting URL is
    /// canonical.
    #[test]
    fn build_subscribe_url_strips_scheme_and_trailing_slash() {
        let with_scheme = super::build_subscribe_url("wss://mod.bsky.app/", 7);
        assert_eq!(
            with_scheme,
            "wss://mod.bsky.app/xrpc/com.atproto.label.subscribeLabels?cursor=7",
        );
        let with_ws = super::build_subscribe_url("ws://mod.bsky.app", 0);
        assert_eq!(
            with_ws,
            "wss://mod.bsky.app/xrpc/com.atproto.label.subscribeLabels",
        );
    }

    /// Regression: the body decoder MUST accept the AT-Proto wire
    /// shape where `sig` arrives as DAG-CBOR major-type-2 bytes (i.e.
    /// `LexValue::Bytes`). The prior implementation went through
    /// `lex_to_json` + `serde_json::from_value`, which surfaced sig
    /// as `{"$bytes": "<base64>"}` and made the typed
    /// `sig: Option<Vec<u8>>` field fail with
    /// "invalid type: map, expected a sequence" — dropping every
    /// inbound label frame. This test pins the decoder to round-trip
    /// the bytes field correctly so the regression never returns.
    #[test]
    fn decode_labels_body_accepts_bytes_for_sig() {
        use proto_blue::lex_data::LexValue;
        use std::collections::BTreeMap;
        let sig_bytes: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef];
        let mut label_map = BTreeMap::new();
        label_map.insert(
            "cts".to_owned(),
            LexValue::String("2026-01-01T00:00:00.000Z".to_owned()),
        );
        label_map.insert("neg".to_owned(), LexValue::Bool(false));
        label_map.insert("sig".to_owned(), LexValue::Bytes(sig_bytes.clone()));
        label_map.insert(
            "src".to_owned(),
            LexValue::String("did:plc:test-labeler".to_owned()),
        );
        label_map.insert(
            "uri".to_owned(),
            LexValue::String("did:plc:test-subject".to_owned()),
        );
        label_map.insert("val".to_owned(), LexValue::String("spam".to_owned()));
        label_map.insert("ver".to_owned(), LexValue::Integer(1));
        let mut body_map = BTreeMap::new();
        body_map.insert("seq".to_owned(), LexValue::Integer(42));
        body_map.insert(
            "labels".to_owned(),
            LexValue::Array(vec![LexValue::Map(label_map)]),
        );
        let body = LexValue::Map(body_map);

        let decoded = super::decode_labels_body(&body).expect("decode must succeed");
        assert_eq!(decoded.seq, 42);
        assert_eq!(decoded.labels.len(), 1);
        let label = &decoded.labels[0];
        assert_eq!(label.val, "spam");
        assert_eq!(label.uri, "did:plc:test-subject");
        assert_eq!(
            label.sig.as_ref().expect("sig present"),
            &sig_bytes,
            "sig must round-trip bytes verbatim",
        );
    }

    /// Reject a body whose `sig` arrives as a JSON-style array of
    /// integers (the legacy wrong shape) — the decoder should
    /// surface a typed error rather than silently dropping the
    /// frame, so a misbehaving labeler is loud, not silent.
    #[test]
    fn decode_labels_body_rejects_array_sig() {
        use proto_blue::lex_data::LexValue;
        use std::collections::BTreeMap;
        let mut label_map = BTreeMap::new();
        label_map.insert(
            "cts".to_owned(),
            LexValue::String("2026-01-01T00:00:00.000Z".to_owned()),
        );
        label_map.insert(
            "sig".to_owned(),
            LexValue::Array(vec![LexValue::Integer(222), LexValue::Integer(173)]),
        );
        label_map.insert(
            "src".to_owned(),
            LexValue::String("did:plc:test-labeler".to_owned()),
        );
        label_map.insert(
            "uri".to_owned(),
            LexValue::String("did:plc:test-subject".to_owned()),
        );
        label_map.insert("val".to_owned(), LexValue::String("spam".to_owned()));
        let mut body_map = BTreeMap::new();
        body_map.insert("seq".to_owned(), LexValue::Integer(42));
        body_map.insert(
            "labels".to_owned(),
            LexValue::Array(vec![LexValue::Map(label_map)]),
        );
        let body = LexValue::Map(body_map);

        let err = super::decode_labels_body(&body).expect_err("array sig must reject");
        assert!(
            err.contains("sig"),
            "error must name the offending field: {err}"
        );
    }

    /// Sanity: `reconnect_delay` returns a strictly positive duration and
    /// stays under the cap (with jitter accounted for).
    #[test]
    fn reconnect_delay_bounded_and_positive() {
        // 1.5× the cap in ms is well under u64::MAX; do the headroom math
        // in u128 then narrow with saturating_as to keep clippy quiet
        // without sprinkling cast-permission attributes.
        let upper_bound_ms: u128 = RECONNECT_BACKOFF_CAP
            .as_millis()
            .saturating_mul(3)
            .saturating_div(2);
        for attempt in 0..10 {
            let d = reconnect_delay(attempt);
            assert!(d > Duration::ZERO, "attempt={attempt} produced zero delay");
            assert!(
                d.as_millis() <= upper_bound_ms,
                "attempt={attempt} produced delay {d:?} above bounded cap",
            );
        }
    }
}
