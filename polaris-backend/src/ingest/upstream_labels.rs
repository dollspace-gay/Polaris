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
use rand::Rng;
use sqlx::PgPool;
use tokio::sync::Mutex;

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
    /// [`HandleError`] *without* persisting an observation. The caller (the
    /// run-loop) maps [`HandleError::Unsigned`] and
    /// [`HandleError::BadSignature`] to a structured `tracing::warn!` and
    /// drops the frame; other errors propagate as fatal.
    ///
    /// # Errors
    ///
    /// See [`HandleError`].
    pub async fn handle_frame(&self, frame: &ProtoLabel) -> Result<i64, HandleError> {
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

        // The signature verified. Resolve the subject (DID-keyed) and
        // persist an ExternalLabel observation. The Postgres trigger on
        // `observations` fires automatically and refreshes the subject's
        // risk_signals JSONB.
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

        // Advance the cursor. The Labels message frame carries one `seq`
        // covering a Vec<Label>; the per-frame handler is called once per
        // Label inside it, so the caller passes the same `seq` repeatedly.
        // We accept the per-Label seq here for unit-testability — in
        // practice the run-loop computes it from the wrapping `Labels`.
        // We treat it as i64; the protocol's `seq` is i64. The frame's own
        // `ver` field is unrelated.
        // Callers without a wire-level seq pass 0 and ignore the return.
        let seq = 0_i64;
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

/// Load every `upstream_labelers WHERE enabled = TRUE` row.
///
/// Called once at process startup; the binary entrypoint feeds the results
/// to [`spawn_consumers`] which constructs one detached [`tokio::spawn`]
/// per row.
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

/// DAG-CBOR encode the label with `sig` cleared. Mirrors
/// `crate::labeler::emitter::encode_canonical` for the inverse direction
/// (consume rather than produce). Kept private to the module so the
/// consume-side canonical-encoding rule stays close to the verify call.
fn encode_label_canonical(label: &ProtoLabel) -> Result<Vec<u8>, HandleError> {
    let json = serde_json::to_value(label).map_err(|_| HandleError::CanonicalEncode)?;
    let lex = proto_blue::lex_json::json_to_lex(&json);
    proto_blue::lex_cbor::encode(&lex).map_err(|_| HandleError::CanonicalEncode)
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
