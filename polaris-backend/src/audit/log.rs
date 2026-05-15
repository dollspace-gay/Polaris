//! Hash-chained audit log: append + verify (issue #35; design.md §6 + §9).
//!
//! [`AuditLog::record`] appends one row in the caller's transaction.
//! Each row's `this_hash` commits the prior row's `this_hash` via:
//!
//! ```text
//! preimage = prev_hash || canonical_cbor(payload) || iso8601_utc(ts)
//!         || actor_bytes || kind_bytes
//! this_hash = SHA-256(preimage)
//! ```
//!
//! # Canonical CBOR
//!
//! The payload is encoded with [`proto_blue::lex_cbor::encode`], the
//! atproto-canonical DAG-CBOR encoder: length-then-lex sorted map keys,
//! shortest-form integers, no floats, no indefinite-length items.
//! `serde_json::Value` is bridged to `LexValue` via
//! `proto_blue::lex_json::json_to_lex` (lenient — never fails).
//! Choosing the atproto-canonical encoder over `serde_ipld_dagcbor`:
//!
//! - the workspace already depends on `proto-blue`, so no new crate;
//! - `proto-blue::lex_cbor::encode` is byte-for-byte interoperable with
//!   the TypeScript atproto reference implementation, so an auditor in
//!   a different language can recompute the chain;
//! - the labeler emitter (`crate::labeler::emitter`) and the upstream
//!   labels ingest (`crate::ingest::upstream_labels`) already use the
//!   same encoder for label signing — one canonicalisation primitive
//!   across the codebase.
//!
//! # Timestamp precision
//!
//! Timestamps are rendered as `YYYY-MM-DDTHH:MM:SS.ffffffZ` —
//! microsecond precision, always UTC, fixed-width. Microsecond
//! precision matches Postgres `TIMESTAMPTZ`'s storage granularity, so
//! the chain hash is stable even after a database round-trip
//! (`tokio-postgres` truncates nanosecond input to microsecond storage,
//! which would otherwise silently break the chain).
//!
//! # Preimage layout (verbatim)
//!
//! ```text
//! offset 0       : prev_hash[0..32]
//! offset 32      : canonical_cbor(payload)         (variable length)
//! after payload  : ts_iso8601[0..27]               (always 27 ASCII bytes)
//! after ts       : actor_utf8                      (variable length)
//! after actor    : kind_utf8                       (variable length)
//! ```
//!
//! No separators are written between fields; the format is
//! self-delimiting given the fixed lengths of `prev_hash` and the
//! formatted timestamp and the known-out-of-band `actor` and `kind`
//! lengths recorded alongside the hash. Concatenation order is fixed
//! and documented in both this file and migration 18's SQL header.

use chrono::{DateTime, SubsecRound as _, Utc};
use proto_blue::{lex_cbor, lex_json};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

/// Fixed-width SHA-256 length, in bytes.
const HASH_LEN: usize = 32;

/// The 32-byte zero hash used as `prev_hash` for the genesis row.
const GENESIS_PREV: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// One audit-log event: a `(actor, kind, payload)` triple.
///
/// `actor` is a free-form identifier — a moderator UUID rendered as
/// hyphenated hex, `"system"`, `"worker"`, etc. `kind` is the closed
/// set of event names documented at the top of this module. `payload`
/// is the per-kind body, serialised as JSON for storage and CBOR for
/// hashing.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Free-form actor identifier.
    pub actor: String,
    /// Event kind (free-form; the project convention is dotted
    /// `noun.verb`, e.g. `"action.commit"`).
    pub kind: String,
    /// Event payload as a JSON value.
    pub payload: serde_json::Value,
}

/// Errors raised by [`AuditLog::record`].
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// Database error (chain break detected by the trigger included).
    #[error("audit-log database error")]
    Db(#[source] sqlx::Error),
    /// Canonical-CBOR encoding of the payload failed.
    #[error("audit-log payload encoding failed: {reason}")]
    Encode {
        /// Diagnostic category for the encode failure.
        reason: &'static str,
    },
    /// The previous row's `this_hash` was not the expected 32 bytes.
    /// Indicates schema drift (e.g. the CHECK on
    /// `octet_length(this_hash) = 32` was dropped) — not a transient
    /// failure.
    #[error("audit-log row at seq {at_seq} has malformed hash length")]
    HashMismatch {
        /// Seq number of the offending row.
        at_seq: i64,
    },
}

impl From<sqlx::Error> for AuditError {
    fn from(err: sqlx::Error) -> Self {
        Self::Db(err)
    }
}

/// Names the preimage field at which a chain-tamper was detected.
///
/// The verifier can localise a tamper to one of two row-level checks
/// — the row's `prev_hash` link (i.e. the row's claim about the
/// previous row's `this_hash`) or the row's own `this_hash` (i.e. the
/// SHA-256 of this row's preimage).
///
/// # Granularity caveat
///
/// True per-input localisation (which of `payload | ts | actor | kind`
/// was mutated when [`TamperedField::ThisHash`] fires) is **not**
/// expressible with the current schema. Each row stores only the
/// final `this_hash`, so the verifier can prove "the recomputed digest
/// disagrees with the stored digest" but cannot identify *which*
/// input was tampered. Reaching finer granularity would require
/// storing each preimage component's hash separately — a schema
/// change explicitly out of scope for this issue (and arguably not
/// worth the storage cost given the verifier's threat model is
/// "detect any tamper", not "blame any tamper").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TamperedField {
    /// The row's stored `prev_hash` does not match the previous row's
    /// `this_hash`. The link between consecutive rows is broken.
    PrevHash,
    /// The row's recomputed `this_hash` (SHA-256 of its preimage) does
    /// not match the row's stored `this_hash`. The row's own commitment
    /// is invalid; the tamper is on one of `prev_hash | payload | ts
    /// | actor | kind` — see [`TamperedField`]'s granularity caveat.
    ThisHash,
}

impl std::fmt::Display for TamperedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrevHash => f.write_str("prev_hash"),
            Self::ThisHash => f.write_str("this_hash"),
        }
    }
}

/// Errors raised by [`verify_chain`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Database error.
    #[error("audit-log verify database error")]
    Db(#[source] sqlx::Error),
    /// Canonical-CBOR encoding of a stored payload failed during
    /// re-hashing.
    #[error("audit-log verify payload encoding failed at seq {at_seq}: {reason}")]
    Encode {
        /// Seq number of the offending row.
        at_seq: i64,
        /// Diagnostic category for the encode failure.
        reason: &'static str,
    },
    /// A row's recorded hash does not match the recomputed hash, OR a
    /// row's `prev_hash` does not match the previous row's
    /// `this_hash`. The verifier reports the seq of the first offending
    /// row, which preimage field mismatched (see [`TamperedField`]),
    /// and the expected and found 32-byte hashes.
    #[error("audit-log chain tampered at seq {at_seq} (field: {field})")]
    Tampered {
        /// Seq number where the chain breaks.
        at_seq: i64,
        /// Which preimage field the verifier detected as mismatched.
        field: TamperedField,
        /// Hash the verifier expected (recomputed from preimage / prior
        /// row).
        expected: [u8; HASH_LEN],
        /// Hash actually persisted in the row.
        found: [u8; HASH_LEN],
    },
}

impl From<sqlx::Error> for VerifyError {
    fn from(err: sqlx::Error) -> Self {
        Self::Db(err)
    }
}

/// Marker for the audit-log service. Holds no state — every operation
/// either takes a `&mut PgConnection` (append, inside the caller's
/// transaction) or a `&PgPool` (verify, read-only).
#[derive(Debug, Clone, Copy)]
pub struct AuditLog;

impl AuditLog {
    /// Append an event in the caller's transaction.
    ///
    /// Computes the hash chain end-to-end and INSERTs a row whose
    /// `prev_hash` points at the current head's `this_hash` (32 zero
    /// bytes for the genesis insert). Returns the assigned `seq`.
    ///
    /// # Atomicity
    ///
    /// The append uses the caller's transaction handle. If the caller
    /// rolls back, the audit row goes with it — no orphan rows. The
    /// chain-ordering trigger in migration 18 enforces that any
    /// concurrent transaction whose `prev_hash` does not match the
    /// committed head fails closed (SQLSTATE `P0001`).
    ///
    /// # Errors
    ///
    /// - [`AuditError::Db`] for any underlying SQL error (including
    ///   chain-break / append-only violations from the migration-18
    ///   triggers).
    /// - [`AuditError::Encode`] when canonical CBOR encoding of the
    ///   payload fails. In practice unreachable — `json_to_lex` is
    ///   lenient/infallible and `lex_cbor::encode` only errors on
    ///   nested data structures we never produce — but the typed path
    ///   keeps the error chain uniform.
    /// - [`AuditError::HashMismatch`] when the current head's
    ///   `this_hash` column is not 32 bytes (schema drift).
    pub async fn record(tx: &mut sqlx::PgConnection, event: AuditEvent) -> Result<i64, AuditError> {
        // Look up current head (this_hash of MAX(seq)). The
        // chain-ordering trigger in migration 18 will reject any
        // concurrent INSERT whose prev_hash disagrees with the
        // committed head, so the read-then-write is safe under
        // concurrency: the worst case is a transient P0001 from the
        // trigger that the caller can retry.
        let head_row = sqlx::query!(
            r#"
            SELECT seq, this_hash
            FROM audit_log
            ORDER BY seq DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let prev_hash: [u8; HASH_LEN] = match head_row {
            None => GENESIS_PREV,
            Some(row) => {
                let bytes = row.this_hash;
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| AuditError::HashMismatch { at_seq: row.seq })?
            }
        };

        // Microsecond-precision timestamp, rounded to match what
        // Postgres will round-trip back from TIMESTAMPTZ. Calling
        // `trunc_subsecs(6)` (chrono's microsecond truncation) makes
        // the in-memory bytes byte-identical to what `verify_chain`
        // will re-format from the DB on read.
        let ts: DateTime<Utc> = Utc::now().trunc_subsecs(6);

        let this_hash = compute_hash(&prev_hash, &event.payload, ts, &event.actor, &event.kind)?;

        let seq = sqlx::query_scalar!(
            r#"
            INSERT INTO audit_log (ts, actor, kind, payload, prev_hash, this_hash)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING seq
            "#,
            ts,
            event.actor,
            event.kind,
            event.payload,
            &prev_hash[..],
            &this_hash[..],
        )
        .fetch_one(&mut *tx)
        .await?;

        Ok(seq)
    }
}

/// Format a `DateTime<Utc>` as the canonical preimage timestamp.
///
/// `YYYY-MM-DDTHH:MM:SS.ffffffZ` — 27 ASCII bytes, microsecond
/// precision, always UTC. The format string `%.6f` always emits exactly
/// 6 fractional digits (chrono pads with zeros), so the byte width is
/// invariant across all valid timestamps. The fixed width matters for
/// the preimage layout because the timestamp field has no length
/// prefix.
fn format_ts(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

/// Canonically encode a JSON payload as DAG-CBOR.
///
/// Bridge: `serde_json::Value → LexValue → DAG-CBOR bytes`. The first
/// hop is lenient (never errors). The second hop is strict canonical
/// DAG-CBOR — sorted maps, shortest-form integers, no floats, no
/// indefinite-length items.
fn canonical_payload(payload: &serde_json::Value) -> Result<Vec<u8>, &'static str> {
    let lex = lex_json::json_to_lex(payload);
    lex_cbor::encode(&lex).map_err(|_| "DAG-CBOR encode failed")
}

/// Compute `this_hash` from the documented preimage.
fn compute_hash(
    prev: &[u8; HASH_LEN],
    payload: &serde_json::Value,
    ts: DateTime<Utc>,
    actor: &str,
    kind: &str,
) -> Result<[u8; HASH_LEN], AuditError> {
    let cbor = canonical_payload(payload).map_err(|reason| AuditError::Encode { reason })?;
    let ts_bytes = format_ts(ts);

    let mut hasher = Sha256::new();
    hasher.update(prev);
    hasher.update(&cbor);
    hasher.update(ts_bytes.as_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(kind.as_bytes());
    Ok(hasher.finalize().into())
}

/// Walk the chain from `seq = 1` to the current head. Re-hashes every
/// row and asserts `prev_hash` chains forward correctly.
///
/// Returns the seq of the chain head on a clean walk, or
/// [`VerifyError::Tampered`] for the first offending row.
///
/// # Errors
///
/// - [`VerifyError::Db`] for any underlying SQL error.
/// - [`VerifyError::Encode`] when a stored payload cannot be re-encoded
///   as canonical CBOR.
/// - [`VerifyError::Tampered`] when the recomputed `this_hash` differs
///   from the stored value, or when the stored `prev_hash` does not
///   match the prior row's `this_hash`. Either case indicates a
///   privilege-escalating writer bypassed the append-only triggers.
pub async fn verify_chain(pool: &PgPool) -> Result<i64, VerifyError> {
    use futures::StreamExt as _;

    let mut conn = pool.acquire().await?;

    // Stream rows in seq order. The chain is verified in linear time
    // with `O(1)` memory — the audit log is potentially large
    // (millions of rows in a busy deployment) so we never load it all
    // into a `Vec`.
    let mut rows = sqlx::query!(
        r#"
        SELECT seq, ts, actor, kind, payload, prev_hash, this_hash
        FROM audit_log
        ORDER BY seq ASC
        "#,
    )
    .fetch(&mut *conn);

    let mut expected_prev: [u8; HASH_LEN] = GENESIS_PREV;
    let mut last_seq: i64 = 0;
    while let Some(row_result) = rows.next().await {
        let row = row_result?;
        let seq = row.seq;

        let stored_prev: [u8; HASH_LEN] =
            row.prev_hash
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::Tampered {
                    at_seq: seq,
                    field: TamperedField::PrevHash,
                    expected: expected_prev,
                    found: GENESIS_PREV,
                })?;
        if stored_prev != expected_prev {
            return Err(VerifyError::Tampered {
                at_seq: seq,
                field: TamperedField::PrevHash,
                expected: expected_prev,
                found: stored_prev,
            });
        }

        let stored_this: [u8; HASH_LEN] =
            row.this_hash
                .as_slice()
                .try_into()
                .map_err(|_| VerifyError::Tampered {
                    at_seq: seq,
                    field: TamperedField::ThisHash,
                    expected: expected_prev,
                    found: GENESIS_PREV,
                })?;

        // chrono round-trip: the DB-side value is already at
        // microsecond precision, so re-formatting is byte-identical
        // to what was hashed at insert time.
        let recomputed = {
            let cbor = canonical_payload(&row.payload).map_err(|reason| VerifyError::Encode {
                at_seq: seq,
                reason,
            })?;
            let mut hasher = Sha256::new();
            hasher.update(stored_prev);
            hasher.update(&cbor);
            hasher.update(format_ts(row.ts).as_bytes());
            hasher.update(row.actor.as_bytes());
            hasher.update(row.kind.as_bytes());
            let out: [u8; HASH_LEN] = hasher.finalize().into();
            out
        };

        if recomputed != stored_this {
            return Err(VerifyError::Tampered {
                at_seq: seq,
                field: TamperedField::ThisHash,
                expected: recomputed,
                found: stored_this,
            });
        }

        expected_prev = stored_this;
        last_seq = seq;
    }

    Ok(last_seq)
}

/// Read the current chain head's `this_hash` (the maximum-seq row).
///
/// Returns `None` when the chain is empty (no rows yet). Used by
/// [`crate::audit::AttestationWorker`] to snapshot the head to the
/// external blob store on each tick.
///
/// # Errors
///
/// [`sqlx::Error`] for any underlying SQL failure.
pub async fn current_head(pool: &PgPool) -> Result<Option<(i64, Vec<u8>)>, sqlx::Error> {
    let row = sqlx::query!(
        r#"
        SELECT seq, this_hash
        FROM audit_log
        ORDER BY seq DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.seq, r.this_hash)))
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
    use chrono::TimeZone as _;

    fn fixed_ts() -> DateTime<Utc> {
        // 2026-05-14T12:34:56.123456Z — within the chrono valid range,
        // microsecond-aligned so `trunc_subsecs(6)` is a no-op.
        Utc.with_ymd_and_hms(2026, 5, 14, 12, 34, 56)
            .single()
            .expect("fixed timestamp must construct")
            + chrono::Duration::microseconds(123_456)
    }

    fn sample_payload() -> serde_json::Value {
        serde_json::json!({
            "action_id": "00000000-0000-0000-0000-000000000000",
            "kind": "label",
            "subject_id": "11111111-1111-1111-1111-111111111111",
        })
    }

    #[test]
    fn compute_hash_is_deterministic_for_identical_inputs() {
        let prev = [7u8; HASH_LEN];
        let ts = fixed_ts();
        let payload = sample_payload();
        let h1 = compute_hash(&prev, &payload, ts, "moderator-a", "action.commit").unwrap();
        let h2 = compute_hash(&prev, &payload, ts, "moderator-a", "action.commit").unwrap();
        assert_eq!(h1, h2, "identical inputs must yield identical hash");
    }

    #[test]
    fn compute_hash_changes_when_prev_changes() {
        let ts = fixed_ts();
        let payload = sample_payload();
        let h1 = compute_hash(
            &[0u8; HASH_LEN],
            &payload,
            ts,
            "moderator-a",
            "action.commit",
        )
        .unwrap();
        let h2 = compute_hash(
            &[1u8; HASH_LEN],
            &payload,
            ts,
            "moderator-a",
            "action.commit",
        )
        .unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_hash_changes_when_payload_changes() {
        let prev = [0u8; HASH_LEN];
        let ts = fixed_ts();
        let p1 = sample_payload();
        let mut p2 = sample_payload();
        // Mutating any payload byte produces a distinct CBOR encoding,
        // which produces a distinct preimage.
        p2["kind"] = serde_json::json!("reverse");
        let h1 = compute_hash(&prev, &p1, ts, "m", "k").unwrap();
        let h2 = compute_hash(&prev, &p2, ts, "m", "k").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_hash_changes_when_ts_changes() {
        let prev = [0u8; HASH_LEN];
        let payload = sample_payload();
        let t1 = fixed_ts();
        let t2 = t1 + chrono::Duration::microseconds(1);
        let h1 = compute_hash(&prev, &payload, t1, "m", "k").unwrap();
        let h2 = compute_hash(&prev, &payload, t2, "m", "k").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_hash_changes_when_actor_changes() {
        let prev = [0u8; HASH_LEN];
        let ts = fixed_ts();
        let payload = sample_payload();
        let h1 = compute_hash(&prev, &payload, ts, "actor-a", "k").unwrap();
        let h2 = compute_hash(&prev, &payload, ts, "actor-b", "k").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn compute_hash_changes_when_kind_changes() {
        let prev = [0u8; HASH_LEN];
        let ts = fixed_ts();
        let payload = sample_payload();
        let h1 = compute_hash(&prev, &payload, ts, "m", "action.commit").unwrap();
        let h2 = compute_hash(&prev, &payload, ts, "m", "action.reverse").unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn genesis_prev_hash_is_32_zero_bytes() {
        // Documented invariant: the genesis row's prev_hash is the
        // all-zero 32-byte vector. Migration 18's chain-check trigger
        // also enforces this; this test pins the in-Rust constant so a
        // refactor that ships a different sentinel is caught locally.
        assert_eq!(GENESIS_PREV, [0u8; 32]);
        assert_eq!(GENESIS_PREV.len(), HASH_LEN);
    }

    #[test]
    fn format_ts_is_27_ascii_bytes() {
        // The preimage layout relies on the timestamp being a
        // fixed-width 27-byte ASCII string. Anything else would make
        // the preimage ambiguous.
        let s = format_ts(fixed_ts());
        assert_eq!(s.len(), 27, "ts must be 27 ASCII bytes");
        assert!(s.is_ascii());
        assert_eq!(s, "2026-05-14T12:34:56.123456Z");
    }
}
