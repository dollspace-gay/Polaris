//! Repository functions for the federation state machine (issue #108 / M5 PR 2).
//!
//! # Transactional invariant
//!
//! Every multi-step operation (materialize + transition-insert + quarantine-delete)
//! runs inside one `sqlx::Transaction`. A crash or cancellation mid-flight
//! leaves the database in the pre-operation state — no partially-materialised
//! escalation, no orphaned quarantine row.
//!
//! # Append-only tables
//!
//! `federation_state_transitions` and `federation_messages` are append-only.
//! This module never issues `UPDATE` or `DELETE` against those tables.
//!
//! # Idempotent materialise
//!
//! `materialize_from_quarantine` uses `INSERT … ON CONFLICT (original_cid) DO
//! NOTHING RETURNING id`. A replay (e.g. restart after a crash between the
//! `DELETE` and the outer transaction commit) silently skips the insert and
//! returns [`MaterializeOutcome::AlreadyMaterialized`].
//!
//! # sqlx offline cache note
//!
//! All queries in this module use the **untyped** `sqlx::query` / `query_scalar`
//! forms (without the `!` macro) rather than the compile-time-checked `query!`
//! macros. This is consistent with the PR 1 federation ingest layer and avoids
//! the `cargo sqlx prepare` requirement for new tables. Compile-time query
//! checking can be enabled after a `cargo sqlx prepare` pass once a live DB
//! is available.

use chrono::Utc;
use sqlx::{PgConnection, Row as _};
use tracing::info_span;
use uuid::Uuid;

use crate::federation::state::{EscalationState, FederationStateError, UnknownStateError};
use polaris_types::lexicon_mapping::{self, MappingError};

// ── error type ────────────────────────────────────────────────────────────

/// Errors produced by the federation repository layer.
#[derive(Debug, thiserror::Error)]
pub enum FederationRepoError {
    /// A Postgres-level error (connection lost, constraint violation, etc.).
    #[error("database error in federation repo")]
    Database(#[from] sqlx::Error),

    /// A state-machine transition was rejected.
    #[error("state machine error")]
    State(#[from] FederationStateError),

    /// The lexicon mapping rejected the quarantine record.
    ///
    /// This happens when the CBOR decoded to a shape that does not satisfy
    /// the privacy-boundary invariants (e.g. an unknown subject discriminator).
    #[error("lexicon mapping error")]
    Mapping(#[from] MappingError),

    /// The raw CBOR in the quarantine row could not be decoded.
    #[error("CBOR decode failed for cid={cid}: {message}")]
    CborDecode {
        /// The CID of the quarantine row that could not be decoded.
        cid: String,
        /// Human-readable description of the decode failure.
        message: String,
    },

    /// The quarantine row carried an unrecognised `state` column value.
    ///
    /// Indicates schema drift between the application and database.
    #[error("unknown state in federation_escalations row")]
    UnknownState(#[from] UnknownStateError),

    /// The quarantine row referenced by `cid` was not found.
    ///
    /// This can happen if two workers race to materialise the same CID;
    /// the loser should treat this as success.
    #[error("quarantine row not found for cid={cid}")]
    QuarantineNotFound {
        /// The CID that was not found.
        cid: String,
    },
}

// ── outcome type ──────────────────────────────────────────────────────────

/// Result of a [`materialize_from_quarantine`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializeOutcome {
    /// A new `federation_escalations` row was created.
    ///
    /// The `id` is the UUID assigned by the application (v4).
    Created {
        /// The newly-created escalation UUID.
        escalation_id: Uuid,
    },
    /// The quarantine row's `original_cid` was already present in
    /// `federation_escalations`. The existing row was left untouched.
    ///
    /// This is the replay-safe path: the function is a no-op and returns
    /// the existing escalation's id.
    AlreadyMaterialized {
        /// The existing escalation UUID.
        escalation_id: Uuid,
    },
}

// ── quarantine decode helper ──────────────────────────────────────────────

/// Fields decoded from a `federation_quarantine` raw CBOR payload.
struct DecodedEscalation {
    source_did: String,
    target_did: String,
    subject_did_or_uri: String,
    reason: String,
}

/// Decode the DAG-CBOR bytes from a quarantine row into the internal field set.
///
/// DAG-CBOR → `LexValue` → `serde_json::Value` → wire type → internal fields.
/// This is a pure synchronous helper; callers must not hold `tx` across it.
fn decode_quarantine_cbor(
    raw_cbor: &[u8],
    cid: &str,
) -> Result<DecodedEscalation, FederationRepoError> {
    let lex_value =
        proto_blue::lex_cbor::decode(raw_cbor).map_err(|e| FederationRepoError::CborDecode {
            cid: cid.to_owned(),
            message: e.to_string(),
        })?;

    let json_value = proto_blue::lex_json::lex_to_json(&lex_value);

    let wire =
        serde_json::from_value::<polaris_lexicons::gay::dollspace::polaris::escalation::Main>(
            json_value,
        )
        .map_err(|e| FederationRepoError::CborDecode {
            cid: cid.to_owned(),
            message: format!("escalation deserialise: {e}"),
        })?;

    let escalation = lexicon_mapping::from_lexicon_escalation(wire)?;
    Ok(DecodedEscalation {
        source_did: escalation.source_did.as_str().to_owned(),
        target_did: escalation.target_did.as_str().to_owned(),
        subject_did_or_uri: escalation.subject.as_str().to_owned(),
        reason: escalation.reason.clone(),
    })
}

// ── materialize_from_quarantine ───────────────────────────────────────────

/// Promote a verified quarantine row into an active `federation_escalations` row.
///
/// Steps (all inside `tx`):
/// 1. `SELECT` the quarantine row by `cid` (returns
///    [`FederationRepoError::QuarantineNotFound`] if absent).
/// 2. Decode the `raw_cbor` bytes — see [`decode_quarantine_cbor`].
/// 3. `INSERT INTO federation_escalations … ON CONFLICT (original_cid) DO NOTHING
///    RETURNING id` — idempotent.
/// 4. If the row was inserted (not skipped): append a `federation_state_transitions`
///    row recording the `'' → proposed` initial state.
/// 5. `DELETE FROM federation_quarantine WHERE cid = $1`.
///
/// The caller must commit `tx` after this function returns `Ok`.
///
/// # Errors
///
/// - [`FederationRepoError::QuarantineNotFound`] — quarantine row absent (race).
/// - [`FederationRepoError::CborDecode`] — raw bytes are not valid CBOR.
/// - [`FederationRepoError::Mapping`] — wire type failed the lexicon mapping.
/// - [`FederationRepoError::Database`] — any Postgres error.
pub async fn materialize_from_quarantine(
    tx: &mut PgConnection,
    quarantine_cid: &str,
) -> Result<MaterializeOutcome, FederationRepoError> {
    // Note: do NOT use `.entered()` in async functions — the guard is not
    // `Send` across `.await`.
    let _span = info_span!("federation_materialize", cid = %quarantine_cid);

    // ── 1. Fetch the quarantine row ───────────────────────────────────────
    let row = sqlx::query(
        "SELECT source_did, raw_cbor \
         FROM   federation_quarantine \
         WHERE  cid = $1",
    )
    .bind(quarantine_cid)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| FederationRepoError::QuarantineNotFound {
        cid: quarantine_cid.to_owned(),
    })?;

    let raw_cbor: Vec<u8> = row.try_get("raw_cbor")?;

    // ── 2. Decode CBOR (sync helper — no .await) ──────────────────────────
    let decoded = decode_quarantine_cbor(&raw_cbor, quarantine_cid)?;

    // ── 3. Idempotent insert into federation_escalations ─────────────────
    let escalation_id = Uuid::new_v4();
    let initial_state = EscalationState::Proposed.as_str();
    let now = Utc::now();

    let inserted_row = sqlx::query(
        "INSERT INTO federation_escalations \
            (id, source_did, target_did, state, subject_did_or_uri, original_cid, reason, \
             opened_at, last_event_at) \
         VALUES \
            ($1, $2, $3, $4, $5, $6, $7, $8, $8) \
         ON CONFLICT (original_cid) DO NOTHING \
         RETURNING id",
    )
    .bind(escalation_id)
    .bind(&decoded.source_did)
    .bind(&decoded.target_did)
    .bind(initial_state)
    .bind(&decoded.subject_did_or_uri)
    .bind(quarantine_cid)
    .bind(&decoded.reason)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;

    // ── 4. Append initial state transition (only on new insert) ───────────
    let outcome = if let Some(inserted) = inserted_row {
        let new_id: Uuid = inserted.try_get("id")?;
        sqlx::query(
            "INSERT INTO federation_state_transitions \
                (escalation_id, from_state, to_state, triggered_by_cid, at) \
             VALUES ($1, '', $2, $3, $4)",
        )
        .bind(new_id)
        .bind(initial_state)
        .bind(quarantine_cid)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tracing::info!(
            cid = %quarantine_cid, escalation_id = %new_id,
            source_did = %decoded.source_did, target_did = %decoded.target_did,
            "materialised quarantine row into federation_escalations",
        );
        MaterializeOutcome::Created {
            escalation_id: new_id,
        }
    } else {
        let existing_row =
            sqlx::query("SELECT id FROM federation_escalations WHERE original_cid = $1")
                .bind(quarantine_cid)
                .fetch_one(&mut *tx)
                .await?;
        let existing_id: Uuid = existing_row.try_get("id")?;
        tracing::info!(
            cid = %quarantine_cid, escalation_id = %existing_id,
            "quarantine row already materialised; skipping duplicate",
        );
        MaterializeOutcome::AlreadyMaterialized {
            escalation_id: existing_id,
        }
    };

    // ── 5. Delete the quarantine row ──────────────────────────────────────
    sqlx::query("DELETE FROM federation_quarantine WHERE cid = $1")
        .bind(quarantine_cid)
        .execute(&mut *tx)
        .await?;

    Ok(outcome)
}

// ── transition_escalation ─────────────────────────────────────────────────

/// Apply a validated state-machine transition to an escalation.
///
/// Steps (all inside `tx`):
/// 1. Validate via [`crate::federation::state::validate_transition`].
/// 2. `UPDATE federation_escalations SET state = $2, last_event_at = now()`.
/// 3. `INSERT INTO federation_state_transitions …` — append-only audit row.
///
/// # Errors
///
/// - [`FederationRepoError::Database`] — Postgres error or escalation row absent.
/// - [`FederationRepoError::State`] — transition rejected by the state machine.
pub async fn transition_escalation(
    tx: &mut PgConnection,
    escalation_id: Uuid,
    from: EscalationState,
    to: EscalationState,
    triggered_by_cid: Option<&str>,
) -> Result<(), FederationRepoError> {
    // Validate the requested transition BEFORE touching the DB.
    crate::federation::state::validate_transition(from, to)?;

    let new_state = to.as_str();
    let now = Utc::now();

    // ── UPDATE federation_escalations ─────────────────────────────────────
    sqlx::query(
        "UPDATE federation_escalations \
         SET    state = $1, \
                last_event_at = $2 \
         WHERE  id = $3",
    )
    .bind(new_state)
    .bind(now)
    .bind(escalation_id)
    .execute(&mut *tx)
    .await?;

    // ── Append audit row (append-only table) ──────────────────────────────
    sqlx::query(
        "INSERT INTO federation_state_transitions \
            (escalation_id, from_state, to_state, triggered_by_cid, at) \
         VALUES \
            ($1, $2, $3, $4, $5)",
    )
    .bind(escalation_id)
    .bind(from.as_str())
    .bind(new_state)
    .bind(triggered_by_cid)
    .bind(now)
    .execute(&mut *tx)
    .await?;

    tracing::info!(
        escalation_id = %escalation_id,
        from = %from,
        to = %to,
        "applied federation state transition",
    );

    Ok(())
}

// ── unit tests ────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code — rust-quality §7"
)]
mod tests {
    use super::*;
    use crate::federation::state::{EscalationState, FederationStateError};

    /// Validate that [`FederationRepoError`] variants are constructible and have
    /// meaningful Display output.
    #[test]
    fn repo_error_display() {
        let e = FederationRepoError::Database(sqlx::Error::RowNotFound);
        assert!(
            e.to_string().contains("database error"),
            "expected 'database error' in {e}",
        );

        let e = FederationRepoError::State(FederationStateError::InvalidTransition {
            from: EscalationState::Proposed,
            to: EscalationState::Resolved,
        });
        assert!(
            e.to_string().contains("state machine error"),
            "expected 'state machine error' in {e}",
        );

        let e = FederationRepoError::CborDecode {
            cid: "bafybeiabc".to_owned(),
            message: "invalid varint".to_owned(),
        };
        let s = e.to_string();
        assert!(s.contains("bafybeiabc"), "expected cid in {s}");

        let e = FederationRepoError::QuarantineNotFound {
            cid: "bafyxyz".to_owned(),
        };
        assert!(e.to_string().contains("bafyxyz"), "expected cid in {e}",);
    }

    /// Validate [`MaterializeOutcome`] variants are distinct.
    #[test]
    fn materialize_outcome_variants() {
        let id = Uuid::new_v4();
        let created = MaterializeOutcome::Created { escalation_id: id };
        let already = MaterializeOutcome::AlreadyMaterialized { escalation_id: id };
        assert_ne!(created, already);
    }
}
