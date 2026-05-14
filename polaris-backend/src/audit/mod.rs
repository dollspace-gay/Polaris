//! Hash-chained audit log + external attestation (issue #35; design.md
//! §6 + §9).
//!
//! Every mutating path in the backend (action commit, action reverse,
//! labeler key rotation, config change, etc.) appends a row to the
//! `audit_log` table. Each row's `this_hash` commits the prior row's
//! `this_hash`, so internal tampering with a historic row breaks the
//! chain at that row and every row after.
//!
//! # Threat model
//!
//! Design `§9` calls out "insider tampering with audit log" as one of
//! the primary threats. The mitigations are layered:
//!
//! 1. **In-band detection.** The chain is verifiable in linear time by
//!    [`verify_chain`]. Any rewrite of a historic row (or insertion at
//!    a gap, or deletion) is detected. A row-level edit through the
//!    database (modulo bypassing the trigger via superuser) breaks the
//!    chain.
//! 2. **Append-only triggers.** [`audit_log_append_only`] (the SQL
//!    trigger declared in migration 18) rejects every UPDATE and
//!    DELETE against `audit_log`. A non-superuser actor cannot bypass
//!    this without a privilege escalation.
//! 3. **External attestation.** [`AttestationWorker`] periodically
//!    snapshots the chain head (the `this_hash` of the maximum-seq
//!    row) to a [`crate::evidence::BlobStore`] under
//!    `audit-attestation/{iso8601}.txt`. Operators wire the bucket to
//!    S3 object-lock (compliance-mode WORM) so the snapshots cannot be
//!    deleted even by the operator's own credentials. An external
//!    auditor compares the local head against the attested head to
//!    detect tampering that escaped the in-band guarantee (a privilege
//!    escalation that *did* bypass the SQL triggers).
//!
//! # Append shape
//!
//! ```ignore
//! let mut tx = pool.begin().await?;
//! // ... do the work being audited inside `tx` ...
//! AuditLog::record(&mut *tx, AuditEvent { actor, kind, payload }).await?;
//! tx.commit().await?;
//! ```
//!
//! The append is in the caller's transaction so the audit row commits
//! atomically with the event being audited. If `tx.commit()` rolls
//! back, the audit row goes with it — no orphan rows.

pub mod attestation;
pub mod log;

pub use attestation::{AttestationError, AttestationWorker};
pub use log::{AuditError, AuditEvent, AuditLog, VerifyError, verify_chain};
