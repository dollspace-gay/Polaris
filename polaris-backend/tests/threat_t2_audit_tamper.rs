//! Threat-model T2 — insider tampering with the audit log
//! (`design.md` §9 #2; issue #39).
//!
//! # Mitigation under test
//!
//! Each row in `audit_log` commits the previous row's `this_hash` into
//! its own preimage. The migration-18 triggers reject UPDATE / DELETE
//! and any INSERT whose `prev_hash` disagrees with the committed head.
//! [`polaris_backend::audit::verify_chain`] is the independent
//! verifier — it walks the chain from `seq = 1` and recomputes every
//! row's `this_hash`, returning [`VerifyError::Tampered`] at the first
//! offending row.
//!
//! # Test strategy
//!
//! `tests/audit_chain.rs` (issue #35) already covers the triggers (no
//! UPDATE, no DELETE, no chain-break-at-INSERT). This file targets the
//! *verifier itself*: an attacker who bypasses the triggers (e.g. via
//! superuser, via a buggy migration that drops the triggers, via direct
//! `pg_class` mutation) leaves a corrupted historic row; the verifier
//! must detect it.
//!
//! We exercise the verifier by:
//!
//! 1. Appending 5 audit events the normal way (via `AuditLog::record`).
//! 2. Temporarily disabling the append-only triggers (the same pattern
//!    used by `tests/reversal_workflow.rs::force_window_expired`).
//! 3. Flipping a single byte of `this_hash` on `seq = 3`.
//! 4. Re-enabling the triggers.
//! 5. Calling `verify_chain` and asserting it returns
//!    `VerifyError::Tampered { at_seq: 3, … }`.
//!
//! Step 2's bypass is intentionally narrow — the triggers stay
//! disabled for exactly one `UPDATE` and are re-enabled before
//! `verify_chain` runs. The test simulates an attacker who bypasses
//! the *guards* but cannot bypass the *cryptographic verifier*.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use polaris_backend::audit::{AuditEvent, AuditLog, TamperedField, VerifyError, verify_chain};

#[path = "threats_common/mod.rs"]
mod common;

fn sample_event(actor: &str, kind: &str, n: u32) -> AuditEvent {
    AuditEvent {
        actor: actor.to_owned(),
        kind: kind.to_owned(),
        payload: serde_json::json!({
            "seq_in_test": n,
            "action_id": "00000000-0000-0000-0000-000000000000",
            "kind": "label",
        }),
    }
}

/// T2 MUST-PASS: `verify_chain` flags a historic-row hash flip.
///
/// Appends 5 audit events, disables the append-only triggers,
/// corrupts `seq = 3`'s `this_hash`, re-enables triggers, then
/// asserts the verifier returns `Tampered { at_seq: 3, … }`.
#[tokio::test]
async fn verify_chain_detects_byte_flip_on_historic_row() -> Result<(), Box<dyn std::error::Error>>
{
    if !common::docker_available() {
        println!("SKIP threat_t2_audit_tamper: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    // 1. Seed 5 audit events through the normal path.
    for i in 1..=5u32 {
        let mut tx = fixture.pool.begin().await?;
        let seq = AuditLog::record(&mut tx, sample_event("system", "seed", i)).await?;
        tx.commit().await?;
        assert_eq!(seq, i64::from(i), "seed seq must match insert ordinal");
    }

    // Sanity: chain verifies clean before tampering.
    let head = verify_chain(&fixture.pool).await?;
    assert_eq!(head, 5, "pre-tamper chain must verify to seq=5");

    // 2-4. Disable triggers, flip a byte on seq=3, re-enable triggers.
    //
    // The bypass mirrors the pattern in `tests/reversal_workflow.rs`:
    // `ALTER TABLE … DISABLE TRIGGER` + targeted UPDATE + ENABLE.
    // The trigger surface (already tested by `tests/audit_chain.rs`)
    // is not what we're verifying here — we're verifying that even
    // when the triggers are gone, the cryptographic verifier still
    // detects the tamper.
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update")
        .execute(&fixture.pool)
        .await?;
    // Flip the high bit of byte 0 of `this_hash` at seq=3. A single
    // bit-flip is the strongest invariant to assert: the verifier
    // must detect the smallest possible corruption, not just gross
    // mutation.
    sqlx::query(
        "UPDATE audit_log
            SET this_hash = SET_BYTE(this_hash, 0, GET_BYTE(this_hash, 0) # 128)
            WHERE seq = 3",
    )
    .execute(&fixture.pool)
    .await?;
    sqlx::query("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update")
        .execute(&fixture.pool)
        .await?;

    // 5. Verifier must flag seq=3 (the row whose `this_hash` no longer
    // matches the recomputed preimage). The chain at seq=4 ALSO
    // breaks (because seq=4's prev_hash points at the OLD seq=3
    // this_hash, which no longer equals the stored seq=3 this_hash),
    // but the verifier walks from seq=1 and the first row it flags is
    // seq=3 — the row whose own preimage no longer hashes to the
    // stored `this_hash`.
    let err = verify_chain(&fixture.pool)
        .await
        .expect_err("verify_chain must reject the tampered chain");

    match err {
        VerifyError::Tampered {
            at_seq,
            field,
            expected,
            found,
        } => {
            assert_eq!(
                at_seq, 3,
                "verifier must flag the row whose hash was flipped"
            );
            assert_eq!(
                field,
                TamperedField::ThisHash,
                "a flipped this_hash byte must surface as TamperedField::ThisHash",
            );
            assert_ne!(
                expected, found,
                "tampered row's expected and found hashes must differ",
            );
        }
        other => panic!("expected VerifyError::Tampered, got {other:?}"),
    }

    Ok(())
}

/// T2 MUST-PASS: `verify_chain` flags a `prev_hash` link break too.
///
/// Complements the above: where the first test corrupts a row's own
/// hash, this one corrupts the link from seq=N to seq=N+1. Both
/// failure modes are within the verifier's contract.
#[tokio::test]
async fn verify_chain_detects_prev_hash_link_break() -> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t2_audit_tamper link-break: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    // Seed 5 events.
    for i in 1..=5u32 {
        let mut tx = fixture.pool.begin().await?;
        AuditLog::record(&mut tx, sample_event("system", "seed", i)).await?;
        tx.commit().await?;
    }

    // Disable triggers, scramble `prev_hash` on seq=4 (so seq=4's link
    // to seq=3 breaks), re-enable triggers.
    sqlx::query("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update")
        .execute(&fixture.pool)
        .await?;
    sqlx::query(
        "UPDATE audit_log
            SET prev_hash = decode(repeat('FF', 32), 'hex')
            WHERE seq = 4",
    )
    .execute(&fixture.pool)
    .await?;
    sqlx::query("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update")
        .execute(&fixture.pool)
        .await?;

    let err = verify_chain(&fixture.pool)
        .await
        .expect_err("verify_chain must reject the link break");

    match err {
        VerifyError::Tampered { at_seq, field, .. } => {
            assert_eq!(
                at_seq, 4,
                "verifier must flag seq=4 (the row whose prev_hash no longer links to seq=3)",
            );
            assert_eq!(
                field,
                TamperedField::PrevHash,
                "a scrambled prev_hash must surface as TamperedField::PrevHash",
            );
        }
        other => panic!("expected VerifyError::Tampered, got {other:?}"),
    }

    Ok(())
}
