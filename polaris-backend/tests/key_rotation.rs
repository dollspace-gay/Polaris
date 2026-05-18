//! AC-15 binding integration test for the labeler key rotation flow (#65).
//!
//! Three scenarios:
//!
//! 1. **End-to-end rotation with cross-key verification** — emit L1 under K1,
//!    rotate, emit L2 under K2, then verify both signatures via the
//!    [`verify_label`](polaris_backend::labeler::verify::verify_label) helper
//!    that consults `signing_key_history` to recover the issuance-time key
//!    for each label.
//! 2. **Mid-rotation failure injection** — seed a `rotation_state` row at
//!    `last_step = 'key_written'` (matching the on-disk-key idempotency
//!    contract documented on `RotationContext::step_generate_key`), resume
//!    via [`RotationContext::resume`], and confirm the rotation completes
//!    cleanly *without* regenerating the K-256 secret (the on-disk hash is
//!    captured before resume and re-checked after).
//! 3. **Append-only triggers** — directly attempt `DELETE` and illegal
//!    `UPDATE` mutations against `signing_key_history` and `revoked_keys`;
//!    the migration-14 triggers must reject each with SQLSTATE `P0001`. The
//!    single legal `UPDATE` (the "retire" transition that sets
//!    `active_until` from `NULL` to a timestamp on the active row) must
//!    succeed.
//!
//! All three skip cleanly when the Docker daemon is not reachable, matching
//! the convention across the rest of `tests/`.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "integration test code is allowed to panic — rust-quality §7 convention; \
              long linear AC-15 scenarios are expected here (single Postgres startup per test); \
              `emitter` / `emitted` are the most readable names for the local emitter handle \
              and its return value"
)]

use std::io::Write as _;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::labeler::emitter::{EmittedLabel, LabelEmitter, SubjectRef};
use polaris_backend::labeler::rotation::{
    CustodyMode, RotationContext, RotationCustodyParams, RotationStep, bootstrap_active_key,
};
use polaris_backend::labeler::server::LabelBroadcaster;
use polaris_backend::labeler::signer::SigningKey;
use polaris_backend::labeler::signer::file_plain::FilePlainSigner;
use polaris_backend::labeler::verify::verify_label;
use polaris_backend::repo::{
    ActionRepo as _, IncidentRepo as _, NewAction, NewIncident, NewSubject, PgActionRepo,
    PgIncidentRepo, PgSubjectRepo, SubjectRepo as _,
};
use polaris_types::{
    ActionKind, Did, IncidentStatus, LabelValue, ModeratorId, PolicyId, Severity, SubjectKind,
};
use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Keypair as _};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use sqlx::Row as _;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

// ── Fixture helpers ─────────────────────────────────────────────────────

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a hermetic Postgres 16-alpine via testcontainers and run every
/// migration through the production [`db::connect`] path. Returns the
/// migrated pool and the container handle (the latter must stay alive
/// for the duration of the test — dropping it stops the container).
async fn fresh_pool() -> Result<
    (
        testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
        PgPool,
    ),
    Box<dyn std::error::Error>,
> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await?;
    let pool = database.pool().clone();
    Ok((container, pool))
}

/// Write a freshly-generated K-256 secret to a temp file under
/// `dir` at mode `0o600` and return the resulting [`FilePlainSigner`]
/// (already loaded), the keypair, and the on-disk path.
fn build_signer_in_dir(dir: &Path) -> (FilePlainSigner, K256Keypair, std::path::PathBuf) {
    let keypair = K256Keypair::generate();
    let secret = keypair.export_private_key();
    let path = dir.join(format!("polaris-key-{}.hex", Uuid::new_v4()));
    let mut file = std::fs::File::create(&path).expect("create key file");
    file.write_all(hex::encode(secret).as_bytes())
        .expect("write hex secret");
    file.flush().expect("flush key file");
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0o600");
    }
    let signer = FilePlainSigner::from_path(&path).expect("load signer");
    (signer, keypair, path)
}

/// SHA-256 the bytes at `path`.
fn sha256_of(path: &Path) -> [u8; 32] {
    let bytes = std::fs::read(path).expect("read key file for hash");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let out = hasher.finalize();
    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&out);
    arr
}

async fn insert_moderator(pool: &PgPool) -> ModeratorId {
    let external_id = format!("rotation-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await
    .expect("insert moderator");
    ModeratorId(row.id)
}

/// Seed the subject / incident / action chain the emitter needs and
/// return the originating action plus the subject ref so the caller can
/// drive [`LabelEmitter::emit`].
async fn seed_label_action(
    pool: &PgPool,
    moderator: ModeratorId,
    subject_did_str: &str,
    label_value: &str,
) -> Result<(polaris_types::Action, SubjectRef), Box<dyn std::error::Error>> {
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let actions = PgActionRepo::new(pool.clone());

    let subject = subjects
        .insert(NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new(subject_did_str)),
            uri: None,
            created_at: Utc::now(),
        })
        .await?;
    let incident = incidents
        .insert(NewIncident {
            primary_subject: subject.id,
            status: IncidentStatus::Open,
            severity: Severity::Medium,
            assigned_to: None,
        })
        .await?;
    let action = actions
        .insert(NewAction {
            incident_id: incident.id,
            subject_id: subject.id,
            moderator_id: moderator,
            kind: ActionKind::Label,
            label: Some(LabelValue::new(label_value)),
            reasoning: "long enough reasoning for the rotation AC-15 test".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            llm_audit: None,
        })
        .await?;

    let subject_ref = SubjectRef {
        did: Some(subject_did_str.to_owned()),
        uri: None,
        cid: None,
    };
    Ok((action, subject_ref))
}

/// Emit one Label row under `signer` and return the [`EmittedLabel`].
async fn emit_one_label(
    pool: &PgPool,
    signer: Arc<dyn SigningKey>,
    moderator: ModeratorId,
    subject_did_str: &str,
    label_value: &str,
) -> Result<EmittedLabel, Box<dyn std::error::Error>> {
    let broadcaster = LabelBroadcaster::with_default_capacity();
    let emitter = LabelEmitter::new(signer, pool.clone(), broadcaster);
    let (action, subject_ref) =
        seed_label_action(pool, moderator, subject_did_str, label_value).await?;
    let emitted = emitter.emit(&action, &subject_ref, None).await?;
    assert_eq!(emitted.len(), 1, "Label action emits exactly one row");
    Ok(emitted.into_iter().next().expect("one row guaranteed"))
}

// ── Test 1: AC-15 end-to-end ────────────────────────────────────────────

#[tokio::test]
async fn emit_rotate_emit_verify_both_under_issuance_time_keys()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP key_rotation::emit_rotate_emit_verify_both_under_issuance_time_keys: \
             docker daemon not reachable.",
        );
        return Ok(());
    }

    let (_container, pool) = fresh_pool().await?;
    let tmp = tempfile::tempdir()?;
    let moderator = insert_moderator(&pool).await;

    // ── Phase A: stand up K1 + emit L1 ──────────────────────────────────
    let (signer1, _keypair1, k1_path) = build_signer_in_dir(tmp.path());
    let k1_did = signer1.public_key_did().to_owned();
    let arc_signer1: Arc<dyn SigningKey> = Arc::new(signer1);

    // Bootstrap K1 into signing_key_history (active_from=now, active_until=NULL).
    bootstrap_active_key(&pool, &k1_did, CustodyMode::FilePlain).await?;

    let l1 = emit_one_label(
        &pool,
        Arc::clone(&arc_signer1),
        moderator,
        "did:plc:rotationtest1",
        "spam",
    )
    .await?;
    assert_eq!(l1.signing_did, k1_did);

    // ── Phase B: drive a full rotation K1 → K2 via the state machine ────
    //
    // The rotation CLI is the documented operator-side surface for this;
    // we invoke its underlying state machine in-process. The new-key path
    // lands inside the test's temp dir so the file is cleaned up with the
    // tempdir handle.
    let k2_path = tmp.path().join("k2.hex");
    let mut rotation = RotationContext::new_rotation(
        pool.clone(),
        CustodyMode::FilePlain,
        k2_path.clone(),
        RotationCustodyParams::FilePlain,
    )
    .await?;
    rotation.run().await?;
    assert_eq!(
        rotation.plan().last_step,
        RotationStep::Complete,
        "rotation must reach Complete on a clean run",
    );

    // The rotation wrote the new K-256 secret to k2_path; load it as the
    // live process signer for L2.
    let signer2 = FilePlainSigner::from_path(&k2_path)?;
    let k2_did = signer2.public_key_did().to_owned();
    assert_ne!(k1_did, k2_did, "rotation must yield a distinct key");
    assert_eq!(
        rotation.plan().new_did.as_deref(),
        Some(k2_did.as_str()),
        "rotation plan's new_did must match the on-disk key",
    );
    let arc_signer2: Arc<dyn SigningKey> = Arc::new(signer2);

    let l2 = emit_one_label(
        &pool,
        Arc::clone(&arc_signer2),
        moderator,
        "did:plc:rotationtest2",
        "spam",
    )
    .await?;
    assert_eq!(l2.signing_did, k2_did);

    // ── Phase C: verify both labels under their issuance-time keys ──────
    //
    // L1's signed_at lies in K1's active window (K1 was active when L1
    // was emitted; K1's active_until got set to a timestamp >= L1.signed_at
    // by the rotation). L2's signed_at lies in K2's active window
    // (K2 is current). verify_label resolves each via active_key_at.
    verify_label(&pool, &l1.cbor, &l1.signature, l1.signed_at)
        .await
        .expect("L1 must verify under issuance-time K1");
    verify_label(&pool, &l2.cbor, &l2.signature, l2.signed_at)
        .await
        .expect("L2 must verify under issuance-time K2");

    // Tamper detection still works across the history boundary: flipping
    // a byte in L1's CBOR must NOT verify even though we look it up
    // under K1.
    let mut tampered = l1.cbor.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x80;
    let tamper_result = verify_label(&pool, &tampered, &l1.signature, l1.signed_at).await;
    assert!(
        tamper_result.is_err(),
        "tampered L1 CBOR must NOT verify under K1, got {tamper_result:?}",
    );

    // ── Phase D: schema-level invariants ────────────────────────────────
    //
    // signing_key_history must have exactly two rows: K1 (with
    // active_until set) and K2 (with active_until NULL).
    let history_rows = sqlx::query(
        r"SELECT public_key_did, active_until IS NULL AS still_active
          FROM signing_key_history
          ORDER BY id ASC",
    )
    .fetch_all(&pool)
    .await?;
    assert_eq!(
        history_rows.len(),
        2,
        "signing_key_history must carry exactly K1 + K2 after one rotation",
    );
    let row0_did: String = history_rows[0].try_get("public_key_did")?;
    let row0_active: bool = history_rows[0].try_get("still_active")?;
    let row1_did: String = history_rows[1].try_get("public_key_did")?;
    let row1_active: bool = history_rows[1].try_get("still_active")?;
    assert_eq!(row0_did, k1_did);
    assert!(!row0_active, "K1's active_until must be set post-rotation");
    assert_eq!(row1_did, k2_did);
    assert!(row1_active, "K2 must be the current active key (NULL)");

    // revoked_keys must contain K1 with reason='rotation'.
    let revoked_rows =
        sqlx::query(r"SELECT public_key_did, reason FROM revoked_keys ORDER BY revoked_at ASC")
            .fetch_all(&pool)
            .await?;
    assert_eq!(
        revoked_rows.len(),
        1,
        "exactly one key must be revoked after the K1 → K2 rotation",
    );
    let revoked_did: String = revoked_rows[0].try_get("public_key_did")?;
    let revoked_reason: String = revoked_rows[0].try_get("reason")?;
    assert_eq!(revoked_did, k1_did);
    assert_eq!(revoked_reason, "rotation");

    // Sanity: the K1 file is untouched (rotation should never modify the
    // outgoing key file — it only writes the new one).
    assert!(k1_path.exists(), "K1 key file must remain on disk");

    Ok(())
}

// ── Test 2: failure-injection mid-rotation resume ───────────────────────

#[tokio::test]
async fn failure_injection_mid_rotation_resumes_cleanly_without_regenerating_key()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP key_rotation::failure_injection_mid_rotation_resumes_cleanly_without_regenerating_key: \
             docker daemon not reachable.",
        );
        return Ok(());
    }

    let (_container, pool) = fresh_pool().await?;
    let tmp = tempfile::tempdir()?;

    // ── Phase A: bootstrap K1 so the rotation has an outgoing key ──────
    let (signer1, _keypair1, _k1_path) = build_signer_in_dir(tmp.path());
    let k1_did = signer1.public_key_did().to_owned();
    bootstrap_active_key(&pool, &k1_did, CustodyMode::FilePlain).await?;

    // ── Phase B: simulate a crash AT last_step='key_written' ────────────
    //
    // The rotation CLI's idempotency contract (documented on
    // `RotationContext::step_generate_key`) is: if the row carries
    // `new_public_key_did` and the on-disk key file matches that did,
    // a resume MUST NOT regenerate the K-256 secret. We replicate the
    // exact on-disk state a real crash would leave behind, then drive
    // the resume path.
    //
    // 1. Generate K2's keypair in test code.
    // 2. Write its hex to `k2_path` at mode 0o600.
    // 3. INSERT a rotation_state row with `last_step = 'key_written'`,
    //    `new_public_key_did = K2.did()`, `old_public_key_did = K1.did()`,
    //    `new_key_path = k2_path`.
    let k2_keypair = K256Keypair::generate();
    let k2_did_expected = k2_keypair.did();
    let k2_path = tmp.path().join("k2-resume.hex");
    {
        let mut file = std::fs::File::create(&k2_path)?;
        file.write_all(hex::encode(k2_keypair.export_private_key()).as_bytes())?;
        file.flush()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&k2_path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    let pre_resume_hash = sha256_of(&k2_path);

    // The rotation_state.last_step column is the `rotation_step` enum;
    // the runtime `sqlx::query` form lets us bind the wire-name TEXT and
    // cast it inside the statement.
    let rotation_id: Uuid = sqlx::query(
        r"INSERT INTO rotation_state (
              last_step, custody_mode, new_public_key_did,
              old_public_key_did, new_key_path
          ) VALUES ($1::TEXT::rotation_step, $2, $3, $4, $5)
          RETURNING id",
    )
    .bind("key_written")
    .bind(CustodyMode::FilePlain.as_str())
    .bind(&k2_did_expected)
    .bind(&k1_did)
    .bind(k2_path.to_string_lossy().into_owned())
    .fetch_one(&pool)
    .await?
    .try_get("id")?;

    // ── Phase C: resume from the persisted row ──────────────────────────
    let mut resumed = RotationContext::resume(
        pool.clone(),
        rotation_id,
        CustodyMode::FilePlain,
        RotationCustodyParams::FilePlain,
    )
    .await?;
    assert_eq!(
        resumed.plan().last_step,
        RotationStep::KeyWritten,
        "resume must reload `last_step = 'key_written'`",
    );
    assert_eq!(
        resumed.plan().new_did.as_deref(),
        Some(k2_did_expected.as_str()),
        "resume must reload the persisted new_public_key_did",
    );

    resumed.run().await?;
    assert_eq!(
        resumed.plan().last_step,
        RotationStep::Complete,
        "resume must drive to Complete from key_written",
    );

    // ── Phase D: the key file is byte-identical (no regen) ──────────────
    let post_resume_hash = sha256_of(&k2_path);
    assert_eq!(
        pre_resume_hash, post_resume_hash,
        "resume must NOT regenerate the K-256 secret — on-disk hash must match",
    );

    // ── Phase E: post-condition matches the clean-run AC-15 state ───────
    let history_count: i64 = sqlx::query("SELECT COUNT(*) AS cnt FROM signing_key_history")
        .fetch_one(&pool)
        .await?
        .try_get("cnt")?;
    assert_eq!(
        history_count, 2,
        "post-resume signing_key_history must carry K1 + K2",
    );
    let active_did: String =
        sqlx::query(r"SELECT public_key_did FROM signing_key_history WHERE active_until IS NULL")
            .fetch_one(&pool)
            .await?
            .try_get("public_key_did")?;
    assert_eq!(
        active_did, k2_did_expected,
        "K2 must be the active key after resume",
    );
    let revoked_did: String = sqlx::query("SELECT public_key_did FROM revoked_keys")
        .fetch_one(&pool)
        .await?
        .try_get("public_key_did")?;
    assert_eq!(revoked_did, k1_did, "K1 must be revoked after resume");

    Ok(())
}

// ── Test 3: append-only triggers ────────────────────────────────────────

#[tokio::test]
async fn append_only_triggers_reject_illegal_mutations() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP key_rotation::append_only_triggers_reject_illegal_mutations: \
             docker daemon not reachable.",
        );
        return Ok(());
    }

    let (_container, pool) = fresh_pool().await?;

    // Insert one signing_key_history row to act on.
    let inserted_id: i64 = sqlx::query(
        r"INSERT INTO signing_key_history (public_key_did, custody_mode)
          VALUES ($1, $2)
          RETURNING id",
    )
    .bind("did:key:zTriggerTest")
    .bind(CustodyMode::FilePlain.as_str())
    .fetch_one(&pool)
    .await?
    .try_get("id")?;

    // ── 1. DELETE on signing_key_history must be rejected (P0001) ───────
    let delete_err = sqlx::query("DELETE FROM signing_key_history WHERE id = $1")
        .bind(inserted_id)
        .execute(&pool)
        .await
        .expect_err("DELETE on signing_key_history must be rejected by the trigger");
    assert_p0001(&delete_err, "append-only");

    // ── 2. Illegal UPDATE (changing public_key_did) must be rejected ────
    let illegal_update_err =
        sqlx::query("UPDATE signing_key_history SET public_key_did = $1 WHERE id = $2")
            .bind("did:key:zFake")
            .bind(inserted_id)
            .execute(&pool)
            .await
            .expect_err("UPDATE changing public_key_did must be rejected by the trigger");
    assert_p0001(&illegal_update_err, "append-only");

    // ── 3. Legal UPDATE (active_until: NULL → now()) must SUCCEED ───────
    let retire_result =
        sqlx::query("UPDATE signing_key_history SET active_until = now() WHERE id = $1")
            .bind(inserted_id)
            .execute(&pool)
            .await
            .expect("retiring the active key (active_until NULL → now()) must succeed");
    assert_eq!(
        retire_result.rows_affected(),
        1,
        "the retire UPDATE must touch exactly one row",
    );

    // Confirm the row is now retired (active_until IS NOT NULL).
    let retired_at: Option<DateTime<Utc>> =
        sqlx::query("SELECT active_until FROM signing_key_history WHERE id = $1")
            .bind(inserted_id)
            .fetch_one(&pool)
            .await?
            .try_get("active_until")?;
    assert!(
        retired_at.is_some(),
        "after the legal UPDATE, active_until must be populated",
    );

    // ── 4. Un-retire (active_until: non-NULL → NULL) must be rejected ───
    let unretire_err =
        sqlx::query("UPDATE signing_key_history SET active_until = NULL WHERE id = $1")
            .bind(inserted_id)
            .execute(&pool)
            .await
            .expect_err("un-retiring a retired row must be rejected by the trigger");
    assert_p0001(&unretire_err, "append-only");

    // ── 5. revoked_keys triggers (DELETE + UPDATE both rejected) ────────
    //
    // The migration-14 schema for `revoked_keys` mounts an append-only
    // trigger that raises P0001 on both DELETE and UPDATE. We exercise
    // both arms.
    sqlx::query(
        r"INSERT INTO revoked_keys (public_key_did, reason)
          VALUES ($1, 'rotation')",
    )
    .bind("did:key:zRevokedTriggerTest")
    .execute(&pool)
    .await?;

    let revoked_delete_err = sqlx::query("DELETE FROM revoked_keys WHERE public_key_did = $1")
        .bind("did:key:zRevokedTriggerTest")
        .execute(&pool)
        .await
        .expect_err("DELETE on revoked_keys must be rejected by the trigger");
    assert_p0001(&revoked_delete_err, "append-only");

    let revoked_update_err =
        sqlx::query("UPDATE revoked_keys SET reason = $1 WHERE public_key_did = $2")
            .bind("mutated")
            .bind("did:key:zRevokedTriggerTest")
            .execute(&pool)
            .await
            .expect_err("UPDATE on revoked_keys must be rejected by the trigger");
    assert_p0001(&revoked_update_err, "append-only");

    Ok(())
}

/// Assert a `sqlx::Error` carries SQLSTATE `P0001` and the trigger
/// message contains `expected_marker` (case-insensitive). Centralised
/// here so all six trigger checks in test 3 share one failure idiom.
fn assert_p0001(err: &sqlx::Error, expected_marker: &str) {
    match err {
        sqlx::Error::Database(db_err) => {
            let code = db_err
                .code()
                .map(std::borrow::Cow::into_owned)
                .expect("trigger error must carry a SQLSTATE");
            assert_eq!(
                code, "P0001",
                "trigger rejection must surface as P0001, got {code}: {db_err}",
            );
            assert!(
                db_err
                    .message()
                    .to_lowercase()
                    .contains(&expected_marker.to_lowercase()),
                "trigger message should mention {expected_marker:?}; got: {}",
                db_err.message(),
            );
        }
        other => panic!("expected sqlx::Error::Database, got: {other:?}"),
    }
}
