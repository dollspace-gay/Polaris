//! Threat-model T6 — moderator identity leaking via emitted labels
//! (`design.md` §9 #6; issue #39).
//!
//! # Mitigation under test
//!
//! Per design.md §9 #6: "moderator identity never leaves the audit
//! log; public-facing label emission is signed by the labeler key,
//! not the moderator." The emitter from issue #28
//! ([`polaris_backend::labeler::emitter::LabelEmitter`]) implements
//! this by setting the Label record's `src` field to the **labeler
//! signing DID**, never the moderator id. The persisted `labels` row
//! shape (migration 12+13) has `signing_did` + `src` + `subject_did`,
//! but **no `moderator_id` column** — the column simply does not
//! exist on the public-facing emission surface.
//!
//! # Test strategy
//!
//! Three observable invariants:
//!
//! 1. **In-row check.** The persisted `labels` row's `src` column
//!    equals the labeler's signing DID, and decoding the persisted
//!    `label_cbor` recovers the same DID under the spec-canonical
//!    `src` field. No moderator UUID appears anywhere in the row.
//! 2. **Schema check.** The `labels` table has no `moderator_id`
//!    column. The `subscribeLabels` / `queryLabels` SELECT
//!    projection (see `polaris-backend/src/labeler/server.rs`) reads
//!    exactly the public-facing columns, so by construction the wire
//!    response cannot carry a moderator id.
//! 3. **Audit-log check.** The moderator id IS recorded in the
//!    `audit_log` row (which is internal, not public-facing) so the
//!    moderator's decision stays attributable to operators. This is
//!    the other half of the §9 #6 invariant: "moderator identity
//!    never leaves the audit log" — it MUST stay in the audit log so
//!    internal accountability works.
//!
//! This test SHOULD pass live (the emitter already enforces it).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::io::Write as _;
use std::sync::Arc;

use chrono::Utc;
use polaris_backend::labeler::emitter::{LabelEmitter, SubjectRef};
use polaris_backend::labeler::server::LabelBroadcaster;
use polaris_backend::labeler::signer::SigningKey;
use polaris_backend::labeler::signer::file_plain::FilePlainSigner;
use polaris_backend::repo::{ActionRepo as _, NewAction, PgActionRepo};
use polaris_types::{
    ActionKind, IncidentId, LabelValue, ModeratorId, PolicyId, Severity, SubjectId,
};
use proto_blue::crypto::{ExportableKeypair as _, K256Keypair};
use sqlx::Row as _;

#[path = "threats_common/mod.rs"]
mod common;

/// Build a `FilePlainSigner` over a freshly-generated K-256 keypair.
/// Mirrors the helper in `tests/label_emitter.rs`; duplicated here
/// because Cargo's integration-test boundary forbids importing across
/// test binaries.
fn build_signer() -> FilePlainSigner {
    let kp = K256Keypair::generate();
    let secret = kp.export_private_key();
    let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
    write!(tmp, "{}", hex::encode(secret)).expect("write hex");
    tmp.flush().expect("flush");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = tmp.as_file().metadata().unwrap().permissions();
        perms.set_mode(0o600);
        tmp.as_file().set_permissions(perms).unwrap();
    }
    let signer = FilePlainSigner::from_path(tmp.path()).expect("load signer");
    drop(tmp);
    signer
}

/// T6 MUST-PASS: emitted label carries the signer DID, never the
/// moderator id.
#[tokio::test]
#[allow(
    clippy::too_many_lines,
    clippy::similar_names,
    reason = "linear end-to-end scenario covering moderator, subject, incident, action, \
              label emission, and three invariant assertions in a single Postgres-startup; \
              splitting would force three container starts. The `emitted` / `emitter` \
              binding similarity mirrors the production naming."
)]
async fn emitted_label_src_is_labeler_did_not_moderator_id()
-> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t6_moderator_identity_leak: docker daemon not reachable.");
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let signer = build_signer();
    let signing_did = signer.public_key_did().to_owned();
    let arc_signer: Arc<dyn SigningKey> = Arc::new(signer);
    let emitter = LabelEmitter::new(
        arc_signer,
        fixture.pool.clone(),
        LabelBroadcaster::with_default_capacity(),
    );

    // Set up moderator, subject, incident, label-kind action.
    let moderator: ModeratorId = fixture.insert_moderator().await?;
    let moderator_uuid_str = moderator.into_uuid().to_string();
    let subject_did_str = "did:plc:t6subject1";
    let subject_id: SubjectId = fixture.insert_account_subject(subject_did_str).await?;
    let incident_id: IncidentId = fixture
        .insert_incident(subject_id, Severity::Medium)
        .await?;
    let actions = PgActionRepo::new(fixture.pool.clone());
    let action = actions
        .insert(NewAction {
            incident_id,
            subject_id,
            moderator_id: moderator,
            kind: ActionKind::Label,
            label: Some(LabelValue::new("spam")),
            reasoning: "moderator identity-leak threat test — long enough reasoning".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
        })
        .await?;

    let subject_ref = SubjectRef {
        did: Some(subject_did_str.to_owned()),
        uri: None,
        cid: None,
    };

    // Emit the label.
    let emitted = emitter.emit(&action, &subject_ref, None).await?;
    assert_eq!(emitted.len(), 1);
    let emitted_label = &emitted[0];

    // ── Invariant 1: in-row `src` column == signing DID, not moderator id ─
    let row = sqlx::query!(
        r#"
        SELECT id, seq, src, uri, val, neg, sig, action_id,
               subject_did, label_cbor, signing_did
        FROM labels
        WHERE action_id = $1
        "#,
        action.id.0,
    )
    .fetch_one(&fixture.pool)
    .await?;
    assert_eq!(
        row.src, signing_did,
        "labels.src must be the labeler signing DID, not the moderator id",
    );
    assert_eq!(
        row.signing_did, signing_did,
        "labels.signing_did must mirror src",
    );
    assert_ne!(
        row.src, moderator_uuid_str,
        "labels.src must NOT be the moderator UUID",
    );

    // ── Invariant 2: decoded canonical CBOR carries the signing DID, not the moderator id ─
    //
    // We reuse proto-blue's own decoder — the same decoder downstream
    // subscribeLabels consumers use — so the assertion is on the
    // observable wire shape, not the in-row column projection.
    let decoded = proto_blue::lex_cbor::decode(&row.label_cbor)
        .expect("persisted label_cbor must decode via proto-blue");
    match decoded {
        proto_blue::lex_data::LexValue::Map(map) => {
            let src_val = map.get("src").expect("Label CBOR must carry `src`");
            match src_val {
                proto_blue::lex_data::LexValue::String(s) => {
                    assert_eq!(
                        s, &signing_did,
                        "decoded label src must equal the signing DID",
                    );
                    assert_ne!(
                        s, &moderator_uuid_str,
                        "decoded label src must NOT be the moderator UUID",
                    );
                }
                other => panic!("expected src=String, got {other:?}"),
            }
        }
        other => panic!("expected LexValue::Map, got {other:?}"),
    }

    // ── Invariant 3: the persisted `labels` row carries NO column that
    // is the moderator id. Iterate every textual column and assert it
    // does not equal the moderator UUID. (sig + label_cbor are
    // binary; src/uri/val/signing_did/subject_did are textual.)
    for textual in [
        &row.src,
        &row.uri,
        &row.val,
        &row.signing_did,
        &row.subject_did,
    ] {
        assert_ne!(
            textual, &moderator_uuid_str,
            "no textual column on the labels row may equal the moderator UUID; \
             found offending column carrying {textual}",
        );
    }
    // The remaining columns are: `id` (UUID — Polaris-internal label
    // identifier, not a moderator), `seq` (BIGSERIAL), `action_id` (the
    // action FK — links emit→action, but no moderator is exposed via this).
    // Confirm action_id is the action's id, not the moderator's id.
    let action_id_from_row = row.action_id.expect("action_id must be populated");
    assert_eq!(
        action_id_from_row, action.id.0,
        "labels.action_id must be the action's id, not the moderator's id",
    );
    assert_ne!(
        action_id_from_row.to_string(),
        moderator_uuid_str,
        "labels.action_id must NOT collide with the moderator UUID",
    );

    // Sanity: the emitted-label struct returned by emit() agrees.
    assert_eq!(emitted_label.signing_did, signing_did);
    assert_ne!(emitted_label.signing_did, moderator_uuid_str);

    Ok(())
}

/// T6 MUST-PASS: the public-facing `labels` SELECT projection
/// excludes any moderator-identifying column.
///
/// This is a schema-level assertion: `information_schema.columns`
/// must report no `moderator_id` (or any synonym) on the `labels`
/// table. The wire-side response cannot leak a column that does not
/// exist.
#[tokio::test]
async fn labels_table_has_no_moderator_column() -> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t6_moderator_identity_leak schema: docker daemon not reachable.",);
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let rows = sqlx::query(
        "SELECT column_name
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND table_name = 'labels'",
    )
    .fetch_all(&fixture.pool)
    .await?;

    let column_names: Vec<String> = rows
        .iter()
        .map(|r| r.try_get::<String, _>("column_name").expect("column_name"))
        .collect();

    // Forbidden columns: anything that names "moderator". The exact
    // spelling depends on convention, so we reject any case-insensitive
    // substring match.
    for name in &column_names {
        let lower = name.to_lowercase();
        assert!(
            !lower.contains("moderator"),
            "labels schema leaks moderator identity via column `{name}`; \
             public-facing tables must not carry moderator-identifying columns",
        );
    }

    // Positive assertion: the columns we DO expect are present.
    for required in [
        "src",
        "uri",
        "val",
        "neg",
        "sig",
        "signing_did",
        "subject_did",
    ] {
        assert!(
            column_names.iter().any(|c| c == required),
            "labels schema must carry `{required}`; found {column_names:?}",
        );
    }

    Ok(())
}

/// T6 MUST-PASS: the audit_log DOES record the moderator id (the
/// other half of the §9 #6 invariant — internal accountability
/// stays).
///
/// "Moderator identity never leaves the audit log" means it MUST be
/// in the audit log; the threat is only realised if the audit row is
/// somehow exfiltrated outside Polaris. This test pins the
/// positive-direction invariant so a refactor that drops the
/// moderator from the audit-log `actor` field is caught loudly.
#[tokio::test]
async fn audit_log_actor_carries_moderator_id_on_action_commit()
-> Result<(), Box<dyn std::error::Error>> {
    if !common::docker_available() {
        println!("SKIP threat_t6_moderator_identity_leak audit: docker daemon not reachable.",);
        return Ok(());
    }
    let fixture = common::ThreatFixture::boot().await?;

    let moderator = fixture.insert_moderator().await?;
    let subject_id = fixture.insert_account_subject("did:plc:t6audit1").await?;
    let incident_id = fixture
        .insert_incident(subject_id, Severity::Medium)
        .await?;
    let actions = PgActionRepo::new(fixture.pool.clone());
    let _action = actions
        .insert(NewAction {
            incident_id,
            subject_id,
            moderator_id: moderator,
            kind: ActionKind::Label,
            label: Some(LabelValue::new("spam")),
            reasoning: "audit-actor invariant test — long enough reasoning".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
        })
        .await?;

    let row = sqlx::query("SELECT actor, kind FROM audit_log ORDER BY seq DESC LIMIT 1")
        .fetch_one(&fixture.pool)
        .await?;
    let actor: String = row.try_get("actor")?;
    let kind: String = row.try_get("kind")?;
    assert_eq!(
        actor,
        moderator.into_uuid().to_string(),
        "audit_log.actor must be the moderator UUID — internal accountability",
    );
    assert_eq!(
        kind, "action.commit",
        "audit_log.kind must be action.commit for a label submit",
    );

    Ok(())
}
