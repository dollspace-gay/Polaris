//! Label emitter integration test (issue #28).
//!
//! Spins up Postgres 16 via testcontainers, applies every migration,
//! constructs a `FilePlainSigner` from a freshly-generated K-256 secret,
//! wires up a `LabelEmitter`, and exercises:
//!
//! 1. **Build-sign-persist round trip** — emit a Label-kind action, verify
//!    the persisted `sig` over `label_cbor` against the signer's K-256
//!    public key.
//! 2. **Tamper detection** — flip a byte in the persisted `label_cbor` and
//!    re-verify; the signature must NOT verify.
//! 3. **Takedown with negation** — emit a Takedown action with a
//!    `revokes_value`; the emitter writes both a `!takedown` positive row
//!    and a negation row of the revoked value.
//! 4. **Idempotency** — emit on the same action twice; the second call
//!    must return [`EmitterError::DuplicateAction`].
//! 5. **End-to-end via the HTTP API** — POST a Label action to
//!    `/api/cases/{subject_id}/actions` against the live router with the
//!    emitter installed; verify a label row lands in Postgres keyed on the
//!    new action's id.
//!
//! # Skip behaviour
//!
//! Docker not reachable → print a clear skip and return successfully,
//! matching the convention from `tests/repo_roundtrip.rs` and friends.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::similar_names,
    reason = "integration test code is allowed to panic — rust-quality §7 convention; \
              long linear scenarios are expected here (single Postgres startup per test); \
              similar-names is the cost of mirroring repo / row / persisted shapes"
)]

use std::io::Write as _;
use std::process::Command;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt as _;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::ModeratorAuthCtx;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::labeler::emitter::{EmitterError, LabelEmitter, SubjectRef};
use polaris_backend::labeler::server::LabelBroadcaster;
use polaris_backend::labeler::signer::SigningKey;
use polaris_backend::labeler::signer::file_plain::FilePlainSigner;
use polaris_backend::repo::{
    ActionRepo, IncidentRepo, NewAction, NewIncident, NewSubject, PgActionRepo, PgIncidentRepo,
    PgSubjectRepo, SubjectRepo,
};
use polaris_types::{
    ActionKind, AtUri, Did, IncidentStatus, LabelValue, ModeratorId, PolicyId, Severity,
    SubjectKind,
};
use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Keypair as _, Verifier as _};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use uuid::Uuid;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build a `FilePlainSigner` over a freshly-generated K-256 keypair.
/// Returns the signer and the keypair (the keypair is kept so tests can
/// verify signatures against its public key).
fn build_signer() -> (FilePlainSigner, K256Keypair) {
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
    // Keep tmp alive via leak: tests run fast and the OS reclaims on
    // process exit. (`NamedTempFile::keep` would let us reclaim the path
    // but we don't need it here.)
    drop(tmp);
    (signer, kp)
}

async fn insert_moderator(pool: &sqlx::PgPool) -> ModeratorId {
    let external_id = format!("emit-test-{}", Uuid::new_v4());
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

#[tokio::test]
async fn emit_label_signs_persists_and_verifies() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP label_emitter::emit_label_signs_persists_and_verifies: no docker.");
        return Ok(());
    }

    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 5,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();

    let (signer, keypair) = build_signer();
    let signing_did = signer.public_key_did().to_owned();
    let arc_signer: Arc<dyn SigningKey> = Arc::new(signer);
    let broadcaster = LabelBroadcaster::with_default_capacity();
    let emitter = LabelEmitter::new(arc_signer, pool.clone(), broadcaster);

    // Set up the prerequisite rows: subject -> incident -> action.
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let actions = PgActionRepo::new(pool.clone());
    let moderator = insert_moderator(&pool).await;

    let subject_did_str = "did:plc:emittest1";
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
            label: Some(LabelValue::new("spam")),
            reasoning: "long enough reasoning for the emitter test".to_owned(),
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

    // ── 1. Emit + verify signature against the signer's pubkey ──────
    let emitted = emitter.emit(&action, &subject_ref, None).await?;
    assert_eq!(emitted.len(), 1, "Label action emits exactly one row");
    let row = &emitted[0];
    assert!(!row.neg, "Label emission is positive");
    assert_eq!(row.value, "spam");
    assert_eq!(row.signing_did, signing_did);
    assert_eq!(row.subject_did, subject_did_str);
    assert_eq!(row.signature.as_bytes().len(), 64);

    let verifier = K256Keypair::verifier_from_compressed(&keypair.public_key_compressed())?;
    assert!(
        verifier.verify(&row.cbor, row.signature.as_bytes())?,
        "signature must verify against the signer's published public key",
    );

    // ── 2. Tamper detection: flipping a byte breaks verification ────
    let mut tampered = row.cbor.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x80;
    let still_verifies = matches!(
        verifier.verify(&tampered, row.signature.as_bytes()),
        Ok(true),
    );
    assert!(
        !still_verifies,
        "tampered CBOR must not verify against the original signature",
    );

    // ── 3. Persistence: a row exists in `labels` keyed on action.id ─
    let persisted = sqlx::query!(
        r#"
        SELECT sig, label_cbor, signing_did, subject_did, val, neg, action_id
        FROM labels
        WHERE action_id = $1
        "#,
        action.id.0,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(persisted.sig.len(), 64);
    assert_eq!(persisted.sig, row.signature.as_bytes().to_vec());
    assert_eq!(persisted.label_cbor, row.cbor);
    assert_eq!(persisted.signing_did, signing_did);
    assert_eq!(persisted.subject_did, subject_did_str);
    assert_eq!(persisted.val, "spam");
    assert!(!persisted.neg);

    // ── 4. Idempotency: second emit returns DuplicateAction ─────────
    let dup = emitter.emit(&action, &subject_ref, None).await;
    let err = dup.expect_err("second emit must fail");
    match err {
        EmitterError::DuplicateAction { action_id } => {
            assert_eq!(action_id, action.id);
        }
        other => panic!("expected DuplicateAction, got {other:?}"),
    }

    Ok(())
}

#[tokio::test]
async fn emit_takedown_with_revoked_value_emits_negation() -> Result<(), Box<dyn std::error::Error>>
{
    if !docker_available() {
        println!("SKIP label_emitter::emit_takedown_with_revoked_value_emits_negation: no docker.");
        return Ok(());
    }

    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 5,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();

    let (signer, keypair) = build_signer();
    let arc_signer: Arc<dyn SigningKey> = Arc::new(signer);
    let broadcaster = LabelBroadcaster::with_default_capacity();
    let emitter = LabelEmitter::new(arc_signer, pool.clone(), broadcaster);

    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let actions = PgActionRepo::new(pool.clone());
    let moderator = insert_moderator(&pool).await;
    let subject = subjects
        .insert(NewSubject {
            kind: SubjectKind::Account,
            did: Some(Did::new("did:plc:emittest2")),
            uri: None,
            created_at: Utc::now(),
        })
        .await?;
    let incident = incidents
        .insert(NewIncident {
            primary_subject: subject.id,
            status: IncidentStatus::Open,
            severity: Severity::High,
            assigned_to: None,
        })
        .await?;
    let takedown = actions
        .insert(NewAction {
            incident_id: incident.id,
            subject_id: subject.id,
            moderator_id: moderator,
            kind: ActionKind::Takedown,
            label: None,
            reasoning: "long enough reasoning for the takedown test".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
        })
        .await?;

    let subject_ref = SubjectRef {
        did: Some("did:plc:emittest2".to_owned()),
        uri: None,
        cid: None,
    };
    let emitted = emitter.emit(&takedown, &subject_ref, Some("spam")).await?;
    assert_eq!(emitted.len(), 2, "takedown + negation = two rows");

    let primary = emitted.iter().find(|r| !r.neg).expect("primary present");
    let negation = emitted.iter().find(|r| r.neg).expect("negation present");

    assert_eq!(primary.value, "!takedown");
    assert_eq!(negation.value, "spam");

    // Both signatures verify independently.
    let verifier = K256Keypair::verifier_from_compressed(&keypair.public_key_compressed())?;
    assert!(verifier.verify(&primary.cbor, primary.signature.as_bytes())?);
    assert!(verifier.verify(&negation.cbor, negation.signature.as_bytes())?);

    Ok(())
}

/// End-to-end: drive the action-submission HTTP route with the emitter
/// installed on ApiState; verify a label row lands in Postgres.
#[tokio::test]
async fn submit_action_emits_label_via_http_route() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP label_emitter::submit_action_emits_label_via_http_route: no docker.");
        return Ok(());
    }

    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 5,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();

    // Wire ApiState with an emitter; the test issues an authenticated
    // request through a router-level Extension layer that injects a
    // `ModeratorAuthCtx`, bypassing the cookie-auth middleware (which
    // would require a full OIDC handshake). Other integration tests in
    // this crate follow the same pattern.
    let crypto = Crypto::new([0_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let api_state = ApiState::new(pool.clone(), sessions);

    let (signer, _keypair) = build_signer();
    let arc_signer: Arc<dyn SigningKey> = Arc::new(signer);
    let emitter = Arc::new(LabelEmitter::new(
        arc_signer,
        pool.clone(),
        api_state.label_broadcaster.clone(),
    ));
    let api_state = api_state.with_label_emitter(emitter);

    // Seed subject + incident + moderator so the action submission can
    // succeed against real FKs.
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let moderator_id = insert_moderator(&pool).await;
    let subject = subjects
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new("did:plc:emittest3")),
            uri: Some(AtUri::new("at://did:plc:emittest3/app.bsky.feed.post/abc")),
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

    // Build a minimal router that mounts only the submit-action route
    // and injects a moderator context (skipping the auth middleware).
    let ctx = ModeratorAuthCtx::new(
        polaris_backend::auth::ModeratorId(moderator_id.0),
        std::collections::HashSet::new(),
    );
    let router = Router::new()
        .route(
            "/api/cases/{subject_id}/actions",
            axum::routing::post(polaris_backend::api::cases::submit_action),
        )
        .layer(axum::extract::Extension(ctx))
        .with_state(api_state);

    // REQ-A3: `submit_action` now enforces
    // `polaris_setup_state.signing_pubkey_did IS NOT NULL` for
    // Label / Takedown kinds before letting the action through to
    // the emitter. The labeler subsystem in this test already holds
    // a real K-256 key (built by `build_signer` above); the wizard's
    // DB-side `UPDATE polaris_setup_state` step is the part the test
    // would otherwise have skipped, so we seed the column inline.
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind("did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme")
    .execute(&pool)
    .await?;

    // WB-2 (#224): seed the placeholder policy set so the cited
    // `polaris.spam` identifier resolves to a current row in
    // `mod_policies`.
    polaris_backend::test_support::seed_placeholder_policies(&pool, moderator_id.0).await?;

    use tower::ServiceExt as _;
    let body_json = serde_json::json!({
        "incident_id": incident.id,
        "kind": "label",
        "label": "spam",
        "reasoning": "this is a sufficiently long reasoning string for the test",
        "policy_refs": ["polaris.spam"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject.id.0))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_json)?))?;
    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await?.to_bytes();
    let inserted: serde_json::Value = serde_json::from_slice(&body)?;
    let action_id: Uuid = inserted
        .get("id")
        .and_then(|v| v.as_str())
        .expect("inserted.id")
        .parse()?;

    // A label row exists in `labels` keyed on the new action_id.
    let row = sqlx::query!(
        r#"
        SELECT val, neg, sig, action_id
        FROM labels
        WHERE action_id = $1
        "#,
        action_id,
    )
    .fetch_one(&pool)
    .await?;
    assert_eq!(row.val, "spam");
    assert!(!row.neg);
    assert_eq!(row.sig.len(), 64);

    Ok(())
}
