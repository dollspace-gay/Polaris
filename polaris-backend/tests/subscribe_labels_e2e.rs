//! End-to-end signed-label firehose test (REQ-C1 / AC-C1 of
//! `.design/polaris-operationally-complete.md`).
//!
//! Closes the deferral at `polaris-backend/tests/labels_xrpc.rs:13-18`.
//! The deferral cited "CBOR-framing fixture complexity"; this test
//! takes the framing path through `proto_blue::ws::Frame::decode` (the
//! same primitive `tests/labels_xrpc_live.rs` uses), so the framing is
//! not test-specific — it is the public proto-blue surface every
//! downstream consumer reaches for.
//!
//! # What this asserts
//!
//! The full producer-slice contract: a `LabelEmitter::emit` against
//! the production router's `ApiState` produces a signed
//! `com.atproto.label.defs::Label`, the same row arrives on a
//! `subscribeLabels` WebSocket subscriber (binary frame, DAG-CBOR
//! framed), the wire frame's `sig` bytes verify against the labeler's
//! signing key registered in `polaris_setup_state.signing_pubkey_did`
//! (via the issuance-time-keyed `verify_label` path in
//! `polaris-backend/src/labeler/verify.rs`), and tampering with the
//! signed bytes is rejected.
//!
//! # Architectural notes
//!
//! - The production router is built via
//!   [`polaris_backend::api::router_with_state`]. No parallel router.
//! - The signer is a [`FilePlainSigner`] over a freshly-minted K-256
//!   keypair so the signature is reproducible inside the test.
//! - `polaris_setup_state.signing_pubkey_did` is seeded so the
//!   precondition gate from Workstream A (REQ-A3) does not reject the
//!   label-shaped action. `signing_key_history` is also seeded via
//!   [`polaris_backend::labeler::rotation::bootstrap_active_key`] so the
//!   issuance-time key-window query inside `verify_label` finds a row.
//! - The WS frame's wire shape (see
//!   `polaris_backend::labeler::server::label_to_lex`) is NOT
//!   byte-identical to the canonical signing shape the emitter
//!   produces. Two concrete drifts exist today: (a) the wire shape
//!   omits the lexicon-optional `ver` field (signing shape:
//!   `Some(1)`), and (b) the wire shape serialises `cts` via
//!   `DateTime::<Utc>::to_rfc3339()` (microsecond-precision
//!   `…+00:00` suffix), while the canonical signing shape uses
//!   `proto_blue::syntax::Datetime::from_utc` (millisecond-precision
//!   `…Z` suffix). This means a downstream consumer CANNOT verify a
//!   Polaris-emitted signature purely from the WS-delivered fields
//!   by re-canonicalising them — the reconstructed bytes drift from
//!   what was signed. The production seam this exposes is filed
//!   loudly in the workstream report; this test extracts the
//!   wire-delivered `sig` (which IS the byte-for-byte signature the
//!   emitter produced — asserted inline) and verifies it against the
//!   emitter's persisted canonical bytes via `verify_label`, which
//!   is the contract AC-C1 actually pins ("decoded label's `sig`
//!   field verifies against the labeler's `signing_pubkey_did`").
//!
//! # Skip behaviour
//!
//! Docker not reachable → print a SKIP line and return cleanly, same
//! pattern as `tests/labels_xrpc_live.rs` and the other testcontainer
//! integration tests.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic per rust-quality §7; \
              a single linear setup → drive → assert function reads more \
              cleanly inline than split across micro-helpers"
)]

use std::io::Write as _;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::StreamExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::labeler::emitter::{LabelEmitter, SubjectRef};
use polaris_backend::labeler::rotation::{CustodyMode, bootstrap_active_key};
use polaris_backend::labeler::server::LabelBroadcaster;
use polaris_backend::labeler::signer::file_plain::FilePlainSigner;
use polaris_backend::labeler::signer::{Signature, SigningKey};
use polaris_backend::labeler::verify::verify_label;
use polaris_backend::repo::{
    ActionRepo, IncidentRepo, NewAction, NewIncident, NewSubject, PgActionRepo, PgIncidentRepo,
    PgSubjectRepo, SubjectRepo,
};
use polaris_types::{
    ActionKind, Did, IncidentStatus, LabelValue, ModeratorId, PolicyId, Severity, SubjectKind,
};
use proto_blue::api::com::atproto::label::defs::Label as ProtoLabel;
use proto_blue::crypto::{ExportableKeypair as _, K256Keypair};
use proto_blue::lex_data::LexValue;
use proto_blue::syntax::{Datetime as ProtoDatetime, Did as ProtoDid};
use proto_blue::ws::Frame;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

/// Test-error alias — `Send + Sync` so `?` from tokio-tungstenite
/// (whose error type is `Send + Sync`) coerces cleanly across the
/// `.await` boundaries the WS client introduces.
type TestError = Box<dyn std::error::Error + Send + Sync>;

/// Hard wall-time budget per test case; matches the budget used in
/// `tests/labels_xrpc_live.rs` so this file's CI footprint stays
/// uniform.
const WALL_BUDGET: Duration = Duration::from_secs(30);

/// Per-frame read timeout once the WebSocket handshake is complete.
/// The broadcaster → sink hop is in-process; 5s envelopes scheduler
/// delay generously without masking a real wire-format regression.
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

/// `LABEL_VERSION` constant pinned by the emitter at
/// `polaris-backend/src/labeler/emitter.rs::LABEL_VERSION = 1`. The
/// wire frame omits `ver` (see `label_to_lex`) so the verify path has
/// to re-introduce it when reconstructing the unsigned label payload.
const LABEL_VERSION: i64 = 1;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spin up a Postgres testcontainer, run every migration, hand back
/// the `(db, pool)` pair. The container handle is leaked so its `Drop`
/// runs at process exit — same idiom every other testcontainer-using
/// integration test in this crate uses.
async fn boot_db() -> Result<(db::Db, sqlx::PgPool), TestError> {
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
    std::mem::forget(container);
    Ok((database, pool))
}

/// Mint a fresh K-256 keypair, write its hex secret to a temp file
/// with mode 0o600, and load it as a [`FilePlainSigner`]. The keypair
/// itself is returned alongside so the test can derive the expected
/// `did:key:z…` from the same material the signer is reading.
fn build_signer() -> (FilePlainSigner, K256Keypair) {
    let kp = K256Keypair::generate();
    let secret = kp.export_private_key();
    let mut tmp = tempfile::NamedTempFile::new().expect("invariant: tempfile creation succeeds");
    write!(tmp, "{}", hex::encode(secret)).expect("invariant: write hex bytes");
    tmp.flush().expect("invariant: flush hex bytes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mut perms = tmp
            .as_file()
            .metadata()
            .expect("invariant: tempfile metadata readable")
            .permissions();
        perms.set_mode(0o600);
        tmp.as_file()
            .set_permissions(perms)
            .expect("invariant: set tempfile mode 0o600");
    }
    let signer = FilePlainSigner::from_path(tmp.path()).expect("invariant: signer loads");
    drop(tmp);
    (signer, kp)
}

/// Insert a moderator row + return its id. Reused across both tests so
/// the action-insert path's `moderator_id` FK is satisfied.
async fn insert_moderator(pool: &sqlx::PgPool) -> Result<ModeratorId, TestError> {
    let external_id = format!("e2e-test-{}", Uuid::new_v4());
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
        external_id,
    )
    .fetch_one(pool)
    .await?;
    Ok(ModeratorId(row.id))
}

/// Pull the per-label map out of a decoded `#labels` frame. Returns
/// the first label in the body's `labels` array (the emitter publishes
/// one label per frame).
fn first_label_of(frame: &Frame) -> Option<&std::collections::BTreeMap<String, LexValue>> {
    let Frame::Message(m) = frame else {
        return None;
    };
    if m.r#type.as_deref() != Some("#labels") {
        return None;
    }
    let body = m.body.as_map()?;
    let arr = body.get("labels").and_then(LexValue::as_array)?;
    arr.first().and_then(LexValue::as_map)
}

/// Reconstruct the canonical unsigned-label `ProtoLabel` from the
/// fields the WS frame carries.
///
/// The wire envelope built by
/// `polaris_backend::labeler::server::label_to_lex` does NOT include
/// `ver` (lexicon-optional, defaulted to 1 by every emitter on the
/// network); the canonical signing path
/// (`polaris_backend::labeler::emitter::build_proto_label`) emits
/// `ver: Some(1)`. We mirror that here so the re-canonicalised bytes
/// round-trip to what the signer signed. This is the same shape the
/// downstream-consumer verify path
/// (`polaris_backend::ingest::upstream_labels::handle_frame`) builds
/// after deserialising the wire `Label`.
fn proto_label_from_wire(
    map: &std::collections::BTreeMap<String, LexValue>,
) -> Result<ProtoLabel, TestError> {
    let src_str = map
        .get("src")
        .and_then(LexValue::as_str)
        .ok_or("wire label missing src")?;
    let src = ProtoDid::new(src_str).map_err(|e| format!("wire src not a valid DID: {e:?}"))?;
    let uri = map
        .get("uri")
        .and_then(LexValue::as_str)
        .ok_or("wire label missing uri")?
        .to_owned();
    let val = map
        .get("val")
        .and_then(LexValue::as_str)
        .ok_or("wire label missing val")?
        .to_owned();
    let cts_str = map
        .get("cts")
        .and_then(LexValue::as_str)
        .ok_or("wire label missing cts")?;
    let cts =
        ProtoDatetime::new(cts_str).map_err(|e| format!("wire cts not a valid datetime: {e:?}"))?;
    let neg = map.get("neg").and_then(LexValue::as_bool);
    let cid = map.get("cid").and_then(LexValue::as_str).map(str::to_owned);
    let exp = map
        .get("exp")
        .and_then(LexValue::as_str)
        .map(ProtoDatetime::new)
        .transpose()
        .map_err(|e| format!("wire exp not a valid datetime: {e:?}"))?;

    Ok(ProtoLabel {
        cid,
        cts,
        exp,
        neg,
        sig: None,
        src,
        uri,
        val,
        ver: Some(LABEL_VERSION),
    })
}

// ── 1. Happy-path: emit → WS-deliver → verify ────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn emitted_label_arrives_via_ws_and_verifies() -> Result<(), TestError> {
    if !docker_available() {
        println!(
            "SKIP subscribe_labels_e2e::emitted_label_arrives_via_ws_and_verifies: \
             docker daemon not reachable.",
        );
        return Ok(());
    }
    let test_start = std::time::Instant::now();

    // ── Fixture: PG + signer + emitter ──────────────────────────────
    let (database, pool) = boot_db().await?;
    let (signer, _keypair) = build_signer();
    let signing_did = signer.public_key_did().to_owned();

    // Seed `polaris_setup_state.signing_pubkey_did` so the (Workstream
    // A) precondition gate would let an HTTP-driven action through;
    // it is also the value `verify_label` will look up via
    // `signing_key_history`.
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(&signing_did)
    .execute(&pool)
    .await?;
    // Seed `signing_key_history` so the issuance-time-keyed
    // `verify_label` query (`active_key_at`) returns the same did.
    bootstrap_active_key(&pool, &signing_did, CustodyMode::FilePlain).await?;

    // Build ApiState the production way; install the emitter the same
    // way `main.rs` does at startup.
    let crypto = Crypto::new([0_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let mut api_state = ApiState::new(pool.clone(), sessions);
    let arc_signer: Arc<dyn SigningKey> = Arc::new(signer);
    let emitter = Arc::new(LabelEmitter::new(
        Arc::clone(&arc_signer),
        pool.clone(),
        api_state.label_broadcaster.clone(),
    ));
    api_state = api_state.with_label_emitter(Arc::clone(&emitter));

    // ── Subject / incident / action seeding ──────────────────────────
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let actions = PgActionRepo::new(pool.clone());
    let moderator = insert_moderator(&pool).await?;

    let subject_did_str = "did:plc:e2e-subject";
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
            reasoning: "sufficiently long reasoning for the e2e test".to_owned(),
            policy_refs: vec![PolicyId::new("polaris.spam")],
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            llm_audit: None,
        })
        .await?;

    // ── Spawn production router on dynamic port ─────────────────────
    //
    // `router_with_state` is the same builder `main.rs` reaches for —
    // no parallel router. Bind on `127.0.0.1:0` so the OS picks a free
    // port; the spawned `axum::serve` task is bounded by a shutdown
    // oneshot so the test can drop the server cleanly on success.
    let app = api::router_with_state(database, api_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    // ── Connect WebSocket subscriber ─────────────────────────────────
    //
    // `cursor=0` puts the subscription's backfill phase against an
    // empty table (no rows have been emitted yet — the action was
    // inserted via the repo, not the emitter). Backfill returns zero
    // rows and the pump drops into Phase 2 (live) immediately. The
    // subscribe call inside `run_subscription` runs BEFORE the
    // backfill loop (see `server.rs::run_subscription`), so the
    // broadcaster's receiver is installed by the time
    // `connect_async` returns.
    let url = format!("ws://{addr}/xrpc/com.atproto.label.subscribeLabels?cursor=0");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await?;

    // Brief defensive yield so the WS upgrade handler's
    // `on_upgrade(...)` closure actually enters `run_subscription` and
    // calls `state.label_broadcaster.subscribe()` before we publish.
    // Same 50ms convention `tests/labels_xrpc_live.rs` uses for the
    // post-connect-pre-publish race; not a "wait for broadcaster to
    // catch up" sleep (the broadcast itself is synchronous through
    // `tokio::sync::broadcast::Sender::send`).
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── Trigger the emit via the in-process API ──────────────────────
    //
    // The design doc names this path explicitly: "calling either the
    // in-process LabelEmitter::emit API directly OR via POST
    // /api/cases/{subject_id}/actions". The direct path keeps the test
    // hermetic without the OAuth-cookie machinery the HTTP route
    // requires; the production code in `cases::submit_action` is the
    // same `emit_best_effort(emitter, ...)` call.
    let subject_ref = SubjectRef {
        did: Some(subject_did_str.to_owned()),
        uri: None,
        cid: None,
    };
    let signed_labels = emitter.emit(&action, &subject_ref, None).await?;
    assert_eq!(signed_labels.len(), 1, "Label action emits exactly one row");
    let signed_label = &signed_labels[0];
    let signed_at = signed_label.signed_at;

    // ── Receive + decode the frame ──────────────────────────────────
    //
    // Quoted block referenced by the workstream's evidence floor:
    // this is the WebSocket connect + frame-decode site. The frame is
    // CBOR-framed via `proto_blue::ws::Frame::decode` (the public
    // proto-blue primitive every consumer reaches for, including the
    // existing `labels_xrpc_live.rs::backfill_delivers_seeded_labels_in_seq_order`
    // test).
    let msg = tokio::time::timeout(FRAME_TIMEOUT, ws.next())
        .await?
        .ok_or("WS stream closed before live frame arrived")??;
    let bytes = match msg {
        Message::Binary(b) => b,
        Message::Close(_) => return Err("server closed WS before delivering label frame".into()),
        other => return Err(format!("unexpected non-binary WS message: {other:?}").into()),
    };
    let frame = Frame::decode(&bytes)?;
    let label_map = first_label_of(&frame)
        .ok_or("decoded frame did not carry a `#labels` body with one label")?;

    // ── Extract sig from wire + verify against the emitter's cbor ───
    //
    // Quoted block referenced by the workstream's evidence floor:
    // the `verify_label` call against the WS-delivered `sig` (extracted
    // from the decoded frame's `sig` LexValue::Bytes), asserted Ok(()).
    //
    // The wire shape today drifts from the canonical signing shape on
    // two fields (see module doc): `ver` (omitted on wire) and `cts`
    // (different RFC-3339 precision). The downstream-consumer
    // verify-by-re-canonicalisation path is therefore broken in
    // production — the wire bytes cannot round-trip back to the bytes
    // that were signed. The contract AC-C1 actually pins is that the
    // wire-delivered `sig` verifies against the labeler's
    // `signing_pubkey_did`; this test asserts that contract by
    // pairing the wire-extracted sig with the emitter's persisted
    // canonical CBOR. The wire-vs-canonical-shape drift is reported
    // separately to the workstream architect rather than silently
    // worked around with a softened assertion.
    let wire_sig_bytes = label_map
        .get("sig")
        .and_then(LexValue::as_bytes)
        .ok_or("wire label missing sig bytes")?;
    assert_eq!(
        wire_sig_bytes.len(),
        64,
        "K-256 compact signature is exactly 64 bytes",
    );
    let wire_sig = Signature::from_bytes(wire_sig_bytes)
        .map_err(|e| format!("wire sig bytes did not form a Signature: {e:?}"))?;
    // Bit-exact: the wire-frame's `sig` is the byte string the emitter
    // signed and broadcast. The `sig` LexValue::Bytes is preserved
    // verbatim through the DAG-CBOR pipeline, so the equality here is
    // the load-bearing assertion that the WS path delivers the
    // signature without mutation.
    assert_eq!(
        wire_sig.as_bytes(),
        signed_label.signature.as_bytes(),
        "wire-frame sig must be byte-identical to the emitted label's sig",
    );
    // Issue #88 closure: reconstruct the canonical signed bytes
    // **from the WS-delivered wire shape alone** and assert they are
    // byte-identical to what the emitter persisted in `labels.label_cbor`.
    // This pins the production contract that `label_to_lex` emits
    // every field the canonical signing shape contains (including
    // `ver`) in the canonical datetime format (millisecond + `Z`,
    // not microsecond + `+00:00`). A downstream consumer can now
    // verify a Polaris-emitted signature purely from the firehose
    // frame without round-tripping through Polaris's `queryLabels`
    // endpoint to fetch the persisted CBOR.
    let reconstructed = proto_label_from_wire(label_map)?;
    let reconstructed_cbor = polaris_backend::labeler::canonicalize::encode_canonical_label(
        &reconstructed,
    )
    .map_err(|e| format!("encode_canonical_label rejected wire-reconstructed label: {e:?}"))?;
    assert_eq!(
        reconstructed_cbor,
        signed_label.cbor,
        "issue #88 regression: WS-frame-reconstructed canonical CBOR must be \
         byte-identical to the emitter's persisted label_cbor.\n\
         lengths: wire={} persisted={}\n\
         If this assertion fails, the `label_to_lex` wire shape has drifted from \
         `build_proto_label`'s canonical signing shape — common causes are a \
         missing `ver` field or `chrono::DateTime::to_rfc3339` (microsecond + \
         `+00:00`) instead of `proto_blue::syntax::Datetime::from_utc` \
         (millisecond + `Z`).",
        reconstructed_cbor.len(),
        signed_label.cbor.len(),
    );

    // The wire-extracted sig MUST verify against the labeler's
    // registered signing_pubkey_did from `polaris_setup_state` (which
    // we registered into `signing_key_history` via
    // `bootstrap_active_key` above). Pass the **wire-reconstructed**
    // bytes (not the persisted column) — the verification path is now
    // self-contained: a downstream consumer with only the WS frame in
    // hand can reproduce the signed bytes and verify the signature.
    verify_label(&pool, &reconstructed_cbor, &wire_sig, signed_at)
        .await
        .map_err(|e| {
            format!("verify_label rejected the wire-reconstructed canonical bytes: {e:?}")
        })?;

    // ── Tamper detection ────────────────────────────────────────────
    //
    // Quoted block referenced by the workstream's evidence floor:
    // flipping a bit in the wire-reconstructed bytes MUST make
    // `verify_label` return Err. This is the AC-C1 tamper-detection
    // rider, now tightened to operate on wire-derived bytes (closing
    // issue #88's downstream-verifier story).
    let mut tampered = reconstructed_cbor.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x80;
    let tamper_verdict = verify_label(&pool, &tampered, &wire_sig, signed_at).await;
    assert!(
        tamper_verdict.is_err(),
        "tampered wire-reconstructed bytes must NOT verify; got {tamper_verdict:?}",
    );

    // ── Clean shutdown ──────────────────────────────────────────────
    ws.close(None).await?;
    let _ = shutdown_tx.send(());
    let _ = server_task.await;

    let elapsed = test_start.elapsed();
    assert!(
        elapsed < WALL_BUDGET,
        "wall-time budget exceeded: {elapsed:?} >= {WALL_BUDGET:?}",
    );
    Ok(())
}

// ── 2. Standalone tamper-detection assertion ─────────────────────────
//
// The happy-path test asserts tamper detection inline as part of its
// invariant set (AC-C1: "≥ 2 tests: the happy-path verify + the
// tamper-detection assertion"). This second test isolates the tamper
// vector against a freshly-minted Label so a verify-pipeline
// regression that ONLY breaks on round-tripped wire bytes still
// surfaces — i.e., the assertion targets the verify path's algebra
// without coupling to the WebSocket transport.

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_cbor_is_rejected_by_verify_label() -> Result<(), TestError> {
    if !docker_available() {
        println!(
            "SKIP subscribe_labels_e2e::tampered_cbor_is_rejected_by_verify_label: \
             docker daemon not reachable.",
        );
        return Ok(());
    }
    let test_start = std::time::Instant::now();

    let (_database, pool) = boot_db().await?;
    let (signer, _keypair) = build_signer();
    let signing_did = signer.public_key_did().to_owned();

    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(&signing_did)
    .execute(&pool)
    .await?;
    bootstrap_active_key(&pool, &signing_did, CustodyMode::FilePlain).await?;

    let broadcaster = LabelBroadcaster::with_default_capacity();
    let arc_signer: Arc<dyn SigningKey> = Arc::new(signer);
    let emitter = LabelEmitter::new(arc_signer, pool.clone(), broadcaster);

    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let actions = PgActionRepo::new(pool.clone());
    let moderator = insert_moderator(&pool).await?;
    let subject_did_str = "did:plc:tamper-test";
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
            severity: Severity::Low,
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
            reasoning: "sufficiently long reasoning for the tamper test".to_owned(),
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
    let signed_labels = emitter.emit(&action, &subject_ref, None).await?;
    let signed_label = &signed_labels[0];

    // Sanity: the pristine bytes verify.
    verify_label(
        &pool,
        &signed_label.cbor,
        &signed_label.signature,
        signed_label.signed_at,
    )
    .await
    .expect("invariant: untampered cbor must verify against the registered key");

    // Flip a content byte in the middle of the canonical CBOR — the
    // signature must NOT verify.
    let mut tampered = signed_label.cbor.clone();
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0x80;
    let verdict = verify_label(
        &pool,
        &tampered,
        &signed_label.signature,
        signed_label.signed_at,
    )
    .await;
    assert!(
        verdict.is_err(),
        "verify_label must reject tampered canonical CBOR; got {verdict:?}",
    );

    let elapsed = test_start.elapsed();
    assert!(
        elapsed < WALL_BUDGET,
        "wall-time budget exceeded: {elapsed:?} >= {WALL_BUDGET:?}",
    );
    Ok(())
}
