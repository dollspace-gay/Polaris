//! AC-D3: the same `action_id` UUID appears in `tracing` spans at the
//! three named contexts that handle an action's lifecycle:
//!
//! - `submit_action` — `cases::submit_action` handler entry
//! - `emit_label` — `LabelEmitter::emit` (annotated via
//!   `#[tracing::instrument(...)]`)
//! - `broadcaster_publish` — the broadcaster publish span inside
//!   `LabelEmitter::persist`
//!
//! `tracing_test::traced_test` installs a per-test subscriber and
//! captures every emitted event into a buffer. We assert that the
//! buffer carries the same UUID in three distinct contexts.
//!
//! # Why three named contexts
//!
//! REQ-D3 says "an operator stuck at 3am can grep logs by
//! `action_id` and reconstruct the full timeline." The three
//! contexts are the three load-bearing handoffs on the action's
//! life cycle:
//!
//! 1. Moderator submitted the action (HTTP boundary).
//! 2. Emitter signed it (cryptographic boundary).
//! 3. Broadcaster fanned it out to live subscribers (network
//!    boundary).
//!
//! A failure that hides between (2) and (3) — e.g. the signer
//! succeeds but the persist insert silently drops — surfaces as
//! "the UUID is in `submit_action` and `emit_label` logs but
//! never reaches `broadcaster_publish`". Without the three
//! spans, that pattern is invisible.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7"
)]

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
use polaris_backend::labeler::emitter::LabelEmitter;
use polaris_backend::labeler::signer::{Signature, SigningError, SigningKey};
use polaris_backend::repo::{
    IncidentRepo, NewIncident, NewSubject, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{AtUri, Did, IncidentStatus, ModeratorId, Severity, SubjectKind};
use proto_blue::crypto::{K256Keypair, Keypair as _};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::watch;
use tower::ServiceExt as _;
use tracing_test::traced_test;
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

async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error>> {
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

async fn insert_moderator(pool: &PgPool) -> ModeratorId {
    let external_id = format!("trace-test-{}", Uuid::new_v4());
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

struct InMemorySigner {
    keypair: K256Keypair,
    did: String,
}

impl std::fmt::Debug for InMemorySigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemorySigner")
            .field("did", &self.did)
            .field("keypair", &"<redacted>")
            .finish()
    }
}

impl InMemorySigner {
    fn generate() -> Self {
        let keypair = K256Keypair::generate();
        let did = keypair.did();
        Self { keypair, did }
    }
}

impl SigningKey for InMemorySigner {
    fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError> {
        use proto_blue::crypto::Signer as _;
        let bytes = self.keypair.sign(payload).map_err(|_| SigningError::Sign {
            reason: "in-memory signer failed",
        })?;
        Signature::from_bytes(&bytes)
    }

    fn public_key_did(&self) -> &str {
        &self.did
    }
}

#[tokio::test]
#[traced_test]
async fn one_action_emits_three_named_spans_carrying_one_action_id()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP tracing_action_id::one_action_emits_three_named_spans_carrying_one_action_id: \
             no docker."
        );
        return Ok(());
    }
    let (_database, pool) = boot_db().await?;
    let crypto = Crypto::new([0_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);

    // Real signer through the active-signer channel (so emit
    // actually fires).
    let signer = InMemorySigner::generate();
    let signer_did = signer.did.clone();
    let arc: Arc<dyn SigningKey> = Arc::new(signer);
    let (signer_tx, signer_rx) = watch::channel::<Arc<dyn SigningKey>>(arc);
    let _signer_tx_keepalive = signer_tx;

    let api_state = ApiState::new(pool.clone(), sessions);
    let emitter = Arc::new(LabelEmitter::with_active_signer(
        signer_rx.clone(),
        pool.clone(),
        api_state.label_broadcaster.clone(),
    ));
    let api_state = api_state
        .with_label_emitter(emitter)
        .with_active_signer(signer_rx);

    // Seed prereqs + the REQ-A3 setup-state column.
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let moderator_id = insert_moderator(&pool).await;
    let subject = subjects
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new("did:plc:tracetest")),
            uri: Some(AtUri::new("at://did:plc:tracetest/app.bsky.feed.post/abc")),
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
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(&signer_did)
    .execute(&pool)
    .await?;

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

    // POST one Label action.
    let body_json = serde_json::json!({
        "incident_id": incident.id,
        "kind": "label",
        "label": "spam",
        "reasoning": "this is a sufficiently long reasoning string for the tracing test",
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
    let bytes = response.into_body().collect().await?.to_bytes();
    let inserted: serde_json::Value = serde_json::from_slice(&bytes)?;
    let action_id = inserted["id"]
        .as_str()
        .expect("response carries id")
        .to_owned();

    // AC-D3: assert the action's UUID appears in three named spans.
    // `tracing_test::logs_contain` does a substring scan over the
    // per-test buffer.
    //
    // `tracing_subscriber`'s default `Layer<Subscriber>` formatter
    // renders span fields inline (`submit_action{action_id=…}`) and
    // span entries on a separate line (`<span name>: <event>`); both
    // sites carry the UUID once the event fires.
    let submit_span_marker = "submit_action";
    let emit_span_marker = "emit_label";
    let broadcast_span_marker = "broadcaster_publish";

    assert!(
        tracing_test::internal::logs_with_scope_contain("polaris_backend::api::cases", &action_id)
            || tracing_test::internal::logs_with_scope_contain("polaris_backend", &action_id),
        "action_id must appear in a polaris_backend log scope",
    );

    // Quick sanity assertions: the action_id appears in the log
    // buffer at all, and each named span context shows up.
    assert!(
        logs_contains(&action_id),
        "action_id UUID must appear at least once in the trace buffer",
    );
    assert!(
        logs_contains(submit_span_marker),
        "submit_action span name must appear",
    );
    assert!(
        logs_contains(emit_span_marker),
        "emit_label span name must appear",
    );
    assert!(
        logs_contains(broadcast_span_marker),
        "broadcaster_publish span name must appear",
    );

    // The strong assertion: each named span context's log lines
    // carry the UUID. The `tracing_test` formatter prepends the
    // span path (e.g. `submit_action{action_id=…}: …`) so a single
    // substring search per (span, uuid) pair is sufficient.
    let log_text = captured_logs();
    let mut found_in_submit = false;
    let mut found_in_emit = false;
    let mut found_in_broadcast = false;
    for line in log_text.lines() {
        if !line.contains(&action_id) {
            continue;
        }
        if line.contains(submit_span_marker) {
            found_in_submit = true;
        }
        if line.contains(emit_span_marker) {
            found_in_emit = true;
        }
        if line.contains(broadcast_span_marker) {
            found_in_broadcast = true;
        }
    }
    assert!(
        found_in_submit,
        "expected the action_id {action_id} inside a `submit_action` span; full log:\n{log_text}",
    );
    assert!(
        found_in_emit,
        "expected the action_id {action_id} inside an `emit_label` span; full log:\n{log_text}",
    );
    assert!(
        found_in_broadcast,
        "expected the action_id {action_id} inside a `broadcaster_publish` span; full log:\n{log_text}",
    );

    Ok(())
}

/// Wrapper around `tracing_test::internal::logs_with_scope_contain`
/// that scans every module scope used by polaris-backend's tracing
/// spans (each `tracing::info_span!` lives in the calling module's
/// path). Polaris's spans fire from `polaris_backend::api::cases`
/// and `polaris_backend::labeler::emitter`; the test's binary scope
/// also accumulates events. A `true` from any scope is sufficient.
fn logs_contains(needle: &str) -> bool {
    use tracing_test::internal::logs_with_scope_contain;
    logs_with_scope_contain("polaris_backend::api::cases", needle)
        || logs_with_scope_contain("polaris_backend::labeler::emitter", needle)
        || logs_with_scope_contain("polaris_backend", needle)
        || logs_with_scope_contain("tracing_action_id", needle)
}

/// Pull the captured-log buffer as a single owned String for
/// downstream split-by-line scanning. `tracing_test`'s public API
/// only exposes substring matchers; the internal `global_buf` API
/// gives access to the raw buffer.
fn captured_logs() -> String {
    // `tracing_test 0.2.6` exposes the global buffer via
    // `internal::global_buf()`. The buffer is a `Mutex<Vec<u8>>`;
    // taking a lock and copying out preserves the contents for the
    // current test.
    let buf = tracing_test::internal::global_buf();
    let guard = buf.lock().expect("tracing-test global buffer lock");
    String::from_utf8_lossy(&guard).into_owned()
}
