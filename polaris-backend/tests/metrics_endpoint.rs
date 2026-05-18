//! AC-D2: `/metrics` returns Prometheus text exposition; submitting
//! one action surfaces `polaris_actions_total{kind="label"} 1` and the
//! `axum_http_requests_total{...}` auto-counter fires for the same
//! request the test made.
//!
//! # Strategy
//!
//! The `metrics-exporter-prometheus` recorder is a process global.
//! Each integration test in this crate runs as its own binary
//! (cargo's per-test-binary isolation), so installing the recorder
//! once at the top of this test is safe — no other test in this
//! binary touches the recorder.
//!
//! The test:
//! 1. Installs the recorder + builds the layered router (mirrors
//!    `main.rs`).
//! 2. Provisions a real signer through the active-signer channel so
//!    the `submit_action` precondition (REQ-A3) does not reject the
//!    request.
//! 3. Seeds the prerequisite rows (subject, incident, moderator,
//!    `polaris_setup_state.signing_pubkey_did`) so the action insert
//!    succeeds.
//! 4. POSTs one Label action against `/api/cases/{subject_id}/actions`
//!    through a minimal router that injects a moderator context
//!    (same pattern as `label_emitter.rs::submit_action_emits_label_via_http_route`).
//! 5. GETs `/metrics` against the production router and asserts the
//!    body contains `polaris_actions_total{kind="label"} 1` plus an
//!    `axum_http_requests_total{...}` line.

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
use axum_prometheus::PrometheusMetricLayer;
use chrono::Utc;
use http_body_util::BodyExt as _;
use polaris_backend::api;
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
    let external_id = format!("metrics-test-{}", Uuid::new_v4());
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
async fn metrics_endpoint_surfaces_action_counter_and_axum_counter()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP metrics_endpoint::metrics_endpoint_surfaces_action_counter_and_axum_counter: \
             no docker."
        );
        return Ok(());
    }

    // Install the Prometheus recorder ONCE for this test process.
    // The auto-instrumenting `axum-prometheus` layer is constructed
    // alongside; both share one global recorder.
    let (prometheus_layer, prometheus_handle) = PrometheusMetricLayer::pair();
    let prometheus_handle = Arc::new(prometheus_handle);

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([0_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);

    // Real signer (so the `submit_action` precondition is satisfied).
    let real = InMemorySigner::generate();
    let real_did = real.did.clone();
    let real_arc: Arc<dyn SigningKey> = Arc::new(real);
    let (signer_tx, signer_rx) = watch::channel::<Arc<dyn SigningKey>>(real_arc);
    let _signer_tx_keepalive = signer_tx;

    // ApiState mirrors `main.rs`: emitter + active signer + metrics
    // handle all installed.
    let api_state = ApiState::new(pool.clone(), sessions);
    let emitter = Arc::new(LabelEmitter::with_active_signer(
        signer_rx.clone(),
        pool.clone(),
        api_state.label_broadcaster.clone(),
    ));
    let api_state = api_state
        .with_label_emitter(emitter)
        .with_active_signer(signer_rx)
        .with_metrics_handle(Arc::clone(&prometheus_handle));

    // Seed: subject + incident + moderator + setup state.
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let moderator_id = insert_moderator(&pool).await;
    let subject = subjects
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new("did:plc:metricstest")),
            uri: Some(AtUri::new(
                "at://did:plc:metricstest/app.bsky.feed.post/abc",
            )),
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

    // REQ-A3 precondition: stamp the column so `submit_action`
    // proceeds to the emit path.
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(&real_did)
    .execute(&pool)
    .await?;

    // Build the production router with the Prometheus layer attached
    // (mirrors `main.rs`). The same router serves both `/metrics`
    // and the auth-gated `/api/*` routes; the auth middleware
    // rejects requests without a session cookie. The
    // `submit_action` POST therefore goes through a separate
    // minimal router that injects a moderator context — that is
    // the same pattern `label_emitter.rs` uses to drive the route
    // without standing up the OIDC handshake. The auto-instrumented
    // HTTP counter still fires on the production router's
    // `/metrics` GET, so the `axum_http_requests_total` series is
    // observed.
    let production_router: Router =
        api::router_with_state(database, api_state.clone()).layer(prometheus_layer.clone());

    // Minimal router for the action POST — injects a
    // ModeratorAuthCtx Extension and shares the same ApiState (so
    // the metrics counter at `submit_action` fires against the same
    // recorder). The `polaris_actions_total` counter is registered
    // globally via the macros; the recorder is shared.
    let ctx = ModeratorAuthCtx::new(
        polaris_backend::auth::ModeratorId(moderator_id.0),
        std::collections::HashSet::new(),
    );
    let action_router = Router::new()
        .route(
            "/api/cases/{subject_id}/actions",
            axum::routing::post(polaris_backend::api::cases::submit_action),
        )
        .layer(axum::extract::Extension(ctx))
        .with_state(api_state);

    // POST one Label action through the minimal router.
    let body_json = serde_json::json!({
        "incident_id": incident.id,
        "kind": "label",
        "label": "spam",
        "reasoning": "this is a sufficiently long reasoning string for the metrics test",
        "policy_refs": ["polaris.spam"],
        "reversible_until": (Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let action_request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject.id.0))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body_json)?))?;
    let action_response = action_router.oneshot(action_request).await?;
    assert_eq!(
        action_response.status(),
        StatusCode::CREATED,
        "submit_action must succeed",
    );

    // The auto-instrumented `axum_http_requests_total` counter is
    // emitted by `axum-prometheus` on response completion via the
    // tower `LifeCycle` middleware. Rendering `/metrics` in the same
    // request that fires the counter races the recorder — the
    // response is built before the on_response hook runs. So we make
    // one *other* request through the production router first
    // (`/healthz` is the cheapest; it lives on the same subtree).
    // By the time we hit `/metrics`, the prior request's counter
    // has landed.
    let _ = production_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/healthz")
                .body(Body::empty())?,
        )
        .await?;

    // GET `/metrics` through the production (Prometheus-layered)
    // router. The auto-instrumented HTTP counter fires on this very
    // request.
    let metrics_response = production_router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        metrics_response.status(),
        StatusCode::OK,
        "/metrics must return 200",
    );
    let bytes = metrics_response.into_body().collect().await?.to_bytes();
    let body = String::from_utf8_lossy(&bytes);

    // AC-D2 part 1: hand-emitted `polaris_actions_total` counter
    // reflects the single action we POSTed. The exposition format is
    // `<name>{<label>="<value>",…} <count>` so a substring check is
    // sufficient.
    assert!(
        body.contains(r#"polaris_actions_total{kind="label"} 1"#),
        "expected polaris_actions_total{{kind=\"label\"}} 1; body was:\n{body}",
    );

    // AC-D2 part 2: auto-instrumented HTTP counter is present.
    // The exact label set varies by axum-prometheus version
    // (`endpoint` / `method` / `status`) so we only assert the
    // metric name prefix.
    assert!(
        body.contains("axum_http_requests_total"),
        "expected axum_http_requests_total series; body was:\n{body}",
    );
    assert!(
        body.contains("axum_http_requests_duration_seconds"),
        "expected axum_http_requests_duration_seconds histogram; body was:\n{body}",
    );

    Ok(())
}
