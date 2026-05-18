//! AC-A4: `POST /api/setup/generate-key` hot-swaps the freshly-loaded
//! signer through the process-wide `tokio::sync::watch` channel so
//! the next emit picks up the real signer atomically.
//!
//! # What this test asserts
//!
//! 1. Before the wizard runs, the receiver borrows a stub signer
//!    (empty `public_key_did`, `sign()` returns
//!    `SigningError::Sign{"labeler signing key not yet provisioned"}`).
//! 2. The handler writes the key file, persists the DID, AND pushes
//!    a real `FilePlainSigner` through the channel — no process
//!    restart.
//! 3. After the call, the receiver's `borrow()` returns the new
//!    signer: `public_key_did()` is the same `did:key:z…` the
//!    handler returned in its response body, and `sign(&[u8])`
//!    succeeds (the stub-error condition is gone).
//!
//! # AC-A4 carry-over — `labels.signing_did` IS asserted
//!
//! Workstream D's emitter rewire ([`LabelEmitter`] now reads through
//! the active-signer watch channel on every emit) closes the loop:
//! after the wizard's hot-swap, a subsequent `submit_action` produces
//! a `labels` row whose `signing_did` column equals the freshly-
//! minted `did:key:z…`. This test now drives that flow end-to-end:
//!
//! 1. Boot router with a `StubSigner` in the channel.
//! 2. POST `/api/setup/generate-key` — pushes a real
//!    `FilePlainSigner` through the sender.
//! 3. POST `/api/cases/{subject_id}/actions` with kind=Label.
//! 4. `SELECT signing_did FROM labels WHERE action_id = $1` → asserts
//!    it equals the response's `did_key`. The whole point of the
//!    carry-over is that the emitter signs with the NEW key, not
//!    the stub it was constructed against.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    reason = "integration test code is allowed to panic — rust-quality §7"
)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::{SessionStore, SessionToken};
use polaris_backend::auth::{AnyModeratorAuth, Role};
use polaris_backend::config::{DbConfig, LabelerSigningKeyConfig};
use polaris_backend::db;
use polaris_backend::labeler::signer::{SigningKey, stub::StubSigner};
use polaris_backend::middleware::auth::SESSION_COOKIE;
use polaris_backend::repo::{
    IncidentRepo, NewIncident, NewSubject, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{AtUri, Did, IncidentStatus, Severity, SubjectKind};
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{DpopKey, OAuthClient, OAuthClientMetadata, TokenSet};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::watch;
use tower::ServiceExt as _;
use uuid::Uuid;

const TEST_DID: &str = "did:plc:hot-swap-test-moderator";
const TEST_HANDLE: &str = "alice.example.com";
const TEST_PDS_URL: &str = "https://pds.mock.example";

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── MockFetcher (copied from setup_endpoints.rs) ─────────────────────

#[derive(Debug, Clone)]
struct Canned {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
    headers: Vec<(String, String)>,
}

// Note: `Canned::json` and a routing helper would normally live here —
// the AC-A4 test only POSTs `/api/setup/generate-key`, which performs
// no upstream HTTP calls (the mint + DB-update happens in-process),
// so the constructor is intentionally omitted. The mock fetcher stays
// available for symmetry with `tests/setup_endpoints.rs` so a future
// extension (e.g. asserting that hot-swap does NOT trigger any
// upstream HTTP) can add routes without re-introducing the wiring.

#[derive(Debug, Default)]
struct MockState {
    routes: HashMap<(HttpMethod, String), Vec<Canned>>,
}

#[derive(Debug, Default, Clone)]
struct MockFetcher {
    state: Arc<Mutex<MockState>>,
}

impl MockFetcher {
    fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl FetchHandler for MockFetcher {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, FetchError> {
        let url_no_q = req
            .url
            .split('?')
            .next()
            .unwrap_or(&req.url)
            .trim_end_matches('/')
            .to_owned();

        let mut state = self.state.lock().unwrap();
        let queue = state
            .routes
            .get_mut(&(req.method, url_no_q.clone()))
            .ok_or_else(|| {
                FetchError::Network(format!("no mock route for {:?} {}", req.method, url_no_q))
            })?;
        if queue.is_empty() {
            return Err(FetchError::Network(format!(
                "mock route queue exhausted for {:?} {}",
                req.method, url_no_q
            )));
        }
        let canned = queue.remove(0);

        let mut headers = HttpHeaders::new();
        headers.insert("content-type".to_owned(), canned.content_type.to_owned());
        for (k, v) in canned.headers {
            headers.insert(k, v);
        }

        Ok(HttpResponse {
            status: canned.status,
            headers,
            body: canned.body,
        })
    }
}

// ── Verifier wiring (copied from setup_endpoints.rs) ─────────────────

fn make_verifier(
    sessions: SessionStore,
    crypto: Crypto,
    pool: PgPool,
    fetcher: Arc<MockFetcher>,
) -> AtprotoOauthAuthVerifier {
    let metadata = OAuthClientMetadata {
        client_id: "https://polaris.example/client.json".into(),
        redirect_uris: vec!["https://polaris.example/auth/atproto/callback".into()],
        response_types: Some(vec!["code".into()]),
        grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
        scope: Some("atproto transition:generic".into()),
        token_endpoint_auth_method: Some("none".into()),
        token_endpoint_auth_signing_alg: None,
        application_type: Some("web".into()),
        dpop_bound_access_tokens: Some(true),
        client_name: Some("Polaris".into()),
        client_uri: None,
        logo_uri: None,
    };
    let fetch_handle: Arc<dyn FetchHandler> = fetcher as Arc<dyn FetchHandler>;
    let oauth_client = Arc::new(OAuthClient::with_fetch_handler(
        metadata,
        Arc::clone(&fetch_handle),
    ));
    let id_resolver = Arc::new(IdResolver::with_fetch_handler(
        IdentityResolverOpts::default(),
        None,
        Arc::clone(&fetch_handle),
    ));
    AtprotoOauthAuthVerifier::new(
        oauth_client,
        id_resolver,
        fetch_handle,
        sessions,
        crypto,
        pool,
    )
}

// ── Session-bundle seeding (mirrors setup_endpoints.rs) ──────────────

#[derive(serde::Serialize)]
struct TestBundle {
    dpop_keypair_jwk_json: Vec<u8>,
    token_set: TokenSet,
}

fn seal_session_bundle(crypto: &Crypto, did: &str, pds_url: &str) -> Vec<u8> {
    let dpop_key = DpopKey::generate_es256().unwrap();
    let token_set = TokenSet {
        issuer: "https://as.mock.example".into(),
        sub: did.to_owned(),
        scope: "atproto transition:generic".into(),
        access_token: "test-access-token".into(),
        refresh_token: Some("test-refresh-token".into()),
        token_type: "DPoP".into(),
        expires_at: Some(
            (chrono::Utc::now() + chrono::Duration::seconds(3600))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        aud: Some(pds_url.to_owned()),
    };
    let bundle = TestBundle {
        dpop_keypair_jwk_json: serde_json::to_vec(&dpop_key.private_jwk).unwrap(),
        token_set,
    };
    let plain = bincode::serde::encode_to_vec(&bundle, bincode::config::standard()).unwrap();
    let sealed = crypto.seal(&plain).unwrap();
    sealed.to_bytes()
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

async fn seed_admin_with_session(
    pool: &PgPool,
    crypto: &Crypto,
) -> Result<String, Box<dyn std::error::Error>> {
    let row: (Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, display_name)
          VALUES ($1, 'atproto', $2)
          RETURNING id",
    )
    .bind(TEST_DID)
    .bind(TEST_HANDLE)
    .fetch_one(pool)
    .await?;
    let moderator_id = row.0;

    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id)
    .bind(Role::Admin.as_db_str())
    .execute(pool)
    .await?;

    let sealed_bytes = seal_session_bundle(crypto, TEST_DID, TEST_PDS_URL);
    let token = SessionToken::generate();
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query(
        r"INSERT INTO sessions (id, moderator_id, refresh_token_enc, expires_at)
          VALUES ($1, $2, $3, $4)",
    )
    .bind(token.as_str())
    .bind(moderator_id)
    .bind(&sealed_bytes)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(token.as_str().to_owned())
}

async fn read_json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        let snippet = String::from_utf8_lossy(&bytes);
        panic!("response body was not valid JSON: {err}; body was: {snippet}")
    })
}

// ── AC-A4 ──────────────────────────────────────────────────────────────

/// Build a router that carries the same active-signer channel halves
/// production wiring installs. The test asserts that after the
/// wizard's generate-key handler runs, the receiver's borrowed signer
/// has rotated from the stub to a real `FilePlainSigner` with a
/// non-empty `did:key:z…`.
#[tokio::test]
async fn generate_key_hot_swaps_signer_through_active_signer_channel()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP generate_key_hot_swaps_signer::generate_key_hot_swaps_signer_through_active_signer_channel: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    // Per REQ-A2 + REQ-A4: build the channel halves around a
    // StubSigner (the boot-from-zero posture). The receiver lives on
    // ApiState; the sender is what the wizard pushes the real signer
    // through.
    let signing_key_tmp = tempfile::tempdir()?;
    let key_path = signing_key_tmp.path().join("not-yet-provisioned.key");
    assert!(
        !key_path.exists(),
        "test precondition: key file must not exist before the wizard runs",
    );
    let stub: Arc<dyn SigningKey> = Arc::new(StubSigner::new(key_path.clone()));
    let (signer_tx, signer_rx) = watch::channel::<Arc<dyn SigningKey>>(stub);
    let signer_tx = Arc::new(signer_tx);

    // Sanity: receiver currently borrows the stub.
    {
        let borrowed = signer_rx.borrow();
        assert_eq!(
            borrowed.public_key_did(),
            "",
            "before generate_key, the receiver must hold a stub (empty did)",
        );
        let err = borrowed
            .sign(b"any payload")
            .expect_err("stub must refuse to sign");
        match err {
            polaris_backend::labeler::signer::SigningError::Sign { reason } => {
                assert_eq!(reason, "labeler signing key not yet provisioned");
            }
            other => panic!("expected SigningError::Sign{{…}}, got {other:?}"),
        }
    }

    let verifier = make_verifier(sessions.clone(), crypto.clone(), pool.clone(), fetcher);
    let any_auth = Arc::new(AnyModeratorAuth::Atproto(verifier));
    // Workstream D carry-over: build a LabelEmitter that reads
    // through the same active-signer receiver. Before the hot-swap
    // it borrows the StubSigner (which refuses to sign — that's why
    // we don't emit before the wizard runs); after the swap it
    // borrows the fresh FilePlainSigner. A `submit_action` after
    // the wizard exercises the rewired emit path and the
    // `labels.signing_did` column should equal the new DID.
    let base_state = ApiState::new(pool.clone(), sessions);
    let emitter = Arc::new(
        polaris_backend::labeler::emitter::LabelEmitter::with_active_signer(
            signer_rx.clone(),
            pool.clone(),
            base_state.label_broadcaster.clone(),
        ),
    );
    let state = base_state
        .with_moderator_auth(any_auth)
        .with_labeler_signing_key_cfg(LabelerSigningKeyConfig::FilePlain {
            path: key_path.clone(),
        })
        .with_active_signer(signer_rx.clone())
        .with_active_signer_tx(Arc::clone(&signer_tx))
        .with_label_emitter(emitter);
    let router: Router = api::router_with_state(database, state.clone());

    let cookie = seed_admin_with_session(&pool, &crypto).await?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/generate-key")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from("{}"))?;
    let response = router.oneshot(request).await?;

    let status = response.status();
    let body_json = read_json_body(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "generate-key against a writable path must surface 200; body was {body_json}",
    );
    let did_key = body_json["did_key"]
        .as_str()
        .expect("response must carry did_key")
        .to_owned();
    assert!(
        did_key.starts_with("did:key:z"),
        "response did_key must use the z-multibase prefix; got {did_key}",
    );

    // REQ-A4 the wire-level assertion: the channel's receiver now
    // borrows the freshly-loaded signer. The handler's hot-swap
    // happens synchronously inside the request body, so by the time
    // we see the response the receiver MUST have rotated.
    {
        let borrowed = signer_rx.borrow();
        assert_eq!(
            borrowed.public_key_did(),
            did_key.as_str(),
            "after generate_key, the active-signer receiver must hold a signer with the new DID",
        );
        // The new signer can actually sign — the stub-error condition
        // is gone. We don't verify the bytes here (that's covered by
        // file_plain.rs unit tests); we only assert "no longer the
        // stub error".
        let sig = borrowed
            .sign(b"hot-swap-test-payload")
            .expect("real signer must succeed where the stub would fail");
        assert_eq!(
            sig.as_bytes().len(),
            64,
            "K-256 compact signature must be exactly 64 bytes",
        );
    }

    // The key file was actually written, so a process restart would
    // re-load it via FilePlainSigner. (This is the redundancy the
    // hot-swap saves: without it the operator would have to restart.)
    let meta = std::fs::metadata(&key_path)?;
    assert!(meta.is_file());
    assert!(meta.len() > 0);

    // And the DB column is correct.
    let persisted: (Option<String>,) =
        sqlx::query_as("SELECT signing_pubkey_did FROM polaris_setup_state WHERE id = TRUE")
            .fetch_one(&pool)
            .await?;
    assert_eq!(persisted.0.as_deref(), Some(did_key.as_str()));

    // ── AC-A4 end-to-end: the emitter signs with the NEW key ────────
    //
    // Workstream D's emitter rewire makes `LabelEmitter::emit` read
    // through the active-signer watch receiver on every call. After
    // the hot-swap above, a subsequent action POST should produce a
    // `labels` row whose `signing_did` column equals `did_key`. If
    // the rewire regressed, the emitter would still hold the
    // StubSigner and the action submission would either fail
    // (StubSigner::sign returns SigningError::Sign) or silently sign
    // with the wrong DID. Either way, the assertion below catches
    // the regression.

    // Seed the prereqs the action-submission path needs (subject +
    // incident + moderator row). `polaris_setup_state.signing_pubkey_did`
    // was just stamped by the wizard handler above, so the REQ-A3
    // precondition is satisfied.
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let subject_row = subjects
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new("did:plc:hotswaptest")),
            uri: Some(AtUri::new(
                "at://did:plc:hotswaptest/app.bsky.feed.post/abc",
            )),
            created_at: chrono::Utc::now(),
        })
        .await?;
    let incident_row = incidents
        .insert(NewIncident {
            primary_subject: subject_row.id,
            status: IncidentStatus::Open,
            severity: Severity::Medium,
            assigned_to: None,
        })
        .await?;

    // Use the same moderator_id our session was minted against
    // (lookup by external_id rather than re-deriving).
    let mod_row: (Uuid,) =
        sqlx::query_as("SELECT id FROM moderators WHERE external_id = $1 LIMIT 1")
            .bind(TEST_DID)
            .fetch_one(&pool)
            .await?;
    let moderator_id_uuid = mod_row.0;

    // Minimal router for the action POST. Inject the
    // ModeratorAuthCtx Extension so the auth middleware (which
    // would otherwise reject without a session cookie when going
    // through the production router) is bypassed. The state holds
    // the emitter that reads through the active-signer channel,
    // so the assertion below is the AC-A4 binding observation.
    let action_ctx = polaris_backend::auth::ModeratorAuthCtx::new(
        polaris_backend::auth::ModeratorId(moderator_id_uuid),
        std::collections::HashSet::new(),
    );
    let action_router = Router::new()
        .route(
            "/api/cases/{subject_id}/actions",
            axum::routing::post(polaris_backend::api::cases::submit_action),
        )
        .layer(axum::extract::Extension(action_ctx))
        .with_state(state);

    let body_json = serde_json::json!({
        "incident_id": incident_row.id,
        "kind": "label",
        "label": "spam",
        "reasoning": "this is a sufficiently long reasoning string for the AC-A4 hot-swap end-to-end test",
        "policy_refs": ["polaris.spam"],
        "reversible_until": (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let action_request = Request::builder()
        .method("POST")
        .uri(format!("/api/cases/{}/actions", subject_row.id.0))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body_json)?))?;
    let action_response = action_router.oneshot(action_request).await?;
    let action_status = action_response.status();
    let action_body = read_json_body(action_response).await;
    assert_eq!(
        action_status,
        StatusCode::CREATED,
        "submit_action after hot-swap must succeed; response: {action_body}",
    );
    let action_id_str = action_body["id"]
        .as_str()
        .expect("response carries id")
        .to_owned();
    let action_id: Uuid = action_id_str.parse()?;

    // The strong assertion: the persisted label row's signing_did
    // equals the new DID, not the empty stub-DID and not some
    // pre-rewire stale value. This is the AC-A4 end-to-end check
    // the previous version of the test couldn't make because the
    // emitter held an `Arc<dyn SigningKey>` by value and ignored
    // the channel.
    let label_row: (String,) =
        sqlx::query_as("SELECT signing_did FROM labels WHERE action_id = $1")
            .bind(action_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        label_row.0, did_key,
        "AC-A4 carry-over: labels.signing_did after the hot-swap must equal the new did:key, \
         not the StubSigner's empty DID or any pre-rewire value",
    );

    Ok(())
}
