//! `/api/setup/*` endpoint integration tests (#85).
//!
//! Pins the wire contract of the four setup-wizard handlers under
//! [`polaris_backend::api::setup`]:
//!
//! 1. `POST /api/setup/generate-key`        — admin-gated K-256 mint
//! 2. `POST /api/setup/publish-labeler-record` — `app.bsky.labeler.service` putRecord
//! 3. `POST /api/setup/request-plc-signature` — `identity.requestPlcOperationSignature`
//! 4. `POST /api/setup/submit-plc-operation`  — `identity.signPlcOperation` + `submitPlcOperation`
//!
//! The fixture pattern mirrors `tests/atproto_refresh.rs`:
//!
//! - Real Postgres via `testcontainers` so the
//!   `polaris_setup_state` UPDATEs and the moderator/role/session rows
//!   participate in real SQL.
//! - A [`MockFetcher`] (per-key response queue) installed on the
//!   atproto-OAuth verifier so the OAuthSession's
//!   `POST <pds>/xrpc/...` calls land on test stubs without binding a
//!   TCP listener.
//! - A pre-sealed session bundle (DPoP JWK + `TokenSet`) written
//!   directly into `sessions.refresh_token_enc`. The TokenSet carries
//!   `aud = <mock pds>` so
//!   [`AtprotoOauthAuthVerifier::build_oauth_session_for_moderator`]
//!   skips DID-document resolution and the MockFetcher does not need
//!   to model the PLC directory.
//!
//! The integration is end-to-end through the production router:
//! `router_with_state` is built around an [`ApiState`] that carries
//! the test's `Arc<AnyModeratorAuth>` and a `LabelerSigningKeyConfig`
//! pointing at a per-test temp directory. The auth middleware runs
//! the cookie lookup, the handler does its admin check, builds the
//! OAuth session, hits the (mocked) PDS, and persists the resulting
//! `polaris_setup_state` columns — every observable surface of the
//! wire contract is asserted.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    reason = "test code is allowed to panic per rust-quality §7"
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
use polaris_backend::middleware::auth::SESSION_COOKIE;
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{DpopKey, OAuthClient, OAuthClientMetadata, TokenSet};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon. Mirrors the rest of the
/// integration suite so the skip behaviour is uniform.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── MockFetcher (per-key queue) — copied from atproto_refresh.rs ───────

/// A single canned response from the mock PDS.
#[derive(Debug, Clone)]
struct Canned {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
    headers: Vec<(String, String)>,
}

impl Canned {
    fn json(body: serde_json::Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
            content_type: "application/json",
            headers: Vec::new(),
        }
    }
}

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

    fn route(&self, method: HttpMethod, url: impl Into<String>, c: Canned) {
        self.state
            .lock()
            .unwrap()
            .routes
            .entry((method, url.into()))
            .or_default()
            .push(c);
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

// ── Verifier wiring ──────────────────────────────────────────────────

/// Build an [`AtprotoOauthAuthVerifier`] wired against the supplied mock
/// fetcher.
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

// ── Session-bundle plumbing ──────────────────────────────────────────

/// Mirror of the private `atproto::SerializedSessionState`. Same fields,
/// same order — the bincode envelope must be byte-identical so
/// `build_oauth_session_for_moderator` can decode it.
///
/// If production drifts, the `atproto_refresh.rs` test will fail in
/// lockstep — we re-derive it here rather than re-export it from the
/// crate's public API.
#[derive(serde::Serialize)]
struct TestBundle {
    dpop_keypair_jwk_json: Vec<u8>,
    token_set: TokenSet,
}

/// Build a session-row seed for the given DID + PDS URL. The TokenSet
/// carries `aud = pds_url` so the verifier's PDS-endpoint resolution
/// takes the cheap path and the test does not have to model the PLC
/// directory.
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

// ── DB / fixture helpers ─────────────────────────────────────────────

/// Boot a Postgres testcontainer + migrate + return the `(db, pool)`
/// pair. The container handle is leaked so its `Drop` runs at process
/// exit rather than at the helper's stack frame — same idiom every
/// other integration test in this crate uses.
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

/// Insert a moderator row, grant a role, and seed an active session
/// whose `refresh_token_enc` is the sealed bincode session bundle.
///
/// Returns the moderator's UUID + the cookie token the test injects in
/// `polaris_session=…`.
async fn seed_moderator_with_session(
    pool: &PgPool,
    crypto: &Crypto,
    role: Role,
    did: &str,
    handle: &str,
    pds_url: &str,
) -> Result<(Uuid, String), Box<dyn std::error::Error>> {
    let row: (Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, display_name)
          VALUES ($1, 'atproto', $2)
          RETURNING id",
    )
    .bind(did)
    .bind(handle)
    .fetch_one(pool)
    .await?;
    let moderator_id = row.0;

    sqlx::query(
        r"INSERT INTO moderator_roles (moderator_id, role)
          VALUES ($1, $2)
          ON CONFLICT DO NOTHING",
    )
    .bind(moderator_id)
    .bind(role.as_db_str())
    .execute(pool)
    .await?;

    let sealed_bytes = seal_session_bundle(crypto, did, pds_url);
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

    Ok((moderator_id, token.as_str().to_owned()))
}

/// Build the full Axum router around a state that carries:
/// - the atproto auth verifier (wired against `fetcher`),
/// - a `LabelerSigningKeyConfig::FilePlain` pointing at `signing_key_path`.
fn build_router_with_setup_state(
    database: db::Db,
    pool: PgPool,
    sessions: SessionStore,
    fetcher: Arc<MockFetcher>,
    crypto: Crypto,
    signing_key_path: std::path::PathBuf,
) -> Router {
    let verifier = make_verifier(sessions.clone(), crypto, pool.clone(), fetcher);
    let any_auth = Arc::new(AnyModeratorAuth::Atproto(verifier));
    let state = ApiState::new(pool, sessions)
        .with_moderator_auth(any_auth)
        .with_labeler_signing_key_cfg(LabelerSigningKeyConfig::FilePlain {
            path: signing_key_path,
        });
    api::router_with_state(database, state)
}

/// Pull the response body into a `serde_json::Value`. Same helper shape
/// as `tests/case_api.rs` so the per-test assertion line stays readable.
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

// ── Test constants ───────────────────────────────────────────────────

/// The DID the seeded moderator owns; mirrored into `TokenSet.sub` so
/// `build_oauth_session_for_moderator` carries it through to the
/// `oauth_ctx.did` field.
const TEST_DID: &str = "did:plc:setup-test-moderator";
/// The handle written into `moderators.display_name`. Used by
/// `submit_plc_operation` to derive the `did:web:<handle>` id.
const TEST_HANDLE: &str = "alice.example.com";
/// The PDS URL the OAuth session is bound to (the `aud` claim). Every
/// `OAuthSession::post` call inside the setup handlers builds its URL
/// as `<pds_url>/xrpc/<nsid>`, so the MockFetcher routes off this base.
const TEST_PDS_URL: &str = "https://pds.mock.example";
/// A valid `did:key:z…` value used to pre-populate
/// `polaris_setup_state.signing_pubkey_did` for the publish + submit
/// tests. K-256 multikey form (`ES256K`) — both
/// `polaris-publish-labeler-record` and `polaris-publish-did-service`
/// accept this curve.
const TEST_SIGNING_DID_KEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";

// ── 1. generate_key — non-admin → 403 ────────────────────────────────

#[tokio::test]
async fn generate_key_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP setup_endpoints::generate_key_requires_admin: docker daemon not reachable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    let router = build_router_with_setup_state(
        database,
        pool.clone(),
        sessions,
        fetcher,
        crypto.clone(),
        key_path,
    );

    // Seed a moderator with the plain `moderator` role — not admin.
    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        TEST_DID,
        TEST_HANDLE,
        TEST_PDS_URL,
    )
    .await?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/generate-key")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from("{}"))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "non-admin caller must surface 403 from require_admin()",
    );
    let body = read_json_body(response).await;
    assert_eq!(
        body["code"], "forbidden",
        "403 body must carry code=forbidden; body was {body}",
    );
    Ok(())
}

// ── 2. generate_key — admin happy path → 200 + DB row ────────────────

#[tokio::test]
async fn generate_key_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP setup_endpoints::generate_key_happy_path: docker daemon not reachable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    let router = build_router_with_setup_state(
        database,
        pool.clone(),
        sessions,
        fetcher,
        crypto.clone(),
        key_path.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Admin,
        TEST_DID,
        TEST_HANDLE,
        TEST_PDS_URL,
    )
    .await?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/generate-key")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from("{}"))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "admin caller against a writable key path must surface 200",
    );
    let body = read_json_body(response).await;
    let did_key = body["did_key"]
        .as_str()
        .expect("response must carry did_key")
        .to_owned();
    assert!(
        did_key.starts_with("did:key:z"),
        "did_key must use the z-multibase prefix; got {did_key}",
    );

    // `polaris_setup_state.signing_pubkey_did` must round-trip what the
    // handler returned (single source of truth — the wizard re-reads
    // this column on subsequent steps).
    let persisted: (Option<String>,) =
        sqlx::query_as("SELECT signing_pubkey_did FROM polaris_setup_state WHERE id = TRUE")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        persisted.0.as_deref(),
        Some(did_key.as_str()),
        "polaris_setup_state.signing_pubkey_did must equal the response's did_key",
    );

    // The signing-key file was written and is non-empty (the contents
    // are private — we never assert their value, only that the file
    // exists and was populated).
    let file_meta = std::fs::metadata(&key_path)?;
    assert!(
        file_meta.is_file(),
        "signing-key file must exist after generate_key"
    );
    assert!(
        file_meta.len() > 0,
        "signing-key file must be non-empty after generate_key",
    );
    Ok(())
}

// ── 3. generate_key — pre-existing key file → 409 ────────────────────

#[tokio::test]
async fn generate_key_conflict_on_existing_file() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP setup_endpoints::generate_key_conflict_on_existing_file: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    // Pre-create the key file with non-empty content so
    // `refuse_existing_key_file` rejects.
    std::fs::write(&key_path, "pre-existing-key-content")?;

    let router = build_router_with_setup_state(
        database,
        pool.clone(),
        sessions,
        fetcher,
        crypto.clone(),
        key_path.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Admin,
        TEST_DID,
        TEST_HANDLE,
        TEST_PDS_URL,
    )
    .await?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/generate-key")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from("{}"))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "non-empty existing key file must surface 409 Conflict",
    );
    let body = read_json_body(response).await;
    assert_eq!(
        body["code"], "conflict",
        "409 body must carry code=conflict; body was {body}",
    );

    // The pre-existing file content was NOT overwritten — the safety
    // contract of `refuse_existing_key_file` is that the handler
    // never touches the file when it bails on 409.
    let after = std::fs::read_to_string(&key_path)?;
    assert_eq!(after, "pre-existing-key-content");
    Ok(())
}

// ── 4. publish_labeler_record — non-admin → 403 ──────────────────────

#[tokio::test]
async fn publish_labeler_record_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP setup_endpoints::publish_labeler_record_requires_admin: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    let router = build_router_with_setup_state(
        database,
        pool.clone(),
        sessions,
        fetcher,
        crypto.clone(),
        key_path,
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        TEST_DID,
        TEST_HANDLE,
        TEST_PDS_URL,
    )
    .await?;

    let body = serde_json::json!({
        "service_url": "https://example.com",
        "label_values": ["spam"],
    });
    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/publish-labeler-record")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "non-admin caller must surface 403",
    );
    Ok(())
}

// ── 5. publish_labeler_record — admin happy path → 200 + DB row ──────

#[tokio::test]
async fn publish_labeler_record_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP setup_endpoints::publish_labeler_record_happy_path: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    // Wire the PDS's putRecord endpoint.
    let put_uri = format!("at://{TEST_DID}/app.bsky.labeler.service/self");
    let put_cid = "bafyTESTCID0000000000000000000000000000000000000000000000".to_owned();
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.repo.putRecord"),
        Canned::json(serde_json::json!({
            "uri": put_uri,
            "cid": put_cid,
        })),
    );

    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    let router = build_router_with_setup_state(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
        key_path,
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Admin,
        TEST_DID,
        TEST_HANDLE,
        TEST_PDS_URL,
    )
    .await?;

    // Pre-populate `polaris_setup_state.signing_pubkey_did` so the
    // handler does not bounce on the missing-prereq path.
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(TEST_SIGNING_DID_KEY)
    .execute(&pool)
    .await?;

    let body = serde_json::json!({
        "service_url": "https://example.com",
        "label_values": ["spam"],
    });
    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/publish-labeler-record")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(request).await?;

    let status = response.status();
    let body_json = read_json_body(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin + valid PDS putRecord stub must surface 200; body was {body_json}",
    );
    assert_eq!(
        body_json["at_uri"].as_str(),
        Some(put_uri.as_str()),
        "response.at_uri must echo the PDS's putRecord uri",
    );
    assert_eq!(
        body_json["cid"].as_str(),
        Some(put_cid.as_str()),
        "response.cid must echo the PDS's putRecord cid",
    );

    // `polaris_setup_state.labeler_record_uri` must equal the
    // returned at_uri — the wizard re-reads it on a re-visited
    // /setup screen.
    let persisted: (Option<String>,) =
        sqlx::query_as("SELECT labeler_record_uri FROM polaris_setup_state WHERE id = TRUE")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        persisted.0.as_deref(),
        Some(put_uri.as_str()),
        "polaris_setup_state.labeler_record_uri must equal the returned at_uri",
    );
    Ok(())
}

// ── 6. request_plc_signature — admin happy path → 200 + message ──────

#[tokio::test]
async fn request_plc_signature_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP setup_endpoints::request_plc_signature_happy_path: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    // The lexicon for requestPlcOperationSignature declares no input;
    // proto-blue always writes a JSON body so the handler sends `{}`
    // and the PDS replies with an empty JSON object.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.requestPlcOperationSignature"),
        Canned::json(serde_json::json!({})),
    );

    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    let router = build_router_with_setup_state(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
        key_path,
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Admin,
        TEST_DID,
        TEST_HANDLE,
        TEST_PDS_URL,
    )
    .await?;

    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/request-plc-signature")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from("{}"))?;
    let response = router.oneshot(request).await?;

    let status = response.status();
    let body_json = read_json_body(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin + valid PDS stub must surface 200; body was {body_json}",
    );
    let message = body_json["message"]
        .as_str()
        .expect("response must carry a `message` field");
    assert!(
        !message.is_empty(),
        "response.message must be non-empty (the wizard surfaces it verbatim)",
    );
    Ok(())
}

// ── 7. submit_plc_operation — admin happy path → 200 + DB row ────────

#[tokio::test]
async fn submit_plc_operation_happy_path() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP setup_endpoints::submit_plc_operation_happy_path: \
             docker daemon not reachable"
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    // signPlcOperation returns the signed operation envelope; the
    // handler then forwards `.operation` to submitPlcOperation.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.signPlcOperation"),
        Canned::json(serde_json::json!({
            "operation": {}
        })),
    );
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.submitPlcOperation"),
        Canned::json(serde_json::json!({})),
    );

    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    let router = build_router_with_setup_state(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
        key_path,
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Admin,
        TEST_DID,
        TEST_HANDLE,
        TEST_PDS_URL,
    )
    .await?;

    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(TEST_SIGNING_DID_KEY)
    .execute(&pool)
    .await?;

    // Sanity: pre-call `did_document_updated_at` is NULL.
    let pre: (Option<chrono::DateTime<chrono::Utc>>,) =
        sqlx::query_as("SELECT did_document_updated_at FROM polaris_setup_state WHERE id = TRUE")
            .fetch_one(&pool)
            .await?;
    assert!(
        pre.0.is_none(),
        "polaris_setup_state.did_document_updated_at must start NULL; got {:?}",
        pre.0,
    );

    let body = serde_json::json!({
        "token": "abc123",
        "service_url": "https://example.com",
    });
    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/submit-plc-operation")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body)?))?;
    let response = router.oneshot(request).await?;

    let status = response.status();
    let body_json = read_json_body(response).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "admin + valid sign+submit stubs must surface 200; body was {body_json}",
    );
    assert_eq!(
        body_json["did"].as_str(),
        Some(TEST_DID),
        "response.did must echo the OAuth context's DID (the moderator's sub claim)",
    );

    let post: (Option<chrono::DateTime<chrono::Utc>>,) =
        sqlx::query_as("SELECT did_document_updated_at FROM polaris_setup_state WHERE id = TRUE")
            .fetch_one(&pool)
            .await?;
    assert!(
        post.0.is_some(),
        "polaris_setup_state.did_document_updated_at must be set after a successful submit",
    );
    Ok(())
}
