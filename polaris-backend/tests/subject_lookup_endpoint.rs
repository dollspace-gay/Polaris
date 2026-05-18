//! Integration test for `POST /api/subjects/lookup` (issue #92).
//!
//! Covers AC-1 of the command-palette implementation:
//!
//! 1. Resolve a `https://bsky.app/profile/<handle>` URL → new
//!    `subjects` row + 200 response.
//! 2. Idempotent re-lookup of the same identifier returns the SAME
//!    `subject_id`.
//! 3. Bare `did:plc:...` → new account-kind row.
//! 4. AT-URI `at://did:plc:.../app.bsky.feed.post/<rkey>` → new
//!    post-kind row.
//! 5. Empty identifier → 400 `malformed_identifier`.
//! 6. Non-existent handle (MockFetcher returns 404 on the
//!    `.well-known/atproto-did` path) → 404 `identifier_unresolvable`.
//!
//! Fixture pattern is the same as `setup_endpoints.rs`:
//!
//! - Real Postgres via `testcontainers`.
//! - [`MockFetcher`] installed on the atproto verifier's bound
//!   [`IdResolver`] (and the OAuth client, though no OAuth round-trips
//!   here).
//! - Pre-sealed session bundle written directly into
//!   `sessions.refresh_token_enc` so the auth middleware accepts the
//!   moderator's cookie.

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
use polaris_backend::config::DbConfig;
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

// ── Docker availability probe ────────────────────────────────────────

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── MockFetcher (per-key queue) — copied from setup_endpoints.rs ─────

#[derive(Debug, Clone)]
struct Canned {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
    headers: Vec<(String, String)>,
}

impl Canned {
    fn text(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            body: body.into().into_bytes(),
            content_type: "text/plain",
            headers: Vec::new(),
        }
    }

    fn not_found() -> Self {
        Self {
            status: 404,
            body: Vec::new(),
            content_type: "text/plain",
            headers: Vec::new(),
        }
    }
}

#[derive(Debug, Default)]
struct MockState {
    routes: HashMap<(HttpMethod, String), Vec<Canned>>,
    /// Stable canned response for routes that may be hit many times
    /// (handle / DID resolution paths). When the per-key queue is
    /// empty for a `(method, url)` pair we fall back to this map
    /// keyed only on URL — the value is cloned per call so the queue
    /// behaviour stays single-shot for OAuth-style routes while the
    /// resolver routes are sticky.
    sticky: HashMap<(HttpMethod, String), Canned>,
}

#[derive(Debug, Default, Clone)]
struct MockFetcher {
    state: Arc<Mutex<MockState>>,
}

impl MockFetcher {
    fn new() -> Self {
        Self::default()
    }

    /// Install a sticky (re-usable) canned response for the given
    /// route. Sticky routes survive an arbitrary number of fetches
    /// without exhausting — the handle / DID resolver pathways may
    /// be invoked any number of times per test.
    fn sticky(&self, method: HttpMethod, url: impl Into<String>, c: Canned) {
        self.state
            .lock()
            .unwrap()
            .sticky
            .insert((method, url.into()), c);
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
        let key = (req.method, url_no_q.clone());

        let canned = if let Some(queue) = state.routes.get_mut(&key) {
            if queue.is_empty() {
                None
            } else {
                Some(queue.remove(0))
            }
        } else {
            None
        };

        let canned = if let Some(c) = canned {
            c
        } else if let Some(c) = state.sticky.get(&key) {
            c.clone()
        } else {
            return Err(FetchError::Network(format!(
                "no mock route for {:?} {}",
                req.method, url_no_q,
            )));
        };

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
    // Tight HTTP timeout so the test fails fast when the mock has no
    // route registered for a path the resolver hits.
    let opts = IdentityResolverOpts {
        timeout_ms: 1_500,
        plc_url: None,
        backup_nameservers: None,
    };
    let id_resolver = Arc::new(IdResolver::with_fetch_handler(
        opts,
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

#[derive(serde::Serialize)]
struct TestBundle {
    dpop_keypair_jwk_json: Vec<u8>,
    token_set: TokenSet,
}

fn seal_session_bundle(crypto: &Crypto, did: &str) -> Vec<u8> {
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
        aud: Some("https://pds.mock.example".to_owned()),
    };
    let bundle = TestBundle {
        dpop_keypair_jwk_json: serde_json::to_vec(&dpop_key.private_jwk).unwrap(),
        token_set,
    };
    let plain = serde_json::to_vec(&bundle).unwrap();
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

async fn seed_moderator_with_session(
    pool: &PgPool,
    crypto: &Crypto,
    role: Role,
    did: &str,
    handle: &str,
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

    let sealed_bytes = seal_session_bundle(crypto, did);
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

fn build_router(
    database: db::Db,
    pool: PgPool,
    sessions: SessionStore,
    fetcher: Arc<MockFetcher>,
    crypto: Crypto,
) -> Router {
    let verifier = make_verifier(sessions.clone(), crypto, pool.clone(), fetcher);
    let any_auth = Arc::new(AnyModeratorAuth::Atproto(verifier));
    let state = ApiState::new(pool, sessions).with_moderator_auth(any_auth);
    api::router_with_state(database, state)
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

// ── Test constants ───────────────────────────────────────────────────

const SEED_MODERATOR_DID: &str = "did:plc:lookup-test-mod";
const SEED_MODERATOR_HANDLE: &str = "operator.example.com";

const ALICE_HANDLE: &str = "alice.test";
const ALICE_DID: &str = "did:plc:alice123";

// ── Helpers to issue requests ─────────────────────────────────────────

fn post_lookup(cookie: &str, identifier: &str) -> Request<Body> {
    let body = serde_json::json!({ "identifier": identifier });
    Request::builder()
        .method("POST")
        .uri("/api/subjects/lookup")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// Wire the MockFetcher with a working handle-resolution path for
/// `ALICE_HANDLE` → `ALICE_DID`. The handle resolver hits
/// `https://<handle>/.well-known/atproto-did` first (the HTTPS path
/// works on every target the resolver supports). The DNS path falls
/// through because `.test` is reserved by RFC 2606 and the
/// hickory-resolver's lookup at the system level returns nothing.
fn install_alice_resolution(fetcher: &MockFetcher) {
    fetcher.sticky(
        HttpMethod::Get,
        format!("https://{ALICE_HANDLE}/.well-known/atproto-did"),
        Canned::text(ALICE_DID),
    );
}

// ── 1. https://bsky.app/profile/<handle> → 200 + new row ─────────────

#[tokio::test]
async fn lookup_bsky_app_profile_handle_creates_new_subject()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP subject_lookup::bsky_app_profile_handle: docker unavailable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());
    install_alice_resolution(&fetcher);

    let router = build_router(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        SEED_MODERATOR_DID,
        SEED_MODERATOR_HANDLE,
    )
    .await?;

    let response = router
        .oneshot(post_lookup(
            &cookie,
            &format!("https://bsky.app/profile/{ALICE_HANDLE}"),
        ))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json_body(response).await;
    assert_eq!(body["did"], ALICE_DID);
    assert_eq!(body["kind"], "account");
    assert!(body["uri"].is_null());

    // The subjects row was actually inserted.
    let subject_id_str = body["subject_id"]
        .as_str()
        .expect("subject_id present")
        .to_owned();
    let subject_id = Uuid::parse_str(&subject_id_str).expect("subject_id parses as UUID");
    let row: (String, Option<String>) =
        sqlx::query_as("SELECT kind, did FROM subjects WHERE id = $1")
            .bind(subject_id)
            .fetch_one(&pool)
            .await?;
    assert_eq!(row.0, "account");
    assert_eq!(row.1.as_deref(), Some(ALICE_DID));
    Ok(())
}

// ── 2. Idempotent re-lookup returns the same subject_id ──────────────

#[tokio::test]
async fn lookup_is_idempotent_for_repeat_calls() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP subject_lookup::idempotent: docker unavailable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());
    install_alice_resolution(&fetcher);

    let router = build_router(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        SEED_MODERATOR_DID,
        SEED_MODERATOR_HANDLE,
    )
    .await?;

    let path = format!("https://bsky.app/profile/{ALICE_HANDLE}");
    let first_response = router.clone().oneshot(post_lookup(&cookie, &path)).await?;
    let first_body = read_json_body(first_response).await;
    let first_id = first_body["subject_id"].as_str().unwrap().to_owned();

    let second_response = router.oneshot(post_lookup(&cookie, &path)).await?;
    assert_eq!(second_response.status(), StatusCode::OK);
    let second_body = read_json_body(second_response).await;
    let second_id = second_body["subject_id"].as_str().unwrap().to_owned();

    assert_eq!(
        first_id, second_id,
        "second lookup must return the SAME subject_id (idempotent)",
    );
    Ok(())
}

// ── 3. Bare did:plc:... → new account-kind row ───────────────────────

#[tokio::test]
async fn lookup_bare_did_plc_creates_account_subject() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP subject_lookup::bare_did_plc: docker unavailable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    let router = build_router(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        SEED_MODERATOR_DID,
        SEED_MODERATOR_HANDLE,
    )
    .await?;

    let did = "did:plc:abc123";
    let response = router.oneshot(post_lookup(&cookie, did)).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json_body(response).await;
    assert_eq!(body["did"], did);
    assert_eq!(body["kind"], "account");
    assert!(body["uri"].is_null());
    Ok(())
}

// ── 4. AT-URI for a post → new post-kind row ─────────────────────────

#[tokio::test]
async fn lookup_at_uri_post_creates_post_subject() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP subject_lookup::at_uri_post: docker unavailable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    let router = build_router(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        SEED_MODERATOR_DID,
        SEED_MODERATOR_HANDLE,
    )
    .await?;

    let at_uri = "at://did:plc:abc/app.bsky.feed.post/3lxyz";
    let response = router.oneshot(post_lookup(&cookie, at_uri)).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = read_json_body(response).await;
    assert_eq!(body["did"], "did:plc:abc");
    assert_eq!(body["kind"], "post");
    assert_eq!(body["uri"], at_uri);
    Ok(())
}

// ── 5. Empty identifier → 400 malformed_identifier ───────────────────

#[tokio::test]
async fn lookup_empty_identifier_returns_400_malformed() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP subject_lookup::empty_identifier: docker unavailable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    let router = build_router(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        SEED_MODERATOR_DID,
        SEED_MODERATOR_HANDLE,
    )
    .await?;

    let response = router.oneshot(post_lookup(&cookie, "")).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = read_json_body(response).await;
    assert_eq!(body["code"], "bad_request");
    // The body's "error" string carries the static message. The
    // contract surface is the HTTP code + body code; the inner
    // "malformed_identifier" wording is captured in the message.
    let err_text = body["error"].as_str().unwrap_or_default();
    assert!(
        err_text.contains("malformed_identifier"),
        "error body should embed malformed_identifier, got: {err_text}",
    );
    Ok(())
}

// ── 6. Non-existent handle (404 from MockFetcher) → 404 unresolvable ─

#[tokio::test]
async fn lookup_unresolvable_handle_returns_404() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP subject_lookup::unresolvable_handle: docker unavailable");
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());
    // Wire `https://ghost.test/.well-known/atproto-did` to return
    // 404. The resolver's other path (DNS) falls through because
    // `.test` is RFC 2606 reserved; the HTTP 404 collapses to
    // `Ok(None)` at the resolver and the handler maps that to
    // `ApiError::NotFound`.
    fetcher.sticky(
        HttpMethod::Get,
        "https://ghost.test/.well-known/atproto-did",
        Canned::not_found(),
    );

    let router = build_router(
        database,
        pool.clone(),
        sessions,
        Arc::clone(&fetcher),
        crypto.clone(),
    );

    let (_moderator_id, cookie) = seed_moderator_with_session(
        &pool,
        &crypto,
        Role::Moderator,
        SEED_MODERATOR_DID,
        SEED_MODERATOR_HANDLE,
    )
    .await?;

    let response = router.oneshot(post_lookup(&cookie, "ghost.test")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = read_json_body(response).await;
    assert_eq!(body["code"], "not_found");
    Ok(())
}
