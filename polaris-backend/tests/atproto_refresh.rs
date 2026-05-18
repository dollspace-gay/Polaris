//! Integration test — drives the ATProto OAuth refresh flow against a
//! mock authorization server.
//!
//! Issue #66 / DPoP-nonce-rotation refresh.
//!
//! Spins up:
//!
//! 1. A `testcontainers`-driven Postgres so the session row's sealed
//!    bundle, `expires_at`, and `last_seen_at` columns can be asserted
//!    against real SQL.
//! 2. A custom `FetchHandler` impl (`MockFetcher`) that supports a
//!    per-key response queue so the AS `/token` endpoint can return
//!    `use_dpop_nonce` on the first call and a fresh token-set on the
//!    retry — exercising proto-blue-oauth's DPoP-nonce-rotation path
//!    end-to-end without us touching the DPoP-proof construction.
//!
//! Then drives `AtprotoOauthAuthVerifier::refresh_session` and asserts
//! the row's `refresh_token_enc` ciphertext changes, the `expires_at`
//! moves forward, and the sealed-and-decoded bundle carries the new
//! access + refresh tokens.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::{Crypto, SealedBytes};
use polaris_backend::auth::session::{SessionStore, SessionToken};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{DpopKey, OAuthClient, OAuthClientMetadata, TokenSet};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A single canned response from the mock authorization server.
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
    /// Per-key response queue. A key registered with N responses pops
    /// the front on each fetch; once the queue is exhausted the
    /// fetcher errors out so the test surfaces a missing stub rather
    /// than silently re-using a stale response. Single-response keys
    /// (the common case) push exactly one entry.
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

    /// Register a single-response stub. Same shape as the
    /// `atproto_login.rs` helper so the two test files share intuition.
    fn route(&self, method: HttpMethod, url: impl Into<String>, c: Canned) {
        self.state
            .lock()
            .unwrap()
            .routes
            .entry((method, url.into()))
            .or_default()
            .push(c);
    }

    /// Register a sequence of responses for the same `(method, url)`
    /// key. Used to model DPoP-nonce-rotation, where the first
    /// `/token` call is rejected with `use_dpop_nonce` and the second
    /// — carrying the AS-issued nonce in the retry DPoP proof —
    /// returns the rotated token set.
    fn route_sequence(&self, method: HttpMethod, url: impl Into<String>, seq: Vec<Canned>) {
        let mut state = self.state.lock().unwrap();
        let entry = state.routes.entry((method, url.into())).or_default();
        for c in seq {
            entry.push(c);
        }
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

/// Stand up a verifier wired against the supplied MockFetcher.
fn make_verifier(
    sessions: SessionStore,
    crypto: Crypto,
    pool: sqlx::PgPool,
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

/// Mirror of the private `atproto::SerializedSessionState`. We rebuild
/// the same envelope here at test seed time so we don't have to drag a
/// crate-internal type into the public surface just for the test.
/// Field shape, names, and serialisation MUST match the production
/// definition — if production drifts, this test must be updated in
/// lockstep (a regression test below pins the bundle round-trip).
#[derive(serde::Serialize)]
struct TestBundle {
    dpop_keypair_jwk_json: Vec<u8>,
    token_set: TokenSet,
}

/// Deserialisation counterpart to [`TestBundle`]. Used after refresh
/// to decode the freshly-rotated sealed bundle and assert it carries
/// the new access + refresh tokens.
#[derive(serde::Deserialize)]
struct DecodedBundle {
    #[allow(dead_code)]
    dpop_keypair_jwk_json: Vec<u8>,
    token_set: TokenSet,
}

/// Build a session-row seed: a fresh DPoP keypair, a TokenSet pointing
/// at the supplied issuer, and the sealed bincode envelope ready to
/// drop into `sessions.refresh_token_enc`.
fn seed_session_bundle(crypto: &Crypto, issuer: &str) -> (DpopKey, TokenSet, Vec<u8>) {
    let dpop_key = DpopKey::generate_es256().unwrap();
    let token_set = TokenSet {
        issuer: issuer.to_owned(),
        sub: "did:plc:moderator-mock-1".into(),
        scope: "atproto transition:generic".into(),
        access_token: "initial-access-token".into(),
        refresh_token: Some("initial-refresh-token".into()),
        token_type: "DPoP".into(),
        // 2 minutes from now so `is_expired(10)` does not pre-empt
        // the refresh logic — proto-blue's `OAuthSession::refresh`
        // proceeds unconditionally because the call site (here, the
        // verifier) drives it directly rather than via the
        // auto-refresh path.
        expires_at: Some(
            (chrono::Utc::now() + chrono::Duration::seconds(120))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
        aud: Some("https://pds.mock.example".into()),
    };
    let bundle = TestBundle {
        dpop_keypair_jwk_json: serde_json::to_vec(&dpop_key.private_jwk).unwrap(),
        token_set: token_set.clone(),
    };
    // Match production's `encode_bundle` envelope (issue #89 closure):
    // `polaris-backend/src/auth/atproto.rs` migrated bincode → serde_json
    // because bincode cannot round-trip `TokenSet`'s `#[serde(skip_serializing_if =
    // "Option::is_none")]` fields. The fixture must serialise identically
    // or `decode_bundle` parses garbage and returns `DpopBindingFailed`.
    let plain = serde_json::to_vec(&bundle).unwrap();
    let sealed = crypto.seal(&plain).unwrap();
    (dpop_key, token_set, sealed.to_bytes())
}

/// Register the canned responses needed for refresh to succeed against
/// the mock AS. The `/token` endpoint runs in **DPoP-nonce-rotation**
/// mode: the first hit returns 400 `use_dpop_nonce` with a
/// `DPoP-Nonce` header, the second hit (carrying the AS-issued nonce
/// in the retry DPoP proof) returns a fresh token set.
fn wire_refresh_routes(fetcher: &MockFetcher, iss: &str) {
    // AS discovery — used by `refresh_session` to re-discover the AS
    // metadata from the persisted issuer URL.
    let as_url = format!("{iss}/.well-known/oauth-authorization-server");
    fetcher.route(
        HttpMethod::Get,
        as_url.trim_end_matches('/'),
        Canned::json(serde_json::json!({
            "issuer": iss,
            "authorization_endpoint": format!("{iss}/oauth/authorize"),
            "token_endpoint": format!("{iss}/oauth/token"),
            "dpop_signing_alg_values_supported": ["ES256"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["atproto", "transition:generic"],
            "response_types_supported": ["code"],
        })),
    );

    // /token — two-shot sequence to exercise DPoP-nonce-rotation.
    let token_url = format!("{iss}/oauth/token");
    fetcher.route_sequence(
        HttpMethod::Post,
        token_url,
        vec![
            // First hit: server demands a nonce. proto-blue-oauth's
            // `is_use_dpop_nonce_error` inspects both the JSON body
            // and the 400 status — match both.
            Canned {
                status: 400,
                body: serde_json::to_vec(&serde_json::json!({
                    "error": "use_dpop_nonce",
                    "error_description": "Authorization server requires nonce in DPoP proof",
                }))
                .unwrap(),
                content_type: "application/json",
                headers: vec![("dpop-nonce".to_owned(), "mock-nonce-v1".to_owned())],
            },
            // Retry: succeed with rotated access + refresh tokens.
            Canned {
                status: 200,
                body: serde_json::to_vec(&serde_json::json!({
                    "access_token": "rotated-access-token",
                    "token_type": "DPoP",
                    "scope": "atproto transition:generic",
                    "refresh_token": "rotated-refresh-token",
                    "expires_in": 3600,
                    "sub": "did:plc:moderator-mock-1",
                }))
                .unwrap(),
                content_type: "application/json",
                headers: Vec::new(),
            },
        ],
    );
}

/// Insert a moderator row + a session row pointing at the supplied
/// sealed bundle. Returns the session token the test will refresh.
async fn seed_session_row(pool: &sqlx::PgPool, sealed_bytes: &[u8]) -> SessionToken {
    let did = "did:plc:moderator-mock-1";
    let (moderator_id,): (uuid::Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, display_name)
          VALUES ($1, 'atproto', $2) RETURNING id",
    )
    .bind(did)
    .bind("alice.example.com")
    .fetch_one(pool)
    .await
    .unwrap();

    let token = SessionToken::generate();
    // Seed with an old `expires_at` so the refresh's new expiry is
    // unambiguously forward of the seed.
    let seeded_expires = chrono::Utc::now() + chrono::Duration::hours(1);

    sqlx::query(
        r"INSERT INTO sessions (id, moderator_id, refresh_token_enc, expires_at)
          VALUES ($1, $2, $3, $4)",
    )
    .bind(token.as_str())
    .bind(moderator_id)
    .bind(sealed_bytes)
    .bind(seeded_expires)
    .execute(pool)
    .await
    .unwrap();

    token
}

#[tokio::test]
async fn atproto_refresh_session_rotates_bundle_and_extends_expiry() {
    if !docker_available() {
        println!("SKIP atproto_refresh: docker daemon not reachable");
        return;
    }

    // --- 1. Postgres ------------------------------------------------
    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .unwrap();
    let host_port = pg.get_host_port_ipv4(5432).await.unwrap();
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.unwrap();
    let pool = database.pool().clone();

    // --- 2. Mock AS wiring ------------------------------------------
    let iss = "https://as.mock.example";
    let fetcher = Arc::new(MockFetcher::new());
    wire_refresh_routes(&fetcher, iss);

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto.clone(), pool.clone(), fetcher.clone());

    // --- 3. Seed a session row with a sealed bundle -----------------
    let (_dpop_key, original_token_set, sealed_bytes) = seed_session_bundle(&crypto, iss);
    let session_token = seed_session_row(&pool, &sealed_bytes).await;

    // Capture pre-refresh state for the differential assertions.
    let pre: (Vec<u8>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT refresh_token_enc, expires_at FROM sessions WHERE id = $1")
            .bind(session_token.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    let pre_bytes = pre.0;
    let pre_expires = pre.1;

    // --- 4. Drive the refresh ---------------------------------------
    let new_expires = verifier
        .refresh_session(&session_token)
        .await
        .expect("refresh_session must succeed against the mock AS");

    // --- 5. Assertions ----------------------------------------------
    // 5a. expires_at moved forward.
    assert!(
        new_expires > pre_expires,
        "expires_at must advance: pre={pre_expires} new={new_expires}",
    );

    // 5b. Row reflects the new sealed bundle + new expires_at.
    let post: (Vec<u8>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as("SELECT refresh_token_enc, expires_at FROM sessions WHERE id = $1")
            .bind(session_token.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    let post_bytes = post.0;
    let post_expires = post.1;

    assert_ne!(
        pre_bytes, post_bytes,
        "refresh_token_enc must rotate after a successful refresh"
    );
    // Postgres TIMESTAMPTZ has microsecond precision, while
    // `chrono::Utc::now()` produces nanoseconds — compare within a
    // 1us window rather than for equality so the truncation doesn't
    // fail the assertion.
    let delta = (post_expires - new_expires).num_microseconds().unwrap_or(0);
    assert!(
        delta.abs() <= 1,
        "DB expires_at must match the value returned by refresh_session within 1us: \
         db={post_expires} returned={new_expires} delta={delta}us",
    );

    // 5c. Decoded bundle carries the rotated upstream tokens.
    // Issue #89 closure: production now decodes via `serde_json::from_slice`
    // (see `polaris-backend/src/auth/atproto.rs::decode_bundle`), so the
    // post-refresh bundle is JSON-shaped — bincode would error out
    // identically to what the bug reported.
    let sealed_post = SealedBytes::from_bytes(&post_bytes).unwrap();
    let plaintext_post = crypto.open(&sealed_post).unwrap();
    let decoded: DecodedBundle = serde_json::from_slice(&plaintext_post).unwrap();
    assert_eq!(
        decoded.token_set.access_token, "rotated-access-token",
        "post-refresh bundle must carry the new access token",
    );
    assert_eq!(
        decoded.token_set.refresh_token.as_deref(),
        Some("rotated-refresh-token"),
        "post-refresh bundle must carry the new refresh token",
    );
    assert_eq!(
        decoded.token_set.sub, original_token_set.sub,
        "sub claim must round-trip the refresh unchanged",
    );

    // 5d. The /token endpoint's queue was fully drained — both the
    //     `use_dpop_nonce` 400 and the retry 200 fired, exercising
    //     proto-blue's DPoP-nonce-rotation path end-to-end.
    let state = fetcher.state.lock().unwrap();
    let token_queue = state
        .routes
        .get(&(HttpMethod::Post, format!("{iss}/oauth/token")))
        .expect("token endpoint route must be present");
    assert!(
        token_queue.is_empty(),
        "both nonce-challenge and retry responses must have been consumed; \
         remaining queue length = {}",
        token_queue.len(),
    );
}

#[tokio::test]
async fn atproto_refresh_session_with_unknown_token_returns_session_not_found() {
    if !docker_available() {
        println!("SKIP atproto_refresh unknown-token: docker daemon not reachable");
        return;
    }

    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .unwrap();
    let host_port = pg.get_host_port_ipv4(5432).await.unwrap();
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.unwrap();
    let pool = database.pool().clone();

    let fetcher = Arc::new(MockFetcher::new());
    let crypto = Crypto::new([9_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto, pool, fetcher);

    let unknown = SessionToken::generate();
    let err = verifier
        .refresh_session(&unknown)
        .await
        .expect_err("refresh_session with unknown token must fail");
    assert!(
        matches!(err, polaris_backend::auth::AuthError::SessionNotFound),
        "expected SessionNotFound, got {err:?}",
    );
}

#[tokio::test]
async fn atproto_refresh_session_with_tampered_bundle_returns_crypto_error() {
    if !docker_available() {
        println!("SKIP atproto_refresh tampered-bundle: docker daemon not reachable");
        return;
    }

    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .unwrap();
    let host_port = pg.get_host_port_ipv4(5432).await.unwrap();
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let database = db::connect(&cfg).await.unwrap();
    let pool = database.pool().clone();

    let fetcher = Arc::new(MockFetcher::new());
    let crypto = Crypto::new([11_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto, pool.clone(), fetcher);

    // Seed a session row whose refresh_token_enc is a valid-shape but
    // wrong-key/wrong-ciphertext payload. AEAD authentication will
    // fail when refresh_session opens it.
    let did = "did:plc:moderator-tampered";
    let (moderator_id,): (uuid::Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend) VALUES ($1, 'atproto') RETURNING id",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .unwrap();

    let token = SessionToken::generate();
    let expires = chrono::Utc::now() + chrono::Duration::hours(1);
    sqlx::query(
        r"INSERT INTO sessions (id, moderator_id, refresh_token_enc, expires_at)
          VALUES ($1, $2, $3, $4)",
    )
    .bind(token.as_str())
    .bind(moderator_id)
    .bind(vec![0_u8; 64])
    .bind(expires)
    .execute(&pool)
    .await
    .unwrap();

    let err = verifier
        .refresh_session(&token)
        .await
        .expect_err("tampered bundle must surface as failure");
    assert!(
        matches!(err, polaris_backend::auth::AuthError::Crypto { .. }),
        "expected Crypto error for tampered refresh_token_enc, got {err:?}",
    );
}
