//! Integration test — drives the ATProto OAuth code-exchange flow
//! against a mock authorization server.
//!
//! Issue #31 / REQ-4 / AC-4 / AC-5 (atproto half).
//!
//! Spins up:
//!
//! 1. A `testcontainers`-driven Postgres so the state row, moderator row,
//!    and session row can be asserted against real SQL.
//! 2. A custom `FetchHandler` impl (`MockFetcher`) that routes URLs to
//!    canned responses for: the PDS protected-resource metadata, the
//!    AS authorization-server metadata, the PAR endpoint, and the
//!    token endpoint. Using a `FetchHandler` (rather than a `wiremock`
//!    HTTP server) avoids the DNS leg of `proto-blue-identity`'s handle
//!    resolver — the test exercises the PDS-URL input branch of
//!    `resolve_input` so the handle-resolution path's network side
//!    effects are out of scope (proto-blue's own test suite exercises
//!    that branch).
//!
//! Then drives `AtprotoOauthAuthVerifier::start_login` → manual callback
//! simulation → `AtprotoOauthAuthVerifier::complete_login` and asserts
//! the resulting `ModeratorAuthCtx` plus the on-disk rows.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::panic,
    clippy::needless_pass_by_value,
    clippy::field_reassign_with_default,
    clippy::default_trait_access,
    clippy::unused_async,
    clippy::missing_panics_doc
)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{AnyModeratorAuth, AuthError, LoginHint, ModeratorAuth};
use polaris_backend::config::{AppConfig, AtprotoAuthConfig, AuthBackend, AuthConfig, DbConfig};
use polaris_backend::db;
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{OAuthClient, OAuthClientMetadata};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use url::Url;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Canned response keyed by `(method, url)`. The URL is matched as a
/// prefix so test setup can register one stub per endpoint without
/// reasoning about the exact query-string ordering proto-blue may emit.
#[derive(Debug, Clone)]
struct Canned {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
    /// Optional response headers (besides Content-Type).
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
    routes: HashMap<(HttpMethod, String), Canned>,
    /// Captured requests for assertions.
    seen: Vec<HttpRequest>,
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
            .insert((method, url.into()), c);
    }
}

#[async_trait]
impl FetchHandler for MockFetcher {
    async fn fetch(&self, req: HttpRequest) -> Result<HttpResponse, FetchError> {
        // Normalise the URL by stripping the query string so test
        // setup can register one stub per endpoint regardless of how
        // proto-blue orders the form parameters.
        let url_no_q = req
            .url
            .split('?')
            .next()
            .unwrap_or(&req.url)
            .trim_end_matches('/')
            .to_owned();

        let mut state = self.state.lock().unwrap();
        state.seen.push(req.clone());

        let canned = state
            .routes
            .get(&(req.method, url_no_q.clone()))
            .cloned()
            .ok_or_else(|| {
                FetchError::Network(format!("no mock route for {:?} {}", req.method, url_no_q))
            })?;

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

/// Stand up a wired-up verifier with the MockFetcher pre-loaded for the
/// resource-discovery + AS-metadata + PAR + token endpoints.
async fn make_verifier(
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

/// Register the canned responses needed for the start_login → callback
/// dance to succeed. `pds_url` is the URL the input maps to; `iss` is
/// the AS issuer URL; the returned `pds_url` is also used as the
/// `LoginHint` argument so the resolve-by-URL branch of `resolve_input`
/// fires (the handle branch would require DNS).
fn wire_routes(fetcher: &MockFetcher, pds_url: &str, iss: &str) {
    // 1) Protected-resource discovery at {pds_url}/.well-known/oauth-protected-resource.
    let resource_url = format!("{pds_url}/.well-known/oauth-protected-resource");
    fetcher.route(
        HttpMethod::Get,
        resource_url.trim_end_matches('/'),
        Canned::json(serde_json::json!({
            "resource": pds_url,
            "authorization_servers": [iss],
        })),
    );

    // 2) Authorization-server metadata at {iss}/.well-known/oauth-authorization-server.
    let as_url = format!("{iss}/.well-known/oauth-authorization-server");
    fetcher.route(
        HttpMethod::Get,
        as_url.trim_end_matches('/'),
        Canned::json(serde_json::json!({
            "issuer": iss,
            "authorization_endpoint": format!("{iss}/oauth/authorize"),
            "token_endpoint": format!("{iss}/oauth/token"),
            "pushed_authorization_request_endpoint": format!("{iss}/oauth/par"),
            "dpop_signing_alg_values_supported": ["ES256"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["atproto", "transition:generic"],
            "response_types_supported": ["code"],
        })),
    );

    // 3) PAR endpoint at {iss}/oauth/par.
    fetcher.route(
        HttpMethod::Post,
        format!("{iss}/oauth/par"),
        Canned {
            status: 201,
            body: serde_json::to_vec(&serde_json::json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:mock-par-123",
                "expires_in": 60,
            }))
            .unwrap(),
            content_type: "application/json",
            headers: Vec::new(),
        },
    );

    // 4) Token endpoint at {iss}/oauth/token. The DID handed back in
    //    `sub` is the moderator's stable identifier — what becomes the
    //    `moderators.external_id` column under `auth_backend='atproto'`.
    fetcher.route(
        HttpMethod::Post,
        format!("{iss}/oauth/token"),
        Canned {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "mock-dpop-bound-access-token",
                "token_type": "DPoP",
                "scope": "atproto transition:generic",
                "refresh_token": "mock-refresh-token",
                "expires_in": 3600,
                "sub": "did:plc:moderator-mock-1",
            }))
            .unwrap(),
            content_type: "application/json",
            headers: Vec::new(),
        },
    );
}

#[tokio::test]
async fn atproto_login_flow_persists_session_row() {
    if !docker_available() {
        println!("SKIP atproto_login_flow: docker daemon not reachable");
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

    // --- 2. Mock auth server + verifier wiring ----------------------
    let pds_url = "https://pds.mock.example";
    let iss = "https://as.mock.example";
    let fetcher = Arc::new(MockFetcher::new());
    wire_routes(&fetcher, pds_url, iss);

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto, pool.clone(), fetcher.clone()).await;

    // --- 3. start_login ---------------------------------------------
    // Pass the PDS URL as the hint. proto-blue's `resolve_input`
    // treats any `http(s)://` prefix as a PDS URL, skipping the
    // handle-resolution leg entirely; the start-login → PAR → token
    // path still runs.
    let redirect = verifier
        .start_login(LoginHint::AtprotoHandle(pds_url.to_owned()))
        .await
        .expect("start_login should succeed");

    // Authorize URL should embed the PAR request_uri.
    let url = Url::parse(&redirect.authorize_url).unwrap();
    let request_uri = url
        .query_pairs()
        .find_map(|(k, v)| (k == "request_uri").then(|| v.to_string()));
    assert_eq!(
        request_uri.as_deref(),
        Some("urn:ietf:params:oauth:request_uri:mock-par-123"),
        "authorize URL must include the PAR request_uri",
    );

    // State row should be persisted with sealed DPoP keypair (not plaintext).
    let state_row: (Vec<u8>, String) = sqlx::query_as(
        "SELECT dpop_keypair_enc, handle FROM auth_atproto_login_states WHERE state = $1",
    )
    .bind(&redirect.state)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !state_row.0.is_empty(),
        "dpop_keypair_enc column must be non-empty"
    );
    // 12-byte nonce + 16-byte AES-GCM tag = 28 bytes minimum sealed envelope.
    assert!(state_row.0.len() >= 28);
    // Sanity: the sealed bytes must not contain the plaintext
    // JWK marker `"crv"` — that would mean the row is unsealed.
    assert!(
        !state_row.0.windows(5).any(|w| w == b"\"crv\""),
        "sealed dpop_keypair_enc must not contain plaintext JWK markers"
    );
    assert_eq!(state_row.1, pds_url);

    // --- 4. complete_login ------------------------------------------
    let result = verifier
        .complete_login(&redirect.state, "mock-auth-code")
        .await
        .expect("complete_login should succeed against the mock AS");

    // State row must be deleted (single-use).
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM auth_atproto_login_states WHERE state = $1")
            .bind(&redirect.state)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 0, "login-state row must be deleted post-exchange");

    // A moderator row with auth_backend='atproto' and the DID was upserted.
    let moderator_id: (uuid::Uuid,) = sqlx::query_as(
        "SELECT id FROM moderators WHERE auth_backend = 'atproto' AND external_id = $1",
    )
    .bind("did:plc:moderator-mock-1")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(moderator_id.0, result.ctx.moderator_id.0);

    // A session row exists with the DPoP keypair sealed bytes in
    // refresh_token_enc.
    let session_row: (Vec<u8>,) =
        sqlx::query_as("SELECT refresh_token_enc FROM sessions WHERE id = $1")
            .bind(result.session_token.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !session_row.0.is_empty(),
        "session refresh_token_enc must be non-empty"
    );
    assert!(session_row.0.len() >= 28);

    // First-user-admin grant (Workstream A — REQ-A's first-run path
    // in `polaris-backend/src/auth/atproto.rs::maybe_grant_first_user_admin`):
    // the very first moderator to complete login on a fresh database
    // is automatically granted `Role::Admin` so the setup wizard is
    // immediately reachable from their session without an out-of-band
    // role-assignment step. This test seeds an empty `moderators` +
    // `moderator_roles` pair (via the fresh testcontainer), so the
    // moderator we just logged in is the first user — they must
    // therefore see `["admin"]` in their role set.
    assert_eq!(
        result
            .ctx
            .roles
            .iter()
            .map(polaris_backend::auth::Role::as_db_str)
            .collect::<Vec<_>>(),
        vec!["admin"],
        "first moderator on a fresh deployment must get Role::Admin via the \
         first-user-admin grant (Workstream A)",
    );
}

#[tokio::test]
async fn atproto_complete_login_with_wrong_state_returns_state_mismatch() {
    if !docker_available() {
        println!("SKIP atproto wrong-state: docker daemon not reachable");
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
    let verifier = make_verifier(sessions, crypto, pool, fetcher).await;

    let err = verifier
        .complete_login("definitely-not-a-real-state", "mock-code")
        .await
        .expect_err("complete_login with unknown state must fail");
    assert!(
        matches!(err, AuthError::StateMismatch),
        "expected StateMismatch, got {err:?}",
    );
}

#[tokio::test]
async fn atproto_complete_login_with_expired_state_returns_state_mismatch() {
    if !docker_available() {
        println!("SKIP atproto expired-state: docker daemon not reachable");
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
    let verifier = make_verifier(sessions, crypto, pool.clone(), fetcher).await;

    // Insert an "expired" row directly (created_at older than the
    // 10-minute window the SELECT enforces).
    sqlx::query(
        r"INSERT INTO auth_atproto_login_states
          (state, pkce_verifier, dpop_keypair_enc, handle, par_request_uri, issuer, created_at)
          VALUES ($1, $2, $3, $4, $5, $6, now() - interval '11 minutes')",
    )
    .bind("expired-state-token")
    .bind("v")
    .bind(vec![0_u8; 28])
    .bind("alice.example.com")
    .bind("urn:test")
    .bind("https://as.example.com")
    .execute(&pool)
    .await
    .unwrap();

    let err = verifier
        .complete_login("expired-state-token", "mock-code")
        .await
        .expect_err("expired state row must surface as failure");
    assert!(
        matches!(err, AuthError::StateMismatch),
        "expected StateMismatch for expired row, got {err:?}",
    );
}

#[tokio::test]
async fn atproto_complete_login_with_tampered_dpop_returns_crypto_error() {
    if !docker_available() {
        println!("SKIP atproto tampered-dpop: docker daemon not reachable");
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
    let crypto = Crypto::new([13_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto.clone(), pool.clone(), fetcher).await;

    // Insert a state row with a valid-shape-but-wrong-ciphertext
    // dpop_keypair_enc. The AEAD authentication will fail on open;
    // SealedBytes::from_bytes accepts any payload >= 28 bytes, but
    // crypto.open returns Decrypt error on tag mismatch.
    sqlx::query(
        r"INSERT INTO auth_atproto_login_states
          (state, pkce_verifier, dpop_keypair_enc, handle, par_request_uri, issuer)
          VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind("tampered-state")
    .bind("v")
    .bind(vec![0_u8; 64])
    .bind("alice.example.com")
    .bind("urn:test")
    .bind("https://as.example.com")
    .execute(&pool)
    .await
    .unwrap();

    let err = verifier
        .complete_login("tampered-state", "mock-code")
        .await
        .expect_err("tampered dpop_keypair_enc must surface as failure");
    assert!(
        matches!(err, AuthError::Crypto { .. }),
        "expected Crypto error for tampered dpop_keypair_enc, got {err:?}",
    );
}

#[tokio::test]
async fn factory_selects_atproto_backend_from_config() {
    if !docker_available() {
        println!("SKIP factory atproto: docker daemon not reachable");
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

    // Write a client metadata JSON the factory can read.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
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
    std::fs::write(&path, serde_json::to_vec(&metadata).unwrap()).unwrap();

    let mut app_cfg = AppConfig::default();
    app_cfg.auth = AuthConfig {
        backend: AuthBackend::Atproto,
        oidc: Default::default(),
        atproto: AtprotoAuthConfig {
            client_metadata_path: path.clone(),
            client_id: metadata.client_id.clone(),
        },
        // Hardware-key gate (issue #40) is orthogonal to this backend-routing
        // test; leave it unset so the per-profile default applies.
        require_hardware_key: None,
    };

    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let any =
        polaris_backend::auth::build_moderator_auth(&app_cfg.auth, sessions, crypto, pool.clone())
            .await
            .expect("factory must build the atproto backend");

    match &*any {
        AnyModeratorAuth::Atproto(_) => {}
        AnyModeratorAuth::Oidc(_) => panic!("factory routed atproto config to OIDC"),
    }
}

#[tokio::test]
async fn oidc_verifier_rejects_atproto_hint() {
    // This is the trait-level regression test from #31g item 5.
    // Build the cheapest possible OIDC verifier exposure: the
    // `NullAuthVerifier` already satisfies the trait. We assert that
    // passing an atproto hint surfaces as a Config error.
    use polaris_backend::auth::oidc::NullAuthVerifier;
    let v = NullAuthVerifier;
    let err = v
        .start_login(LoginHint::AtprotoHandle("alice.example.com".to_owned()))
        .await
        .expect_err("null verifier must reject any hint");
    assert!(matches!(err, AuthError::Config { .. }));

    // The hint::None path still surfaces a Config error from the null
    // verifier — but with a different message. Both flow through the
    // same error variant so callers can match either uniformly.
    let err = v
        .start_login(LoginHint::None)
        .await
        .expect_err("null verifier must reject none hint");
    assert!(matches!(err, AuthError::Config { .. }));
}
