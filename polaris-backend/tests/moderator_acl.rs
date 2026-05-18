//! Integration tests for the Ozone-style moderator ACL (issue #214).
//!
//! Five tests:
//!
//! 1. Non-allowlisted DID is rejected at the OAuth callback path: the
//!    verifier surfaces `AuthError::NotAllowed` and no session row is
//!    persisted.
//! 2. First-user bootstrap sets `moderators.pinned_admin = TRUE` and
//!    grants the `admin` role atomically.
//! 3. Admin `DELETE /api/admin/moderators/:did` for the pinned admin
//!    returns 409 Conflict.
//! 4. Admin `PATCH /api/admin/moderators/:did/roles` revoking
//!    `admin` from the pinned admin returns 409 Conflict.
//! 5. Direct `UPDATE moderators SET pinned_admin = FALSE` against the
//!    pinned row raises a Postgres exception (the migration-46
//!    trigger enforces monotonicity at the DB layer).
//!
//! The fixture mirrors `tests/first_run_admin.rs`'s MockFetcher pattern
//! for the OAuth-dance tests and `tests/case_api.rs`'s router-oneshot
//! pattern for the admin-endpoint tests. Re-deriving both shapes here
//! (rather than factoring into shared helpers) keeps each integration
//! test file self-contained per the convention the rest of the suite
//! follows.

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
    clippy::missing_panics_doc,
    reason = "integration test code — rust-quality §7 convention"
)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt as _;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{
    AnyModeratorAuth, AuthError, LoginHint, ModeratorAuth, ModeratorId as AuthModeratorId,
};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::middleware::auth::SESSION_COOKIE;
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{OAuthClient, OAuthClientMetadata};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;
use uuid::Uuid;

/// Probe for a working Docker daemon.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── MockFetcher (mirrors tests/first_run_admin.rs) ─────────────────────

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
    routes: HashMap<(HttpMethod, String), Canned>,
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
        let url_no_q = req
            .url
            .split('?')
            .next()
            .unwrap_or(&req.url)
            .trim_end_matches('/')
            .to_owned();
        let state = self.state.lock().unwrap();
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

async fn make_verifier(
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

fn wire_routes(fetcher: &MockFetcher, pds_url: &str, iss: &str, did: &str) {
    let resource_url = format!("{pds_url}/.well-known/oauth-protected-resource");
    fetcher.route(
        HttpMethod::Get,
        resource_url.trim_end_matches('/'),
        Canned::json(serde_json::json!({
            "resource": pds_url,
            "authorization_servers": [iss],
        })),
    );
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
                "sub": did,
            }))
            .unwrap(),
            content_type: "application/json",
            headers: Vec::new(),
        },
    );
}

/// Boot a fresh Postgres testcontainer, run migrations, return (db, pool).
async fn boot_db() -> (db::Db, PgPool) {
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
    std::mem::forget(pg);
    (database, pool)
}

// ── 1. Non-allowlisted DID rejected at callback ───────────────────────

#[tokio::test]
async fn non_allowlisted_did_rejected_at_callback() {
    if !docker_available() {
        println!(
            "SKIP moderator_acl::non_allowlisted_did_rejected_at_callback: docker not reachable"
        );
        return;
    }

    let (_db, pool) = boot_db().await;

    // Seed a pre-existing admin so `moderators` is non-empty and the
    // bootstrap carve-out does NOT fire.
    let admin_uuid: (uuid::Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, pinned_admin)
          VALUES ($1, 'atproto', TRUE)
          RETURNING id",
    )
    .bind("did:plc:admin")
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO moderator_roles (moderator_id, role) VALUES ($1, 'admin')")
        .bind(admin_uuid.0)
        .execute(&pool)
        .await
        .unwrap();

    let pds_url = "https://pds.mock.example";
    let iss = "https://as.mock.example";
    let rejected_did = "did:plc:not-allowed";

    let fetcher = Arc::new(MockFetcher::new());
    wire_routes(&fetcher, pds_url, iss, rejected_did);

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto, pool.clone(), fetcher).await;

    let redirect = verifier
        .start_login(LoginHint::AtprotoHandle(pds_url.to_owned()))
        .await
        .expect("start_login must succeed");

    let err = verifier
        .complete_login(&redirect.state, "mock-auth-code")
        .await
        .expect_err("complete_login must reject non-allowlisted DID");
    match err {
        AuthError::NotAllowed { handle } => {
            assert_eq!(
                handle, pds_url,
                "AuthError::NotAllowed must echo the handle from the login-state row"
            );
        }
        other => panic!("expected AuthError::NotAllowed, got {other:?}"),
    }

    // No moderator row was created for the rejected DID.
    let count: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM moderators WHERE external_id = $1 AND auth_backend = 'atproto'",
    )
    .bind(rejected_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        count.0, 0,
        "rejected DID must not have produced a moderator row"
    );

    // No session row was created at all (the only existing
    // moderator is the seeded admin, who has no live session).
    let sessions: (i64,) = sqlx::query_as("SELECT count(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        sessions.0, 0,
        "no session row must exist after a rejected login"
    );
}

// ── 2. First-user bootstrap sets pinned_admin ──────────────────────────

#[tokio::test]
async fn first_user_bootstrap_sets_pinned_admin() {
    if !docker_available() {
        println!(
            "SKIP moderator_acl::first_user_bootstrap_sets_pinned_admin: docker not reachable"
        );
        return;
    }

    let (_db, pool) = boot_db().await;

    // Sanity: empty deployment.
    let pre: (i64,) = sqlx::query_as("SELECT count(*) FROM moderators")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pre.0, 0);

    let pds_url = "https://pds.mock.example";
    let iss = "https://as.mock.example";
    let did = "did:plc:operator";

    let fetcher = Arc::new(MockFetcher::new());
    wire_routes(&fetcher, pds_url, iss, did);

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto, pool.clone(), fetcher).await;

    let redirect = verifier
        .start_login(LoginHint::AtprotoHandle(pds_url.to_owned()))
        .await
        .expect("start_login");
    let _result = verifier
        .complete_login(&redirect.state, "mock-auth-code")
        .await
        .expect("complete_login must succeed for first user");

    let row: (bool,) = sqlx::query_as(
        "SELECT pinned_admin FROM moderators WHERE external_id = $1 AND auth_backend = 'atproto'",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(row.0, "first user must have pinned_admin = TRUE");

    let roles: Vec<(String,)> = sqlx::query_as(
        r"SELECT role FROM moderator_roles r
          JOIN moderators m ON r.moderator_id = m.id
          WHERE m.external_id = $1",
    )
    .bind(did)
    .fetch_all(&pool)
    .await
    .unwrap();
    let role_strs: Vec<&str> = roles.iter().map(|(r,)| r.as_str()).collect();
    assert_eq!(
        role_strs,
        vec!["admin"],
        "first user must have admin role; got {role_strs:?}"
    );
}

// ── 3. Pinned admin cannot be deleted ─────────────────────────────────

/// Seed a pinned-admin row plus an active session, build the router,
/// and return everything the admin-endpoint tests need.
async fn boot_admin_fixture() -> (
    axum::Router,
    PgPool,
    SessionStore,
    AuthModeratorId,
    String, // session cookie value
    String, // pinned admin DID
) {
    let (database, pool) = boot_db().await;
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let pinned_did = "did:plc:pinned-admin";
    let row: (uuid::Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, pinned_admin)
          VALUES ($1, 'atproto', TRUE)
          RETURNING id",
    )
    .bind(pinned_did)
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO moderator_roles (moderator_id, role) VALUES ($1, 'admin')")
        .bind(row.0)
        .execute(&pool)
        .await
        .unwrap();
    let new_session = sessions
        .create(AuthModeratorId(row.0), b"test-refresh-token")
        .await
        .unwrap();
    let state = ApiState::new(pool.clone(), sessions.clone());
    let router = api::router_with_state(database, state);
    (
        router,
        pool,
        sessions,
        AuthModeratorId(row.0),
        new_session.token.as_str().to_owned(),
        pinned_did.to_owned(),
    )
}

#[tokio::test]
async fn delete_pinned_admin_returns_409() {
    if !docker_available() {
        println!("SKIP moderator_acl::delete_pinned_admin_returns_409: docker not reachable");
        return;
    }
    let (router, _pool, _sessions, _admin_id, cookie, pinned_did) = boot_admin_fixture().await;

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/admin/moderators/{pinned_did}"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "conflict");
}

// ── 4. Pinned admin cannot lose admin role via PATCH ──────────────────

#[tokio::test]
async fn patch_pinned_admin_demote_returns_409() {
    if !docker_available() {
        println!("SKIP moderator_acl::patch_pinned_admin_demote_returns_409: docker not reachable");
        return;
    }
    let (router, _pool, _sessions, _admin_id, cookie, pinned_did) = boot_admin_fixture().await;

    let body = serde_json::json!({ "role": "admin", "grant": false }).to_string();
    let req = Request::builder()
        .method("PATCH")
        .uri(format!("/api/admin/moderators/{pinned_did}/roles"))
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["code"], "conflict");
}

// ── 5. DB trigger blocks direct UPDATE pinned_admin = FALSE ───────────

#[tokio::test]
async fn trigger_blocks_direct_pinned_admin_clear() {
    if !docker_available() {
        println!(
            "SKIP moderator_acl::trigger_blocks_direct_pinned_admin_clear: docker not reachable"
        );
        return;
    }
    let (_db, pool) = boot_db().await;

    let did = "did:plc:pinned-direct";
    let row: (uuid::Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend, pinned_admin)
          VALUES ($1, 'atproto', TRUE)
          RETURNING id",
    )
    .bind(did)
    .fetch_one(&pool)
    .await
    .unwrap();

    let result = sqlx::query("UPDATE moderators SET pinned_admin = FALSE WHERE id = $1")
        .bind(row.0)
        .execute(&pool)
        .await;
    assert!(
        result.is_err(),
        "direct UPDATE clearing pinned_admin must error; got: {result:?}",
    );
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("monotone")
            || msg.contains("pinned_admin")
            || msg.to_lowercase().contains("cannot clear"),
        "error must mention the monotonicity invariant; got: {msg}"
    );

    // The row's pinned_admin is still TRUE.
    let still_pinned: (bool,) = sqlx::query_as("SELECT pinned_admin FROM moderators WHERE id = $1")
        .bind(row.0)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        still_pinned.0,
        "pinned_admin must remain TRUE after a refused clear"
    );

    // Silence unused-warning on the kept imports.
    let _ = (AnyModeratorAuth::as_atproto, Uuid::new_v4());
}
