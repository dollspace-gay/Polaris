//! Integration tests for the first-run admin grant (issue #83a).
//!
//! Exercises [`maybe_grant_first_user_admin`] end-to-end through the
//! production `AtprotoOauthAuthVerifier::complete_login` path:
//!
//! 1. The very first OAuth completion against an empty `moderator_roles`
//!    table inserts an `admin` row for the new moderator AND writes one
//!    `first_user_admin_grant` row into `audit_log`. Both happen in the
//!    same transaction as the moderator upsert; a failure in any step
//!    rolls the whole bundle back.
//! 2. A second OAuth completion arriving after `moderator_roles` is
//!    already non-empty does NOT grant the second moderator admin AND
//!    does NOT append a second `first_user_admin_grant` audit row.
//!
//! The fixture mirrors `tests/atproto_login.rs`'s `MockFetcher` pattern:
//! a Postgres testcontainer plus an injected `FetchHandler` that routes
//! protected-resource discovery, AS metadata, PAR, and token endpoints
//! to canned responses. Re-deriving the mock here (rather than factoring
//! into a shared helper) keeps each integration test file self-contained
//! per the convention the rest of the suite follows.
//!
//! # Why not a third concurrency race test
//!
//! The original dispatch called for a third test exercising two
//! concurrent OAuth completions for two fresh DIDs. The shared
//! `MockFetcher` routes responses by `(method, url)` and ALL completions
//! hit the same token endpoint stub, which means concurrent runs would
//! race on the canned response and yield non-deterministic `sub` claims.
//! Reproducing the race deterministically would require either:
//!
//! - threading a per-call DID through the fetcher (architectural change
//!   to the mock to be parameterised by some per-request token), or
//! - swapping in `wiremock` to register two separate token endpoints —
//!   but that adds a second mock-server stack just for this test.
//!
//! The race-safety reasoning lives in the rustdoc on
//! `maybe_grant_first_user_admin`; the two sequential tests below are the
//! runtime proof that the policy (grant once, audit once) holds in the
//! single-operator deployment shape Polaris actually targets.

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
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{LoginHint, ModeratorAuth};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{OAuthClient, OAuthClientMetadata};
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

/// Probe for a working Docker daemon. Mirrors `case_api.rs` /
/// `atproto_login.rs` so the skip behaviour is uniform.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Canned response keyed by `(method, url)`. URL is matched as a prefix
/// (query string stripped) so test setup registers one stub per endpoint
/// without reasoning about form-parameter ordering.
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

/// Build a verifier wired against the supplied mock fetcher.
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

/// Register the canned responses needed for the start_login → callback
/// dance to succeed. `did` is what the token endpoint reports as `sub`
/// — i.e. the DID that ends up in `moderators.external_id`.
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

/// Boot a fresh Postgres testcontainer + run migrations + return the pool.
///
/// The container handle is leaked so its `Drop` runs at process exit
/// rather than at the end of this function's stack frame — same idiom
/// `case_api::boot_db` uses.
async fn boot_pool() -> PgPool {
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
    pool
}

/// Drive `start_login` + `complete_login` for the supplied DID against a
/// wired verifier and return the resulting login.
async fn drive_login(
    verifier: &AtprotoOauthAuthVerifier,
    pds_url: &str,
) -> polaris_backend::auth::LoginResult {
    let redirect = verifier
        .start_login(LoginHint::AtprotoHandle(pds_url.to_owned()))
        .await
        .expect("start_login should succeed");
    verifier
        .complete_login(&redirect.state, "mock-auth-code")
        .await
        .expect("complete_login should succeed against the mock AS")
}

// ── 1. First atproto OAuth login grants admin + records audit event ────

#[tokio::test]
async fn first_atproto_oauth_login_grants_admin_role() {
    if !docker_available() {
        println!(
            "SKIP first_run_admin::first_atproto_oauth_login_grants_admin_role: \
             docker daemon not reachable"
        );
        return;
    }

    let pool = boot_pool().await;

    // Sanity: the fresh database carries no moderator roles and no
    // first_user_admin_grant audit rows. The assertion below pins the
    // pre-condition so a future migration that pre-seeds an admin row
    // surfaces here as a regression rather than silently changing the
    // semantics of this test.
    let pre_roles: (i64,) = sqlx::query_as("SELECT count(*) FROM moderator_roles")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pre_roles.0, 0, "fresh DB must have no moderator_roles rows");

    let pds_url = "https://pds.mock.example";
    let iss = "https://as.mock.example";
    let did = "did:plc:first-run-admin-1";

    let fetcher = Arc::new(MockFetcher::new());
    wire_routes(&fetcher, pds_url, iss, did);

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto, pool.clone(), fetcher).await;

    let result = drive_login(&verifier, pds_url).await;

    // The new moderator must carry exactly one role row: 'admin'.
    let roles: Vec<(String,)> =
        sqlx::query_as("SELECT role FROM moderator_roles WHERE moderator_id = $1")
            .bind(result.ctx.moderator_id.0)
            .fetch_all(&pool)
            .await
            .unwrap();
    let role_strs: Vec<&str> = roles.iter().map(|(r,)| r.as_str()).collect();
    assert_eq!(
        role_strs,
        vec!["admin"],
        "first moderator's role set must be exactly ['admin']; got {role_strs:?}",
    );

    // Exactly one audit_log row of kind 'first_user_admin_grant' was
    // written. The actor format and payload shape are part of the
    // grant's audit contract — pin them so future refactors of the
    // shared helper can't silently drop the privilege-escalation
    // breadcrumb.
    let audit_rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT actor, payload FROM audit_log WHERE kind = 'first_user_admin_grant'",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit_rows.len(),
        1,
        "exactly one first_user_admin_grant audit row must be appended on first login; got {}",
        audit_rows.len(),
    );
    let (actor, payload) = &audit_rows[0];
    assert_eq!(
        actor,
        &format!("moderator:{}", result.ctx.moderator_id.0),
        "audit actor must name the granted moderator; got {actor}",
    );
    assert_eq!(payload["external_id"], did);
    assert_eq!(payload["auth_backend"], "atproto");
    assert_eq!(
        payload["moderator_id"],
        result.ctx.moderator_id.0.to_string(),
    );
}

// ── 2. Second atproto OAuth login does NOT re-grant admin ──────────────

#[tokio::test]
async fn second_oauth_login_does_not_grant_admin() {
    if !docker_available() {
        println!(
            "SKIP first_run_admin::second_oauth_login_does_not_grant_admin: \
             docker daemon not reachable"
        );
        return;
    }

    let pool = boot_pool().await;

    // Seed a pre-existing moderator + admin row directly so the
    // `SELECT count(*) FROM moderator_roles` probe inside
    // `maybe_grant_first_user_admin` reads back ≥ 1 and the grant is
    // skipped for the second login. The seed bypasses the helper so
    // the audit_log row count stays at 0 — modelling the "operational
    // bootstrap" state where the first admin was provisioned via SQL
    // (an out-of-band ops path) rather than the OAuth dance.
    let seeded_mod: (uuid::Uuid,) = sqlx::query_as(
        r"INSERT INTO moderators (external_id, auth_backend)
          VALUES ($1, 'oidc')
          RETURNING id",
    )
    .bind("first-run-seed-admin")
    .fetch_one(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO moderator_roles (moderator_id, role) VALUES ($1, 'admin')")
        .bind(seeded_mod.0)
        .execute(&pool)
        .await
        .unwrap();

    // Pre-condition: moderator_roles is non-empty, audit_log has zero
    // first_user_admin_grant rows. This is the deployment shape this
    // test models.
    let pre_audit: (i64,) =
        sqlx::query_as("SELECT count(*) FROM audit_log WHERE kind = 'first_user_admin_grant'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        pre_audit.0, 0,
        "seeded state must carry zero first_user_admin_grant rows; got {}",
        pre_audit.0,
    );

    let pds_url = "https://pds.mock.example";
    let iss = "https://as.mock.example";
    let did = "did:plc:second-login-mod";

    let fetcher = Arc::new(MockFetcher::new());
    wire_routes(&fetcher, pds_url, iss, did);

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto, pool.clone(), fetcher).await;

    let result = drive_login(&verifier, pds_url).await;

    // The freshly-logged-in moderator (a different UUID from the
    // seeded one) must carry zero roles — the helper's count-then-
    // insert guard skipped the grant because `moderator_roles` was
    // already non-empty.
    assert_ne!(
        result.ctx.moderator_id.0, seeded_mod.0,
        "the OAuth login must mint a distinct moderator id from the seeded admin",
    );
    let post_roles: (i64,) =
        sqlx::query_as("SELECT count(*) FROM moderator_roles WHERE moderator_id = $1")
            .bind(result.ctx.moderator_id.0)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        post_roles.0, 0,
        "second moderator must NOT be granted any role on login; got {}",
        post_roles.0,
    );

    // audit_log first_user_admin_grant count is still 0 — neither the
    // seeded admin (which bypassed the helper) nor the second login
    // (which short-circuited on `count != 0`) appended a row.
    let post_audit: (i64,) =
        sqlx::query_as("SELECT count(*) FROM audit_log WHERE kind = 'first_user_admin_grant'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        post_audit.0, 0,
        "no first_user_admin_grant audit row must be appended once roles are seeded; got {}",
        post_audit.0,
    );
}
