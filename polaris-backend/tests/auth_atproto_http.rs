//! Integration tests for the ATProto OAuth HTTP handlers (issue #67).
//!
//! Drives the two routes (`POST /auth/atproto/login`,
//! `GET /auth/atproto/callback`) end-to-end against:
//!
//! 1. A `testcontainers`-driven Postgres 16-alpine so the
//!    `auth_atproto_login_states` / `moderators` / `sessions` rows participate
//!    in real SQL (same fixture pattern as `tests/atproto_login.rs` and
//!    `tests/case_api.rs`).
//! 2. A `proto_blue::common::fetch::FetchHandler` mock that routes URLs to
//!    canned responses for the PDS-protected-resource discovery,
//!    authorization-server metadata, PAR endpoint, and token endpoint.
//!    Using a `FetchHandler` (rather than a `wiremock` HTTP server) lets
//!    the test drive the verifier through `proto-blue-oauth` without
//!    standing up a real HTTPS endpoint — the same trick
//!    `tests/atproto_login.rs` uses.
//! 3. `tower::ServiceExt::oneshot` to drive the assembled Axum router as a
//!    tower service in-process; the cookie-emission contract is asserted
//!    against the response's `Set-Cookie` header rather than a TCP round-
//!    trip.
//!
//! The four scenarios — happy-path login, happy-path callback (with cookie),
//! 400 on empty handle, and the `AuthError::StateMismatch` mapping — are
//! the AC of #67's brief.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::missing_panics_doc,
    clippy::doc_markdown,
    reason = "integration test code is allowed to panic — rust-quality §7 convention"
)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode, header};
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{AnyModeratorAuth, LoginHint, ModeratorAuth};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use polaris_backend::middleware::auth::SESSION_COOKIE;
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{OAuthClient, OAuthClientMetadata};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tower::ServiceExt as _;

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Boot a Postgres testcontainer + migrate + leak the container handle so
/// it survives the boot function's stack frame for the lifetime of the
/// test process. Mirrors the pattern in `tests/case_api.rs` and
/// `tests/atproto_login.rs`.
async fn boot_db() -> Result<(db::Db, sqlx::PgPool), Box<dyn std::error::Error>> {
    let container = Postgres::default().with_tag("16-alpine").start().await?;
    let host_port = container.get_host_port_ipv4(5432).await?;
    let cfg = DbConfig {
        url: format!("postgres://postgres:postgres@127.0.0.1:{host_port}/postgres"),
        max_connections: 4,
        min_connections: 1,
        acquire_timeout_secs: 10,
    };
    let db = db::connect(&cfg).await?;
    let pool = db.pool().clone();
    std::mem::forget(container);
    Ok((db, pool))
}

/// Canned response keyed by `(method, normalised-url)`. The URL is matched
/// after stripping the query string so test setup can register one stub
/// per endpoint without reasoning about the exact ordering proto-blue may
/// emit form parameters in.
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

/// Build an `AtprotoOauthAuthVerifier` wired against the supplied
/// `MockFetcher`. Mirrors `tests/atproto_login.rs::make_verifier`.
fn build_verifier(
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
    let fetch_handle: Arc<dyn FetchHandler> = fetcher;
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
/// dance to succeed. Same wiring as `tests/atproto_login.rs::wire_routes`.
fn wire_routes(fetcher: &MockFetcher, pds_url: &str, iss: &str) {
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
                "sub": "did:plc:moderator-mock-http",
            }))
            .unwrap(),
            content_type: "application/json",
            headers: Vec::new(),
        },
    );
}

/// Test-facing handle to the installed verifier.
///
/// The HTTP handler reaches the verifier through `AnyModeratorAuth`, and
/// the test needs to drive `start_login` directly to obtain a persisted
/// state row whose token can be threaded into the callback URL. The
/// cleanest way to share one verifier between both call sites is to keep
/// it inside the `AnyModeratorAuth` enum and reach into the enum from
/// the test, which mirrors the exact accessor (`as_atproto`) the
/// production handler uses.
struct Fixture {
    router: axum::Router,
    moderator_auth: Arc<AnyModeratorAuth>,
    pool: sqlx::PgPool,
}

impl Fixture {
    fn verifier(&self) -> &AtprotoOauthAuthVerifier {
        self.moderator_auth
            .as_atproto()
            .expect("fixture installs the atproto backend")
    }
}

async fn build_fixture(fetcher: Arc<MockFetcher>) -> Result<Fixture, Box<dyn std::error::Error>> {
    let (db, pool) = boot_db().await?;
    // Deterministic test key — never used outside `#[cfg(test)]`.
    let crypto = Crypto::new([67_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());

    let verifier = build_verifier(sessions.clone(), crypto, pool.clone(), fetcher);
    let moderator_auth = Arc::new(AnyModeratorAuth::Atproto(verifier));

    let state = ApiState::new(pool.clone(), sessions.clone())
        .with_moderator_auth(Arc::clone(&moderator_auth));
    let router = api::router_with_state(db, state);
    Ok(Fixture {
        router,
        moderator_auth,
        pool,
    })
}

/// Read the response body as a `serde_json::Value`. Returns `None` for an
/// empty body (the 303 redirect path).
async fn maybe_json(response: &mut axum::response::Response) -> Option<serde_json::Value> {
    // `to_bytes` consumes the body, so we re-construct the response with
    // an empty body afterwards if the caller still wants to inspect
    // headers. For our purposes the caller has already pulled the
    // headers out before reaching here.
    let body = std::mem::replace(response.body_mut(), Body::empty());
    let bytes = to_bytes(body, 64 * 1024).await.unwrap();
    if bytes.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&bytes).unwrap())
    }
}

// ── 1. POST /auth/atproto/login → 303 with Location header ────────────────

#[tokio::test]
async fn post_login_returns_303_with_location_to_authorize_url()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP auth_atproto_http::post_login_returns_303: docker daemon not reachable");
        return Ok(());
    }

    let pds_url = "https://pds.mock.example";
    let iss = "https://as.mock.example";
    let fetcher = Arc::new(MockFetcher::new());
    wire_routes(&fetcher, pds_url, iss);

    let fixture = build_fixture(fetcher).await?;

    // `proto-blue`'s `resolve_input` accepts an `http(s)://` prefix as a
    // PDS-URL hint, which lets the test bypass DNS handle resolution and
    // exercise the start_login → PAR → authorize-URL path against the
    // mock AS.
    //
    // Body shape: `application/x-www-form-urlencoded` — the browser
    // login page (issue #82) submits a real HTML form rather than a
    // fetch() call so the handler's 303 propagates to the browser's
    // location bar.
    let body = form_urlencoded_body(&[("handle", pds_url)]);
    let request = Request::builder()
        .method("POST")
        .uri("/auth/atproto/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))?;
    let response = fixture.router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "login must return 303 See Other",
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("Location header must be present on 303");
    let location_str = location.to_str().expect("Location must be ASCII");
    assert!(
        location_str.starts_with(&format!("{iss}/oauth/authorize")),
        "Location must point at the AS authorize endpoint; got {location_str}",
    );
    assert!(
        location_str
            .contains("request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Amock-par-123")
            || location_str.contains("request_uri=urn:ietf:params:oauth:request_uri:mock-par-123"),
        "authorize URL must carry the PAR request_uri; got {location_str}",
    );
    Ok(())
}

// ── 2. GET /auth/atproto/callback with valid state+code → 303 + cookie ────

#[tokio::test]
async fn get_callback_sets_session_cookie_and_redirects_to_root()
-> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP auth_atproto_http::get_callback_sets_session_cookie: docker daemon not reachable",
        );
        return Ok(());
    }

    let pds_url = "https://pds.mock.example";
    let iss = "https://as.mock.example";
    let fetcher = Arc::new(MockFetcher::new());
    wire_routes(&fetcher, pds_url, iss);

    let fixture = build_fixture(fetcher).await?;

    // Drive start_login directly through the verifier so the test has
    // the persisted `state` token. The HTTP handler in `auth_atproto::login`
    // would do the same call internally, but the test needs the state
    // token in hand to assemble the callback URL.
    let redirect = fixture
        .verifier()
        .start_login(LoginHint::AtprotoHandle(pds_url.to_owned()))
        .await
        .expect("start_login should succeed against the mock AS");

    let request = Request::builder()
        .method("GET")
        .uri(format!(
            "/auth/atproto/callback?state={}&code=mock-auth-code",
            urlencoding_encode(&redirect.state),
        ))
        .body(Body::empty())?;
    let response = fixture.router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "callback must return 303 See Other on success",
    );
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("Location header must be present");
    assert_eq!(
        location.to_str().unwrap(),
        "/",
        "callback must redirect to /",
    );

    let set_cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header must be present");
    let cookie_str = set_cookie.to_str().expect("Set-Cookie must be ASCII");
    assert!(
        cookie_str.starts_with(&format!("{SESSION_COOKIE}=")),
        "Set-Cookie must carry the polaris_session cookie; got {cookie_str}",
    );
    assert!(
        cookie_str.contains("HttpOnly"),
        "session cookie must be HttpOnly; got {cookie_str}",
    );
    assert!(
        cookie_str.contains("Secure"),
        "session cookie must be Secure; got {cookie_str}",
    );
    assert!(
        cookie_str.contains("SameSite=Lax"),
        "session cookie must be SameSite=Lax; got {cookie_str}",
    );
    assert!(
        cookie_str.contains("Path=/"),
        "session cookie must be Path=/; got {cookie_str}",
    );
    assert!(
        cookie_str.contains("Max-Age="),
        "session cookie must carry Max-Age; got {cookie_str}",
    );

    // The session row must exist with the cookie value as its id.
    let cookie_value = cookie_str
        .split(';')
        .next()
        .unwrap()
        .trim()
        .strip_prefix(&format!("{SESSION_COOKIE}="))
        .unwrap();
    let session_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions WHERE id = $1")
        .bind(cookie_value)
        .fetch_one(&fixture.pool)
        .await?;
    assert_eq!(
        session_count.0, 1,
        "session row must be persisted at the cookie value",
    );
    Ok(())
}

// ── 3. POST /auth/atproto/login with empty handle → 400 ───────────────────

#[tokio::test]
async fn post_login_with_empty_handle_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP auth_atproto_http::post_login_empty_handle: docker daemon not reachable");
        return Ok(());
    }

    let fetcher = Arc::new(MockFetcher::new());
    let fixture = build_fixture(fetcher).await?;

    let body = form_urlencoded_body(&[("handle", "")]);
    let request = Request::builder()
        .method("POST")
        .uri("/auth/atproto/login")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))?;
    let mut response = fixture.router.oneshot(request).await?;

    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "empty handle must surface as 400 Bad Request",
    );
    let body = maybe_json(&mut response)
        .await
        .expect("400 body should be JSON");
    assert_eq!(body["code"], "bad_request");
    Ok(())
}

// ── 4. GET /auth/atproto/callback with wrong state → 400 ──────────────────

#[tokio::test]
async fn get_callback_with_wrong_state_returns_400() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!("SKIP auth_atproto_http::get_callback_wrong_state: docker daemon not reachable",);
        return Ok(());
    }

    let fetcher = Arc::new(MockFetcher::new());
    let fixture = build_fixture(fetcher).await?;

    let request = Request::builder()
        .method("GET")
        .uri("/auth/atproto/callback?state=definitely-not-a-real-state&code=whatever")
        .body(Body::empty())?;
    let mut response = fixture.router.oneshot(request).await?;

    // The verifier surfaces `AuthError::StateMismatch` for an unknown
    // state token; the handler maps that to `ApiError::BadRequest`.
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "unknown state must surface as 400 Bad Request",
    );
    let body = maybe_json(&mut response)
        .await
        .expect("400 body should be JSON");
    assert_eq!(body["code"], "bad_request");
    Ok(())
}

/// Build an `application/x-www-form-urlencoded` body from a list of
/// `(name, value)` pairs.
///
/// Mirrors the `&`-joined `key=value` shape a browser produces from an
/// HTML form (the encoding rules the
/// [WHATWG URL form-encoding standard][1] specifies). We deliberately
/// avoid pulling `serde_urlencoded` or `form_urlencoded` into the
/// dev-dep set for the one call site the tests use.
///
/// [1]: https://url.spec.whatwg.org/#application/x-www-form-urlencoded
fn form_urlencoded_body(pairs: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (i, (name, value)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&urlencoding_encode(name));
        out.push('=');
        out.push_str(&urlencoding_encode(value));
    }
    out
}

/// Minimal URL-encoder for the small character set the state tokens use
/// (the verifier emits base64url, which is already URL-safe — but the
/// callback URL embedding pattern stays robust if proto-blue ever shifts
/// to a different alphabet). We deliberately avoid pulling `urlencoding`
/// or `percent-encoding` into the dev-dep set just for this single call
/// site.
fn urlencoding_encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            let mut buf = [0_u8; 4];
            for &byte in c.encode_utf8(&mut buf).as_bytes() {
                // Writing to a String is infallible; the `unwrap` is the
                // standard idiom for `fmt::Write` to `String` in test code.
                write!(out, "%{byte:02X}").unwrap();
            }
        }
    }
    out
}
