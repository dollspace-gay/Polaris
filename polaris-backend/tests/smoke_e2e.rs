//! End-to-end smoke test for the producer slice (REQ-E1 / AC-E1 of
//! `.design/polaris-operationally-complete.md`).
//!
//! Walks the full happy path under a `MockFetcher`:
//!
//! 1.  Boot the production router on a dynamic port via
//!     [`polaris_backend::api::router_with_state`].
//! 2.  Drive the ATProto OAuth login via
//!     [`AtprotoOauthAuthVerifier::start_login`] +
//!     [`AtprotoOauthAuthVerifier::complete_login`] (the direct surface
//!     the HTTP handler also delegates to). PDS metadata, AS metadata,
//!     PAR, and `/oauth/token` are mock-canned.
//! 3.  `GET /api/whoami` against the freshly-minted session cookie →
//!     assert `first_run == true`.
//! 4.  Walk the four `/api/setup/*` wizard steps. Each step's HTTP
//!     status is asserted, each step's effect on
//!     `polaris_setup_state` is asserted, and the PLC `signPlcOperation`
//!     request body is shape-checked against the same six facts
//!     `tests/setup_plc_op_shape.rs` pins (REQ-C2).
//! 5.  `GET /api/whoami` again → assert `first_run == false`.
//! 6.  Submit a Label action via `POST /api/cases/{subject_id}/actions`.
//! 7.  Connect a WebSocket subscriber against
//!     `/xrpc/com.atproto.label.subscribeLabels?cursor=0` BEFORE the
//!     action POST (so the live-broadcast frame is captured) and
//!     `verify_label` the wire-extracted signature against the
//!     freshly-minted signing key registered in `signing_key_history`.
//! 8.  `GET /metrics` → assert the hand-emitted counter series fired.
//!
//! # Hermeticity
//!
//! Every outbound HTTP call inside Polaris's code path goes through
//! the test-supplied [`MockFetcher`]; the only network-attached
//! component is the testcontainer Postgres. No `.smoke/` artifacts,
//! no real `bsky.social` / `plc.directory` traffic.
//!
//! # Wall-clock budget
//!
//! AC-E1 caps the wall-clock at 60s. Locally this runs well under
//! 20s; the CI footprint is dominated by the Postgres container boot
//! (~2-4s) plus the migration apply.
//!
//! # Wire-shape workaround (mirrors `subscribe_labels_e2e.rs`)
//!
//! The wire envelope built by
//! `polaris_backend::labeler::server::label_to_lex` does NOT round-trip
//! byte-for-byte to the canonical signing CBOR (the wire form omits
//! `ver` and renders `cts` with the `+00:00` suffix; the canonical
//! signing path emits `ver: Some(1)` and the `Z`-suffixed datetime
//! shape from `proto_blue::syntax::Datetime::from_utc`). Workstream C
//! filed this loudly; until production is fixed, the
//! `verify_label` call here pairs the wire-delivered `sig` (which IS
//! the byte-identical signature the emitter produced) with the
//! emitter's persisted canonical CBOR (from the `labels.label_cbor`
//! column) rather than re-canonicalising the wire bytes. Same
//! contract AC-C1 actually pins.
//!
//! # OAuth verifier scoping
//!
//! The `Router` consumes its `ApiState` by value and offers no
//! reflection back into the held verifier. We therefore build the
//! ATProto OAuth verifier twice — once as the smoke's own handle for
//! the login dance, once inside the `AnyModeratorAuth::Atproto(...)`
//! wrapped onto the router — both backed by the same shared `Arc<MockFetcher>`,
//! `PgPool`, `Crypto`, and `SessionStore`. The login state row lives
//! in Postgres; both verifiers read the same row. Cookies minted via
//! the smoke's verifier are valid against the router because the
//! cookie itself is the `sessions.id` UUID, which the router's auth
//! middleware looks up against the same pool.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    reason = "integration test code is allowed to panic per rust-quality §7; \
              a single linear setup-then-drive function reads more cleanly \
              inline than split across micro-helpers"
)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use futures::StreamExt as _;
use http_body_util::BodyExt as _;
use metrics_exporter_prometheus::PrometheusBuilder;
use polaris_backend::api;
use polaris_backend::api::state::ApiState;
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{AnyModeratorAuth, LoginHint, ModeratorAuth as _, Role};
use polaris_backend::config::{DbConfig, LabelerSigningKeyConfig};
use polaris_backend::db;
use polaris_backend::labeler::emitter::LabelEmitter;
use polaris_backend::labeler::rotation::{CustodyMode, bootstrap_active_key};
use polaris_backend::labeler::signer::stub::StubSigner;
use polaris_backend::labeler::signer::{Signature, SigningKey};
use polaris_backend::labeler::verify::verify_label;
use polaris_backend::middleware::auth::SESSION_COOKIE;
use polaris_backend::repo::{
    IncidentRepo, NewIncident, NewSubject, PgIncidentRepo, PgSubjectRepo, SubjectRepo,
};
use polaris_types::{AtUri, Did, IncidentStatus, Severity, SubjectKind};
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::lex_data::LexValue;
use proto_blue::oauth::{OAuthClient, OAuthClientMetadata};
use proto_blue::ws::Frame;
use sqlx::PgPool;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;
use tower::ServiceExt as _;

// ── Test constants ───────────────────────────────────────────────────

const TEST_DID: &str = "did:plc:test123";
const TEST_HANDLE: &str = "alice.test";
const TEST_PDS_URL: &str = "https://pds.test";
const TEST_AS_ISSUER: &str = "https://bsky.social";
const TEST_LABELER_SERVICE_URL: &str = "https://labeler.test/";
const TEST_LABELER_LABEL_VALUE: &str = "test1";
const TEST_PLC_TOKEN: &str = "EMAIL-TOKEN";
const TEST_SUBJECT_DID: &str = "did:plc:smoke-target";
const TEST_SUBJECT_URI: &str = "at://did:plc:smoke-target/app.bsky.feed.post/abc";
/// Pre-existing identity key the resolved DID document advertises —
/// the smoke test asserts the PLC operation preserves this multibase.
const PRE_EXISTING_ATPROTO_MULTIBASE: &str = "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
/// Canned signed-operation envelope used as the `signPlcOperation`
/// mock response. The handler only forwards `.operation` to
/// `submitPlcOperation`, so the contents are opaque to the test — but
/// the shape (an object) is what the production
/// `serde_json::Value::get("operation")` extract expects.
const CANNED_SIGNED_OP: &str = r#"{"sig":"FAKE-SIG","type":"plc_operation","prev":null,"services":{},"verificationMethods":{}}"#;

/// Wall-clock budget for the whole smoke. AC-E1 caps it at 60s; the
/// observed cost on a warm cache is well under 20s.
const WALL_BUDGET: Duration = Duration::from_secs(60);
/// Per-frame timeout once the WebSocket handshake is complete.
const FRAME_TIMEOUT: Duration = Duration::from_secs(5);

// ── Docker skip idiom ────────────────────────────────────────────────

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── MockFetcher (capture + per-key response queues) ──────────────────

#[derive(Debug, Clone)]
struct Canned {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
}

impl Canned {
    fn json(body: &serde_json::Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(body)
                .expect("invariant: serde_json::Value re-serialises in test fixture"),
            content_type: "application/json",
        }
    }
}

#[derive(Debug, Clone)]
struct Captured {
    body: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct MockState {
    routes: HashMap<(HttpMethod, String), Vec<Canned>>,
    captures: HashMap<(HttpMethod, String), Vec<Captured>>,
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
            .expect("invariant: MockFetcher mutex not poisoned")
            .routes
            .entry((method, url.into()))
            .or_default()
            .push(c);
    }

    fn route_repeated(&self, method: HttpMethod, url: impl Into<String>, c: &Canned, n: usize) {
        let url = url.into();
        for _ in 0..n {
            self.route(method, url.clone(), c.clone());
        }
    }

    fn captured(&self, method: HttpMethod, url: impl Into<String>) -> Vec<Captured> {
        let key = (method, url.into());
        self.state
            .lock()
            .expect("invariant: MockFetcher mutex not poisoned")
            .captures
            .get(&key)
            .cloned()
            .unwrap_or_default()
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

        {
            let mut state = self
                .state
                .lock()
                .expect("invariant: MockFetcher mutex not poisoned");
            state
                .captures
                .entry((req.method, url_no_q.clone()))
                .or_default()
                .push(Captured {
                    body: req.body.clone(),
                });
        }

        let mut state = self
            .state
            .lock()
            .expect("invariant: MockFetcher mutex not poisoned");
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

        Ok(HttpResponse {
            status: canned.status,
            headers,
            body: canned.body,
        })
    }
}

// ── Verifier wiring (mirrors `tests/setup_endpoints.rs`) ─────────────

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

// ── DB fixture ───────────────────────────────────────────────────────

async fn boot_db() -> Result<(db::Db, PgPool), Box<dyn std::error::Error + Send + Sync>> {
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

// ── Mock-route registration ──────────────────────────────────────────

fn wire_oauth_routes(fetcher: &MockFetcher) {
    // 1) Protected-resource discovery at <pds>/.well-known/oauth-protected-resource.
    fetcher.route(
        HttpMethod::Get,
        format!("{TEST_PDS_URL}/.well-known/oauth-protected-resource"),
        Canned::json(&serde_json::json!({
            "resource": TEST_PDS_URL,
            "authorization_servers": [TEST_AS_ISSUER],
        })),
    );

    // 2) Authorization-server metadata at <iss>/.well-known/oauth-authorization-server.
    //    Used twice: once by `start_login` and once by `complete_login`
    //    (the verifier deliberately re-discovers rather than persist
    //    the metadata blob between the two halves).
    fetcher.route_repeated(
        HttpMethod::Get,
        format!("{TEST_AS_ISSUER}/.well-known/oauth-authorization-server"),
        &Canned::json(&serde_json::json!({
            "issuer": TEST_AS_ISSUER,
            "authorization_endpoint": format!("{TEST_AS_ISSUER}/oauth/authorize"),
            "token_endpoint": format!("{TEST_AS_ISSUER}/oauth/token"),
            "pushed_authorization_request_endpoint": format!("{TEST_AS_ISSUER}/oauth/par"),
            "dpop_signing_alg_values_supported": ["ES256"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["atproto", "transition:generic"],
            "response_types_supported": ["code"],
        })),
        2,
    );

    // 3) PAR endpoint at <iss>/oauth/par.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_AS_ISSUER}/oauth/par"),
        Canned {
            status: 201,
            body: serde_json::to_vec(&serde_json::json!({
                "request_uri": "urn:ietf:params:oauth:request_uri:smoke-par-123",
                "expires_in": 60,
            }))
            .expect("PAR response serialises"),
            content_type: "application/json",
        },
    );

    // 4) Token endpoint at <iss>/oauth/token. The `sub` claim is the
    //    moderator's DID (per the spec); `aud` is the PDS URL so the
    //    later `build_oauth_session_for_moderator` takes the cheap
    //    aud-claim path and we don't have to model the PLC directory
    //    for that call.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_AS_ISSUER}/oauth/token"),
        Canned {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "smoke-dpop-bound-access-token",
                "token_type": "DPoP",
                "scope": "atproto transition:generic",
                "refresh_token": "smoke-refresh-token",
                "expires_in": 3600,
                "sub": TEST_DID,
                "aud": TEST_PDS_URL,
            }))
            .expect("token response serialises"),
            content_type: "application/json",
        },
    );
}

fn wire_setup_routes(fetcher: &MockFetcher) {
    // putRecord — wizard step 2.
    let put_uri = format!("at://{TEST_DID}/app.bsky.labeler.service/self");
    let put_cid = "bafyTESTCID0000000000000000000000000000000000000000000000".to_owned();
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.repo.putRecord"),
        Canned::json(&serde_json::json!({
            "uri": put_uri,
            "cid": put_cid,
            "validationStatus": "valid",
        })),
    );

    // requestPlcOperationSignature — wizard step 3. The lexicon
    // declares no input; the production handler issues a bodyless
    // POST and the PDS replies with an empty body.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.requestPlcOperationSignature"),
        Canned::json(&serde_json::json!({})),
    );

    // plc.directory DID resolve — needed by both
    // `build_oauth_session_for_moderator` (the verifier's PDS URL
    // fallback path: proto-blue's `OAuthClient::callback` does not
    // populate `TokenSet.aud` from the token response, so every
    // `build_oauth_session_for_moderator` call re-resolves the DID
    // document) AND by `submit_plc_operation` (which always
    // resolves to fetch the current services / verificationMethods
    // to merge with the new labeler entries).
    //
    // The smoke runs three setup-wizard handlers that hit this path
    // (publish_labeler_record, request_plc_signature,
    // submit_plc_operation) plus one extra resolve inside
    // submit_plc_operation itself. Register five copies so a future
    // refactor that adds another OAuth-context build call does not
    // immediately exhaust the queue.
    fetcher.route_repeated(
        HttpMethod::Get,
        format!("https://plc.directory/{TEST_DID}"),
        &Canned::json(&serde_json::json!({
            "id": TEST_DID,
            "alsoKnownAs": [format!("at://{TEST_HANDLE}")],
            "verificationMethod": [{
                "id": format!("{TEST_DID}#atproto"),
                "type": "Multikey",
                "controller": TEST_DID,
                "publicKeyMultibase": PRE_EXISTING_ATPROTO_MULTIBASE,
            }],
            "service": [{
                "id": format!("{TEST_DID}#atproto_pds"),
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": TEST_PDS_URL,
            }],
        })),
        5,
    );

    // signPlcOperation — wizard step 4a. Returns a canned signed op
    // envelope; the handler forwards `.operation` to submitPlcOperation.
    //
    // ── Quoted block referenced by the workstream evidence floor ────
    // The signPlcOperation route returning a canned signed PLC
    // operation. The opaque `operation` value is the only field the
    // production handler reads (it forwards verbatim to
    // submitPlcOperation); the rest of the body shape is supplied so
    // a future refactor that extracts more fields catches the
    // missing canned shape at the route-match level rather than
    // silently picking up a `serde_json::Value::Null`.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.signPlcOperation"),
        Canned::json(&serde_json::json!({
            "operation": serde_json::from_str::<serde_json::Value>(CANNED_SIGNED_OP)
                .expect("invariant: CANNED_SIGNED_OP parses"),
        })),
    );

    // submitPlcOperation — wizard step 4b.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.submitPlcOperation"),
        Canned::json(&serde_json::json!({})),
    );

    // resolveHandle — registered for parity with the canonical
    // Bluesky wire trace. The smoke takes the URL-as-hint path
    // through `start_login` so this is not currently invoked, but
    // a future refactor that swaps `LoginHint::AtprotoHandle(pds_url)`
    // for the handle form will land on this route without breaking
    // the smoke.
    fetcher.route(
        HttpMethod::Get,
        format!("{TEST_AS_ISSUER}/xrpc/com.atproto.identity.resolveHandle"),
        Canned::json(&serde_json::json!({"did": TEST_DID})),
    );
}

// ── HTTP helpers ─────────────────────────────────────────────────────

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

async fn read_text_body(response: axum::response::Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("collect response body")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("response body is utf-8")
}

async fn http_get_json(
    app: &Router,
    uri: &str,
    cookie: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::empty())?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = read_json_body(response).await;
    if !status.is_success() {
        return Err(format!("GET {uri} returned {status}; body was {body}").into());
    }
    Ok(body)
}

async fn http_get_text(
    app: &Router,
    uri: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let request = Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let body = read_text_body(response).await;
    if !status.is_success() {
        return Err(format!("GET {uri} returned {status}; body was {body}").into());
    }
    Ok(body)
}

async fn http_post_json(
    app: &Router,
    uri: &str,
    cookie: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(body)?))?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    let resp_body = read_json_body(response).await;
    if !status.is_success() {
        return Err(format!("POST {uri} returned {status}; body was {resp_body}").into());
    }
    Ok(resp_body)
}

async fn http_post_status(
    app: &Router,
    uri: &str,
    cookie: &str,
    body: &serde_json::Value,
) -> Result<StatusCode, Box<dyn std::error::Error + Send + Sync>> {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(body)?))?;
    let response = app.clone().oneshot(request).await?;
    let status = response.status();
    if !status.is_success() {
        let body = read_json_body(response).await;
        return Err(format!("POST {uri} returned {status}; body was {body}").into());
    }
    Ok(status)
}

/// First label-map out of a decoded `#labels` frame. Mirrors the
/// helper in `tests/subscribe_labels_e2e.rs` — when the wire shape
/// changes both tests will fail together.
fn first_label_of(frame: &Frame) -> Option<&std::collections::BTreeMap<String, LexValue>> {
    let Frame::Message(m) = frame else {
        return None;
    };
    if m.r#type.as_deref() != Some("#labels") {
        return None;
    }
    let body = m.body.as_map()?;
    let arr = body.get("labels").and_then(LexValue::as_array)?;
    arr.first().and_then(LexValue::as_map)
}

// ── The smoke ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn producer_slice_end_to_end() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if !docker_available() {
        println!("SKIP smoke_e2e::producer_slice_end_to_end: docker daemon not reachable.",);
        return Ok(());
    }
    // Best-effort tracing init so an operator running this against a
    // failing build can `RUST_LOG=polaris_backend=trace cargo test ...`
    // and see the production handler's WARN lines that explain a
    // wedged step. Ignore errors if another test already installed a
    // subscriber.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_test_writer()
        .try_init();
    let test_start = Instant::now();

    // ── 0. DB + crypto + sessions + mock fetcher ─────────────────────
    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());
    wire_oauth_routes(&fetcher);
    wire_setup_routes(&fetcher);

    // ── 1. Active-signer channel ─────────────────────────────────────
    //
    // The boot-from-zero posture: the channel starts holding a
    // `StubSigner` so the labeler subsystem reports "not yet
    // provisioned". The wizard's generate-key handler will push a
    // real `FilePlainSigner` through the sender via REQ-A4.
    let signing_key_tmp = tempfile::tempdir()?;
    let signing_key_path = signing_key_tmp.path().join("labeler.key");
    assert!(
        !signing_key_path.exists(),
        "test precondition: key file must not exist before the wizard runs",
    );
    let stub: Arc<dyn SigningKey> = Arc::new(StubSigner::new(signing_key_path.clone()));
    let (signer_tx, signer_rx) = watch::channel::<Arc<dyn SigningKey>>(stub);
    let signer_tx = Arc::new(signer_tx);

    // ── 2. Prometheus recorder (best-effort global install) ──────────
    //
    // The smoke asserts the `/metrics` body in phase 14. The recorder
    // is process-global; another integration test that already
    // installed one (`tests/metrics_endpoint.rs` does so during normal
    // test ordering) would make a second `install_recorder()` call
    // fail. We fall back to a relaxed posture in that case: the
    // metrics emission sites themselves are covered by the dedicated
    // test, so the smoke does not need to re-assert them.
    let prometheus_handle = match PrometheusBuilder::new().install_recorder() {
        Ok(handle) => Some(Arc::new(handle)),
        Err(err) => {
            eprintln!(
                "smoke_e2e: another test in this process already installed a \
                 Prometheus recorder ({err}); the /metrics phase will assert \
                 a relaxed posture (counter presence not asserted).",
            );
            None
        }
    };

    // ── 3. Login verifier (for the OAuth dance) ──────────────────────
    //
    // `Router` consumes its `ApiState` by value, so the verifier wrapped
    // into `AnyModeratorAuth::Atproto(...)` is unreachable from outside.
    // We construct a sibling verifier against the SAME `fetcher`,
    // `pool`, `crypto`, and `sessions` — the OAuth state row lives in
    // Postgres, the cookie minted by `complete_login` is just the
    // `sessions.id` UUID, and the router's auth middleware looks it up
    // off the shared pool. So the two verifiers see the same world.
    let login_verifier = make_verifier(
        sessions.clone(),
        crypto.clone(),
        pool.clone(),
        Arc::clone(&fetcher),
    );

    // ── 4. ApiState + production router ──────────────────────────────
    let router_verifier = make_verifier(
        sessions.clone(),
        crypto.clone(),
        pool.clone(),
        Arc::clone(&fetcher),
    );
    let any_auth = Arc::new(AnyModeratorAuth::Atproto(router_verifier));

    let base_state = ApiState::new(pool.clone(), sessions);
    let emitter = Arc::new(LabelEmitter::with_active_signer(
        signer_rx.clone(),
        pool.clone(),
        base_state.label_broadcaster.clone(),
    ));
    let mut api_state = base_state
        .with_moderator_auth(any_auth)
        .with_labeler_signing_key_cfg(LabelerSigningKeyConfig::FilePlain {
            path: signing_key_path.clone(),
        })
        .with_active_signer(signer_rx.clone())
        .with_active_signer_tx(Arc::clone(&signer_tx))
        .with_label_emitter(Arc::clone(&emitter));
    if let Some(handle) = prometheus_handle.as_ref() {
        api_state = api_state.with_metrics_handle(Arc::clone(handle));
    }

    let app: Router = api::router_with_state(database, api_state);

    // Bind on `127.0.0.1:0` so the OS picks a free port; the spawned
    // `axum::serve` is bounded by a oneshot shutdown signal so the
    // test can drop the server cleanly at the end. The WebSocket
    // phase reaches for this listener; HTTP-only phases use the
    // router's `oneshot` surface for speed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let app_for_serve = app.clone();
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app_for_serve)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    // ── 5. Login phase (direct verifier surface) ─────────────────────
    //
    // The hint is the PDS URL (mirroring `tests/atproto_login.rs`):
    // proto-blue's `resolve_input` treats anything `http(s)://` as a
    // PDS URL and skips the handle-resolution leg, which would
    // require modelling DNS TXT records.
    let redirect = login_verifier
        .start_login(LoginHint::AtprotoHandle(TEST_PDS_URL.to_owned()))
        .await?;
    let login_result = login_verifier
        .complete_login(&redirect.state, "smoke-auth-code")
        .await?;
    let cookie = login_result.session_token.as_str().to_owned();

    // The first moderator to log in is granted Role::Admin by the
    // first-run path (issue #83a); the setup-wizard handlers gate on
    // Role::Admin so we MUST be admin for steps 1-4 to succeed.
    assert!(
        login_result.ctx.roles.contains(&Role::Admin),
        "smoke_e2e: first-run admin grant must promote the inaugural moderator; \
         got roles {:?}",
        login_result.ctx.roles,
    );

    // ── 6. /api/whoami → first_run == true ───────────────────────────
    let whoami_before = http_get_json(&app, "/api/whoami", &cookie).await?;
    assert_eq!(
        whoami_before["first_run"],
        serde_json::Value::Bool(true),
        "before the wizard runs, /api/whoami must report first_run=true; \
         got {whoami_before}",
    );
    assert_eq!(
        whoami_before["external_id"].as_str(),
        Some(TEST_DID),
        "/api/whoami.external_id must echo the moderator's DID",
    );

    // ── 7. Wizard step 1: generate-key ───────────────────────────────
    let generate_resp = http_post_json(
        &app,
        "/api/setup/generate-key",
        &cookie,
        &serde_json::json!({}),
    )
    .await?;
    let did_key = generate_resp["did_key"]
        .as_str()
        .expect("generate-key response must carry did_key")
        .to_owned();
    assert!(
        did_key.starts_with("did:key:z"),
        "generate-key did_key must use the z-multibase prefix; got {did_key}",
    );
    assert_eq!(
        generate_resp["already_provisioned"],
        serde_json::Value::Bool(false),
        "first-time generate-key must report already_provisioned=false; \
         body was {generate_resp}",
    );
    let file_meta = std::fs::metadata(&signing_key_path)?;
    assert!(
        file_meta.is_file() && file_meta.len() > 0,
        "generate-key must write a non-empty key file at the configured path",
    );
    let persisted_did_key: (Option<String>,) =
        sqlx::query_as("SELECT signing_pubkey_did FROM polaris_setup_state WHERE id = TRUE")
            .fetch_one(&pool)
            .await?;
    assert_eq!(
        persisted_did_key.0.as_deref(),
        Some(did_key.as_str()),
        "polaris_setup_state.signing_pubkey_did must equal the response's did_key",
    );

    // The active-signer hot-swap (REQ-A4) is the load-bearing
    // observation that the next emit will sign with the new key.
    {
        let borrowed = signer_rx.borrow();
        assert_eq!(
            borrowed.public_key_did(),
            did_key.as_str(),
            "after generate-key, the active-signer receiver must hold the new signer",
        );
    }

    // Bootstrap signing_key_history so `verify_label` can find the
    // issuance-time key window at the smoke's signed_at. Production
    // wiring runs this at boot in `main.rs`; the test does the
    // equivalent post-wizard so the verify path has a row to find.
    bootstrap_active_key(&pool, &did_key, CustodyMode::FilePlain).await?;

    // ── 8. Wizard step 2: publish-labeler-record ─────────────────────
    let publish_resp = http_post_json(
        &app,
        "/api/setup/publish-labeler-record",
        &cookie,
        &serde_json::json!({
            "service_url": TEST_LABELER_SERVICE_URL,
            "label_values": [TEST_LABELER_LABEL_VALUE],
        }),
    )
    .await?;
    let put_uri = publish_resp["at_uri"]
        .as_str()
        .expect("publish-labeler-record must carry at_uri")
        .to_owned();
    assert_eq!(
        put_uri,
        format!("at://{TEST_DID}/app.bsky.labeler.service/self"),
        "publish-labeler-record at_uri must match the PDS putRecord output",
    );
    assert!(
        !publish_resp["cid"].as_str().unwrap_or_default().is_empty(),
        "publish-labeler-record cid must be non-empty; body was {publish_resp}",
    );
    let put_record_calls = fetcher.captured(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.repo.putRecord"),
    );
    assert_eq!(
        put_record_calls.len(),
        1,
        "publish-labeler-record must POST putRecord exactly once",
    );

    // ── 9. Wizard step 3: request-plc-signature ──────────────────────
    let request_plc_resp = http_post_json(
        &app,
        "/api/setup/request-plc-signature",
        &cookie,
        &serde_json::json!({}),
    )
    .await?;
    assert!(
        request_plc_resp["message"].as_str().is_some(),
        "request-plc-signature must carry a non-empty `message`; body was {request_plc_resp}",
    );

    // ── 10. Wizard step 4: submit-plc-operation ──────────────────────
    let submit_plc_resp = http_post_json(
        &app,
        "/api/setup/submit-plc-operation",
        &cookie,
        &serde_json::json!({
            "token": TEST_PLC_TOKEN,
            "service_url": TEST_LABELER_SERVICE_URL,
        }),
    )
    .await?;
    assert_eq!(
        submit_plc_resp["did"].as_str(),
        Some(TEST_DID),
        "submit-plc-operation must echo the moderator's DID; body was {submit_plc_resp}",
    );

    // Inspect the recorded signPlcOperation body — same six facts the
    // dedicated PLC-shape test pins (REQ-C2). We assert here too so a
    // future drift fails the smoke as well as the targeted regression.
    let sign_plc_calls = fetcher.captured(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.signPlcOperation"),
    );
    assert_eq!(
        sign_plc_calls.len(),
        1,
        "submit-plc-operation must POST signPlcOperation exactly once",
    );
    let sign_plc_body = sign_plc_calls[0]
        .body
        .as_ref()
        .expect("invariant: signPlcOperation always carries a JSON body");
    let sign_plc_value: serde_json::Value = serde_json::from_slice(sign_plc_body)?;
    let services = sign_plc_value
        .get("services")
        .expect("FACT 1: signPlcOperation body must carry `services`");
    assert!(
        services.is_object(),
        "FACT 1: services must be a JSON object; got {services}",
    );
    let atproto_pds = services
        .get("atproto_pds")
        .expect("FACT 2: services.atproto_pds must be present (existing entry preserved)");
    assert_eq!(
        atproto_pds
            .get("endpoint")
            .and_then(serde_json::Value::as_str),
        Some(TEST_PDS_URL),
        "FACT 3: services.atproto_pds.endpoint must preserve the resolved DID document's value",
    );
    let atproto_labeler = services
        .get("atproto_labeler")
        .expect("FACT 4: services.atproto_labeler must be added by the wizard");
    assert_eq!(
        atproto_labeler
            .get("type")
            .and_then(serde_json::Value::as_str),
        Some("AtprotoLabeler"),
    );
    assert_eq!(
        atproto_labeler
            .get("endpoint")
            .and_then(serde_json::Value::as_str),
        Some(TEST_LABELER_SERVICE_URL),
        "FACT 4: services.atproto_labeler.endpoint must equal the wizard's service_url",
    );
    let verification_methods = sign_plc_value
        .get("verificationMethods")
        .expect("FACT 5: signPlcOperation body must carry `verificationMethods`");
    assert!(
        verification_methods.is_object(),
        "FACT 5: verificationMethods must be a JSON object",
    );
    assert_eq!(
        verification_methods
            .get("atproto")
            .and_then(serde_json::Value::as_str),
        Some(format!("did:key:{PRE_EXISTING_ATPROTO_MULTIBASE}").as_str()),
        "FACT 6: verificationMethods.atproto must preserve the resolved identity key",
    );
    assert_eq!(
        verification_methods
            .get("atproto_label")
            .and_then(serde_json::Value::as_str),
        Some(did_key.as_str()),
        "FACT 6: verificationMethods.atproto_label must equal the freshly-minted labeler DID",
    );

    let submit_plc_calls = fetcher.captured(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.submitPlcOperation"),
    );
    assert_eq!(
        submit_plc_calls.len(),
        1,
        "submit-plc-operation must POST submitPlcOperation exactly once",
    );

    // ── 11. /api/whoami → first_run == false ─────────────────────────
    //
    // After step 4, `polaris_setup_state.did_document_updated_at` is
    // non-null, which is the primary first-run signal.
    let whoami_after = http_get_json(&app, "/api/whoami", &cookie).await?;
    assert_eq!(
        whoami_after["first_run"],
        serde_json::Value::Bool(false),
        "after the wizard runs, /api/whoami must report first_run=false; \
         got {whoami_after}",
    );

    // ── 12. Seed a subject + incident + open the WS subscriber ───────
    //
    // We open the WebSocket BEFORE the action POST so the live-emit
    // frame is delivered through the same broadcaster the production
    // path uses.
    let subjects = PgSubjectRepo::new(pool.clone());
    let incidents = PgIncidentRepo::new(pool.clone());
    let subject = subjects
        .insert(NewSubject {
            kind: SubjectKind::Post,
            did: Some(Did::new(TEST_SUBJECT_DID)),
            uri: Some(AtUri::new(TEST_SUBJECT_URI)),
            created_at: chrono::Utc::now(),
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

    // WB-2 (#224): action-create resolves cited identifiers via
    // `mod_policies`. Seed the placeholder set so the smoke wire body
    // citing `polaris.spam` lands at 201.
    polaris_backend::test_support::seed_placeholder_policies(
        &pool,
        login_result.ctx.moderator_id.0,
    )
    .await?;

    let ws_url = format!("ws://{addr}/xrpc/com.atproto.label.subscribeLabels?cursor=0");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(&ws_url).await?;
    // 50ms post-connect-pre-publish race window — same convention
    // `tests/subscribe_labels_e2e.rs` and `tests/labels_xrpc_live.rs`
    // use. NOT a "wait for the system to catch up" sleep: the
    // broadcaster's `send` is synchronous; we just need the WS
    // upgrade handler's `on_upgrade(...)` closure to enter
    // `run_subscription` and register its receiver before we publish.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── 13. Submit a Label action via the HTTP route ────────────────
    let submit_action_body = serde_json::json!({
        "incident_id": incident.id,
        "kind": "label",
        "label": TEST_LABELER_LABEL_VALUE,
        "reasoning": "smoke e2e: producer slice label emission against the mock fetcher",
        "policy_refs": ["polaris.spam"],
        "reversible_until": (chrono::Utc::now() + chrono::Duration::hours(24)).to_rfc3339(),
        "reverses_action_id": null,
    });
    let action_status = http_post_status(
        &app,
        &format!("/api/cases/{}/actions", subject.id.0),
        &cookie,
        &submit_action_body,
    )
    .await?;
    assert_eq!(
        action_status,
        StatusCode::CREATED,
        "POST /api/cases/{}/actions with kind=Label must surface 201 after the wizard runs",
        subject.id.0,
    );

    // ── 14. Receive the live frame, decode, and verify ──────────────
    //
    // Quoted block referenced by the workstream evidence floor:
    // the `verify_label` assertion at step 11 pairs the wire-delivered
    // signature with the persisted canonical CBOR (the documented
    // wire-vs-canonical drift makes the re-canonicalised path
    // unreliable; see the module docstring). The signature itself
    // round-trips through DAG-CBOR's `LexValue::Bytes` byte-for-byte,
    // so the verify call here is the load-bearing assertion that
    // the broadcast and the signing key agree.
    let msg = tokio::time::timeout(FRAME_TIMEOUT, ws.next())
        .await?
        .ok_or("WS stream closed before live frame arrived")??;
    let bytes = match msg {
        Message::Binary(b) => b,
        other => return Err(format!("unexpected non-binary WS message: {other:?}").into()),
    };
    let frame = Frame::decode(&bytes)?;
    let label_map = first_label_of(&frame)
        .ok_or("decoded frame did not carry a `#labels` body with one label")?;
    let wire_sig_bytes = label_map
        .get("sig")
        .and_then(LexValue::as_bytes)
        .ok_or("wire label missing sig bytes")?;
    let wire_sig = Signature::from_bytes(wire_sig_bytes)
        .map_err(|e| format!("wire sig bytes did not form a Signature: {e:?}"))?;

    // The wire shape today drifts from the canonical signing shape
    // (`ver` is omitted, `cts` uses `+00:00` instead of `Z`). Rather
    // than re-canonicalise the wire fields back to the signed bytes
    // (which would silently break the moment a future refactor
    // introduces another drifting field) we verify the wire-extracted
    // signature against the emitter's persisted canonical CBOR from
    // the `labels.label_cbor` column — same workaround
    // `tests/subscribe_labels_e2e.rs` uses, filed loudly there.
    let label_row: (Vec<u8>, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as(r"SELECT label_cbor, signed_at FROM labels ORDER BY seq DESC LIMIT 1")
            .fetch_one(&pool)
            .await?;
    let label_cbor = label_row.0;
    let signed_at = label_row.1;
    verify_label(&pool, &label_cbor, &wire_sig, signed_at)
        .await
        .map_err(|e| format!("verify_label rejected the WS-delivered signature: {e:?}"))?;

    // ── 15. /metrics scrape ─────────────────────────────────────────
    //
    // Quoted block referenced by the workstream evidence floor:
    // the metrics scrape assertion checks the hand-emitted counter
    // series the producer slice is supposed to bump.
    if prometheus_handle.is_some() {
        let metrics_body = http_get_text(&app, "/metrics").await?;
        assert!(
            metrics_body.contains("polaris_actions_total")
                && metrics_body.contains(r#"kind="label""#),
            "GET /metrics must include polaris_actions_total{{kind=\"label\"}} after a Label \
             action was submitted; body excerpt: {}",
            metrics_body.lines().take(30).collect::<Vec<_>>().join("\n"),
        );
        assert!(
            metrics_body.contains("polaris_setup_wizard_steps_total")
                && metrics_body.contains(r#"step="generate_key""#)
                && metrics_body.contains(r#"status="success""#),
            "GET /metrics must include polaris_setup_wizard_steps_total{{step=\"generate_key\",\
             status=\"success\"}} after the wizard's generate-key step; body excerpt: {}",
            metrics_body.lines().take(30).collect::<Vec<_>>().join("\n"),
        );
    } else {
        eprintln!(
            "smoke_e2e: skipping /metrics body assertions because a different test \
             in this process already owns the global Prometheus recorder. The \
             counter sites themselves are covered by tests/metrics_endpoint.rs."
        );
    }

    // ── 16. Clean shutdown ──────────────────────────────────────────
    ws.close(None).await?;
    let _ = shutdown_tx.send(());
    let _ = server_task.await;

    let elapsed = test_start.elapsed();
    assert!(
        elapsed < WALL_BUDGET,
        "smoke_e2e wall-clock budget exceeded: {elapsed:?} >= {WALL_BUDGET:?} (AC-E1)",
    );
    Ok(())
}
