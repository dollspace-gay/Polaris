//! Regression test — issue #90: the ATProto OAuth `complete_login`
//! path resolves the moderator's PDS URL and persists it on the
//! sealed [`TokenSet`] bundle as `aud`.
//!
//! Background: proto-blue's `OAuthClient::callback` returns a
//! `TokenSet` with `aud = None` because the OAuth token-response JSON
//! does not carry an audience field (audience is a resource-server
//! concept, not an authorization-server concept; the ATProto SDK
//! exposes the audience-aware `callback_with_iss_and_aud` for callers
//! that have already resolved the PDS URL). Without explicit
//! audience propagation at the Polaris call site, every later call
//! to [`AtprotoOauthAuthVerifier::build_oauth_session_for_moderator`]
//! falls through to a fresh DID-document re-resolve — wiring
//! 50–200 ms of latency into every setup-wizard step and every
//! per-moderator XRPC call that needs a session reconstructed.
//!
//! This test pins the desired contract: after a successful
//! `complete_login`, the persisted session bundle's `token_set.aud`
//! is `Some(<PDS URL>)`. It mirrors the existing `atproto_login.rs`
//! fixture, plus a single mock route for the PLC directory's
//! DID-document response so the audience-resolution path lands.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use polaris_backend::auth::atproto::AtprotoOauthAuthVerifier;
use polaris_backend::auth::crypto::{Crypto, SealedBytes};
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{LoginHint, ModeratorAuth};
use polaris_backend::config::DbConfig;
use polaris_backend::db;
use proto_blue::common::fetch::{
    FetchError, FetchHandler, HttpHeaders, HttpMethod, HttpRequest, HttpResponse,
};
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::{OAuthClient, OAuthClientMetadata};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;

const MOCK_DID: &str = "did:plc:moderator-mock-1";
const MOCK_PDS_URL: &str = "https://pds.mock.example";
const MOCK_AS_URL: &str = "https://as.mock.example";

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

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
            body: serde_json::to_vec(body).unwrap(),
            content_type: "application/json",
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

        let canned = self
            .state
            .lock()
            .unwrap()
            .routes
            .get(&(req.method, url_no_q.clone()))
            .cloned()
            .ok_or_else(|| {
                FetchError::Network(format!("no mock route for {:?} {}", req.method, url_no_q))
            })?;

        let mut headers = HttpHeaders::new();
        headers.insert("content-type".to_owned(), canned.content_type.to_owned());
        Ok(HttpResponse {
            status: canned.status,
            headers,
            body: canned.body,
        })
    }
}

fn wire_routes(fetcher: &MockFetcher, pds_url: &str, iss: &str, did: &str) {
    // Protected-resource discovery — proto-blue calls this when the
    // login hint is a PDS URL (skipping the handle resolver's DNS leg).
    fetcher.route(
        HttpMethod::Get,
        format!("{pds_url}/.well-known/oauth-protected-resource"),
        Canned::json(&serde_json::json!({
            "resource": pds_url,
            "authorization_servers": [iss],
        })),
    );

    // Authorization-server metadata.
    fetcher.route(
        HttpMethod::Get,
        format!("{iss}/.well-known/oauth-authorization-server"),
        Canned::json(&serde_json::json!({
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

    // PAR endpoint.
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
        },
    );

    // Token endpoint — issues the DID-bearing token response. Note
    // there is NO `aud` field in the JSON; that is the bug this test
    // pins. Polaris must resolve the PDS URL separately and patch
    // `TokenSet.aud` before sealing the bundle.
    fetcher.route(
        HttpMethod::Post,
        format!("{iss}/oauth/token"),
        Canned::json(&serde_json::json!({
            "access_token": "mock-dpop-bound-access-token",
            "token_type": "DPoP",
            "scope": "atproto transition:generic",
            "refresh_token": "mock-refresh-token",
            "expires_in": 3600,
            "sub": did,
        })),
    );

    // PLC directory — the route Polaris hits to resolve `did:plc:…`
    // into a DID document. proto-blue's IdResolver defaults to
    // `https://plc.directory/{did}`. The returned document carries an
    // `#atproto_pds` service entry pointing at the PDS URL we expect
    // to see persisted as `aud`.
    fetcher.route(
        HttpMethod::Get,
        format!("https://plc.directory/{did}"),
        Canned::json(&serde_json::json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/multikey/v1",
            ],
            "id": did,
            "alsoKnownAs": [format!("at://moderator.mock.example")],
            "verificationMethod": [{
                "id": format!("{did}#atproto"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": "zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF",
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": pds_url,
            }],
        })),
    );
}

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

/// Drive `start_login` + `complete_login` end-to-end, then inspect
/// the persisted session bundle in `sessions.refresh_token_enc`. The
/// bundle is JSON-encoded (per the smoke-session
/// bincode→serde_json migration in
/// `polaris-backend/src/auth/atproto.rs::encode_bundle`); the
/// `token_set.aud` field is the contract being pinned.
#[tokio::test]
async fn complete_login_persists_resolved_pds_url_as_aud() {
    if !docker_available() {
        println!("SKIP complete_login_persists_resolved_pds_url_as_aud: docker not reachable");
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
    wire_routes(&fetcher, MOCK_PDS_URL, MOCK_AS_URL, MOCK_DID);

    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let verifier = make_verifier(sessions, crypto.clone(), pool.clone(), fetcher.clone());

    let redirect = verifier
        .start_login(LoginHint::AtprotoHandle(MOCK_PDS_URL.to_owned()))
        .await
        .expect("start_login should succeed against the mock AS");

    let result = verifier
        .complete_login(&redirect.state, "mock-auth-code")
        .await
        .expect("complete_login should succeed against the mock AS");

    // Pull the persisted bundle. The bundle is sealed by the
    // SessionStore at create time; we re-open via the same Crypto
    // handle the verifier uses.
    let (sealed_bytes,): (Vec<u8>,) =
        sqlx::query_as("SELECT refresh_token_enc FROM sessions WHERE id = $1")
            .bind(result.session_token.as_str())
            .fetch_one(&pool)
            .await
            .expect("session row must exist after complete_login");

    let sealed = SealedBytes::from_bytes(&sealed_bytes)
        .expect("session bundle envelope must parse as SealedBytes");
    let plaintext = crypto
        .open(&sealed)
        .expect("session bundle must decrypt with the verifier's Crypto key");

    // The bundle is `serde_json::to_vec(&SerializedSessionState)`.
    // Inspect via a serde_json::Value rather than deserializing into
    // SerializedSessionState directly (the struct is pub(crate) and
    // unreachable from integration tests by design).
    let bundle: serde_json::Value =
        serde_json::from_slice(&plaintext).expect("bundle plaintext must parse as JSON");

    let aud = bundle
        .get("token_set")
        .and_then(|ts| ts.get("aud"))
        .and_then(serde_json::Value::as_str);

    assert_eq!(
        aud,
        Some(MOCK_PDS_URL),
        "issue #90 regression: complete_login must resolve the moderator's PDS URL \
         and persist it on the session bundle as `token_set.aud`. \
         Found aud = {aud:?} in bundle:\n{bundle:#}",
    );
}
