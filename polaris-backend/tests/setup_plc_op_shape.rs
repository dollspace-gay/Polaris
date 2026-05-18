//! `signPlcOperation` request-body shape regression test (REQ-C2 /
//! AC-C2 of `.design/polaris-operationally-complete.md`).
//!
//! Pins the **six** body-shape facts the smoke session against
//! `polarislabeler.bsky.social` discovered the hard way (a wholesale-
//! replace bug overwrote the account's existing `#atproto` key + the
//! `#atproto_pds` service entry, breaking login). The on-the-wire PLC
//! operation must merge — not replace — the existing services /
//! verificationMethods entries.
//!
//! # The six asserted facts
//!
//! 1. `services` is a JSON object (not an array).
//! 2. `services.atproto_pds` exists with `type` AND `endpoint` keys.
//! 3. `services.atproto_pds.endpoint` is the PDS URL the resolved DID
//!    document advertised (preserved, NOT clobbered).
//! 4. `services.atproto_labeler` exists with
//!    `type == "AtprotoLabeler"` and
//!    `endpoint == <wizard-supplied service URL>`.
//! 5. `verificationMethods` is a JSON object (not an array).
//! 6. `verificationMethods.atproto` matches the existing identity key
//!    from the resolved DID document (preserved), AND
//!    `verificationMethods.atproto_label` matches the labeler's
//!    `did:key:z…` from `polaris_setup_state.signing_pubkey_did`.
//!
//! The pattern mirrors `tests/setup_endpoints.rs`: the production
//! router is built around an `ApiState` carrying a [`MockFetcher`]-
//! backed atproto verifier, a moderator session is pre-sealed into
//! the DB, the `POST /api/setup/submit-plc-operation` route runs, and
//! the captured `signPlcOperation` request body is inspected.
//!
//! # Skip behaviour
//!
//! Docker not reachable → print SKIP and return cleanly, matching
//! every other testcontainer-using integration test in this crate.

#![cfg(test)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::doc_markdown,
    reason = "test code is allowed to panic per rust-quality §7; \
              one long linear set-up-then-assert function reads more clearly inline"
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

/// Probe for a working Docker daemon. Same skip idiom as everywhere
/// else in this crate's integration suite.
fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

// ── MockFetcher with request-body capture ────────────────────────────

/// A single canned response from the mock PDS / mock plc.directory.
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
            body: serde_json::to_vec(body).expect("invariant: serde_json::Value re-serialises"),
            content_type: "application/json",
        }
    }
}

/// A recorded request: the URL (sans query) and the body bytes that
/// the caller sent. The test inspects this after the handler returns.
///
/// `body` is `Option<Vec<u8>>` because `HttpRequest::body` is
/// optional: a bodyless POST (like `requestPlcOperationSignature`)
/// surfaces as `None`. The `signPlcOperation` path always carries
/// a JSON body so the test asserts `Some(_)` below.
#[derive(Debug, Clone)]
struct Captured {
    body: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct MockState {
    routes: HashMap<(HttpMethod, String), Vec<Canned>>,
    /// Per-URL list of captured request bodies. Keyed on the path-only
    /// form (no query) so the test can target a single endpoint.
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
            .expect("invariant: MockFetcher Mutex not poisoned")
            .routes
            .entry((method, url.into()))
            .or_default()
            .push(c);
    }

    /// Return every captured request body for `(method, url)`. The
    /// URL must be the **path-only** form (no query, no trailing
    /// slash); the fetcher canonicalises both on lookup.
    fn captured(&self, method: HttpMethod, url: impl Into<String>) -> Vec<Captured> {
        let key = (method, url.into());
        self.state
            .lock()
            .expect("invariant: MockFetcher Mutex not poisoned")
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

        // Capture the body for assertion-side inspection. We capture
        // BEFORE matching the route so a 404-on-mock at least logs
        // what came in.
        {
            let mut state = self
                .state
                .lock()
                .expect("invariant: MockFetcher Mutex not poisoned");
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
            .expect("invariant: MockFetcher Mutex not poisoned");
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

// ── Verifier wiring (same shape as setup_endpoints.rs) ───────────────

/// Build an [`AtprotoOauthAuthVerifier`] wired against the supplied
/// MockFetcher. Mirrors the pattern in `tests/setup_endpoints.rs`.
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

// ── Session-bundle plumbing (mirrors production `encode_bundle`) ─────

/// Mirror of the private `atproto::SerializedSessionState`. Production
/// `encode_bundle` (see `polaris-backend/src/auth/atproto.rs:158`) is
/// JSON, not bincode (the architect's comment: bincode silently drops
/// `skip_serializing_if = "Option::is_none"` fields and refuses to
/// re-parse them, so JSON is the round-trip-safe envelope). We
/// mirror that here. If production drifts the bundle shape, the
/// shared `tests/atproto_refresh.rs` test will fail in lockstep —
/// re-deriving the struct keeps the integration tests independent of
/// the `pub(crate)` surface.
#[derive(serde::Serialize)]
struct TestBundle {
    dpop_keypair_jwk_json: Vec<u8>,
    token_set: TokenSet,
}

fn seal_session_bundle(crypto: &Crypto, did: &str, pds_url: &str) -> Vec<u8> {
    let dpop_key = DpopKey::generate_es256().expect("invariant: ES256 key generation succeeds");
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
        dpop_keypair_jwk_json: serde_json::to_vec(&dpop_key.private_jwk)
            .expect("invariant: DPoP JWK serialises"),
        token_set,
    };
    // JSON envelope — matches production `encode_bundle`.
    let plain =
        serde_json::to_vec(&bundle).expect("invariant: bundle JSON-encodes round-trip-safely");
    let sealed = crypto.seal(&plain).expect("invariant: AEAD seal succeeds");
    sealed.to_bytes()
}

// ── DB / fixture helpers ─────────────────────────────────────────────

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

/// Insert a moderator + grant `Role::Admin` + seed a session whose
/// `refresh_token_enc` is the sealed bincode session bundle.
async fn seed_admin_session(
    pool: &PgPool,
    crypto: &Crypto,
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
    .bind(Role::Admin.as_db_str())
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

// ── Constants ────────────────────────────────────────────────────────

/// Moderator DID — the value goes into `TokenSet.sub` and (after
/// `build_oauth_session_for_moderator`) becomes the PLC operation's
/// `did:plc:…` target.
const TEST_DID: &str = "did:plc:plc-shape-test";
/// Handle — only used to populate `moderators.display_name`.
const TEST_HANDLE: &str = "shapetest.example.com";
/// PDS URL — the OAuth `TokenSet.aud` claim, also the
/// `oauth_ctx.pds_url` the handler builds its XRPC URLs from.
const TEST_PDS_URL: &str = "https://pds.mock.shape";
/// Existing PDS endpoint the resolved DID document advertises. The
/// regression assertion is that this exact string is preserved on the
/// outgoing `signPlcOperation` body — overwriting it would break the
/// moderator's own login (this is the bug the smoke session caught).
const PRE_EXISTING_PDS_ENDPOINT: &str = "https://existing-pds.shape";
/// Existing `#atproto` multibase key the resolved DID document
/// advertises. Preserved on the PLC operation.
const PRE_EXISTING_ATPROTO_MULTIBASE: &str = "zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
/// Labeler signing did:key:z… — preloaded into
/// `polaris_setup_state.signing_pubkey_did` so the handler's
/// load-step succeeds and so we can assert the value gets spliced
/// into `verificationMethods.atproto_label` verbatim.
const TEST_LABELER_SIGNING_DID_KEY: &str =
    "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
/// Wizard-supplied service URL the labeler should advertise. Goes
/// into the request body and is asserted on the captured PLC
/// operation's `services.atproto_labeler.endpoint`.
const TEST_LABELER_SERVICE_URL: &str = "https://labeler.example/";

#[tokio::test]
async fn submit_plc_operation_sends_merge_shaped_body() -> Result<(), Box<dyn std::error::Error>> {
    if !docker_available() {
        println!(
            "SKIP setup_plc_op_shape::submit_plc_operation_sends_merge_shaped_body: \
             docker daemon not reachable",
        );
        return Ok(());
    }

    let (database, pool) = boot_db().await?;
    let crypto = Crypto::new([7_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto.clone());
    let fetcher = Arc::new(MockFetcher::new());

    // ── Mock plc.directory: resolve the moderator's DID document ────
    //
    // The production handler calls
    // `AtprotoOauthAuthVerifier::resolve_did_document` which goes via
    // `IdResolver::ensure_resolve` → `resolve_plc` →
    // GET `https://plc.directory/<did>`. The response body is a W3C
    // DID document with the moderator's existing identity key and
    // their existing PDS service entry — the two pieces of state the
    // handler must preserve in the outgoing PLC operation.
    fetcher.route(
        HttpMethod::Get,
        format!("https://plc.directory/{TEST_DID}"),
        Canned::json(&serde_json::json!({
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
                "serviceEndpoint": PRE_EXISTING_PDS_ENDPOINT,
            }],
        })),
    );

    // ── Mock signPlcOperation: return a canned signed envelope ──────
    //
    // We do NOT need to return a "real" signed operation here — the
    // handler only forwards `.operation` to submitPlcOperation, and
    // the test inspects the recorded REQUEST body, not the response.
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.signPlcOperation"),
        Canned::json(&serde_json::json!({"operation": {}})),
    );
    // ── Mock submitPlcOperation: empty success ──────────────────────
    fetcher.route(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.submitPlcOperation"),
        Canned::json(&serde_json::json!({})),
    );

    // ── Build the production router around our state ───────────────
    let tmp = tempfile::tempdir()?;
    let key_path = tmp.path().join("labeler.key");
    let verifier = make_verifier(
        sessions.clone(),
        crypto.clone(),
        pool.clone(),
        Arc::clone(&fetcher),
    );
    let any_auth = Arc::new(AnyModeratorAuth::Atproto(verifier));
    let api_state = ApiState::new(pool.clone(), sessions)
        .with_moderator_auth(any_auth)
        .with_labeler_signing_key_cfg(LabelerSigningKeyConfig::FilePlain { path: key_path });
    let router = api::router_with_state(database, api_state);

    // ── Seed moderator + session + setup state ─────────────────────
    let (_moderator_id, cookie) =
        seed_admin_session(&pool, &crypto, TEST_DID, TEST_HANDLE, TEST_PDS_URL).await?;
    sqlx::query(
        r"UPDATE polaris_setup_state
          SET signing_pubkey_did = $1, updated_at = now()
          WHERE id = TRUE",
    )
    .bind(TEST_LABELER_SIGNING_DID_KEY)
    .execute(&pool)
    .await?;

    // ── Drive the handler ──────────────────────────────────────────
    let request_body = serde_json::json!({
        "token": "any-string",
        "service_url": TEST_LABELER_SERVICE_URL,
    });
    let request = Request::builder()
        .method("POST")
        .uri("/api/setup/submit-plc-operation")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, format!("{SESSION_COOKIE}={cookie}"))
        .body(Body::from(serde_json::to_vec(&request_body)?))?;
    let response = router.oneshot(request).await?;
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let response_body: serde_json::Value =
        serde_json::from_slice(&body_bytes).unwrap_or(serde_json::Value::Null);
    assert_eq!(
        status,
        StatusCode::OK,
        "handler must surface 200 on the merge-shape happy path; body was {response_body}",
    );

    // ── Inspect the recorded signPlcOperation request body ─────────
    let captured = fetcher.captured(
        HttpMethod::Post,
        format!("{TEST_PDS_URL}/xrpc/com.atproto.identity.signPlcOperation"),
    );
    assert_eq!(
        captured.len(),
        1,
        "the handler must POST signPlcOperation exactly once",
    );
    let body_bytes = captured[0]
        .body
        .as_ref()
        .expect("invariant: signPlcOperation always carries a JSON body");
    let sign_body: serde_json::Value = serde_json::from_slice(body_bytes)
        .expect("invariant: captured signPlcOperation body parses as JSON");

    // ── Quoted block referenced by the workstream evidence floor ───
    //
    // Six shape facts, asserted mechanically. These mirror REQ-C2 (a)
    // through (f). A future refactor that re-introduces the
    // array-vs-map bug or wholesale-replaces the existing entries
    // will fail at least one of these and break CI loudly.

    // (1) services is an object, not an array.
    let services = sign_body
        .get("services")
        .expect("signPlcOperation body must carry `services`");
    assert!(
        services.is_object(),
        "FACT 1: services MUST be a JSON object (not an array); got {services}",
    );

    // (2) services.atproto_pds exists with type AND endpoint keys.
    let atproto_pds = services
        .get("atproto_pds")
        .expect("FACT 2: services.atproto_pds must be present");
    assert!(
        atproto_pds.is_object(),
        "FACT 2: services.atproto_pds must be an object; got {atproto_pds}",
    );
    assert!(
        atproto_pds.get("type").is_some(),
        "FACT 2: services.atproto_pds must carry a `type` key; got {atproto_pds}",
    );
    assert!(
        atproto_pds.get("endpoint").is_some(),
        "FACT 2: services.atproto_pds must carry an `endpoint` key; got {atproto_pds}",
    );

    // (3) services.atproto_pds.endpoint is the existing PDS endpoint
    // (preserved verbatim from the resolved DID document).
    assert_eq!(
        atproto_pds.get("endpoint").and_then(|v| v.as_str()),
        Some(PRE_EXISTING_PDS_ENDPOINT),
        "FACT 3: services.atproto_pds.endpoint MUST be the resolved DID document's \
         atproto_pds endpoint, preserved verbatim (NOT clobbered)",
    );

    // (4) services.atproto_labeler exists with type=AtprotoLabeler and
    // endpoint=<wizard-supplied service URL>.
    let atproto_labeler = services
        .get("atproto_labeler")
        .expect("FACT 4: services.atproto_labeler must be present");
    assert_eq!(
        atproto_labeler.get("type").and_then(|v| v.as_str()),
        Some("AtprotoLabeler"),
        "FACT 4: services.atproto_labeler.type must equal \"AtprotoLabeler\"",
    );
    assert_eq!(
        atproto_labeler.get("endpoint").and_then(|v| v.as_str()),
        Some(TEST_LABELER_SERVICE_URL),
        "FACT 4: services.atproto_labeler.endpoint must equal the wizard-supplied URL",
    );

    // (5) verificationMethods is an object, not an array.
    let verification_methods = sign_body
        .get("verificationMethods")
        .expect("signPlcOperation body must carry `verificationMethods`");
    assert!(
        verification_methods.is_object(),
        "FACT 5: verificationMethods MUST be a JSON object (not an array); got {verification_methods}",
    );

    // (6) verificationMethods.atproto preserved + atproto_label added.
    assert_eq!(
        verification_methods.get("atproto").and_then(|v| v.as_str()),
        Some(format!("did:key:{PRE_EXISTING_ATPROTO_MULTIBASE}").as_str()),
        "FACT 6: verificationMethods.atproto must equal the resolved DID document's \
         existing #atproto identity key (preserved as `did:key:<multibase>`)",
    );
    assert_eq!(
        verification_methods
            .get("atproto_label")
            .and_then(|v| v.as_str()),
        Some(TEST_LABELER_SIGNING_DID_KEY),
        "FACT 6: verificationMethods.atproto_label must equal the labeler's signing \
         did:key:z… from polaris_setup_state.signing_pubkey_did",
    );

    Ok(())
}
