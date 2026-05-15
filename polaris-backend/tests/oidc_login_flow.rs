//! Integration test — drives the OIDC code-exchange flow against a mock IdP.
//!
//! Test code uses `.unwrap()` / `.expect()` on `Result`s where a failure
//! is itself a test failure with a meaningful panic message. The workspace
//! `unwrap_used` / `expect_used` lints are denied at `--all-targets` level
//! so item-level allow is required here; this is the idiomatic Rust pattern
//! for integration tests (see Rust API Guidelines C-TEST-PANIC).
//!
//! `doc_markdown` and `too_many_lines` are pedantic-group lints; integration
//! tests written as a single linear scenario (set up Postgres, set up mock
//! IdP, drive `start_login`, drive `complete_login`, assert) naturally
//! exceed the 100-line heuristic and use prose-level identifiers like
//! "id_token" / "IdP" in module docs. Both allows are scoped to this test
//! file and do not affect library or binary code.
//!
//! Spins up:
//!
//! 1. A `wiremock` server playing the role of the OIDC issuer. Stubs the
//!    discovery, JWKS, token, and userinfo endpoints.
//! 2. A `testcontainers`-driven Postgres so the session row, moderator row,
//!    and login-state row can be asserted against real SQL.
//!
//! Then drives `OidcAuthVerifier::start_login` → manual callback simulation →
//! `OidcAuthVerifier::complete_login` and asserts the resulting
//! `ModeratorAuthCtx` plus the on-disk session row.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::too_many_lines
)]

use std::collections::HashSet;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use polaris_backend::auth::crypto::Crypto;
use polaris_backend::auth::oidc::OidcAuthVerifier;
use polaris_backend::auth::session::SessionStore;
use polaris_backend::auth::{LoginHint, ModeratorAuth, Role};
use polaris_backend::config::{DbConfig, OidcConfig};
use polaris_backend::db;
use secrecy::SecretString;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt as _;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn docker_available() -> bool {
    Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Empty JWKS — for HS256 the symmetric key is the OIDC `client_secret`
/// per OIDC Core §10.1, not a JWK at /jwks. We still serve a valid
/// (empty) JWKS so the discovery probe doesn't 404.
fn jwks_body() -> serde_json::Value {
    serde_json::json!({ "keys": [] })
}

/// Build an HS256-signed id_token using the OIDC `client_secret` as the
/// HMAC key. Per RFC 7518 + OIDC Core §10.1, HS256 id_tokens are signed
/// with the (UTF-8 bytes of the) client_secret rather than a JWKS-resolved
/// key. `openidconnect` 4.x enforces this convention; signing with any
/// other key produces a "bad HMAC" verification error.
fn make_signed_jwt(payload: &serde_json::Value, client_secret: &str) -> String {
    let header = serde_json::json!({ "alg": "HS256", "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).unwrap());
    let signing_input = format!("{h}.{p}");
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(client_secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    format!("{signing_input}.{sig}")
}

#[tokio::test]
async fn oidc_login_flow_persists_session_row() {
    if !docker_available() {
        println!("SKIP oidc_login_flow: docker daemon not reachable");
        return;
    }

    // --- 1. Postgres -------------------------------------------------
    // Postgres 16-alpine: migration 11 needs generated columns (PG ≥ 12).
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

    // --- 2. Mock OIDC issuer ----------------------------------------
    let server = MockServer::start().await;
    let issuer_url = server.uri();
    let redirect_url = "http://localhost:9999/auth/oidc/callback".to_owned();

    // /.well-known/openid-configuration
    let discovery = serde_json::json!({
        "issuer": issuer_url,
        "authorization_endpoint": format!("{issuer_url}/authorize"),
        "token_endpoint": format!("{issuer_url}/token"),
        "userinfo_endpoint": format!("{issuer_url}/userinfo"),
        "jwks_uri": format!("{issuer_url}/jwks"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": ["sub", "name", "preferred_username", "email"],
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&discovery))
        .mount(&server)
        .await;
    // JWKS — publishes the symmetric HS256 key the mock IdP signs id_tokens with.
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks_body()))
        .mount(&server)
        .await;

    // Token endpoint returns an id_token whose nonce + iss + sub we control.
    // We mount this LATER, after start_login runs, so we know the nonce.

    // --- 3. Build the OIDC verifier ----------------------------------
    let crypto = Crypto::new([42_u8; 32]);
    let sessions = SessionStore::new(pool.clone(), crypto);
    let oidc_cfg = OidcConfig {
        issuer_url: issuer_url.clone(),
        client_id: "polaris-test".to_owned(),
        client_secret: SecretString::from("test-secret".to_owned()),
        redirect_url: redirect_url.clone(),
    };
    let verifier = OidcAuthVerifier::new(&oidc_cfg, sessions, pool.clone())
        .await
        .expect("OidcAuthVerifier::new should discover");

    // --- 4. start_login ----------------------------------------------
    let redirect = verifier.start_login(LoginHint::None).await.unwrap();
    let url = Url::parse(&redirect.authorize_url).unwrap();
    let mut state_param = None;
    let mut nonce_param = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "state" => state_param = Some(v.to_string()),
            "nonce" => nonce_param = Some(v.to_string()),
            _ => {}
        }
    }
    let state = state_param.expect("authorize_url should carry `state`");
    let nonce = nonce_param.expect("authorize_url should carry `nonce`");
    assert_eq!(state, redirect.state);

    // The state row should be persisted.
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM auth_oidc_login_states WHERE state = $1")
            .bind(&state)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count.0, 1, "auth_oidc_login_states should have the row");

    // --- 5. Mount token + userinfo endpoints --------------------------
    let id_token_claims = serde_json::json!({
        "iss": issuer_url,
        "sub": "mock-moderator-1",
        "aud": "polaris-test",
        "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600,
        "iat": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        "nonce": nonce,
        "name": "Test Moderator",
    });
    let id_token = make_signed_jwt(&id_token_claims, "test-secret");
    let token_response = serde_json::json!({
        "access_token": "mock-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "mock-refresh-token",
        "id_token": id_token,
        "scope": "openid email profile",
    });
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/userinfo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "sub": "mock-moderator-1",
            "name": "Test Moderator",
        })))
        .mount(&server)
        .await;

    // --- 6. complete_login -------------------------------------------
    let result = verifier
        .complete_login(&state, "mock-auth-code")
        .await
        .expect("complete_login should succeed against the mock IdP");

    // The login-state row must have been single-use-deleted.
    let count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM auth_oidc_login_states WHERE state = $1")
            .bind(&state)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        count.0, 0,
        "login-state row should be deleted post-exchange"
    );

    // A moderator row was upserted.
    let moderator_id: (uuid::Uuid,) = sqlx::query_as(
        "SELECT id FROM moderators WHERE auth_backend = 'oidc' AND external_id = $1",
    )
    .bind("mock-moderator-1")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(moderator_id.0, result.ctx.moderator_id.0);

    // A session row exists with refresh_token_enc non-empty.
    let session_row: (Vec<u8>,) =
        sqlx::query_as("SELECT refresh_token_enc FROM sessions WHERE id = $1")
            .bind(result.session_token.as_str())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        !session_row.0.is_empty(),
        "encrypted refresh-token column must be non-empty"
    );
    // The minimum size is 12-byte nonce + 16-byte tag = 28 bytes.
    assert!(session_row.0.len() >= 28);

    // Roles are an empty set (we did not grant any) but the type is correct.
    assert_eq!(result.ctx.roles, HashSet::<Role>::new());
}
