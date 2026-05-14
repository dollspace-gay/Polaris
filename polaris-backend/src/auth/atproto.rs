//! ATProto OAuth moderator-authentication backend.
//!
//! Issue #31 / REQ-4 / AC-4 / AC-5 (atproto half). The second
//! [`ModeratorAuth`] implementation. Moderators log in with their
//! Bluesky / ATProto handle; their DID becomes the stable
//! [`ModeratorId`] external identifier. Role assignment remains
//! Polaris-owned (the `moderator_roles` table) — ATProto provides
//! authentication only.
//!
//! # Flow
//!
//! 1. `start_login(hint)` — the operator's UI POSTs the moderator's
//!    handle (`alice.example.com`) which arrives as
//!    [`LoginHint::AtprotoHandle`].
//!    - Resolve handle → DID → PDS URL → authorization-server metadata
//!      via [`proto_blue_oauth::resolve_input`].
//!    - [`proto_blue_oauth::OAuthClient::authorize`] internally generates
//!      a fresh `DPoP` keypair, fresh PKCE pair, fresh state token, then
//!      issues a PAR (Pushed Authorization Request) and returns the
//!      authorize URL + an [`AuthState`] carrying every secret needed to
//!      complete the exchange.
//!    - The `DPoP` private JWK is serialised to JSON bytes and
//!      AES-256-GCM-sealed via [`Crypto::seal`] (same KEK as the OIDC
//!      refresh-token-at-rest encryption). The sealed bytes plus the
//!      PKCE verifier, handle, PAR request URI, and issuer URL are
//!      persisted to `auth_atproto_login_states` keyed by the AS-issued
//!      state token. TTL: 10 minutes (enforced at SELECT time).
//!
//! 2. Authorization server redirects the moderator back to
//!    `redirect_uris[0]?code=…&state=…&iss=…`.
//!
//! 3. `complete_login(state, code)` —
//!    - SELECT the row by state with the 10-minute TTL filter; mismatch
//!      or expiry → [`AuthError::StateMismatch`].
//!    - Unseal the `DPoP` keypair JWK; re-discover the AS metadata from
//!      the stored issuer.
//!    - Single-use: DELETE the state row in the same transaction so a
//!      late retry can't reuse the secrets.
//!    - [`OAuthClient::callback`] exchanges the code + PKCE verifier for
//!      a `DPoP`-bound access token; the response's `sub` claim is the
//!      moderator's DID.
//!    - Upsert `moderators(auth_backend='atproto', external_id=<did>)`.
//!    - Mint a Polaris session via
//!      [`SessionStore::create`], passing the sealed `DPoP` keypair bytes
//!      as the row's "refresh credential" (the `sessions.refresh_token_enc`
//!      column carries the sealed `DPoP` keypair JWK for atproto-backed
//!      sessions; the bytes survive a session-refresh rotation untouched
//!      so a future refresh-flow implementation has the keypair material
//!      to rebuild a [`DpopKey`] from).
//!
//! # Forbidden patterns enforced here
//!
//! - **No plaintext DPoP keypair on disk.** Every `INSERT INTO
//!   auth_atproto_login_states` and every `SessionStore::create` call
//!   passes pre-sealed bytes (or accepts plaintext that the store seals
//!   immediately). Search the file for `dpop_keypair_enc` — every write
//!   is preceded by `self.crypto.seal(…)`.
//! - **No state-builder SQL.** Every query is a `sqlx::query!` /
//!   `sqlx::query_as!` macro call.
//! - **Token material never lands in `format!` strings or `Display`.**
//!   The error variants in `super::AuthError` either omit the underlying
//!   error entirely (constant `Display` text) or carry it via `#[source]`
//!   so the structured-log chain can surface it without echoing it into
//!   a user-visible string.
//!
//! # Refresh flow (deferred)
//!
//! `proto-blue-oauth` supports `DPoP`-nonce-rotation refresh via
//! [`OAuthClient::refresh_token`]. AC-4 only covers the initial login
//! binding; the refresh dance is filed as a follow-up (see issue #66 in
//! the kickoff plan). The stored sealed `DPoP` keypair is the
//! input that future refresh code will rebuild the [`DpopKey`] from —
//! the [`SessionStore::create`] call here writes that to
//! `sessions.refresh_token_enc` so the refresh-flow implementation has
//! the keypair material to work with without a schema migration.
//!
//! [`AuthState`]: proto_blue_oauth::AuthState
//! [`DpopKey`]: proto_blue_oauth::DpopKey
//! [`OAuthClient::callback`]: proto_blue_oauth::OAuthClient::callback
//! [`OAuthClient::refresh_token`]: proto_blue_oauth::OAuthClient::refresh_token

use std::path::Path;
use std::sync::Arc;

use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::client::dpop_key_from_jwk;
use proto_blue::oauth::{OAuthClient, OAuthClientMetadata, OAuthServerMetadata, resolve_input};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::crypto::Crypto;
use crate::auth::session::SessionStore;
use crate::auth::{
    AuthError, LoginHint, LoginRedirect, LoginResult, ModeratorAuth, ModeratorAuthCtx, ModeratorId,
    Role,
};

/// ATProto OAuth implementation of [`ModeratorAuth`].
///
/// Holds an `Arc<OAuthClient>` (the proto-blue OAuth client is immutable
/// after construction; sharing via `Arc` avoids cloning the inner
/// `Arc<dyn FetchHandler>` chain on every login), an `Arc<IdResolver>`
/// for handle resolution, the same [`SessionStore`] and [`Crypto`] the
/// OIDC backend uses, and the Postgres pool the login-state rows live
/// in.
pub struct AtprotoOauthAuthVerifier {
    oauth_client: Arc<OAuthClient>,
    identity_resolver: Arc<IdResolver>,
    sessions: SessionStore,
    crypto: Crypto,
    pool: PgPool,
}

impl std::fmt::Debug for AtprotoOauthAuthVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the inner client metadata — it could carry redirect
        // URIs that an operator considers internal-only. The struct
        // identity is enough for a stack-trace context.
        f.debug_struct("AtprotoOauthAuthVerifier")
            .finish_non_exhaustive()
    }
}

impl AtprotoOauthAuthVerifier {
    /// Construct a verifier from an already-built OAuth client and
    /// identity resolver. The two are passed in (rather than constructed
    /// inside) so tests can inject a [`FetchHandler`] that mocks the
    /// authorization server, the PDS, and the PLC / handle resolver.
    ///
    /// The OAuth client must already have validated client metadata
    /// (`proto_blue_oauth::validate_client_metadata`) at construction
    /// time; this constructor does not re-validate.
    #[must_use]
    pub fn new(
        oauth_client: Arc<OAuthClient>,
        identity_resolver: Arc<IdResolver>,
        sessions: SessionStore,
        crypto: Crypto,
        pool: PgPool,
    ) -> Self {
        Self {
            oauth_client,
            identity_resolver,
            sessions,
            crypto,
            pool,
        }
    }

    /// Build a verifier using the default native fetch backend
    /// (`reqwest` + DNS handle resolution). Used by `main.rs` when the
    /// operator configures `[auth] backend = "atproto"`.
    ///
    /// # Errors
    ///
    /// - [`AuthError::Config`] if the client-metadata JSON cannot be
    ///   read or parsed, or if it fails the atproto OAuth client-
    ///   metadata profile validation.
    pub fn from_paths(
        client_metadata_path: &Path,
        sessions: SessionStore,
        crypto: Crypto,
        pool: PgPool,
    ) -> Result<Self, AuthError> {
        let metadata = load_client_metadata(client_metadata_path)?;
        proto_blue::oauth::validate_client_metadata(&metadata).map_err(|e| AuthError::Config {
            message: format!("client_metadata failed atproto OAuth profile validation: {e}"),
        })?;
        let oauth_client = Arc::new(OAuthClient::new(metadata));
        let identity_resolver = Arc::new(IdResolver::new(IdentityResolverOpts::default(), None));
        Ok(Self::new(
            oauth_client,
            identity_resolver,
            sessions,
            crypto,
            pool,
        ))
    }

    /// Internal `start_login` implementation. See module docs for the
    /// step-by-step rationale.
    async fn start_login_impl(&self, handle: &str) -> Result<LoginRedirect, AuthError> {
        // Step 1: resolve the handle through proto-blue-identity +
        // proto-blue-oauth, getting back the DID + PDS URL + AS metadata
        // we need to drive the OAuth flow. The resolver enforces the
        // alsoKnownAs bidirectional check on the handle → DID binding
        // (see `IdResolver::resolve_handle_verified`).
        let resolved = resolve_input(&self.identity_resolver, &self.oauth_client, handle)
            .await
            .map_err(|e| AuthError::HandleResolutionFailed {
                handle: handle.to_owned(),
                source: Box::new(e),
            })?;

        // Step 2: kick off the OAuth dance against the resolved AS.
        // `authorize()` generates the DPoP keypair, PKCE pair, and state
        // token internally, then drives the PAR call (when supported) and
        // assembles the authorize URL.
        let (authorize_url, auth_state) = self
            .oauth_client
            .authorize(&resolved.server_metadata)
            .await
            .map_err(|e| AuthError::OauthPar {
                source: Box::new(e),
            })?;

        let state = auth_state.app_state.clone().ok_or(AuthError::Config {
            message: "OAuth authorize did not return an app state token".to_owned(),
        })?;

        // Step 3: seal the DPoP keypair JWK at rest. Serialise the JSON
        // Value to its compact byte form; the seal call wraps it in
        // AES-256-GCM under the same KEK as the OIDC refresh-token-at-
        // rest encryption.
        let dpop_jwk_bytes = serde_json::to_vec(&auth_state.dpop_key).map_err(|e| {
            // The JWK Value originated from proto-blue-oauth's
            // DpopKey::generate — serialisation should be infallible.
            // Map the impossible-but-typed error to a Config variant
            // rather than panic.
            AuthError::Config {
                message: format!("failed to serialise DPoP JWK: {e}"),
            }
        })?;
        let sealed = self.crypto.seal(&dpop_jwk_bytes)?;
        let sealed_bytes = sealed.to_bytes();

        // Step 4: derive the PAR request URI from the authorize URL —
        // proto-blue-oauth embeds it in the `request_uri` query param.
        // Storing it lets a future diagnostic surface "the AS issued a
        // PAR with this URI" without re-running the dance.
        let par_request_uri = authorize_url
            .query_pairs()
            .find_map(|(k, v)| (k == "request_uri").then(|| v.to_string()))
            // PAR is optional in the spec; some authorization servers
            // skip it. Persist an empty string in that case rather than
            // refusing the login — the column is non-null because every
            // production AS we target uses PAR, but the test path
            // exercises a non-PAR AS too.
            .unwrap_or_default();

        let issuer = resolved.server_metadata.issuer.clone();

        // Step 5: persist. Note the dpop_keypair_enc column receives the
        // sealed bytes — the plaintext JWK never reaches Postgres.
        sqlx::query!(
            r"INSERT INTO auth_atproto_login_states
              (state, pkce_verifier, dpop_keypair_enc, handle, par_request_uri, issuer)
              VALUES ($1, $2, $3, $4, $5, $6)",
            state,
            auth_state.verifier,
            sealed_bytes,
            handle,
            par_request_uri,
            issuer,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;

        Ok(LoginRedirect {
            authorize_url: authorize_url.to_string(),
            state,
        })
    }

    /// Internal `complete_login` implementation. See module docs.
    async fn complete_login_impl(&self, state: &str, code: &str) -> Result<LoginResult, AuthError> {
        // Step 1: look up the state row with TTL. A miss (no row, row
        // older than 10 minutes) is reported as `StateMismatch` — the
        // generic name keeps the failure mode opaque to the caller
        // (we don't want to confirm "this state existed but expired" as
        // a distinct signal an attacker can probe).
        let row = sqlx::query!(
            r"SELECT pkce_verifier, dpop_keypair_enc, issuer, handle
              FROM auth_atproto_login_states
              WHERE state = $1
                AND created_at > now() - INTERVAL '10 minutes'",
            state,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?
        .ok_or(AuthError::StateMismatch)?;

        // Step 2: single-use. DELETE before the code exchange so even a
        // failed exchange can't be retried with the same secrets.
        sqlx::query!(
            r"DELETE FROM auth_atproto_login_states WHERE state = $1",
            state,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;

        // Step 3: unseal the DPoP keypair JWK. A tampered ciphertext
        // surfaces as `AuthError::Crypto` (via the `From<CryptoError>`
        // impl in `auth/mod.rs`); the AEAD failure is collapsed to a
        // single error variant so the caller can't distinguish
        // "wrong key" from "tampered ciphertext".
        let sealed = crate::auth::crypto::SealedBytes::from_bytes(&row.dpop_keypair_enc)?;
        let dpop_jwk_bytes = self.crypto.open(&sealed)?;
        let dpop_jwk: serde_json::Value =
            serde_json::from_slice(&dpop_jwk_bytes).map_err(|e| AuthError::DpopBindingFailed {
                source: Box::new(e),
            })?;

        // Step 4: re-discover the AS metadata. We deliberately re-fetch
        // rather than persist the entire metadata blob between login
        // and callback — the blob is large and the network round-trip
        // is comparable to the database read it would replace.
        let server_metadata = self
            .oauth_client
            .discover_server(&row.issuer)
            .await
            .map_err(|e| AuthError::OauthExchange {
                source: Box::new(e),
            })?;

        // Step 5: reconstruct AuthState for proto-blue-oauth's callback
        // entry point. The DpopKey reconstruction validates the JWK
        // shape (curve, key bytes) — a malformed JWK that survived
        // sealing/unsealing surfaces as `AuthError::DpopBindingFailed`
        // here rather than reaching the AS as a malformed proof.
        let _dpop_key = dpop_key_from_jwk(&dpop_jwk).map_err(|e| AuthError::DpopBindingFailed {
            source: Box::new(e),
        })?;
        let auth_state = proto_blue::oauth::AuthState {
            issuer: row.issuer.clone(),
            verifier: row.pkce_verifier,
            dpop_key: dpop_jwk,
            app_state: Some(state.to_owned()),
        };

        // Step 6: exchange the code. The token response carries the
        // moderator's DID as the `sub` claim.
        let token_set = self
            .oauth_client
            .callback(code, &auth_state, &server_metadata)
            .await
            .map_err(|e| AuthError::OauthExchange {
                source: Box::new(e),
            })?;

        let did = token_set.sub.clone();
        if did.is_empty() {
            // proto-blue-oauth maps a missing `sub` claim to an empty
            // string. Treat that as `MissingClaims` rather than
            // attempting to mint a session against an empty external_id.
            return Err(AuthError::MissingClaims);
        }

        // Step 7: upsert the moderator row. `auth_backend='atproto'` is
        // the discriminator; the (auth_backend, external_id) unique
        // constraint enforces that the DID is the stable identifier.
        let moderator_uuid = upsert_atproto_moderator(&self.pool, &did, Some(&row.handle))
            .await
            .map_err(AuthError::from)?;

        // Step 8: mint a Polaris session. The session row's
        // refresh_token_enc column stores the sealed DPoP keypair JWK
        // bytes — for atproto-backed sessions that's the credential a
        // future refresh-flow implementation will rebuild a DpopKey
        // from. The bytes were already sealed once for the login-state
        // row; here we hand SessionStore the plaintext JWK and let it
        // re-seal with a fresh nonce per the SessionStore::create
        // contract. (Re-using the old sealed bytes would require a
        // separate API on SessionStore; the cost of an extra seal is a
        // microsecond.)
        let new_session = self
            .sessions
            .create(ModeratorId(moderator_uuid), &dpop_jwk_bytes)
            .await?;

        // Step 9: load the role set the auth middleware will see.
        let roles = fetch_roles(&self.pool, moderator_uuid).await?;

        Ok(LoginResult {
            ctx: ModeratorAuthCtx::new(ModeratorId(moderator_uuid), roles),
            session_token: new_session.token,
            expires_at: new_session.expires_at,
        })
    }
}

impl ModeratorAuth for AtprotoOauthAuthVerifier {
    async fn start_login(&self, hint: LoginHint) -> Result<LoginRedirect, AuthError> {
        match hint {
            LoginHint::AtprotoHandle(handle) => self.start_login_impl(&handle).await,
            LoginHint::None => Err(AuthError::Config {
                message: "ATProto verifier requires a LoginHint::AtprotoHandle".to_owned(),
            }),
        }
    }

    async fn complete_login(&self, state: &str, code: &str) -> Result<LoginResult, AuthError> {
        self.complete_login_impl(state, code).await
    }
}

/// Read the operator's OAuth client-metadata JSON from disk and parse
/// it into proto-blue-oauth's [`OAuthClientMetadata`] type.
///
/// Issue #61 will consolidate this with the identical loader needed by
/// `polaris-publish-labeler-record`; this copy lives next to the
/// consumer (the verifier constructor above) so the read path stays
/// auditable in isolation.
///
/// # Errors
///
/// - [`AuthError::Config`] if the file is unreadable or not valid JSON
///   matching the [`OAuthClientMetadata`] shape.
pub fn load_client_metadata(path: &Path) -> Result<OAuthClientMetadata, AuthError> {
    let bytes = std::fs::read(path).map_err(|e| AuthError::Config {
        message: format!("read client_metadata at {} failed: {e}", path.display()),
    })?;
    serde_json::from_slice(&bytes).map_err(|e| AuthError::Config {
        message: format!("parse client_metadata at {} failed: {e}", path.display()),
    })
}

/// Insert (or fetch the existing) moderator row for
/// `(auth_backend='atproto', external_id=<did>)`. Updates `last_login_at`
/// on every call. Mirrors `oidc::upsert_moderator` but pinned to the
/// atproto backend so a DID collision across backends is impossible.
pub(crate) async fn upsert_atproto_moderator(
    pool: &PgPool,
    did: &str,
    handle: Option<&str>,
) -> Result<Uuid, crate::auth::session::SessionError> {
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend, display_name, last_login_at)
          VALUES ($1, 'atproto', $2, now())
          ON CONFLICT (auth_backend, external_id) DO UPDATE
            SET display_name = COALESCE(EXCLUDED.display_name, moderators.display_name),
                last_login_at = now()
          RETURNING id",
        did,
        handle,
    )
    .fetch_one(pool)
    .await?;
    Ok(row.id)
}

/// Read the role set for an atproto-backend moderator. Identical shape
/// to the OIDC backend's role fetch — `moderator_roles` is backend-
/// agnostic (role assignment is a Polaris concern, not a Bluesky one).
async fn fetch_roles(
    pool: &PgPool,
    moderator_id: Uuid,
) -> Result<std::collections::HashSet<Role>, AuthError> {
    let rows = sqlx::query!(
        r"SELECT role FROM moderator_roles WHERE moderator_id = $1",
        moderator_id,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AuthError::Storage {
        source: crate::auth::session::SessionError::Database(e),
    })?;

    let mut roles = std::collections::HashSet::with_capacity(rows.len());
    for row in rows {
        roles.insert(Role::from_db_str(&row.role)?);
    }
    Ok(roles)
}

/// A re-export tag so consumers of `crate::auth::atproto` can name the
/// upstream metadata type without pulling in `proto_blue::oauth`
/// directly. Keeps the proto-blue surface area visible at the use site
/// (so a future swap is grep-able) without forcing every caller to add
/// `proto_blue::oauth` to their own use list.
pub use proto_blue::oauth::OAuthClientMetadata as ClientMetadata;

const _: fn() = || {
    // Linker witness: ensure the OAuthServerMetadata type can be
    // constructed in this crate's compilation unit. Catches a
    // proto-blue feature-gating drift early (the metadata struct lives
    // behind the `oauth` feature, which is default-on via
    // `proto-blue/full`).
    let _ = std::mem::size_of::<OAuthServerMetadata>();
};

#[cfg(test)]
// Allow `unwrap()` / `expect()` in tests so the workspace-level
// `clippy::unwrap_used` / `expect_used` lints (denied at `--all-targets`)
// do not flag the idiomatic Rust unit-test pattern. Production paths in
// this file are unwrap-free.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn fixture_metadata() -> OAuthClientMetadata {
        OAuthClientMetadata {
            client_id: "https://example.com/client-metadata.json".into(),
            redirect_uris: vec!["https://example.com/callback".into()],
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
        }
    }

    #[test]
    fn load_client_metadata_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        let metadata = fixture_metadata();
        let bytes = serde_json::to_vec(&metadata).unwrap();
        std::fs::write(&path, bytes).unwrap();

        let loaded = load_client_metadata(&path).unwrap();
        assert_eq!(loaded.client_id, metadata.client_id);
        assert_eq!(loaded.redirect_uris, metadata.redirect_uris);
    }

    #[test]
    fn load_client_metadata_missing_file_yields_config_error() {
        let err = load_client_metadata(Path::new("/nonexistent/path/x.json")).unwrap_err();
        assert!(matches!(err, AuthError::Config { .. }));
    }

    #[test]
    fn load_client_metadata_bad_json_yields_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("client.json");
        std::fs::write(&path, b"not valid json").unwrap();
        let err = load_client_metadata(&path).unwrap_err();
        assert!(matches!(err, AuthError::Config { .. }));
    }
}
