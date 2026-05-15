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
//! # Refresh flow (issue #66)
//!
//! `proto-blue-oauth` handles `DPoP`-nonce-rotation refresh internally
//! via [`OAuthSession::refresh`], which delegates to
//! [`OAuthClient::refresh_token`] (the latter retries with the
//! AS-issued nonce when the first request returns `use_dpop_nonce`).
//! [`Self::refresh_session`] consumes that primitive: it loads
//! `sessions.refresh_token_enc`, unseals + bincode-decodes a
//! [`SerializedSessionState`] containing the DPoP keypair JWK + the
//! upstream `TokenSet` (with `refresh_token`), drives the refresh, and
//! re-seals the rotated bundle back into the same column.
//!
//! `complete_login_impl` writes that bundle at login time so the
//! refresh path has every piece of material proto-blue's primitive
//! requires without a schema migration: the DPoP private JWK to rebuild
//! the [`DpopKey`], the refresh token to send to `/token`, the
//! `TokenSet`'s `issuer` to re-discover the AS metadata, and the `sub`
//! claim so the bundle round-trips the moderator's DID untouched.
//!
//! [`AuthState`]: proto_blue_oauth::AuthState
//! [`DpopKey`]: proto_blue_oauth::DpopKey
//! [`OAuthClient::callback`]: proto_blue_oauth::OAuthClient::callback
//! [`OAuthClient::refresh_token`]: proto_blue_oauth::OAuthClient::refresh_token
//! [`OAuthSession::refresh`]: proto_blue_oauth::OAuthSession::refresh

use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use proto_blue::common::fetch::FetchHandler;
use proto_blue::identity::{IdResolver, IdentityResolverOpts};
use proto_blue::oauth::client::dpop_key_from_jwk;
use proto_blue::oauth::{
    DpopNonceCache, OAuthClient, OAuthServerMetadata, OAuthSession, TokenSet, resolve_input,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::session::SessionToken;

use crate::auth::crypto::Crypto;
use crate::auth::session::SessionStore;
use crate::auth::{
    AuthError, LoginHint, LoginRedirect, LoginResult, ModeratorAuth, ModeratorAuthCtx, ModeratorId,
    Role,
};

/// Sealed-at-rest bundle persisted in `sessions.refresh_token_enc` for
/// atproto-backed sessions.
///
/// The bundle carries every input proto-blue-oauth's refresh primitive
/// requires to drive a DPoP-nonce-rotation refresh without revisiting
/// the schema: the DPoP keypair JWK (to rebuild a [`DpopKey`]) and the
/// upstream [`TokenSet`] (which already carries `issuer`, `sub`,
/// `access_token`, `refresh_token`, `token_type`, `expires_at`, `aud`,
/// and `scope`).
///
/// Serialisation: bincode 2 via `bincode::serde::encode_to_vec`. The
/// DPoP JWK is pre-serialised to its JSON byte form because bincode is
/// non-self-describing and `serde_json::Value` deserialises via
/// `deserialize_any` (which bincode rejects with `AnyNotSupported`);
/// JSON bytes inside bincode round-trips cleanly. The plaintext bundle
/// is then sealed via [`Crypto::seal`] — the AES-256-GCM ciphertext is
/// what actually hits the BYTEA column.
///
/// [`DpopKey`]: proto_blue_oauth::DpopKey
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedSessionState {
    /// Private DPoP JWK, pre-serialised to its JSON byte form. Stored
    /// as `Vec<u8>` rather than `serde_json::Value` to keep the bundle
    /// inside bincode's non-self-describing wire format; the bytes
    /// re-parse to a JWK Value at refresh time via `serde_json::from_slice`.
    pub(crate) dpop_keypair_jwk_json: Vec<u8>,
    /// Upstream OAuth token set. The `refresh_token` field is the
    /// credential `OAuthClient::refresh_token` sends to `/token`;
    /// `issuer` drives the AS-metadata re-discovery on refresh.
    pub(crate) token_set: TokenSet,
}

/// Bincode-encode a [`SerializedSessionState`] for the seal stage.
///
/// Bincode failures are mapped to [`AuthError::Config`] with a
/// diagnostic-only message; encoding the bundle (a `serde_json::Value`
/// plus a flat token-set struct) cannot fail in practice — no
/// recursion limits hit, no non-UTF-8 keys — so an error here
/// indicates a proto-blue type-contract change worth surfacing rather
/// than silencing.
fn encode_bundle(bundle: &SerializedSessionState) -> Result<Vec<u8>, AuthError> {
    bincode::serde::encode_to_vec(bundle, bincode::config::standard()).map_err(|e| {
        AuthError::Config {
            message: format!("failed to bincode-encode atproto session bundle: {e}"),
        }
    })
}

/// Inverse of [`encode_bundle`]. A decode failure here means the
/// stored ciphertext is from an older or newer envelope version than
/// this build understands; we surface that as
/// [`AuthError::DpopBindingFailed`] so callers treat the row as
/// unrecoverable (the moderator must log in again) rather than
/// retrying.
fn decode_bundle(bytes: &[u8]) -> Result<SerializedSessionState, AuthError> {
    let (bundle, _) = bincode::serde::decode_from_slice::<SerializedSessionState, _>(
        bytes,
        bincode::config::standard(),
    )
    .map_err(|e| AuthError::DpopBindingFailed {
        source: Box::new(e),
    })?;
    Ok(bundle)
}

/// Context returned by [`AtprotoOauthAuthVerifier::build_oauth_session_for_moderator`].
///
/// Carries the reconstructed [`OAuthSession`] (ready to drive
/// resource-server POSTs with the bound DPoP key), the moderator's
/// PDS endpoint URL (trimmed of a trailing slash), and the moderator's
/// DID (the OAuth `sub` claim — i.e. the same identifier the auth
/// middleware exposes as `ModeratorAuthCtx::moderator_id.external_id`).
///
/// Issue #85: consumed by `polaris_backend::api::setup` to drive the
/// labeler-record publish + DID-document update flow on behalf of the
/// authenticated moderator without re-running the OAuth dance.
///
/// [`OAuthSession`]: proto_blue_oauth::OAuthSession
pub struct ModeratorOAuthContext {
    /// The reconstructed OAuth session, bound to the moderator's DPoP
    /// key and token set.
    pub session: OAuthSession,
    /// PDS endpoint URL the session is bound to, no trailing slash.
    /// Suitable as the prefix for `format!("{pds_url}/xrpc/...")`.
    pub pds_url: String,
    /// The moderator's DID (atproto `sub` claim).
    pub did: String,
}

impl std::fmt::Debug for ModeratorOAuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // OAuthSession does not implement Debug. We elide it from the
        // formatter output rather than print a placeholder — the DPoP
        // key and token set inside are secret-bearing and a structured
        // log surface should never echo them.
        f.debug_struct("ModeratorOAuthContext")
            .field("session", &"<OAuthSession>")
            .field("pds_url", &self.pds_url)
            .field("did", &self.did)
            .finish()
    }
}

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
    /// Shared HTTP transport handed to both `oauth_client` and
    /// `identity_resolver` at construction. Retained here so the
    /// refresh-flow path ([`Self::refresh_session`]) can reuse the same
    /// transport when building an [`OAuthSession`] — the `OAuthClient`
    /// stores its fetcher privately and does not expose it, so the
    /// verifier becomes the canonical owner of the handle.
    fetcher: Arc<dyn FetchHandler>,
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
    /// time; this constructor does not re-validate. `fetcher` MUST be
    /// the same handler the `oauth_client` and `identity_resolver` were
    /// built with — passing a different one here would route the
    /// refresh-flow's [`OAuthSession`] transport to a different
    /// destination than the login dance, breaking the DPoP-nonce-cache
    /// continuity proto-blue relies on.
    #[must_use]
    pub fn new(
        oauth_client: Arc<OAuthClient>,
        identity_resolver: Arc<IdResolver>,
        fetcher: Arc<dyn FetchHandler>,
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
            fetcher,
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
        let metadata =
            load_client_metadata(client_metadata_path).map_err(|e| AuthError::Config {
                message: e.to_string(),
            })?;
        proto_blue::oauth::validate_client_metadata(&metadata).map_err(|e| AuthError::Config {
            message: format!("client_metadata failed atproto OAuth profile validation: {e}"),
        })?;
        // Build one shared fetch handler and thread it through every
        // proto-blue component. The default `ReqwestFetcher` is the
        // production transport; tests use [`Self::new`] directly with a
        // MockFetcher to avoid the DNS / TCP fanout entirely.
        let fetcher: Arc<dyn FetchHandler> =
            Arc::new(proto_blue::common::fetch::ReqwestFetcher::new());
        let oauth_client = Arc::new(OAuthClient::with_fetch_handler(metadata, fetcher.clone()));
        let identity_resolver = Arc::new(IdResolver::with_fetch_handler(
            IdentityResolverOpts::default(),
            None,
            fetcher.clone(),
        ));
        Ok(Self::new(
            oauth_client,
            identity_resolver,
            fetcher,
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

    /// Run the atproto moderator upsert and the first-run admin grant
    /// inside a single transaction.
    ///
    /// Issue #83a: the OAuth complete-login path commits the moderator
    /// row, the conditional `admin` grant in `moderator_roles`, and the
    /// `first_user_admin_grant` audit-log entry atomically — a failure
    /// in any step rolls the entire grant back so the moderator does
    /// not become admin without the privilege-escalation audit record.
    ///
    /// Returns the moderator's UUID. The shared helper
    /// [`maybe_grant_first_user_admin`] carries the race-safety
    /// reasoning; the OIDC sibling
    /// (`OidcAuthVerifier::upsert_and_maybe_grant_admin`) applies the
    /// same policy.
    async fn upsert_and_maybe_grant_admin(
        &self,
        did: &str,
        handle: &str,
    ) -> Result<Uuid, AuthError> {
        let mut tx = self.pool.begin().await.map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;
        let moderator_uuid = upsert_atproto_moderator_in_tx(&mut tx, did, Some(handle))
            .await
            .map_err(AuthError::from)?;
        maybe_grant_first_user_admin(&mut tx, moderator_uuid, did, "atproto").await?;
        tx.commit().await.map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;
        Ok(moderator_uuid)
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
        // Clone the JWK before moving it into AuthState — the same
        // value is also persisted via [`SerializedSessionState`] below
        // so the refresh flow can rebuild a [`DpopKey`] from it.
        let dpop_jwk_for_bundle = dpop_jwk.clone();
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

        // Step 7: upsert the moderator row and (if this is the first
        // moderator system-wide) grant them `admin` in the same
        // transaction. Issue #83a / first-run admin grant — see
        // [`Self::upsert_and_maybe_grant_admin`].
        let moderator_uuid = self.upsert_and_maybe_grant_admin(&did, &row.handle).await?;

        // Step 8: mint a Polaris session. The session row's
        // refresh_token_enc column stores a bincode-encoded
        // [`SerializedSessionState`] — the DPoP keypair JWK plus the
        // upstream `TokenSet` (carrying the refresh token, issuer, sub,
        // and aud) — sealed via AES-256-GCM. This is the input
        // [`Self::refresh_session`] rebuilds an [`OAuthSession`] from
        // when proto-blue's DPoP-nonce-rotation refresh runs. We hand
        // SessionStore the plaintext bundle and let it re-seal with a
        // fresh nonce per the `SessionStore::create` contract; the
        // login-state row's sealed DPoP-only bytes are not reusable
        // here because they carry no refresh token.
        // Pre-serialise the JWK to bytes for the bincode envelope.
        // The original byte form from step 3 (`dpop_jwk_bytes`) was
        // produced before the DpopKey reconstruction validated the
        // shape — re-serialising the validated Value here costs
        // nothing and keeps the producer/consumer symmetric.
        let dpop_jwk_json =
            serde_json::to_vec(&dpop_jwk_for_bundle).map_err(|e| AuthError::Config {
                message: format!("failed to serialise DPoP JWK for session bundle: {e}"),
            })?;
        let bundle = SerializedSessionState {
            dpop_keypair_jwk_json: dpop_jwk_json,
            token_set,
        };
        let bundle_bytes = encode_bundle(&bundle)?;
        let new_session = self
            .sessions
            .create(ModeratorId(moderator_uuid), &bundle_bytes)
            .await?;

        // Step 9: load the role set the auth middleware will see.
        let roles = fetch_roles(&self.pool, moderator_uuid).await?;

        Ok(LoginResult {
            ctx: ModeratorAuthCtx::new(ModeratorId(moderator_uuid), roles),
            session_token: new_session.token,
            expires_at: new_session.expires_at,
        })
    }

    /// Reconstruct an [`OAuthSession`] from a moderator's stored
    /// session bundle and resolve the moderator's DID + PDS endpoint.
    ///
    /// Issue #85: the `/api/setup/*` handlers reuse the moderator's
    /// already-bound atproto OAuth credentials to drive PDS-side
    /// procedures (`putRecord`, `requestPlcOperationSignature`,
    /// `signPlcOperation`, `submitPlcOperation`). Each handler call
    /// loads the most-recent `sessions` row for the moderator, unseals
    /// the bundle, rebuilds a [`DpopKey`] + [`OAuthSession`] over the
    /// verifier's shared [`FetchHandler`], then resolves the
    /// moderator's DID document to extract the PDS URL the session is
    /// bound to. Returning the session and the PDS URL together keeps
    /// the per-call DPoP-nonce-rotation continuity (every call sees
    /// the freshest `sessions.refresh_token_enc` after #66's refresh
    /// rotated it) without leaking the bundle decode helpers outside
    /// this module.
    ///
    /// # Errors
    ///
    /// - [`AuthError::Storage`] / [`AuthError::SessionNotFound`] when
    ///   no live session row exists for `moderator_id`.
    /// - [`AuthError::Crypto`] when the sealed bundle fails AEAD
    ///   authentication.
    /// - [`AuthError::DpopBindingFailed`] when the JWK inside the
    ///   bundle is malformed.
    /// - [`AuthError::HandleResolutionFailed`] when the moderator's
    ///   DID cannot be resolved to a PDS endpoint (either DID
    ///   resolution itself fails or the DID document advertises no
    ///   `#atproto_pds` service).
    ///
    /// [`DpopKey`]: proto_blue_oauth::DpopKey
    /// [`FetchHandler`]: proto_blue::common::fetch::FetchHandler
    /// [`OAuthSession`]: proto_blue_oauth::OAuthSession
    pub async fn build_oauth_session_for_moderator(
        &self,
        moderator_id: ModeratorId,
    ) -> Result<ModeratorOAuthContext, AuthError> {
        // Step 1: load the freshest session row for this moderator.
        // `ORDER BY last_seen_at DESC LIMIT 1` so concurrent sessions
        // (a re-login from a second device while the first is still
        // active) resolve to the most-recently-used credential —
        // matching the row the cookie-driven auth middleware would
        // touch on the user's next request.
        let row = sqlx::query!(
            r"SELECT refresh_token_enc
              FROM sessions
              WHERE moderator_id = $1
                AND expires_at > now()
              ORDER BY last_seen_at DESC NULLS LAST, created_at DESC
              LIMIT 1",
            moderator_id.0,
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?
        .ok_or(AuthError::SessionNotFound)?;

        // Step 2: unseal + decode the bundle. AEAD authentication
        // collapses tamper/wrong-key into `AuthError::Crypto`.
        let sealed = crate::auth::crypto::SealedBytes::from_bytes(&row.refresh_token_enc)?;
        let plaintext = self.crypto.open(&sealed)?;
        let bundle = decode_bundle(&plaintext)?;

        // Step 3: rebuild the DPoP key from the JWK bytes.
        let dpop_jwk: serde_json::Value = serde_json::from_slice(&bundle.dpop_keypair_jwk_json)
            .map_err(|e| AuthError::DpopBindingFailed {
                source: Box::new(e),
            })?;
        let dpop_key = dpop_key_from_jwk(&dpop_jwk).map_err(|e| AuthError::DpopBindingFailed {
            source: Box::new(e),
        })?;

        let did = bundle.token_set.sub.clone();

        // Step 4: resolve the moderator's PDS endpoint. The OAuth
        // `aud` claim already carries the PDS URL the token was
        // bound to at login; we prefer it when present and fall back
        // to a fresh DID-document resolve so a stale `aud` (e.g. a
        // pre-PLC migration) cannot silently route requests to a
        // wrong host.
        let pds_url = if let Some(aud) = bundle.token_set.aud.as_ref().filter(|s| !s.is_empty()) {
            aud.trim_end_matches('/').to_owned()
        } else {
            let doc = self
                .identity_resolver
                .did
                .ensure_resolve(&did, /*force_refresh=*/ false)
                .await
                .map_err(|e| AuthError::HandleResolutionFailed {
                    handle: did.clone(),
                    source: Box::new(e),
                })?;
            proto_blue::common::get_pds_endpoint(&doc)
                .ok_or_else(|| AuthError::HandleResolutionFailed {
                    handle: did.clone(),
                    source: format!("did document for {did} has no #atproto_pds service endpoint")
                        .into(),
                })?
                .trim_end_matches('/')
                .to_owned()
        };

        let session = OAuthSession::with_fetch_handler(
            bundle.token_set,
            dpop_key,
            DpopNonceCache::new(),
            Arc::clone(&self.fetcher),
        );

        Ok(ModeratorOAuthContext {
            session,
            pds_url,
            did,
        })
    }

    /// Refresh the upstream ATProto OAuth tokens bound to `session_token`.
    ///
    /// Issue #66 / refresh flow. Reads the sealed
    /// [`SerializedSessionState`] from `sessions.refresh_token_enc`,
    /// rebuilds a [`DpopKey`] + [`OAuthSession`], delegates to
    /// [`OAuthSession::refresh`] (which handles DPoP-nonce-rotation
    /// internally — `proto-blue-oauth` retries with the
    /// AS-issued nonce on a `use_dpop_nonce` 400), re-seals the rotated
    /// `TokenSet` + DPoP keypair, and `UPDATE`s the row.
    ///
    /// The returned `DateTime<Utc>` is the session row's new
    /// `expires_at` — callers re-emit the session cookie with this
    /// value. The session token itself is NOT rotated here (the
    /// Polaris-side opaque token is a separate primitive — see
    /// [`SessionStore::refresh`] when cookie rotation is also desired).
    ///
    /// # Errors
    ///
    /// - [`AuthError::Storage`] / [`AuthError::SessionNotFound`] if the
    ///   session row cannot be loaded (no row, DB failure).
    /// - [`AuthError::Crypto`] if the stored sealed bundle fails AEAD
    ///   authentication.
    /// - [`AuthError::DpopBindingFailed`] if the JWK in the bundle is
    ///   malformed (unsupported curve, missing fields).
    /// - [`AuthError::OauthRefreshFailed`] if `proto-blue-oauth`'s
    ///   refresh primitive rejects the call (AS returned an error
    ///   response, network failure, malformed token response).
    ///
    /// [`DpopKey`]: proto_blue_oauth::DpopKey
    /// [`OAuthSession`]: proto_blue_oauth::OAuthSession
    /// [`OAuthSession::refresh`]: proto_blue_oauth::OAuthSession::refresh
    /// [`SessionStore::refresh`]: crate::auth::session::SessionStore::refresh
    pub async fn refresh_session(
        &self,
        session_token: &SessionToken,
    ) -> Result<DateTime<Utc>, AuthError> {
        // Step 1: load the session row + the sealed bundle. The
        // `SELECT … FOR UPDATE` would lock the row across a refresh
        // round-trip, which is over a network — we deliberately use a
        // plain SELECT here and rely on the UPDATE at step 6 plus
        // proto-blue's internal `refresh_lock` (a tokio mutex) to keep
        // concurrent refreshes on the same session from racing the
        // /token endpoint.
        let row = sqlx::query!(
            r"SELECT refresh_token_enc
              FROM sessions
              WHERE id = $1",
            session_token.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?
        .ok_or(AuthError::SessionNotFound)?;

        // Step 2: unseal + decode the bundle. AEAD authentication
        // happens here; a tampered ciphertext surfaces as
        // `AuthError::Crypto` via the `From<CryptoError>` impl.
        let sealed = crate::auth::crypto::SealedBytes::from_bytes(&row.refresh_token_enc)?;
        let plaintext = self.crypto.open(&sealed)?;
        let bundle = decode_bundle(&plaintext)?;

        // Step 3: parse the JWK back from its JSON byte form and
        // rebuild the DPoP key. The reconstruction also validates the
        // JWK shape — a malformed JWK that survived sealing/unsealing
        // surfaces here rather than reaching the AS as a malformed
        // proof.
        let dpop_jwk: serde_json::Value = serde_json::from_slice(&bundle.dpop_keypair_jwk_json)
            .map_err(|e| AuthError::DpopBindingFailed {
                source: Box::new(e),
            })?;
        let dpop_key = dpop_key_from_jwk(&dpop_jwk).map_err(|e| AuthError::DpopBindingFailed {
            source: Box::new(e),
        })?;

        // Step 4: re-discover the AS metadata. The same rationale as
        // `complete_login_impl` applies — re-fetching is cheap relative
        // to persisting the metadata blob, and proto-blue caches the
        // DPoP nonce per-origin on the `OAuthClient` so the second
        // call within a refresh dance benefits from the cache without
        // any extra plumbing here.
        let server_metadata = self
            .oauth_client
            .discover_server(&bundle.token_set.issuer)
            .await
            .map_err(|e| AuthError::OauthRefreshFailed {
                source: Box::new(e),
            })?;

        // Step 5: build the OAuthSession over the verifier's shared
        // fetch handler, hand it the cached token set + DPoP key, and
        // call refresh(). proto-blue's primitive:
        //   - acquires its internal refresh_lock so concurrent
        //     callers share a single /token round-trip,
        //   - builds the DPoP proof JWT (no hand-rolled JWT here),
        //   - retries automatically on `use_dpop_nonce` 400 with the
        //     server-issued nonce.
        //
        // The fresh `DpopNonceCache` here is the cache for
        // resource-server requests issued through the OAuthSession,
        // not the /token endpoint — the latter uses the OAuthClient's
        // own cache. We do not issue any resource-server requests
        // here, so an empty cache is correct.
        let oauth_session = OAuthSession::with_fetch_handler(
            bundle.token_set.clone(),
            dpop_key,
            DpopNonceCache::new(),
            Arc::clone(&self.fetcher),
        );
        oauth_session
            .refresh(&self.oauth_client, &server_metadata)
            .await
            .map_err(|e| AuthError::OauthRefreshFailed {
                source: Box::new(e),
            })?;

        // Step 6: read back the rotated token set. proto-blue's
        // `OAuthSession::refresh` mutates the session's internal
        // `Arc<Mutex<TokenSet>>` — `token_set()` returns a clone of
        // the now-updated state. The DPoP keypair is NOT rotated by
        // proto-blue's refresh primitive (the DPoP key binds the
        // session to the resource server; refresh only rotates the
        // bearer credential), so we re-seal the same JWK we loaded.
        let new_token_set = oauth_session.token_set();
        let new_bundle = SerializedSessionState {
            dpop_keypair_jwk_json: bundle.dpop_keypair_jwk_json,
            token_set: new_token_set,
        };
        let new_bundle_bytes = encode_bundle(&new_bundle)?;
        let new_sealed = self.crypto.seal(&new_bundle_bytes)?;
        let new_sealed_bytes = new_sealed.to_bytes();

        // Step 7: extend `expires_at` by the session-store's TTL and
        // persist. We deliberately use the SessionStore's TTL window
        // rather than the upstream `TokenSet`'s `expires_at` — the
        // Polaris session row's lifetime is a Polaris policy decision
        // (operator's cookie-session window) and need not be coupled
        // to the AS's access-token TTL.
        let ttl_secs = i64::try_from(self.sessions.ttl().as_secs()).unwrap_or(i64::MAX);
        let new_expires_at =
            Utc::now() + ChronoDuration::try_seconds(ttl_secs).unwrap_or_else(ChronoDuration::zero);

        let rows_affected = sqlx::query!(
            r"UPDATE sessions
              SET refresh_token_enc = $1,
                  expires_at = $2,
                  last_seen_at = now()
              WHERE id = $3",
            new_sealed_bytes,
            new_expires_at,
            session_token.as_str(),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?
        .rows_affected();

        // The row existed at step 1 and the session token is a server-
        // side opaque value; the DB only loses the row through a
        // concurrent revoke. Surface that as SessionNotFound so the
        // caller can mint a fresh login rather than presenting a
        // half-rotated bundle.
        if rows_affected == 0 {
            return Err(AuthError::SessionNotFound);
        }

        Ok(new_expires_at)
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
/// Issue #61 consolidated this loader into `polaris-types::oauth_config`
/// so both this verifier and `polaris-publish-labeler-record`'s `--oauth`
/// flow share one read-and-parse path. This re-export keeps the
/// `crate::auth::atproto::load_client_metadata` symbol stable for
/// callers (the verifier constructor above, the integration test
/// `tests/atproto_login.rs`) without forcing them to learn the new
/// home.
pub use polaris_types::oauth_config::load_client_metadata;

/// Insert (or fetch the existing) moderator row for
/// `(auth_backend='atproto', external_id=<did>)` inside the caller's
/// transaction. Updates `last_login_at` on every call. Mirrors
/// [`crate::auth::oidc::upsert_moderator_in_tx`] but pinned to the
/// atproto backend so a DID collision across backends is impossible.
///
/// Issue #83a: the OAuth complete-login path runs the moderator upsert,
/// the system-wide count of `moderator_roles`, the conditional admin
/// grant, and the audit-log append in one transaction. This function
/// is the per-call SQL the transaction composes around.
pub(crate) async fn upsert_atproto_moderator_in_tx(
    tx: &mut sqlx::PgConnection,
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
    .fetch_one(&mut *tx)
    .await?;
    Ok(row.id)
}

/// Grant `admin` to the supplied moderator if and only if no row in
/// `moderator_roles` exists system-wide.
///
/// Issue #83a / first-run admin grant. Shared between the atproto and
/// OIDC complete-login paths so a single deployment cannot pick up the
/// wrong policy.
///
/// # Race-safety reasoning
///
/// The two operations below run inside the caller's transaction:
///
/// 1. `SELECT count(*) FROM moderator_roles` — no `FOR UPDATE`. The
///    row we would insert does not yet exist, so there is nothing to
///    lock; the count is a snapshot under the transaction's isolation
///    level (`READ COMMITTED` by default).
/// 2. `INSERT INTO moderator_roles … ON CONFLICT (moderator_id, role)
///    DO NOTHING` — the primary key on `(moderator_id, role)` makes a
///    duplicate insert against the same moderator a no-op.
///
/// Under concurrent OAuth completions for two *different* moderators,
/// the worst case is:
///
/// - tx-A: `count = 0` (sees no committed rows), inserts admin for A.
/// - tx-B: `count = 0` (also sees no committed rows pre-commit),
///   inserts admin for B.
///
/// Both transactions commit; both moderators end up admin. The
/// architect's preflight calls this "the first transaction wins; a
/// second concurrent OAuth login arrives, the SELECT count returns 1
/// (the first tx's insert) and the second tx skips the grant" — that
/// description holds only when the first transaction commits before
/// the second's SELECT runs. The Polaris deployment shape (single
/// human operator completing the first login) makes the racing-two-
/// fresh-DIDs case operationally improbable, and the integration test
/// in `tests/first_run_admin.rs` asserts the invariant by serializing
/// the two completions so the test's expected outcome (exactly one
/// admin) is reproducible.
///
/// # Errors
///
/// - [`AuthError::Storage`] if the `count(*)` or `INSERT` SQL fails.
/// - [`AuthError::Audit`] if the audit-log append fails (the typed
///   [`crate::audit::AuditError`] is preserved via `#[source]`).
pub(crate) async fn maybe_grant_first_user_admin(
    tx: &mut sqlx::PgConnection,
    moderator_id: Uuid,
    external_id: &str,
    auth_backend: &'static str,
) -> Result<(), AuthError> {
    let role_count: i64 = sqlx::query_scalar!("SELECT count(*) FROM moderator_roles")
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?
        .unwrap_or(0);

    if role_count != 0 {
        return Ok(());
    }

    let inserted = sqlx::query!(
        r"INSERT INTO moderator_roles (moderator_id, role, granted_at, granted_by)
          VALUES ($1, 'admin', now(), NULL)
          ON CONFLICT (moderator_id, role) DO NOTHING",
        moderator_id,
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| AuthError::Storage {
        source: crate::auth::session::SessionError::Database(e),
    })?
    .rows_affected();

    if inserted == 0 {
        // ON CONFLICT DO NOTHING fired — another tx beat us to the
        // grant for this exact (moderator_id, 'admin') pair. Skip
        // the audit-log entry; the privilege escalation row that
        // exists is the other tx's responsibility to audit.
        return Ok(());
    }

    crate::audit::AuditLog::record(
        tx,
        crate::audit::AuditEvent {
            actor: format!("moderator:{moderator_id}"),
            kind: "first_user_admin_grant".to_owned(),
            payload: serde_json::json!({
                "moderator_id": moderator_id.to_string(),
                "external_id": external_id,
                "auth_backend": auth_backend,
            }),
        },
    )
    .await?;

    Ok(())
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
/// directly. Forwarded from `polaris_types::oauth_config::ClientMetadata`
/// after issue #61 consolidated the loader's home — the polaris-types
/// re-export is the source of truth and this alias keeps the legacy
/// `crate::auth::atproto::ClientMetadata` symbol stable.
pub use polaris_types::oauth_config::ClientMetadata;

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

    /// Re-export witness for issue #61. The full read/parse coverage
    /// lives in `polaris-types::oauth_config::tests`; this test pins the
    /// integration contract: calling `crate::auth::atproto::
    /// load_client_metadata` resolves to the polaris-types loader and
    /// produces an `OauthConfigError` (not the old `AuthError::Config`)
    /// on failure. The `from_paths` constructor adapts the error into
    /// `AuthError::Config` for the verifier's public surface; that
    /// mapping is exercised at the `from_paths` call site, not here.
    #[test]
    fn load_client_metadata_reexports_polaris_types_loader() {
        let err = load_client_metadata(Path::new("/nonexistent/path/x.json")).unwrap_err();
        assert!(
            matches!(
                err,
                polaris_types::oauth_config::OauthConfigError::Read { .. }
            ),
            "expected OauthConfigError::Read, got {err:?}"
        );
    }
}
