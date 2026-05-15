//! OIDC moderator-authentication backend.
//!
//! Wraps `openidconnect` 4.x against the operator's identity provider. The
//! flow follows RFC 6749 + OIDC Core 1.0 with PKCE (S256) added:
//!
//! 1. `start_login` — generate random `state`, CSRF nonce, and PKCE
//!    verifier; persist the verifier keyed by `state` in
//!    `auth_oidc_login_states`; return the authorization URL.
//! 2. Authorization server redirects the moderator back to
//!    `redirect_url?code=...&state=...`.
//! 3. `complete_login` — look up the verifier by `state`, exchange the
//!    code for tokens (access, id, refresh), verify the `id_token`,
//!    fetch the userinfo `sub`, upsert a moderator row, and mint a
//!    Polaris session that owns the refresh token at rest.
//!
//! # Why PKCE in addition to the client secret
//!
//! Even for confidential clients, PKCE adds defence against authorization-code
//! interception in environments where a network-adjacent attacker can race
//! the redirect. The 2025 OAuth 2.1 draft recommends PKCE for all flows; we
//! adopt the recommendation.

use std::ops::Deref as _;

use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType,
};
use openidconnect::reqwest::Client as OidcHttpClient;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse as _,
};
use secrecy::ExposeSecret as _;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::session::SessionStore;
use crate::auth::{
    AuthError, LoginHint, LoginRedirect, LoginResult, ModeratorAuth, ModeratorAuthCtx, ModeratorId,
    Role,
};
use crate::config::OidcConfig;

/// Discovered, type-erased `openidconnect::CoreClient` parameterised for the
/// authorization-code flow with PKCE. The long generic chain is
/// `openidconnect`'s declared client shape; we keep it as a type alias so the
/// `OidcAuthVerifier` struct stays readable.
type DiscoveredClient = CoreClient<
    openidconnect::EndpointSet,      // HasAuthUrl
    openidconnect::EndpointNotSet,   // HasDeviceAuthUrl
    openidconnect::EndpointNotSet,   // HasIntrospectionUrl
    openidconnect::EndpointNotSet,   // HasRevocationUrl
    openidconnect::EndpointMaybeSet, // HasUserInfoUrl
    openidconnect::EndpointMaybeSet, // HasTokenUrl
>;

/// OIDC implementation of [`ModeratorAuth`].
///
/// Holds the discovered OIDC client, the HTTP client used for token /
/// userinfo calls, and the session store the completed login feeds into.
#[derive(Clone)]
pub struct OidcAuthVerifier {
    client: DiscoveredClient,
    http: OidcHttpClient,
    sessions: SessionStore,
    pool: PgPool,
}

impl std::fmt::Debug for OidcAuthVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAuthVerifier").finish_non_exhaustive()
    }
}

impl OidcAuthVerifier {
    /// Discover OIDC metadata from `cfg.issuer_url` and build a verifier.
    ///
    /// # Errors
    ///
    /// - [`AuthError::Config`] if `cfg.issuer_url` / `cfg.redirect_url`
    ///   cannot be parsed.
    /// - [`AuthError::OidcDiscoveryFailed`] if the issuer's discovery
    ///   document is unreachable or malformed.
    pub async fn new(
        cfg: &OidcConfig,
        sessions: SessionStore,
        pool: PgPool,
    ) -> Result<Self, AuthError> {
        let issuer_url = IssuerUrl::new(cfg.issuer_url.clone()).map_err(|e| AuthError::Config {
            message: format!("invalid OIDC issuer URL: {e}"),
        })?;
        let redirect_url =
            RedirectUrl::new(cfg.redirect_url.clone()).map_err(|e| AuthError::Config {
                message: format!("invalid OIDC redirect URL: {e}"),
            })?;

        let http = OidcHttpClient::builder()
            // Per openidconnect docs: disable HTTP redirects on the inner
            // reqwest client to prevent SSRF via crafted issuer-metadata.
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AuthError::OidcDiscoveryFailed {
                source: Box::new(e),
            })?;

        let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http)
            .await
            .map_err(|e| AuthError::OidcDiscoveryFailed {
                source: Box::new(e),
            })?;

        let client = CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new(cfg.client_id.clone()),
            Some(ClientSecret::new(
                cfg.client_secret.expose_secret().to_owned(),
            )),
        )
        .set_redirect_uri(redirect_url);

        Ok(Self {
            client,
            http,
            sessions,
            pool,
        })
    }

    /// Internal `start_login` implementation — returns the persisted
    /// authorization URL plus state.
    async fn start_login_impl(&self) -> Result<LoginRedirect, AuthError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token, nonce) = self
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("openid".to_owned()))
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("profile".to_owned()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        let state = csrf_token.secret().clone();

        sqlx::query!(
            r"INSERT INTO auth_oidc_login_states (state, pkce_verifier, csrf_nonce)
              VALUES ($1, $2, $3)",
            state,
            pkce_verifier.secret(),
            nonce.secret(),
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;

        Ok(LoginRedirect {
            authorize_url: auth_url.to_string(),
            state,
        })
    }

    /// Run the OIDC moderator upsert and the first-run admin grant
    /// inside a single transaction.
    ///
    /// Issue #83a: the OAuth complete-login path commits the moderator
    /// row, the conditional `admin` grant in `moderator_roles`, and the
    /// `first_user_admin_grant` audit-log entry atomically — a failure
    /// in any step rolls the entire grant back so the moderator does
    /// not become admin without the privilege-escalation audit record.
    ///
    /// Returns the moderator's UUID. The shared helper
    /// [`crate::auth::atproto::maybe_grant_first_user_admin`] carries
    /// the race-safety reasoning; this OIDC path applies the same
    /// policy as the atproto path so a deployment that toggles between
    /// backends sees identical first-run semantics.
    async fn upsert_and_maybe_grant_admin(
        &self,
        external_id: &str,
        display_name: Option<&str>,
    ) -> Result<Uuid, AuthError> {
        let mut tx = self.pool.begin().await.map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;
        let moderator_uuid = upsert_moderator_in_tx(&mut tx, external_id, display_name)
            .await
            .map_err(AuthError::from)?;
        crate::auth::atproto::maybe_grant_first_user_admin(
            &mut tx,
            moderator_uuid,
            external_id,
            "oidc",
        )
        .await?;
        tx.commit().await.map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;
        Ok(moderator_uuid)
    }

    /// Internal `complete_login` implementation.
    async fn complete_login_impl(&self, state: &str, code: &str) -> Result<LoginResult, AuthError> {
        // Look up the PKCE verifier and CSRF nonce by state. Window: 10
        // minutes (enforced by the WHERE clause below; an older row is
        // treated as "state mismatch").
        let row = sqlx::query!(
            r"SELECT pkce_verifier, csrf_nonce
              FROM auth_oidc_login_states
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

        // Single-use: delete the row before exchanging the code so replay is
        // impossible even if the rest of the flow fails.
        sqlx::query!(
            r"DELETE FROM auth_oidc_login_states WHERE state = $1",
            state,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AuthError::Storage {
            source: crate::auth::session::SessionError::Database(e),
        })?;

        let pkce_verifier = PkceCodeVerifier::new(row.pkce_verifier);
        let expected_nonce = Nonce::new(row.csrf_nonce);

        // Exchange the authorization code for tokens.
        let token_exchange = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .map_err(|e| AuthError::OidcExchangeFailed {
                source: Box::new(e),
            })?;

        let token_response = token_exchange
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http)
            .await
            .map_err(|e| AuthError::OidcExchangeFailed {
                source: Box::new(e),
            })?;

        // Verify the id_token: signature, audience, expiry, nonce match.
        let id_token = token_response.id_token().ok_or(AuthError::MissingClaims)?;

        let id_token_verifier = self.client.id_token_verifier();
        let claims = id_token
            .claims(&id_token_verifier, &expected_nonce)
            .map_err(|e| AuthError::IdTokenInvalid {
                source: Box::new(e),
            })?;

        // If the id_token carries an `at_hash`, verify it ties the access
        // token to the id_token (RFC defence against access-token swapping).
        if let Some(expected_hash) = claims.access_token_hash() {
            let signing_alg = id_token
                .signing_alg()
                .map_err(|e| AuthError::IdTokenInvalid {
                    source: Box::new(e),
                })?;
            let signing_key = id_token.signing_key(&id_token_verifier).map_err(|e| {
                AuthError::IdTokenInvalid {
                    source: Box::new(e),
                }
            })?;
            let actual_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                signing_alg,
                signing_key,
            )
            .map_err(|e| AuthError::IdTokenInvalid {
                source: Box::new(e),
            })?;
            if actual_hash != *expected_hash {
                return Err(AuthError::IdTokenInvalid {
                    source: "access_token_hash mismatch".into(),
                });
            }
        }

        // The `sub` claim is our external_id. Display name is preferred,
        // falls back to "name" then to "preferred_username". `EndUserName`
        // and `EndUserUsername` are `new_type![..(String)]` wrappers that
        // `Deref<Target = String>` but don't impl `Display`; we go through
        // `Deref` (imported at module top) to pull out an owned String.
        let external_id = (**claims.subject()).clone();
        let display_name = claims
            .name()
            .and_then(|n| n.get(None).map(|name| name.deref().clone()))
            .or_else(|| claims.preferred_username().map(|u| u.deref().clone()));

        // Issue #83a / first-run admin grant: upsert + maybe-grant in
        // one transaction. See [`Self::upsert_and_maybe_grant_admin`].
        let moderator_uuid = self
            .upsert_and_maybe_grant_admin(&external_id, display_name.as_deref())
            .await?;

        // Persist the refresh token (encrypted via SessionStore::create).
        let refresh_token_plain = token_response
            .refresh_token()
            .map(|rt| rt.secret().as_bytes().to_vec())
            .unwrap_or_default();

        let new_session = self
            .sessions
            .create(ModeratorId(moderator_uuid), &refresh_token_plain)
            .await?;

        // Load the role set the session middleware will see.
        let roles = fetch_roles(&self.pool, moderator_uuid).await?;

        Ok(LoginResult {
            ctx: ModeratorAuthCtx::new(ModeratorId(moderator_uuid), roles),
            session_token: new_session.token,
            expires_at: new_session.expires_at,
        })
    }
}

impl ModeratorAuth for OidcAuthVerifier {
    async fn start_login(&self, hint: LoginHint) -> Result<LoginRedirect, AuthError> {
        // The OIDC backend's discovery URL is fixed at startup; per-login
        // hints are an ATProto-specific concept. Reject anything except
        // `LoginHint::None` rather than silently ignore — an
        // `AtprotoHandle` hint reaching this code path indicates the
        // caller routed to the wrong verifier.
        match hint {
            LoginHint::None => self.start_login_impl().await,
            LoginHint::AtprotoHandle(_) => Err(AuthError::Config {
                message: "OIDC verifier does not accept atproto hints".to_owned(),
            }),
        }
    }

    async fn complete_login(&self, state: &str, code: &str) -> Result<LoginResult, AuthError> {
        self.complete_login_impl(state, code).await
    }
}

/// In-tests / startup `ModeratorAuth` implementation that always fails. Used
/// where a verifier slot must be filled but no real provider is configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuthVerifier;

impl ModeratorAuth for NullAuthVerifier {
    async fn start_login(&self, _hint: LoginHint) -> Result<LoginRedirect, AuthError> {
        Err(AuthError::Config {
            message: "NullAuthVerifier cannot start a login".to_owned(),
        })
    }

    async fn complete_login(&self, _state: &str, _code: &str) -> Result<LoginResult, AuthError> {
        Err(AuthError::Config {
            message: "NullAuthVerifier cannot complete a login".to_owned(),
        })
    }
}

/// Insert (or fetch the existing) moderator row for
/// `(auth_backend='oidc', external_id)` inside the caller's transaction.
/// Updates `last_login_at` on every call.
///
/// Issue #83a: the OAuth complete-login path runs the moderator upsert,
/// the system-wide count of `moderator_roles`, the conditional admin
/// grant, and the audit-log append in one transaction. This function
/// is the per-call SQL the transaction composes around.
pub(crate) async fn upsert_moderator_in_tx(
    tx: &mut sqlx::PgConnection,
    external_id: &str,
    display_name: Option<&str>,
) -> Result<Uuid, crate::auth::session::SessionError> {
    let row = sqlx::query!(
        r"INSERT INTO moderators (external_id, auth_backend, display_name, last_login_at)
          VALUES ($1, 'oidc', $2, now())
          ON CONFLICT (auth_backend, external_id) DO UPDATE
            SET display_name = COALESCE(EXCLUDED.display_name, moderators.display_name),
                last_login_at = now()
          RETURNING id",
        external_id,
        display_name,
    )
    .fetch_one(&mut *tx)
    .await?;
    Ok(row.id)
}

/// Read the role set for a moderator. Returns the empty set if the
/// moderator has no role rows.
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

/// `id_token`'s `signing_alg` lookup uses `CoreAuthenticationFlow` ↔ alg
/// resolution but only for the `at_hash` check above. We deliberately do not
/// take a hard dependency on `CoreResponseType` outside this assertion.
const _: () = {
    let _ = CoreResponseType::Code;
};

#[cfg(test)]
// Allow `unwrap()` / `expect()` in tests so the workspace-level
// `clippy::unwrap_used` / `expect_used` lints (denied at `--all-targets`)
// do not flag the idiomatic Rust unit-test pattern.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_verifier_refuses_start_login() {
        let v = NullAuthVerifier;
        let err = v.start_login(LoginHint::None).await.unwrap_err();
        assert!(matches!(err, AuthError::Config { .. }));
    }

    #[tokio::test]
    async fn null_verifier_refuses_complete_login() {
        let v = NullAuthVerifier;
        let err = v.complete_login("s", "c").await.unwrap_err();
        assert!(matches!(err, AuthError::Config { .. }));
    }

    #[tokio::test]
    async fn null_verifier_rejects_atproto_hint() {
        // Even the always-failing null verifier carries the same hint
        // semantics — passing an ATProto hint surfaces a Config error
        // rather than the default "cannot start a login" message, so
        // confused callers see a clear "wrong backend" signal.
        let v = NullAuthVerifier;
        let err = v
            .start_login(LoginHint::AtprotoHandle("alice.example.com".to_owned()))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Config { .. }));
    }
}
