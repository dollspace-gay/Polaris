//! Moderator authentication.
//!
//! Issue #9 introduces the `ModeratorAuth` trait (the abstraction M4 will
//! reuse to plug ATProto OAuth alongside OIDC), the OIDC implementation
//! ([`oidc::OidcAuthVerifier`]), the Polaris session store
//! ([`session::SessionStore`]), and AES-256-GCM refresh-token encryption
//! ([`crypto::Crypto`]).
//!
//! # Design invariants
//!
//! - **Polaris issues opaque session cookies.** The client never sees a raw
//!   OIDC access token or refresh token. The cookie value is a 32-byte
//!   `OsRng` blob, base64url-encoded (no padding), with no derivable
//!   relationship to upstream credentials.
//! - **Refresh tokens are encrypted at rest.** Plaintext refresh tokens
//!   sitting in Postgres would make a database disclosure equivalent to a
//!   full `IdP` credential compromise. AES-256-GCM with a fresh nonce per row
//!   keeps the `IdP` credential at-rest-encrypted under the deployment's
//!   cookie key.
//! - **Async-fn-in-trait (AFIT) only.** MSRV 1.88 covers AFIT (stable since
//!   1.75); we do NOT use the `async_trait` macro.
//! - **Typed errors.** Every public function in this module returns a
//!   `Result<_, AuthError>` (or a sub-error that converts via `From`).
//!   `anyhow` does not appear in the trait surface.
//!
//! # Module layout
//!
//! - [`crypto`] — AES-256-GCM seal/open primitives.
//! - [`session`] — DB-backed opaque session store.
//! - [`oidc`] — `OidcAuthVerifier`: OIDC discovery, login redirect,
//!   code-exchange, session minting.

pub mod atproto;
pub mod crypto;
pub mod login_gate;
pub mod oidc;
pub mod session;
pub mod webauthn;

use std::collections::HashSet;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::atproto::AtprotoOauthAuthVerifier;
use crate::auth::crypto::Crypto;
use crate::auth::oidc::OidcAuthVerifier;
use crate::auth::session::SessionStore;
use crate::config::{AuthBackend, AuthConfig};

use crate::auth::crypto::CryptoError;
use crate::auth::session::SessionError;

/// Stable identifier for a moderator row in Postgres.
///
/// Newtype around `Uuid` (NOT a type alias) so callers cannot accidentally
/// confuse a `ModeratorId` with a `SubjectId` or any other UUID. The inner
/// value is `pub` because consumers in the same workspace need direct access
/// to the wrapped UUID for `SQLx` binding; the newtype barrier still prevents
/// accidental cross-typing through the function-signature surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(transparent)]
#[serde(transparent)]
pub struct ModeratorId(pub Uuid);

impl ModeratorId {
    /// Generate a fresh random `ModeratorId`. Used only in tests today;
    /// production rows get their UUID from Postgres' `gen_random_uuid()`.
    #[must_use]
    pub fn new_v4() -> Self {
        Self(Uuid::new_v4())
    }

    /// Borrow the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl std::fmt::Display for ModeratorId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// Moderator role. Stored as a TEXT column on `moderator_roles.role` and
/// constrained by the SQL CHECK to one of these five values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full system access including role assignment and key rotation.
    Admin,
    /// Senior moderators may co-sign pattern actions and reverse any action.
    SeniorModerator,
    /// Standard moderator — can act on individual cases.
    Moderator,
    /// Triage role — can route and tag but not take terminal action.
    Triage,
    /// Read-only audit role.
    ReadOnly,
}

impl Role {
    /// Database TEXT-column encoding. Matches the CHECK constraint in
    /// `00000000000001_auth.sql`.
    #[must_use]
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::SeniorModerator => "senior_moderator",
            Self::Moderator => "moderator",
            Self::Triage => "triage",
            Self::ReadOnly => "read_only",
        }
    }

    /// Inverse of [`Self::as_db_str`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::UnknownRole`] if `value` is not one of the five
    /// documented role identifiers.
    pub fn from_db_str(value: &str) -> Result<Self, AuthError> {
        match value {
            "admin" => Ok(Self::Admin),
            "senior_moderator" => Ok(Self::SeniorModerator),
            "moderator" => Ok(Self::Moderator),
            "triage" => Ok(Self::Triage),
            "read_only" => Ok(Self::ReadOnly),
            other => Err(AuthError::UnknownRole {
                value: other.to_owned(),
            }),
        }
    }
}

/// Authenticated moderator context.
///
/// Attached to every authenticated request via an Axum
/// `Extension<ModeratorAuthCtx>` by [`crate::middleware::auth::auth_middleware`].
/// `roles` is a `HashSet<Role>` so callers can ask "does this moderator have
/// role X" in O(1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeratorAuthCtx {
    /// Stable moderator identifier — the `moderators.id` PK.
    pub moderator_id: ModeratorId,
    /// Role set granted to this moderator. Derived from `moderator_roles`.
    pub roles: HashSet<Role>,
}

impl ModeratorAuthCtx {
    /// Construct a new `ModeratorAuthCtx`. Used by the auth implementations
    /// and by tests; production handlers receive this via an extension and
    /// do not construct it themselves.
    #[must_use]
    pub fn new(moderator_id: ModeratorId, roles: HashSet<Role>) -> Self {
        Self {
            moderator_id,
            roles,
        }
    }
}

/// First-stage output of a moderator login flow.
///
/// Carries the redirect URL the client must follow to reach the upstream
/// authorization endpoint, plus the `state` parameter the authorization
/// server will echo back so the callback handler can resume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRedirect {
    /// Authorization URL the client should redirect to.
    pub authorize_url: String,
    /// Random state token; persisted server-side in
    /// `auth_oidc_login_states` so the callback can recover the PKCE
    /// verifier.
    pub state: String,
}

/// Output of a successful code-exchange.
///
/// Carries the authenticated [`ModeratorAuthCtx`] plus the opaque Polaris
/// session cookie value the client must present on every subsequent request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginResult {
    /// Authenticated moderator.
    pub ctx: ModeratorAuthCtx,
    /// Opaque Polaris session token. 32 random bytes, base64url-encoded.
    pub session_token: session::SessionToken,
    /// Absolute expiration time of the session row.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Login hint passed to [`ModeratorAuth::start_login`].
///
/// The OIDC backend doesn't need any per-login input (the `IdP` discovery
/// URL is fixed at startup), but the ATProto backend MUST be told which
/// handle to resolve before it can fetch the per-account authorization-server
/// metadata. The `enum`-shaped hint keeps the trait surface uniform; OIDC
/// matches [`LoginHint::None`] and proceeds, anything else returns
/// [`AuthError::Config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginHint {
    /// No hint. The verifier already knows everything it needs (OIDC has
    /// a single discovery URL configured at startup).
    None,
    /// The moderator's ATProto handle, e.g. `alice.example.com`. The
    /// ATProto backend resolves this to a DID + PDS + authorization
    /// server before starting the OAuth dance.
    AtprotoHandle(String),
}

/// Authentication trait: the abstraction the ATProto OAuth backend plugs into.
///
/// Both halves of the login dance (the redirect-out and the callback-in)
/// live on this trait so the OIDC and ATProto implementations lay down the
/// same shape. AFIT (`async fn` in trait) is used directly — no
/// `async_trait` macro, MSRV 1.88 permits it.
#[allow(clippy::missing_errors_doc)] // Trait-level documentation already covers errors.
pub trait ModeratorAuth: Send + Sync {
    /// Begin a login flow.
    ///
    /// Returns the URL the client should redirect to. The caller is expected
    /// to set a `Location` header to `LoginRedirect::authorize_url` and a
    /// 302/303 status.
    ///
    /// `hint` carries any per-login input the verifier needs:
    /// [`LoginHint::AtprotoHandle`] for the ATProto backend (moderator's
    /// handle, e.g. `alice.example.com`), [`LoginHint::None`] for OIDC.
    fn start_login(
        &self,
        hint: LoginHint,
    ) -> impl std::future::Future<Output = Result<LoginRedirect, AuthError>> + Send;

    /// Complete a login flow.
    ///
    /// `state` and `code` come from the authorization server's callback to
    /// `redirect_url`. On success, a fresh Polaris session is minted and
    /// returned alongside the authenticated [`ModeratorAuthCtx`].
    fn complete_login(
        &self,
        state: &str,
        code: &str,
    ) -> impl std::future::Future<Output = Result<LoginResult, AuthError>> + Send;
}

/// Top-level error returned by the auth module.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// The OIDC issuer's metadata could not be discovered.
    #[error("OIDC discovery failed")]
    OidcDiscoveryFailed {
        /// Underlying transport / parse error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The OIDC token endpoint rejected the code exchange.
    #[error("OIDC token exchange failed")]
    OidcExchangeFailed {
        /// Underlying error from `openidconnect`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The OIDC userinfo endpoint rejected the access token.
    #[error("OIDC userinfo request failed")]
    OidcUserinfoFailed {
        /// Underlying error from `openidconnect`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The ID token signature or claims failed validation.
    #[error("OIDC id_token verification failed")]
    IdTokenInvalid {
        /// Underlying claims-verification error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The `state` parameter on the callback did not match a row in
    /// `auth_oidc_login_states`. Either it was forged, replayed, or expired.
    #[error("OIDC state mismatch or expired")]
    StateMismatch,

    /// The OIDC provider returned a userinfo response without a `sub` claim.
    #[error("OIDC response missing required claims")]
    MissingClaims,

    /// The session cookie did not correspond to any row in `sessions`.
    #[error("session not found")]
    SessionNotFound,

    /// The session row was found but its `expires_at` is in the past.
    #[error("session expired")]
    SessionExpired,

    /// Catch-all for [`SessionStore`] errors that surface to the trait API.
    ///
    /// [`SessionStore`]: crate::auth::session::SessionStore
    #[error("session store failure")]
    Storage {
        /// Underlying `SessionError`.
        #[source]
        source: SessionError,
    },

    /// Catch-all for crypto failures bubbling up through this layer.
    #[error("crypto failure")]
    Crypto {
        /// Underlying `CryptoError`.
        #[source]
        source: CryptoError,
    },

    /// The `moderator_roles.role` column contained a value not in the known
    /// role enum. Surfaces as a 500 — it indicates schema drift.
    #[error("unknown role in moderator_roles row: {value}")]
    UnknownRole {
        /// Offending TEXT value from the DB.
        value: String,
    },

    /// Catch-all configuration mistake.
    #[error("invalid auth configuration: {message}")]
    Config {
        /// Operator-facing description of what's wrong.
        message: String,
    },

    /// The ATProto OAuth PAR (Pushed Authorization Request) failed.
    ///
    /// Issue #31 / AC-4 — the operator's authorization server rejected
    /// the PAR call. The underlying error from `proto-blue-oauth` is
    /// captured via `#[source]` for structured logs; the `Display` text
    /// is deliberately generic so it cannot be probed.
    #[error("OAuth PAR request failed")]
    OauthPar {
        /// Underlying error from `proto-blue-oauth`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The ATProto OAuth code-exchange call failed.
    ///
    /// Either the AS rejected the code/verifier pair (replay, expired,
    /// wrong client) or the response was malformed. The `Display` text
    /// is generic by design.
    #[error("OAuth code exchange failed")]
    OauthExchange {
        /// Underlying error from `proto-blue-oauth`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The DPoP keypair could not be reconstructed or used to bind a
    /// proof to the request. Indicates either tampered ciphertext on the
    /// stored keypair row or a JWK-shape mismatch.
    #[error("DPoP binding failed")]
    DpopBindingFailed {
        /// Underlying error from `proto-blue-oauth`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Resolving the moderator's handle to a DID / PDS / authorization
    /// server failed. The handle string is included in the error so an
    /// operator can correlate logs against the user input; the underlying
    /// resolver error is captured via `#[source]`.
    #[error("handle resolution failed: {handle}")]
    HandleResolutionFailed {
        /// The handle the moderator entered.
        handle: String,
        /// Underlying error from `proto-blue-identity` /
        /// `proto-blue-oauth::resolve_input`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The ATProto OAuth refresh call failed.
    ///
    /// Issue #66 / refresh flow — `proto-blue-oauth`'s
    /// [`OAuthSession::refresh`] rejected the request (AS returned an
    /// error response, network failure, or malformed token response).
    /// The `Display` text is deliberately generic so it cannot be
    /// probed; the underlying error is captured via `#[source]` for
    /// structured-log surfaces.
    ///
    /// [`OAuthSession::refresh`]: proto_blue_oauth::OAuthSession::refresh
    #[error("OAuth refresh failed")]
    OauthRefreshFailed {
        /// Underlying error from `proto-blue-oauth`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Audit-log append failed during a login-side privilege grant.
    ///
    /// Issue #83 / first-run admin grant: when the very first
    /// moderator's complete-login path inserts the `admin` row in
    /// `moderator_roles`, it also writes an audit-log entry recording
    /// the privilege escalation. A failure in that append (chain-break,
    /// CBOR encode failure, database error) rolls the transaction back
    /// — the moderator does not become admin if the audit record cannot
    /// be persisted. The `#[source]` chain preserves the underlying
    /// [`crate::audit::AuditError`] for structured-log surfaces.
    #[error("audit-log append failed during login")]
    Audit {
        /// Underlying [`crate::audit::AuditError`].
        #[source]
        source: crate::audit::AuditError,
    },
}

impl From<crate::audit::AuditError> for AuthError {
    fn from(source: crate::audit::AuditError) -> Self {
        Self::Audit { source }
    }
}

impl From<SessionError> for AuthError {
    fn from(source: SessionError) -> Self {
        Self::Storage { source }
    }
}

impl From<CryptoError> for AuthError {
    fn from(source: CryptoError) -> Self {
        Self::Crypto { source }
    }
}

/// A type-erased handle to either authentication backend.
///
/// The [`ModeratorAuth`] trait uses AFIT (`async fn` in trait), which is
/// not `dyn`-compatible. To avoid forcing every consumer of the trait
/// onto a generic parameter, this enum wraps the two concrete verifiers
/// in a `Send + Sync + 'static` shape that can live behind an `Arc` and
/// be threaded through API handler state.
///
/// The enum stays `pub` so a future third backend lands here without an
/// API churn at every call site; the `match` against [`AuthBackend`] in
/// [`build_moderator_auth`] is the single switch.
#[derive(Debug)]
pub enum AnyModeratorAuth {
    /// OIDC backend (issue #9).
    Oidc(OidcAuthVerifier),
    /// ATProto OAuth backend (issue #31).
    Atproto(AtprotoOauthAuthVerifier),
}

impl AnyModeratorAuth {
    /// Borrow the inner [`AtprotoOauthAuthVerifier`] when the variant is
    /// [`AnyModeratorAuth::Atproto`]; `None` otherwise.
    ///
    /// Issue #67 — the `/auth/atproto/{login,callback}` HTTP handlers
    /// reach the atproto-specific surface ([`AtprotoOauthAuthVerifier::start_login`]
    /// / [`AtprotoOauthAuthVerifier::complete_login`]) through this
    /// downcast rather than the trait method on [`ModeratorAuth`],
    /// because the trait method takes a [`LoginHint`] enum and the
    /// HTTP handler already has a typed handle in hand. Routing the
    /// call through the enum-typed trait method would force the
    /// handler to construct a [`LoginHint::AtprotoHandle`] and then
    /// re-match inside the verifier — this method short-circuits that
    /// round-trip when the route is atproto-specific.
    ///
    /// When the deployment's `[auth] backend` is set to `oidc`, the
    /// `/auth/atproto/*` HTTP routes are still mounted (the router is
    /// not backend-aware) and this method returns `None`; the HTTP
    /// handler surfaces that as a 400 with a generic message so the
    /// caller cannot probe the backend selection from a 404 vs. 400
    /// shape.
    #[must_use]
    pub fn as_atproto(&self) -> Option<&AtprotoOauthAuthVerifier> {
        match self {
            Self::Atproto(v) => Some(v),
            Self::Oidc(_) => None,
        }
    }
}

impl ModeratorAuth for AnyModeratorAuth {
    async fn start_login(&self, hint: LoginHint) -> Result<LoginRedirect, AuthError> {
        match self {
            Self::Oidc(v) => v.start_login(hint).await,
            Self::Atproto(v) => v.start_login(hint).await,
        }
    }

    async fn complete_login(&self, state: &str, code: &str) -> Result<LoginResult, AuthError> {
        match self {
            Self::Oidc(v) => v.complete_login(state, code).await,
            Self::Atproto(v) => v.complete_login(state, code).await,
        }
    }
}

/// Construct the active [`ModeratorAuth`] implementation from configuration.
///
/// Both OIDC and ATProto backends compile into every binary; the
/// `[auth] backend` toggle drives the runtime selection. The returned
/// `Arc<AnyModeratorAuth>` lets `main.rs` thread a single trait object
/// through the API layer without monomorphising on the concrete verifier
/// type — the enum wraps the two AFIT-typed verifiers in a shape that
/// can live behind an `Arc` despite the trait itself being non-`dyn`-
/// compatible.
///
/// # Errors
///
/// - [`AuthError::Config`] when the selected backend's required
///   configuration is missing or invalid (empty
///   `atproto.client_metadata_path`, unreadable `client_metadata.json`,
///   etc.).
/// - [`AuthError::OidcDiscoveryFailed`] when the OIDC backend cannot
///   reach the configured issuer's discovery endpoint at startup.
pub async fn build_moderator_auth(
    auth_cfg: &AuthConfig,
    sessions: SessionStore,
    crypto: Crypto,
    pool: PgPool,
) -> Result<Arc<AnyModeratorAuth>, AuthError> {
    match auth_cfg.backend {
        AuthBackend::Oidc => {
            let verifier = OidcAuthVerifier::new(&auth_cfg.oidc, sessions, pool).await?;
            Ok(Arc::new(AnyModeratorAuth::Oidc(verifier)))
        }
        AuthBackend::Atproto => {
            if auth_cfg.atproto.client_metadata_path.as_os_str().is_empty() {
                return Err(AuthError::Config {
                    message: "POLARIS_ATPROTO_CLIENT_METADATA must be set when backend=atproto"
                        .to_owned(),
                });
            }
            let verifier = AtprotoOauthAuthVerifier::from_paths(
                &auth_cfg.atproto.client_metadata_path,
                sessions,
                crypto,
                pool,
            )?;
            Ok(Arc::new(AnyModeratorAuth::Atproto(verifier)))
        }
    }
}

#[cfg(test)]
// Allow `unwrap()` / `expect()` in tests so the workspace-level
// `clippy::unwrap_used` / `expect_used` lints (denied at `--all-targets`)
// do not flag the idiomatic Rust unit-test pattern. Production paths in
// this file are unwrap-free.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn role_round_trip_through_db_string() {
        for role in [
            Role::Admin,
            Role::SeniorModerator,
            Role::Moderator,
            Role::Triage,
            Role::ReadOnly,
        ] {
            let s = role.as_db_str();
            let parsed = Role::from_db_str(s).unwrap();
            assert_eq!(role, parsed);
        }
    }

    #[test]
    fn role_from_db_str_rejects_unknown() {
        let err = Role::from_db_str("superuser").unwrap_err();
        assert!(matches!(err, AuthError::UnknownRole { ref value } if value == "superuser"));
    }

    #[test]
    fn moderator_id_is_distinct_type() {
        // Compile-time check: a `ModeratorId` and a bare `Uuid` are different
        // types. The assertion below would not compile if `ModeratorId` were
        // a type alias.
        let mid = ModeratorId::new_v4();
        let uuid: Uuid = mid.0;
        // The wrapped UUID must equal what `as_uuid` exposes — proves the
        // newtype is a transparent wrapper and not a derivation.
        assert_eq!(&uuid, mid.as_uuid());
    }
}
