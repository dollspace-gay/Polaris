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

pub mod crypto;
pub mod oidc;
pub mod session;

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

/// Authentication trait: the abstraction M4 will plug ATProto OAuth into.
///
/// Both halves of the OIDC login dance (the redirect-out and the callback-in)
/// live on this trait so a future ATProto-OAuth implementor lays down the
/// same shape. AFIT (`async fn` in trait) is used directly — no
/// `async_trait` macro, MSRV 1.88 permits it.
#[allow(clippy::missing_errors_doc)] // Trait-level documentation already covers errors.
pub trait ModeratorAuth: Send + Sync {
    /// Begin a login flow.
    ///
    /// Returns the URL the client should redirect to. The caller is expected
    /// to set a `Location` header to `LoginRedirect::authorize_url` and a
    /// 302/303 status.
    fn start_login(
        &self,
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
