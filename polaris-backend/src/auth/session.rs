//! DB-backed opaque-token session store.
//!
//! # Threat model
//!
//! Session cookies are bearer credentials. They must therefore:
//!
//! - Be **opaque** — there is no derivable relationship between the cookie
//!   value and any upstream OIDC artefact. The client cannot, by inspection,
//!   discover the moderator's identity, the upstream access token, or the
//!   refresh token.
//! - Have **256+ bits of entropy** — drawn from `OsRng` (the OS CSPRNG).
//!   `uuid::Uuid::new_v4` is forbidden here because it only carries 122 bits
//!   of effective entropy and is the wrong primitive for an authentication
//!   secret.
//! - Be **`HttpOnly` + `Secure` + `SameSite=Lax`** at the cookie attribute layer —
//!   set by the OIDC callback handler and by [`Self::cookie_attrs`]. `Strict`
//!   would break the OIDC redirect; `Lax` is the correct middle ground.
//!
//! Refresh-token rows are encrypted via [`crate::auth::crypto::Crypto`]
//! before insert and decrypted on read; plaintext refresh tokens never sit at
//! rest.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::crypto::{Crypto, CryptoError, SealedBytes};
use crate::auth::{ModeratorAuthCtx, ModeratorId, Role};

/// Session ID entropy budget. 32 bytes = 256 bits — well past the practical
/// brute-force horizon.
pub const SESSION_ID_BYTES: usize = 32;

/// Default session lifetime: 12 hours. Sized so a moderator's working shift
/// fits inside one cookie; longer-running activity should drive a refresh.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(12 * 60 * 60);

/// Opaque Polaris session token.
///
/// The wire form is a 43-character base64url string (no padding) over 32
/// random bytes. The newtype prevents callers from accidentally treating a
/// raw `String` as a session token — every conversion site must go through
/// [`SessionToken::from_cookie_str`] or [`SessionToken::generate`].
#[derive(Clone, PartialEq, Eq)]
pub struct SessionToken(String);

impl SessionToken {
    /// Generate a fresh session token: 32 bytes from `OsRng`, base64url-encoded
    /// without padding.
    #[must_use]
    pub fn generate() -> Self {
        let mut buf = [0_u8; SESSION_ID_BYTES];
        OsRng.fill_bytes(&mut buf);
        Self(URL_SAFE_NO_PAD.encode(buf))
    }

    /// Parse a session token from a cookie value, validating shape.
    ///
    /// # Errors
    ///
    /// Returns [`SessionError::InvalidToken`] if `value` is not a 43-char
    /// base64url string or decodes to a different number of bytes than
    /// [`SESSION_ID_BYTES`]. Failing closed here means an attacker cannot
    /// learn anything from the shape-check before the DB roundtrip.
    pub fn from_cookie_str(value: &str) -> Result<Self, SessionError> {
        // 32 bytes -> ceil(32*4/3) = 43 chars in base64url-no-pad.
        if value.len() != 43 {
            return Err(SessionError::InvalidToken);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| SessionError::InvalidToken)?;
        if bytes.len() != SESSION_ID_BYTES {
            return Err(SessionError::InvalidToken);
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrow the wire-form session token. The cookie-emitting handler is
    /// the only caller in the auth subsystem.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Cookie-attribute string for the session cookie. The path is `/` so
    /// every endpoint sees it; `HttpOnly` keeps it out of JS; `Secure` forces
    /// HTTPS-only transmission; `SameSite=Lax` is the maximum strictness
    /// compatible with the OIDC redirect dance.
    #[must_use]
    pub fn cookie_attrs() -> &'static str {
        "Path=/; HttpOnly; Secure; SameSite=Lax"
    }
}

/// `Debug` is hand-rolled so the token value never lands in a log line.
impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SessionToken").field(&"[REDACTED]").finish()
    }
}

/// Errors raised by [`SessionStore`].
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The cookie value failed shape validation: wrong length, wrong charset,
    /// or wrong decoded byte count. Always surfaces to the client as 401 —
    /// `Display` text is generic so it cannot be probed.
    #[error("invalid session token")]
    InvalidToken,

    /// `SELECT … FROM sessions WHERE id = $1` returned no row.
    #[error("session not found")]
    NotFound,

    /// The row was present but `expires_at < now()`.
    #[error("session expired")]
    Expired,

    /// Database-level failure (connection, integrity check, etc.).
    #[error("database failure during session operation")]
    Database(#[source] sqlx::Error),

    /// Failed to decrypt the stored refresh token. This is a fail-closed:
    /// either the cookie key rotated without re-encrypting rows, or the
    /// ciphertext was tampered with.
    #[error("failed to decrypt refresh token")]
    Crypto(#[source] CryptoError),

    /// `moderator_roles.role` held a TEXT value not in the expected enum.
    /// Indicates schema drift; surfaces as 500.
    #[error("unknown role text in moderator_roles row: {value}")]
    UnknownRole {
        /// Offending TEXT value.
        value: String,
    },
}

impl From<sqlx::Error> for SessionError {
    fn from(value: sqlx::Error) -> Self {
        Self::Database(value)
    }
}

impl From<CryptoError> for SessionError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

/// Output of [`SessionStore::refresh`]: the rotated session token plus its
/// new absolute expiry. Callers re-emit the session cookie with this value.
#[derive(Debug, Clone)]
pub struct NewSession {
    /// Newly-minted opaque token. Replaces the previous cookie value.
    pub token: SessionToken,
    /// Absolute expiration. Cookie `Max-Age` should match.
    pub expires_at: DateTime<Utc>,
}

/// Persistent session store backed by Postgres.
///
/// Owns a `PgPool` and a `Crypto` handle. `PgPool` is internally `Arc`-shared
/// so we hold it directly (NOT `Arc<PgPool>`, per the architect's pre-flight).
#[derive(Clone, Debug)]
pub struct SessionStore {
    pool: PgPool,
    crypto: Crypto,
    ttl: Duration,
}

impl SessionStore {
    /// Build a [`SessionStore`] with the default TTL ([`DEFAULT_SESSION_TTL`]).
    #[must_use]
    pub fn new(pool: PgPool, crypto: Crypto) -> Self {
        Self {
            pool,
            crypto,
            ttl: DEFAULT_SESSION_TTL,
        }
    }

    /// Build a [`SessionStore`] with a custom TTL. Used by the
    /// `session_expiry` integration test.
    #[must_use]
    pub fn with_ttl(pool: PgPool, crypto: Crypto, ttl: Duration) -> Self {
        Self { pool, crypto, ttl }
    }

    /// Session TTL window. Borrowed by the atproto refresh-flow
    /// implementation in [`crate::auth::atproto::AtprotoOauthAuthVerifier::refresh_session`]
    /// so the post-refresh `expires_at` aligns with the cookie window
    /// the store would emit on a fresh `create()`.
    #[must_use]
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Create a new session for `moderator_id`, sealing `refresh_token_plain`
    /// at rest.
    ///
    /// # Errors
    ///
    /// - [`SessionError::Crypto`] on encryption failure (only possible on
    ///   pathologically-large plaintexts).
    /// - [`SessionError::Database`] on insert failure.
    pub async fn create(
        &self,
        moderator_id: ModeratorId,
        refresh_token_plain: &[u8],
    ) -> Result<NewSession, SessionError> {
        let token = SessionToken::generate();
        let sealed = self.crypto.seal(refresh_token_plain)?;
        let bytes = sealed.to_bytes();
        let ttl_secs = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let expires_at = Utc::now()
            + chrono::Duration::try_seconds(ttl_secs).unwrap_or_else(chrono::Duration::zero);

        sqlx::query!(
            r"INSERT INTO sessions (id, moderator_id, refresh_token_enc, expires_at)
              VALUES ($1, $2, $3, $4)",
            token.as_str(),
            moderator_id.0,
            bytes,
            expires_at,
        )
        .execute(&self.pool)
        .await?;

        Ok(NewSession { token, expires_at })
    }

    /// Look up a session by cookie value, returning the authenticated
    /// [`ModeratorAuthCtx`] on success.
    ///
    /// # Errors
    ///
    /// - [`SessionError::InvalidToken`] if the cookie fails shape validation.
    /// - [`SessionError::NotFound`] if no row matches.
    /// - [`SessionError::Expired`] if the row is past TTL.
    /// - [`SessionError::Database`] on query failure.
    pub async fn lookup(&self, cookie_value: &str) -> Result<ModeratorAuthCtx, SessionError> {
        let token = SessionToken::from_cookie_str(cookie_value)?;

        let row = sqlx::query!(
            r"SELECT moderator_id, expires_at
              FROM sessions
              WHERE id = $1",
            token.as_str(),
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(SessionError::NotFound)?;

        if row.expires_at <= Utc::now() {
            return Err(SessionError::Expired);
        }

        // Touch `last_seen_at`. Failure here is non-fatal — the lookup
        // already succeeded.
        let _ = sqlx::query!(
            r"UPDATE sessions SET last_seen_at = now() WHERE id = $1",
            token.as_str(),
        )
        .execute(&self.pool)
        .await;

        let roles = self.fetch_roles(row.moderator_id).await?;
        Ok(ModeratorAuthCtx::new(ModeratorId(row.moderator_id), roles))
    }

    /// Rotate the opaque session token, keeping the same `moderator_id` and
    /// resetting `expires_at`. Used after a successful refresh-token-driven
    /// access-token renewal.
    ///
    /// The new token replaces the old row (delete + insert) so the previous
    /// cookie value is rendered invalid in one DB statement.
    ///
    /// # Errors
    ///
    /// - [`SessionError::NotFound`] if `old_token` did not exist.
    /// - [`SessionError::Database`] on transaction failure.
    pub async fn refresh(&self, old_cookie: &str) -> Result<NewSession, SessionError> {
        let old_token = SessionToken::from_cookie_str(old_cookie)?;

        let mut tx = self.pool.begin().await?;

        // Pull the moderator_id + ciphertext, then delete the old row in the
        // same transaction so we cannot end up with two rows pointing at the
        // same moderator from this flow.
        let row = sqlx::query!(
            r"SELECT moderator_id, refresh_token_enc
              FROM sessions
              WHERE id = $1
              FOR UPDATE",
            old_token.as_str(),
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(SessionError::NotFound)?;

        sqlx::query!(r"DELETE FROM sessions WHERE id = $1", old_token.as_str())
            .execute(&mut *tx)
            .await?;

        // Re-seal the refresh token under a fresh nonce. The plaintext is
        // verified by AES-GCM authentication — a tampered row would have
        // failed `open` here.
        let sealed_in = SealedBytes::from_bytes(&row.refresh_token_enc)?;
        let plain = self.crypto.open(&sealed_in)?;
        let sealed_out = self.crypto.seal(&plain)?;
        let bytes = sealed_out.to_bytes();

        let new_token = SessionToken::generate();
        let ttl_secs = i64::try_from(self.ttl.as_secs()).unwrap_or(i64::MAX);
        let expires_at = Utc::now()
            + chrono::Duration::try_seconds(ttl_secs).unwrap_or_else(chrono::Duration::zero);

        sqlx::query!(
            r"INSERT INTO sessions (id, moderator_id, refresh_token_enc, expires_at)
              VALUES ($1, $2, $3, $4)",
            new_token.as_str(),
            row.moderator_id,
            bytes,
            expires_at,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(NewSession {
            token: new_token,
            expires_at,
        })
    }

    /// Delete the session row corresponding to `cookie_value`. Idempotent:
    /// a not-found row is not an error (the cookie is already revoked).
    ///
    /// # Errors
    ///
    /// - [`SessionError::InvalidToken`] on a malformed cookie.
    /// - [`SessionError::Database`] on delete failure.
    pub async fn revoke(&self, cookie_value: &str) -> Result<(), SessionError> {
        let token = SessionToken::from_cookie_str(cookie_value)?;
        sqlx::query!(r"DELETE FROM sessions WHERE id = $1", token.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Resolve the role set for `moderator_id`. Returns the empty set if the
    /// moderator exists but has no role rows (a state the SQL layer permits
    /// — a freshly-created moderator may not yet be granted any role).
    async fn fetch_roles(
        &self,
        moderator_id: Uuid,
    ) -> Result<std::collections::HashSet<Role>, SessionError> {
        let rows = sqlx::query!(
            r"SELECT role FROM moderator_roles WHERE moderator_id = $1",
            moderator_id,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut roles = std::collections::HashSet::with_capacity(rows.len());
        for row in rows {
            let role = Role::from_db_str(&row.role).map_err(|_| SessionError::UnknownRole {
                value: row.role.clone(),
            })?;
            roles.insert(role);
        }
        Ok(roles)
    }
}

// Note: `impl From<SessionError> for AuthError` lives in auth/mod.rs.

#[cfg(test)]
// Allow `unwrap()` / `expect()` in tests so the workspace-level
// `clippy::unwrap_used` / `expect_used` lints (denied at `--all-targets`)
// do not flag the idiomatic Rust unit-test pattern.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_43_char_base64url() {
        let t = SessionToken::generate();
        assert_eq!(t.as_str().len(), 43);
        // Char-set: base64url alphabet (no padding, no `+`, no `/`).
        for c in t.as_str().chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-base64url char: {c}"
            );
        }
    }

    #[test]
    fn two_generates_differ() {
        let a = SessionToken::generate();
        let b = SessionToken::generate();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn from_cookie_str_rejects_short_input() {
        assert!(SessionToken::from_cookie_str("too-short").is_err());
    }

    #[test]
    fn from_cookie_str_rejects_padding() {
        // 44 chars (one '=' padding) — must be rejected, we use the no-pad
        // alphabet on the wire.
        let bad = format!("{}=", "A".repeat(43));
        assert!(SessionToken::from_cookie_str(&bad).is_err());
    }

    #[test]
    fn from_cookie_str_rejects_non_base64url_chars() {
        // Length 43 but contains '+' (standard alphabet, not url-safe).
        let bad = format!("{}+", "A".repeat(42));
        assert!(SessionToken::from_cookie_str(&bad).is_err());
    }

    #[test]
    fn debug_redacts_token_value() {
        let t = SessionToken::generate();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(t.as_str()));
    }

    #[test]
    fn cookie_attrs_includes_required_flags() {
        let attrs = SessionToken::cookie_attrs();
        assert!(attrs.contains("HttpOnly"));
        assert!(attrs.contains("Secure"));
        assert!(attrs.contains("SameSite=Lax"));
        assert!(!attrs.contains("SameSite=Strict"));
    }
}
