//! Firebase Cloud Messaging (FCM) push provider — issue #116 / M5 #44.
//!
//! Implements [`PushProvider`] against Google's FCM HTTP v1 API.
//! The operator configures:
//!
//! - `POLARIS_FCM_SERVICE_ACCOUNT_JSON` — path to the Firebase
//!   service-account JSON key (the file downloaded from the Google
//!   Cloud console for the FCM-enabled project).
//! - `POLARIS_FCM_PROJECT_ID` — Firebase project identifier; used
//!   in the FCM v1 URL path. Read from the service-account JSON's
//!   `project_id` field when not explicitly set, so most operators
//!   need only the JSON file.
//!
//! FCM v1 authentication uses the service-account JWT-bearer flow:
//! the provider signs an RS256 assertion with the service account's
//! private key, exchanges it at `oauth2.googleapis.com/token` for
//! a bearer access token scoped to `firebase.messaging`, then
//! POSTs the message JSON to
//! `https://fcm.googleapis.com/v1/projects/<project>/messages:send`.
//!
//! Access tokens are valid for an hour; we cache them in-process
//! and refresh on demand (when the cached token is within 60
//! seconds of expiry, or on every call if no token has been
//! minted yet).
//!
//! # Status-code mapping
//!
//! - `200` — message accepted. Returns `Ok(())`.
//! - `401` / `403` — token expired or service-account unauthorized.
//!   Surfaces as [`super::provider::PushError::Unauthorized`]. The
//!   cached access token is cleared so the next call re-mints.
//! - `404` — device token not registered. Surfaces as
//!   [`super::provider::PushError::TokenStale`].
//! - `429` — quota exhausted. Surfaces as
//!   [`super::provider::PushError::RateLimited`].
//! - other 4xx/5xx — generic transport failure.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

use super::payload::PushPayload;
use super::provider::{PushError, PushProvider};

/// FCM v1 message-send endpoint template.
const FCM_SEND_URL: &str = "https://fcm.googleapis.com/v1/projects/{project}/messages:send";

/// Google `OAuth2` token-exchange endpoint.
const GOOGLE_OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// FCM v1 `OAuth2` scope.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// Per-call HTTP timeout. FCM responds within ~500ms in practice;
/// 15 seconds covers transient network blips without blocking the
/// fan-out worker.
const FCM_TIMEOUT_SECS: u64 = 15;

/// Refresh the cached access token when it is within this many
/// seconds of expiry. Google issues hour-long tokens; refreshing
/// at 60 seconds left gives ample headroom for clock drift.
const TOKEN_REFRESH_HEADROOM: Duration = Duration::from_secs(60);

/// Minimal subset of a GCP service-account JSON we need for the
/// FCM token exchange. Field names mirror the JSON shape verbatim.
#[derive(Debug, Clone, serde::Deserialize)]
#[allow(
    non_snake_case,
    reason = "field names mirror the Google service-account JSON wire shape verbatim"
)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    project_id: String,
    #[serde(default)]
    token_uri: Option<String>,
}

/// Concrete configuration for an [`FcmProvider`].
///
/// Parsed once at process start from `POLARIS_FCM_*` env vars by
/// [`FcmConfig::from_env`].
#[derive(Debug, Clone)]
pub struct FcmConfig {
    /// Firebase project identifier (FCM v1 URL path component).
    pub project_id: String,
    /// Service-account email (the JWT issuer).
    pub client_email: String,
    /// PEM-encoded RSA private key (the service-account JSON's
    /// `private_key` field).
    pub private_key_pem: String,
    /// `OAuth2` token-exchange endpoint. Defaults to Google's
    /// canonical URL; the service-account JSON may override it.
    pub token_uri: String,
}

impl FcmConfig {
    /// Build an [`FcmConfig`] from the `POLARIS_FCM_*` env vars.
    ///
    /// Reads the service-account JSON file referenced by
    /// `POLARIS_FCM_SERVICE_ACCOUNT_JSON`. If
    /// `POLARIS_FCM_PROJECT_ID` is set it overrides the JSON's
    /// `project_id`; otherwise the JSON's own value is used.
    pub fn from_env() -> Result<Self, &'static str> {
        let sa_path = std::env::var("POLARIS_FCM_SERVICE_ACCOUNT_JSON")
            .map_err(|_| "POLARIS_FCM_SERVICE_ACCOUNT_JSON not set")?;
        let raw = std::fs::read_to_string(&sa_path)
            .map_err(|_| "POLARIS_FCM_SERVICE_ACCOUNT_JSON file not readable")?;
        let sa: ServiceAccount =
            serde_json::from_str(&raw).map_err(|_| "FCM service-account JSON did not parse")?;
        let project_id = std::env::var("POLARIS_FCM_PROJECT_ID")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or(sa.project_id);
        let token_uri = sa
            .token_uri
            .unwrap_or_else(|| GOOGLE_OAUTH_TOKEN_URL.to_owned());
        Ok(Self {
            project_id,
            client_email: sa.client_email,
            private_key_pem: sa.private_key,
            token_uri,
        })
    }
}

/// Cached `OAuth2` access token with its expiry instant.
#[derive(Debug, Clone)]
struct CachedToken {
    /// The bearer token string Google returned.
    access_token: String,
    /// Local-clock deadline at which the token should no longer be
    /// trusted (Google's `expires_in` minus the refresh headroom).
    valid_until: Instant,
}

/// FCM-backed [`PushProvider`].
///
/// Holds the parsed config, a reusable reqwest client, and an
/// in-process cache of the `OAuth2` access token so we don't burn
/// a token exchange on every dispatch.
pub struct FcmProvider {
    cfg: FcmConfig,
    client: reqwest::Client,
    cached_token: Mutex<Option<CachedToken>>,
}

impl FcmProvider {
    /// Construct an [`FcmProvider`] from a parsed config.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the reqwest client cannot be built.
    pub fn new(cfg: FcmConfig) -> Result<Self, &'static str> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(FCM_TIMEOUT_SECS))
            .build()
            .map_err(|_| "could not build FCM HTTP client")?;
        Ok(Self {
            cfg,
            client,
            cached_token: Mutex::new(None),
        })
    }

    /// Hand back a fresh `OAuth2` access token, minting one if the
    /// cache is empty or about to expire.
    async fn access_token(&self) -> Result<String, PushError> {
        if let Ok(guard) = self.cached_token.lock() {
            if let Some(cached) = guard.as_ref() {
                if cached.valid_until > Instant::now() {
                    return Ok(cached.access_token.clone());
                }
            }
        }
        let token = self.mint_access_token().await?;
        if let Ok(mut guard) = self.cached_token.lock() {
            *guard = Some(token.clone());
        }
        Ok(token.access_token)
    }

    /// Sign a JWT assertion and exchange it for an access token at
    /// the operator-supplied token URI.
    async fn mint_access_token(&self) -> Result<CachedToken, PushError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| PushError::Transport("fcm: system clock before UNIX epoch".to_owned()))?
            .as_secs();
        let claims = serde_json::json!({
            "iss":   self.cfg.client_email,
            "scope": FCM_SCOPE,
            "aud":   self.cfg.token_uri,
            "iat":   now,
            "exp":   now + 3600,
        });
        let encoding_key =
            EncodingKey::from_rsa_pem(self.cfg.private_key_pem.as_bytes()).map_err(|_| {
                PushError::Unauthorized {
                    reason: "fcm: service-account private_key did not parse as RSA PEM",
                }
            })?;
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_owned());
        let assertion =
            encode(&header, &claims, &encoding_key).map_err(|_| PushError::Unauthorized {
                reason: "fcm: JWT assertion sign failed",
            })?;

        let response = self
            .client
            .post(&self.cfg.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ])
            .send()
            .await
            .map_err(|e| PushError::Transport(format!("fcm: token exchange send: {e}")))?;
        if !response.status().is_success() {
            return Err(PushError::Unauthorized {
                reason: "fcm: `OAuth2` token exchange returned non-2xx",
            });
        }
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| PushError::Transport(format!("fcm: token exchange decode: {e}")))?;
        let access_token = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or(PushError::Unauthorized {
                reason: "fcm: token-exchange response missing access_token",
            })?
            .to_owned();
        let expires_in = body
            .get("expires_in")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(3600);
        let lifetime = Duration::from_secs(expires_in).saturating_sub(TOKEN_REFRESH_HEADROOM);
        Ok(CachedToken {
            access_token,
            valid_until: Instant::now() + lifetime,
        })
    }

    /// Wrap a [`PushPayload`] in the FCM v1 message envelope.
    ///
    /// FCM v1 requires the device token inside `message.token` and
    /// the application payload inside `message.data`. We keep the
    /// privacy boundary (no PII): `data` carries only the
    /// `type` + `incident_id` keys the mobile app uses as a
    /// deep-link target.
    fn envelope(token: &str, payload: &PushPayload) -> serde_json::Value {
        serde_json::json!({
            "message": {
                "token": token,
                "data": payload,
                "notification": {
                    "title": "Polaris escalation",
                    "body":  "Tap to review",
                },
                "android": {
                    "priority": "HIGH",
                },
            }
        })
    }

    /// Invalidate the cached `OAuth2` token. Called when the FCM API
    /// reports `401` so the next dispatch re-mints rather than
    /// reusing the rejected token.
    fn clear_cached_token(&self) {
        if let Ok(mut guard) = self.cached_token.lock() {
            *guard = None;
        }
    }
}

impl std::fmt::Debug for FcmProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FcmProvider")
            .field("project_id", &self.cfg.project_id)
            .field("client_email", &self.cfg.client_email)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PushProvider for FcmProvider {
    async fn dispatch(&self, token: &str, payload: &PushPayload) -> Result<(), PushError> {
        let access_token = self.access_token().await?;
        let url = FCM_SEND_URL.replace("{project}", &self.cfg.project_id);
        let body = Self::envelope(token, payload);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&access_token)
            .header("content-type", "application/json")
            .body(
                serde_json::to_vec(&body)
                    .map_err(|e| PushError::Transport(format!("fcm: payload serialise: {e}")))?,
            )
            .send()
            .await
            .map_err(|e| PushError::Transport(format!("fcm: send: {e}")))?;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            401 | 403 => {
                // Cached token may have been revoked / expired
                // out-of-band — drop it so the next dispatch
                // re-mints rather than re-using the rejected token.
                self.clear_cached_token();
                Err(PushError::Unauthorized {
                    reason: "fcm: API rejected auth (check service account / project)",
                })
            }
            404 => Err(PushError::TokenStale),
            429 => Err(PushError::RateLimited),
            code => {
                let body_snippet = response
                    .text()
                    .await
                    .unwrap_or_default()
                    .chars()
                    .take(200)
                    .collect::<String>();
                Err(PushError::Transport(format!(
                    "fcm: HTTP {code}: {body_snippet}",
                )))
            }
        }
    }

    fn name(&self) -> &'static str {
        "fcm"
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    fn fake_cfg() -> FcmConfig {
        FcmConfig {
            project_id: "polaris-test".to_owned(),
            client_email: "fcm-pusher@polaris-test.iam.gserviceaccount.com".to_owned(),
            private_key_pem:
                "-----BEGIN PRIVATE KEY-----\nNOT A REAL KEY\n-----END PRIVATE KEY-----".to_owned(),
            token_uri: GOOGLE_OAUTH_TOKEN_URL.to_owned(),
        }
    }

    #[test]
    fn envelope_carries_token_and_payload() {
        let id = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111")
            .expect("valid UUID literal");
        let payload = PushPayload::p1(id);
        let env = FcmProvider::envelope("device-abc", &payload);
        assert_eq!(env["message"]["token"], "device-abc");
        assert_eq!(
            env["message"]["data"]["incident_id"],
            "11111111-1111-1111-1111-111111111111"
        );
        // Privacy boundary: the visible notification must NOT carry
        // the incident id; that goes in `data` only for the app
        // to use as a deep-link target.
        let body = env["message"]["notification"]["body"]
            .as_str()
            .unwrap_or_default();
        assert!(!body.contains("11111111"));
    }

    #[test]
    fn provider_name_is_constant() {
        let p = FcmProvider::new(fake_cfg()).expect("build");
        assert_eq!(p.name(), "fcm");
    }

    #[test]
    fn cache_invalidation_clears_stored_token() {
        let p = FcmProvider::new(fake_cfg()).expect("build");
        // Prime the cache with a fake CachedToken so we can verify
        // clear_cached_token() actually drops it.
        if let Ok(mut guard) = p.cached_token.lock() {
            *guard = Some(CachedToken {
                access_token: "fake".to_owned(),
                valid_until: Instant::now() + Duration::from_secs(3600),
            });
        }
        p.clear_cached_token();
        let cleared = p
            .cached_token
            .lock()
            .expect("lock not poisoned in test")
            .is_none();
        assert!(cleared, "clear_cached_token must drop the stored token");
    }

    #[test]
    fn send_url_substitutes_project_id() {
        // Sanity check: the URL template hits the project the
        // operator configured, not the placeholder string. Catches
        // a future template-format change that breaks the
        // substitution silently.
        let url = FCM_SEND_URL.replace("{project}", "polaris-prod");
        assert_eq!(
            url,
            "https://fcm.googleapis.com/v1/projects/polaris-prod/messages:send",
        );
    }
}
