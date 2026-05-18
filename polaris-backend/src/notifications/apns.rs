//! Apple Push Notification service (APNs) provider — issue #116 / M5 #44.
//!
//! Implements [`PushProvider`] against Apple's HTTP/2 push gateway.
//! The operator configures:
//!
//! - `POLARIS_APNS_KEY_PATH` — path to the `.p8` PEM-encoded ES256
//!   private key Apple issued for the team's push key.
//! - `POLARIS_APNS_KEY_ID` — Apple-issued key identifier (10-char
//!   alphanumeric).
//! - `POLARIS_APNS_TEAM_ID` — Apple Developer team identifier
//!   (10-char alphanumeric).
//! - `POLARIS_APNS_TOPIC` — bundle identifier of the iOS app
//!   receiving the push (e.g., `gay.dollspace.polaris.mobile`).
//! - `POLARIS_APNS_PRODUCTION` — when `true`, use the production
//!   gateway (`api.push.apple.com`); otherwise the development
//!   sandbox (`api.sandbox.push.apple.com`).
//!
//! The provider mints a fresh JWT every call (Apple recommends
//! rotating at most once an hour); for the low Polaris fan-out
//! volume that is operationally fine and removes a stale-token
//! failure mode. JWT signing uses ES256 with the operator's p8 key,
//! the standard Apple flow.
//!
//! # Wire shape
//!
//! - URL: `https://<gateway>/3/device/<token>`
//! - Headers:
//!   - `authorization: bearer <jwt>`
//!   - `apns-topic: <bundle-id>`
//!   - `apns-push-type: alert`
//!   - `apns-priority: 10` (immediate delivery — P1 escalations)
//!   - `apns-expiration: 0` (do not store + retry)
//! - Body: the [`super::payload::PushPayload`] wrapped inside an
//!   APNs envelope (`{"aps": {"alert": {...}}, ...custom...}`).
//!
//! # Status-code mapping
//!
//! - `200` — delivered. Returns `Ok(())`.
//! - `400` — bad payload (treated as transport failure with the
//!   reason body for the operator's WARN log).
//! - `403` — authentication failed (wrong team/key/topic).
//!   Surfaces as [`super::provider::PushError::Unauthorized`].
//! - `410` — device token is no longer valid. Surfaces as
//!   [`super::provider::PushError::TokenStale`]; the fan-out worker
//!   sets `mobile_devices.revoked_at`.
//! - `429` — APNs rate-limited us. Surfaces as
//!   [`super::provider::PushError::RateLimited`].
//! - other 4xx/5xx — generic transport failure with the HTTP code
//!   in the message.

use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

use super::payload::PushPayload;
use super::provider::{PushError, PushProvider};

/// Production APNs HTTP/2 gateway hostname.
const APNS_PROD_HOST: &str = "api.push.apple.com";

/// Development sandbox APNs HTTP/2 gateway hostname.
const APNS_SANDBOX_HOST: &str = "api.sandbox.push.apple.com";

/// HTTPS port — the alternate `2197` is also supported by APNs but
/// `443` works through every operator's outbound firewall.
const APNS_PORT: u16 = 443;

/// Per-call HTTP timeout. APNs responds within ~200ms in practice;
/// 15 seconds is generous for transient network issues without
/// blocking the fan-out worker on a hung connection.
const APNS_TIMEOUT_SECS: u64 = 15;

/// Concrete configuration for an [`ApnsProvider`].
///
/// Parsed once at process start from `POLARIS_APNS_*` env vars by
/// [`ApnsProvider::from_env`]. The fields are NOT optional — APNs
/// rejects requests with missing claims.
#[derive(Debug, Clone)]
pub struct ApnsConfig {
    /// Apple-issued key identifier (10-char alphanumeric).
    pub key_id: String,
    /// Apple Developer team identifier (10-char alphanumeric).
    pub team_id: String,
    /// iOS app bundle identifier (e.g., `gay.dollspace.polaris.mobile`).
    pub topic: String,
    /// PEM-encoded ES256 private key (the contents of the `.p8`
    /// file Apple issued). Stored in-process as `Vec<u8>` so the
    /// JWT signer can borrow it on each dispatch.
    pub private_key_pem: Vec<u8>,
    /// `true` for the production gateway, `false` for the
    /// development sandbox.
    pub production: bool,
}

impl ApnsConfig {
    /// Build an [`ApnsConfig`] from the `POLARIS_APNS_*` env vars.
    ///
    /// Returns `Err(reason)` when any required var is missing or
    /// the key file is unreadable. The reason is operator-actionable
    /// text suitable for a startup-time WARN log.
    pub fn from_env() -> Result<Self, &'static str> {
        let key_path =
            std::env::var("POLARIS_APNS_KEY_PATH").map_err(|_| "POLARIS_APNS_KEY_PATH not set")?;
        let key_id =
            std::env::var("POLARIS_APNS_KEY_ID").map_err(|_| "POLARIS_APNS_KEY_ID not set")?;
        let team_id =
            std::env::var("POLARIS_APNS_TEAM_ID").map_err(|_| "POLARIS_APNS_TEAM_ID not set")?;
        let topic =
            std::env::var("POLARIS_APNS_TOPIC").map_err(|_| "POLARIS_APNS_TOPIC not set")?;
        let production = std::env::var("POLARIS_APNS_PRODUCTION")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let private_key_pem =
            std::fs::read(&key_path).map_err(|_| "POLARIS_APNS_KEY_PATH file not readable")?;
        Ok(Self {
            key_id,
            team_id,
            topic,
            private_key_pem,
            production,
        })
    }
}

/// APNs-backed [`PushProvider`].
///
/// Holds a single `reqwest::Client` (kept across dispatches so the
/// HTTP/2 connection pool is reused) and the parsed
/// [`ApnsConfig`]. Cheap to clone — the underlying reqwest client
/// is internally `Arc`-shared.
pub struct ApnsProvider {
    cfg: ApnsConfig,
    client: reqwest::Client,
}

impl ApnsProvider {
    /// Construct an [`ApnsProvider`] from a parsed config. Builds
    /// the HTTP client once and reuses it across dispatches.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` if the HTTP client cannot be built
    /// (an exotic rustls misconfiguration).
    pub fn new(cfg: ApnsConfig) -> Result<Self, &'static str> {
        let client = reqwest::Client::builder()
            .http2_prior_knowledge()
            .timeout(Duration::from_secs(APNS_TIMEOUT_SECS))
            .build()
            .map_err(|_| "could not build APNs HTTP client")?;
        Ok(Self { cfg, client })
    }

    /// Selected gateway hostname based on the production flag.
    fn host(&self) -> &'static str {
        if self.cfg.production {
            APNS_PROD_HOST
        } else {
            APNS_SANDBOX_HOST
        }
    }

    /// Build the per-call JWT used as the bearer token.
    ///
    /// Apple requires:
    /// - Algorithm: ES256
    /// - Header `kid`: the key id
    /// - Claim `iss`: the team id
    /// - Claim `iat`: unix seconds (must be ≤ 1 hour old at receipt)
    ///
    /// Returns the encoded JWT string on success.
    fn build_jwt(&self) -> Result<String, PushError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| PushError::Transport("apns: system clock before UNIX epoch".to_owned()))?
            .as_secs();
        let claims = serde_json::json!({
            "iss": self.cfg.team_id,
            "iat": now,
        });
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.cfg.key_id.clone());
        let encoding_key = EncodingKey::from_ec_pem(&self.cfg.private_key_pem).map_err(|_| {
            PushError::Unauthorized {
                reason: "apns: p8 key did not parse as ES256 PEM",
            }
        })?;
        encode(&header, &claims, &encoding_key).map_err(|_| PushError::Unauthorized {
            reason: "apns: JWT sign failed",
        })
    }

    /// Wrap a [`PushPayload`] in the APNs envelope.
    ///
    /// APNs requires a top-level `aps` object describing the
    /// notification's display behaviour. We use the minimal shape
    /// for a silent-data push (no alert UI; the app handles the
    /// payload in the background and rings the moderator's device
    /// via its own logic). This matches the privacy boundary in
    /// `super::mod`: no PII in the visible alert.
    fn envelope(payload: &PushPayload) -> serde_json::Value {
        serde_json::json!({
            "aps": {
                "alert": {
                    "title": "Polaris escalation",
                    "body": "Tap to review",
                },
                "sound": "default",
                "category": "POLARIS_P1",
            },
            "polaris": payload,
        })
    }
}

impl std::fmt::Debug for ApnsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApnsProvider")
            .field("host", &self.host())
            .field("topic", &self.cfg.topic)
            .field("key_id", &self.cfg.key_id)
            .field("team_id", &self.cfg.team_id)
            .field("production", &self.cfg.production)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PushProvider for ApnsProvider {
    async fn dispatch(&self, token: &str, payload: &PushPayload) -> Result<(), PushError> {
        let jwt = self.build_jwt()?;
        let url = format!("https://{}:{}/3/device/{}", self.host(), APNS_PORT, token);
        let body = serde_json::to_vec(&Self::envelope(payload))
            .map_err(|e| PushError::Transport(format!("apns: payload serialise: {e}")))?;

        let response = self
            .client
            .post(&url)
            .bearer_auth(jwt)
            .header("apns-topic", &self.cfg.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            .header("apns-expiration", "0")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| PushError::Transport(format!("apns: send: {e}")))?;

        match response.status().as_u16() {
            200..=299 => Ok(()),
            401 | 403 => Err(PushError::Unauthorized {
                reason: "apns: gateway rejected auth (check team_id / key_id / p8)",
            }),
            410 => Err(PushError::TokenStale),
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
                    "apns: HTTP {code}: {body_snippet}",
                )))
            }
        }
    }

    fn name(&self) -> &'static str {
        "apns"
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

    fn fake_cfg(production: bool) -> ApnsConfig {
        ApnsConfig {
            key_id: "ABC1234567".to_owned(),
            team_id: "TEAM123456".to_owned(),
            topic: "gay.dollspace.polaris.mobile".to_owned(),
            // A real ES256 p8 has the BEGIN PRIVATE KEY armor; we use
            // a deterministic placeholder for env-parsing tests — the
            // JWT-build tests live behind a flag because they need
            // a valid p8 we don't want to commit.
            private_key_pem:
                b"-----BEGIN PRIVATE KEY-----\nNOT A REAL KEY\n-----END PRIVATE KEY-----".to_vec(),
            production,
        }
    }

    #[test]
    fn host_selection_honours_production_flag() {
        let prod = ApnsProvider::new(fake_cfg(true)).expect("build");
        assert_eq!(prod.host(), APNS_PROD_HOST);
        let sandbox = ApnsProvider::new(fake_cfg(false)).expect("build");
        assert_eq!(sandbox.host(), APNS_SANDBOX_HOST);
    }

    #[test]
    fn envelope_wraps_polaris_payload_under_top_level_key() {
        let id = uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111")
            .expect("valid UUID literal");
        let payload = PushPayload::p1(id);
        let env = ApnsProvider::envelope(&payload);
        assert!(env.get("aps").is_some(), "APNs envelope must have aps");
        assert!(
            env.get("polaris").is_some(),
            "polaris payload must be present alongside aps",
        );
        // Privacy boundary: the visible alert MUST NOT carry the
        // incident UUID (it's deep-link state, not user-facing).
        let alert_body = env["aps"]["alert"]["body"].as_str().unwrap_or_default();
        assert!(
            !alert_body.contains("11111111"),
            "alert body must not carry the incident id",
        );
    }

    #[test]
    fn provider_name_is_constant() {
        let p = ApnsProvider::new(fake_cfg(false)).expect("build");
        assert_eq!(p.name(), "apns");
    }

    #[test]
    fn build_jwt_with_invalid_key_returns_unauthorized() {
        // The placeholder p8 is not a valid ES256 PEM; the signer
        // must surface a clean PushError::Unauthorized rather than
        // a generic transport error.
        let p = ApnsProvider::new(fake_cfg(false)).expect("build");
        let err = p.build_jwt().expect_err("invalid p8 must error");
        match err {
            PushError::Unauthorized { reason } => {
                assert!(
                    reason.contains("p8") || reason.contains("ES256"),
                    "reason should mention key shape: {reason}",
                );
            }
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }
}
