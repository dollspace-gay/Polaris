//! [`PushProvider`] trait + the v2 baseline impls (issue #116 / M5 #44 PR 2).
//!
//! The trait abstracts over the four push transports (APNs / FCM /
//! ntfy.sh / dev-stub). The fan-out worker holds an `Arc<dyn
//! PushProvider>` and dispatches to whichever the operator
//! configured.

use super::payload::PushPayload;

/// Error variants for the push transport.
#[derive(Debug, thiserror::Error)]
pub enum PushError {
    /// Token rejected by the push service. The fan-out worker
    /// responds by setting `mobile_devices.revoked_at = now()` so
    /// the device drops out of future fan-outs.
    #[error("push token rejected by provider (stale or invalid)")]
    TokenStale,

    /// Provider rate-limited us. The fan-out worker logs + retries
    /// with backoff; no device-side action.
    #[error("push provider rate-limited the call")]
    RateLimited,

    /// Provider authentication failed — operator config error.
    /// Surfaces at WARN and is documented as a setup-time check in
    /// the runbook (#122 PR 8).
    #[error("push provider authentication failed: {reason}")]
    Unauthorized {
        /// Operator-actionable explanation (e.g. "APNs key not configured").
        reason: &'static str,
    },

    /// Generic transport failure.
    #[error("push transport error: {0}")]
    Transport(String),
}

/// Abstract push transport. One impl per provider; operator config
/// selects which one the fan-out worker uses.
#[async_trait::async_trait]
pub trait PushProvider: Send + Sync + 'static {
    /// Deliver a payload to a single device token.
    ///
    /// # Errors
    ///
    /// See [`PushError`] for the variant set. Token-staleness
    /// triggers a downstream UPDATE on `mobile_devices.revoked_at`;
    /// other errors WARN-log and retry.
    async fn dispatch(&self, token: &str, payload: &PushPayload) -> Result<(), PushError>;

    /// Human-readable provider name for logs + the `polaris devices
    /// list` admin output. Returned as a `&'static str` to avoid
    /// allocations.
    fn name(&self) -> &'static str;
}

/// ntfy.sh-backed [`PushProvider`].
///
/// Functional v2 baseline because ntfy.sh requires no per-operator
/// credentials — works against either the public `https://ntfy.sh`
/// instance or a self-hosted ntfy server. Suits the labeler profile
/// where an APNs / FCM setup is operationally heavy.
pub struct NtfyProvider {
    /// Base URL of the ntfy server (e.g. `https://ntfy.sh`).
    base_url: String,
    /// Topic prefix per the ntfy API. Each device's
    /// `mobile_devices.push_token` is the topic suffix.
    topic_prefix: String,
}

impl NtfyProvider {
    /// Construct an ntfy provider rooted at `base_url`. The topic
    /// prefix is appended to each device's `push_token` to build the
    /// full ntfy topic.
    #[must_use]
    pub fn new(base_url: impl Into<String>, topic_prefix: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            topic_prefix: topic_prefix.into(),
        }
    }

    /// Full ntfy topic URL for a device token.
    #[must_use]
    fn topic_url(&self, token: &str) -> String {
        format!(
            "{}/{}{}",
            self.base_url.trim_end_matches('/'),
            self.topic_prefix,
            token
        )
    }
}

impl std::fmt::Debug for NtfyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NtfyProvider")
            .field("base_url", &self.base_url)
            .field("topic_prefix", &self.topic_prefix)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl PushProvider for NtfyProvider {
    async fn dispatch(&self, token: &str, payload: &PushPayload) -> Result<(), PushError> {
        let url = self.topic_url(token);
        let body =
            serde_json::to_string(payload).map_err(|e| PushError::Transport(e.to_string()))?;
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| PushError::Transport(e.to_string()))?;
        match response.status().as_u16() {
            200..=299 => Ok(()),
            401 | 403 => Err(PushError::Unauthorized {
                reason: "ntfy.sh rejected auth (check server config / token)",
            }),
            429 => Err(PushError::RateLimited),
            410 => Err(PushError::TokenStale),
            code => Err(PushError::Transport(format!("ntfy HTTP {code}"))),
        }
    }

    fn name(&self) -> &'static str {
        "ntfy"
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

    #[test]
    fn ntfy_topic_url_composes_correctly() {
        let p = NtfyProvider::new("https://ntfy.sh", "polaris-");
        assert_eq!(p.topic_url("abc"), "https://ntfy.sh/polaris-abc");
    }

    #[test]
    fn ntfy_topic_url_handles_trailing_slash_in_base() {
        let p = NtfyProvider::new("https://ntfy.example.com/", "polaris-");
        assert_eq!(p.topic_url("xyz"), "https://ntfy.example.com/polaris-xyz");
    }

    #[test]
    fn ntfy_provider_name_is_constant() {
        let p = NtfyProvider::new("https://ntfy.sh", "polaris-");
        assert_eq!(p.name(), "ntfy");
    }

    #[test]
    fn push_error_token_stale_display_is_actionable() {
        let e = PushError::TokenStale;
        let msg = e.to_string();
        // Operator-facing message references the stale-token concept
        // so the fan-out worker's WARN log is self-explanatory.
        assert!(msg.contains("stale") || msg.contains("invalid"));
    }
}
