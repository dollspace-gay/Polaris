//! Post-login hardware-key gate (#40, design.md §6 + §9.1).
//!
//! Called immediately after an OIDC or ATProto OAuth login succeeds and the
//! upstream `LoginResult` carries a valid `ModeratorAuthCtx`. The gate
//! consults the deployment profile + per-profile defaults to decide whether
//! to:
//!
//! - Mint the session cookie immediately ([`LoginGateOutcome::SessionReady`])
//!   when `require_hardware_key` is false.
//! - Demand a fresh enrolment ceremony
//!   ([`LoginGateOutcome::EnrollmentRequired`]) when `require_hardware_key`
//!   is true and the moderator has no registered authenticator yet.
//! - Demand an assertion ceremony
//!   ([`LoginGateOutcome::AssertionRequired`]) when `require_hardware_key` is
//!   true and the moderator has at least one registered authenticator.
//!
//! The session cookie is never issued in the second / third arm — that's the
//! entire point of the gate. The frontend follow-up issue (#77) drives the
//! actual enrolment / assertion screens, calling
//! [`crate::api::webauthn::register_start`] / `register_finish` /
//! `assert_start` / `assert_finish`; on success those endpoints mint the
//! session cookie.

use crate::auth::webauthn::{WebauthnError, WebauthnVerifier};
use crate::auth::{LoginResult, ModeratorId};
use crate::config::{AuthConfig, Profile};

/// Outcome of [`apply_hardware_key_gate`].
///
/// The OIDC / ATProto callback handler matches on this to decide which HTTP
/// response shape to return.
#[derive(Debug)]
pub enum LoginGateOutcome {
    /// Hardware-key gate disabled (or moderator already passed via this
    /// session). Carry the original [`LoginResult`] through; the callback
    /// handler emits the session cookie as usual.
    SessionReady(Box<LoginResult>),
    /// Hardware-key gate enabled and no credentials are registered. The
    /// frontend (issue #77) drives the enrolment ceremony via
    /// [`crate::api::webauthn::register_start`] /
    /// [`crate::api::webauthn::register_finish`]; the session cookie is
    /// minted at `register_finish` time.
    EnrollmentRequired {
        /// Authenticated moderator (resolved by the upstream backend) that
        /// must enrol a hardware key before reaching the dashboard.
        moderator_id: ModeratorId,
    },
    /// Hardware-key gate enabled and the moderator has at least one
    /// registered credential. The frontend drives the assertion ceremony
    /// via [`crate::api::webauthn::assert_start`] /
    /// [`crate::api::webauthn::assert_finish`]; the session cookie is
    /// minted at `assert_finish` time.
    AssertionRequired {
        /// Authenticated moderator that must present a hardware-key
        /// assertion before reaching the dashboard.
        moderator_id: ModeratorId,
    },
}

/// Errors raised by [`apply_hardware_key_gate`].
///
/// The gate itself is mostly a config + has-credentials lookup, so the only
/// failure mode beyond `WebauthnError` is "DB unavailable". Both pass
/// through.
#[derive(Debug, thiserror::Error)]
pub enum GateError {
    /// Database / verifier failure during the has-credentials lookup.
    #[error("hardware-key gate lookup failed")]
    Webauthn(
        /// Underlying error from [`WebauthnVerifier::has_credentials`].
        #[from]
        WebauthnError,
    ),
}

/// Resolve the post-login hardware-key gate decision for a freshly-completed
/// OIDC / ATProto login.
///
/// `cfg` is the active [`AuthConfig`]; `profile` is the deployment profile
/// (drives the per-profile default if `cfg.require_hardware_key` is
/// `None`); `login_result` is the upstream-backend output that the gate
/// either passes through or replaces.
///
/// # Errors
///
/// - [`GateError::Webauthn`] when the has-credentials lookup hits a DB or
///   configuration failure. The gate fails closed in that case — the caller
///   should respond with a 5xx rather than let the moderator past.
pub async fn apply_hardware_key_gate(
    cfg: &AuthConfig,
    profile: Profile,
    webauthn: &WebauthnVerifier,
    login_result: LoginResult,
) -> Result<LoginGateOutcome, GateError> {
    if !cfg.resolve_require_hardware_key(profile) {
        return Ok(LoginGateOutcome::SessionReady(Box::new(login_result)));
    }
    let moderator_id = login_result.ctx.moderator_id;
    if webauthn.has_credentials(moderator_id).await? {
        Ok(LoginGateOutcome::AssertionRequired { moderator_id })
    } else {
        Ok(LoginGateOutcome::EnrollmentRequired { moderator_id })
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
    use crate::config::{AtprotoAuthConfig, AuthBackend, AuthConfig, OidcConfig};

    fn cfg_with(require: Option<bool>) -> AuthConfig {
        AuthConfig {
            backend: AuthBackend::Oidc,
            oidc: OidcConfig::default(),
            atproto: AtprotoAuthConfig::default(),
            require_hardware_key: require,
        }
    }

    #[test]
    fn resolve_default_bluesky_on() {
        let cfg = cfg_with(None);
        assert!(
            cfg.resolve_require_hardware_key(Profile::Bluesky),
            "bluesky profile must default-on"
        );
    }

    #[test]
    fn resolve_default_labeler_off() {
        let cfg = cfg_with(None);
        assert!(
            !cfg.resolve_require_hardware_key(Profile::Labeler),
            "labeler profile must default-off"
        );
    }

    #[test]
    fn resolve_explicit_override_wins_labeler_true() {
        let cfg = cfg_with(Some(true));
        assert!(
            cfg.resolve_require_hardware_key(Profile::Labeler),
            "explicit POLARIS_REQUIRE_HARDWARE_KEY=true overrides labeler default"
        );
    }

    #[test]
    fn resolve_explicit_override_wins_bluesky_false() {
        let cfg = cfg_with(Some(false));
        assert!(
            !cfg.resolve_require_hardware_key(Profile::Bluesky),
            "explicit POLARIS_REQUIRE_HARDWARE_KEY=false overrides bluesky default"
        );
    }

    #[test]
    fn login_gate_outcome_carries_moderator_id() {
        // Pure constructor tests — no DB. Confirms the variant shape so a
        // future shape edit shows up here as a deliberate edit.
        let mid = ModeratorId::new_v4();
        let enroll = LoginGateOutcome::EnrollmentRequired { moderator_id: mid };
        match enroll {
            LoginGateOutcome::EnrollmentRequired { moderator_id } => {
                assert_eq!(moderator_id, mid);
            }
            _ => panic!("unexpected variant"),
        }
        let assert_outcome = LoginGateOutcome::AssertionRequired { moderator_id: mid };
        match assert_outcome {
            LoginGateOutcome::AssertionRequired { moderator_id } => {
                assert_eq!(moderator_id, mid);
            }
            _ => panic!("unexpected variant"),
        }
    }
}
