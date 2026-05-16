//! `mobile_devices` table types + repo helpers (issue #116 / M5 #44 PR 2).
//!
//! The full axum handler for `POST /api/devices/register` lives in
//! `polaris-backend/src/api/devices.rs` (registered as a follow-up
//! because the auth-middleware integration is its own concern).
//! This module ships the pure-data types + the DB upsert function.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Mobile platform discriminator. Matches the migration's CHECK
/// constraint on `mobile_devices.platform`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Apple Push Notification service.
    Ios,
    /// Firebase Cloud Messaging.
    Android,
    /// ntfy.sh (operator-self-hosted or public).
    Ntfy,
}

impl Platform {
    /// Wire string for the DB CHECK constraint.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ios => "ios",
            Self::Android => "android",
            Self::Ntfy => "ntfy",
        }
    }
}

/// Row representation for `mobile_devices`. Maps directly onto the
/// migration 0030 columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileDeviceRecord {
    /// Polaris-internal device row PK.
    pub id: Uuid,
    /// Owning moderator.
    pub moderator_id: Uuid,
    /// Platform discriminator.
    pub platform: Platform,
    /// Opaque platform-issued push token.
    pub push_token: String,
    /// Last-active timestamp. Updated each time the mobile shell
    /// successfully completes a push-confirmation round-trip.
    pub last_active_at: chrono::DateTime<chrono::Utc>,
    /// Soft-deletion timestamp. NULL for active devices; set when
    /// the push transport reports the token as stale.
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Registration timestamp.
    pub registered_at: chrono::DateTime<chrono::Utc>,
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
    fn platform_serializes_lowercase() {
        let p = Platform::Ios;
        let s = serde_json::to_string(&p).unwrap();
        assert_eq!(s, "\"ios\"");
    }

    #[test]
    fn platform_as_str_matches_migration_check_constraint() {
        // Migration 0030: CHECK (platform IN ('ios', 'android', 'ntfy')).
        // The Platform::as_str values MUST match these exact strings or
        // the INSERT will fail with a constraint violation.
        assert_eq!(Platform::Ios.as_str(), "ios");
        assert_eq!(Platform::Android.as_str(), "android");
        assert_eq!(Platform::Ntfy.as_str(), "ntfy");
    }

    #[test]
    fn platform_round_trips_through_serde() {
        for p in [Platform::Ios, Platform::Android, Platform::Ntfy] {
            let json = serde_json::to_string(&p).unwrap();
            let back: Platform = serde_json::from_str(&json).unwrap();
            assert_eq!(p, back);
        }
    }
}
