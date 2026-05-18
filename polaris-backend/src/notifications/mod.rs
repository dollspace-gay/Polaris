//! Mobile push-notification subsystem (issue #116 / M5 #44 PR 2).
//!
//! Polaris-backend dispatches P1 escalation events to registered
//! mobile devices via APNs (iOS), FCM (Android), or ntfy.sh (labeler
//! profile). The dispatcher is mobile-shell-agnostic — the
//! Tauri-vs-PWA decision (#115) doesn't affect this module.
//!
//! # Privacy boundary
//!
//! Per AC-8 / REQ-8: push payloads carry NO PII. The payload shape
//! is `{ "type": "p1", "incident_id": "<uuid>" }`. The mobile app
//! uses the incident_id as a deep-link target after the moderator
//! taps the notification.
//!
//! # PR 2 scope
//!
//! - `PushProvider` trait + three impl types (apns, fcm, ntfy).
//! - `mobile_devices` Postgres table (migration 0030) + repo helpers.
//! - `register` POST endpoint surface for the mobile shell to upsert
//!   its push token.
//! - Push payload type + serde-Serialize derive.
//!
//! # Provider matrix
//!
//! - [`NtfyProvider`] — operator-public ntfy.sh transport. No
//!   credentials; works against `https://ntfy.sh` or a self-hosted
//!   ntfy server. Suited to the labeler profile.
//! - [`ApnsProvider`] — Apple HTTP/2 push gateway with ES256 JWT
//!   auth. Reads `POLARIS_APNS_*` env vars; the operator supplies
//!   a `.p8` key file, team id, key id, and bundle topic.
//! - [`FcmProvider`] — Firebase Cloud Messaging v1 with OAuth2
//!   service-account auth. Reads `POLARIS_FCM_*` env vars; the
//!   operator supplies a Firebase service-account JSON.
//!
//! What's NOT in this PR (deferred):
//!
//! - The fan-out subscriber that consumes the v1 internal bus and
//!   dispatches to PushProvider. That's the spawn-and-loop wiring;
//!   the PushProvider abstraction it spawns against ships here.

pub mod apns;
pub mod fcm;
pub mod payload;
pub mod provider;
pub mod registration;

pub use apns::{ApnsConfig, ApnsProvider};
pub use fcm::{FcmConfig, FcmProvider};
pub use payload::PushPayload;
pub use provider::{NtfyProvider, PushError, PushProvider};
pub use registration::{MobileDeviceRecord, Platform};
