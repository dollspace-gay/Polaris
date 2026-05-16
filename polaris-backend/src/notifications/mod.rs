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
//! What's NOT in this PR (deferred):
//!
//! - The live APNs / FCM HTTP clients — they need real provider
//!   credentials (Apple Dev account, Firebase project) to integration
//!   test. The trait impls in `apns.rs` / `fcm.rs` ship as
//!   `unimplemented!()`-shaped stubs that the integration work
//!   replaces in a follow-up. The `NtfyProvider` ships functional
//!   because ntfy.sh requires no per-operator credentials.
//! - The fan-out subscriber that consumes the v1 internal bus and
//!   dispatches to PushProvider. That's the spawn-and-loop wiring;
//!   the PushProvider abstraction it spawns against ships here.

pub mod payload;
pub mod provider;
pub mod registration;

pub use payload::PushPayload;
pub use provider::{NtfyProvider, PushError, PushProvider};
pub use registration::{MobileDeviceRecord, Platform};
