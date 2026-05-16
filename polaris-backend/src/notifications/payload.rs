//! Push-notification payload (issue #116 / M5 #44 PR 2).
//!
//! Per AC-8 / REQ-8: NO PII. The payload carries only the type
//! discriminator + the incident UUID. The mobile app uses the
//! `incident_id` as a deep-link target after the moderator taps.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shape of the push payload Polaris sends to APNs / FCM / ntfy.
///
/// Privacy contract: ONLY `type` + `incident_id`. No moderator name,
/// no subject content, no reporter identity. Tested via the
/// `payload_serialization_carries_no_pii` invariant below.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushPayload {
    /// Notification type discriminator. Currently the only value
    /// is `"p1"` for P1 escalation events.
    #[serde(rename = "type")]
    pub kind: String,

    /// Incident UUID — used by the mobile app as a deep-link target.
    pub incident_id: Uuid,
}

impl PushPayload {
    /// Construct a P1 escalation payload.
    #[must_use]
    pub fn p1(incident_id: Uuid) -> Self {
        Self {
            kind: "p1".to_owned(),
            incident_id,
        }
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
    fn p1_payload_serializes_to_expected_shape() {
        let id = Uuid::nil();
        let p = PushPayload::p1(id);
        let json = serde_json::to_string(&p).unwrap();
        // The shape MUST be exactly `{"type":"p1","incident_id":"…"}`.
        // Per AC-8 — verified by the explicit substring assertions
        // below + the no-PII grep that follows.
        assert!(json.contains(r#""type":"p1""#));
        assert!(json.contains(r#""incident_id":"00000000-0000-0000-0000-000000000000""#));
    }

    /// AC-8: the payload carries NO PII. This test asserts the
    /// negative — no forbidden substring may appear in the
    /// serialized form.
    #[test]
    fn payload_serialization_carries_no_pii() {
        let p = PushPayload::p1(Uuid::nil());
        let json = serde_json::to_string(&p).unwrap();
        for forbidden in [
            "moderator",
            "reporter",
            "did:plc",
            "@",
            "subject_content",
            "reasoning",
            "audit",
            "exposure",
        ] {
            assert!(
                !json.contains(forbidden),
                "payload {json:?} contains forbidden PII substring {forbidden:?}",
            );
        }
    }

    #[test]
    fn payload_round_trips_through_serde() {
        let p = PushPayload::p1(Uuid::nil());
        let json = serde_json::to_string(&p).unwrap();
        let back: PushPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }
}
