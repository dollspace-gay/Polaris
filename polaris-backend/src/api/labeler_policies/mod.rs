//! `GET /api/labeler/policies` — read-only access to the labeler's
//! declared label values + definitions for the moderator's frontend
//! (issue #96 / mod-workstation feature #6).
//!
//! # Why this endpoint exists
//!
//! The frontend's `SubscriberEffectPreview` component (inside
//! `ActionComposer`) needs the labeler's declared
//! `labelValueDefinitions` to compute the per-label subscriber-effect
//! forecast — i.e. "this label as `warn` will hide-by-default for
//! ~85% of subscribers". The data is operator-public (it lives in
//! the `app.bsky.labeler.service` record on the operator's PDS), so
//! the endpoint has no admin gate: any authenticated moderator can
//! read it.
//!
//! # Data source
//!
//! Reads `polaris_setup_state.label_values` + `label_value_definitions`,
//! which are persisted by `publish_labeler_record` (issue #85, extended
//! by #96). The handler does NOT round-trip to the operator's PDS:
//!
//! 1. The PDS is the canonical source, but a remote hop on every
//!    composer keystroke would make the preview unusable.
//! 2. The local row is the same data the wizard published — the
//!    `publish_labeler_record` step is the single writer.
//!
//! # `subscriber_likes` field
//!
//! Populated from the AppView's `app.bsky.labeler.getServices`
//! endpoint via the process-local TTL cache in
//! [`subscriber_likes`]. The cache TTL (5 minutes) keeps the
//! upstream load bounded under the moderator's composer-render
//! fan-out; on a cache miss the lookup happens out of band and
//! the response either carries the fresh count or `None` if the
//! upstream is degraded. The frontend renders the absolute count
//! when present and falls back to the AT-Proto reference-defaults
//! caveat when absent.

use axum::Json;
use axum::extract::State;

use crate::api::error::ApiError;
use crate::api::state::ApiState;

pub mod forecast;
pub(crate) mod subscriber_likes;

/// Response payload for `GET /api/labeler/policies`.
///
/// Mirrors the frontend's `LabelerPoliciesResponse` DTO field-for-field.
/// The fields' wire shape follows the AT-Proto labeler service record's
/// `policies` object literally — so the frontend reads a layout it
/// can re-use for any future server-rendered preview consumer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LabelerPoliciesResponse {
    /// The set of label values this labeler declares it can emit.
    /// Mirrors `policies.labelValues` on the labeler service record.
    pub label_values: Vec<String>,
    /// Per-value rendering metadata (severity, defaultSetting, locales,
    /// blurs flag). Each entry is the lexicon-shaped
    /// `LabelValueDefinition` JSON object verbatim.
    ///
    /// `serde_json::Value` because the wire shape IS the lexicon
    /// shape; the policies endpoint is a pass-through over the JSONB
    /// column. Validation happens in `publish_labeler_record` before
    /// the row is written.
    pub label_value_definitions: serde_json::Value,
    /// The labeler's subscriber-count proxy (the
    /// `app.bsky.labeler.getServices` `likeCount` field), populated
    /// via the process-local TTL cache in [`subscriber_likes`].
    /// `Some(n)` when the AppView returned a fresh count (`n` may
    /// be zero for a freshly-published labeler); `None` when the
    /// operator has not yet published a labeler record OR the
    /// upstream fetch failed. The frontend renders the absolute
    /// count when present and falls back to the AT-Proto reference
    /// defaults caveat otherwise.
    pub subscriber_likes: Option<u32>,
}

/// `GET /api/labeler/policies` — return the operator's declared label
/// policies for the moderator's frontend.
///
/// # Errors
///
/// - [`ApiError::NotFound`] when `polaris_setup_state` carries no
///   `label_values` (i.e. the operator has not completed the
///   `publish-labeler-record` step yet). The frontend interprets
///   404 here as "preview unavailable; recommend completing setup".
/// - [`ApiError::Internal`] on a DB failure or a malformed JSONB
///   payload (the persist path stamps a known-valid shape, so the
///   internal-error variant is unreachable in practice; it exists
///   for completeness).
pub async fn policies(
    State(state): State<ApiState>,
) -> Result<Json<LabelerPoliciesResponse>, ApiError> {
    let row = sqlx::query!(
        r"SELECT label_values, label_value_definitions
            FROM polaris_setup_state
            WHERE id = TRUE",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    // `label_values` is the load-bearing field: a row with no
    // `label_values` means the setup wizard has not yet published a
    // record, so there is no policy to preview. Surface as 404 so
    // the frontend can render the "complete setup" affordance.
    let Some(label_values) = row.label_values else {
        return Err(ApiError::NotFound);
    };

    let label_value_definitions = row
        .label_value_definitions
        .unwrap_or_else(|| serde_json::Value::Array(Vec::new()));

    // Subscriber-likes fetch is best-effort: a transport failure
    // surfaces as `None` and the frontend falls back to the
    // reference-defaults caveat. Only a database failure (couldn't
    // read `labeler_record_uri`) bubbles up as 500.
    let subscriber_likes = subscriber_likes::fetch_subscriber_likes(&state.pool)
        .await
        .map_err(|e| ApiError::Internal(anyhow::Error::new(e)))?;

    Ok(Json(LabelerPoliciesResponse {
        label_values,
        label_value_definitions,
        subscriber_likes,
    }))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;

    #[test]
    fn response_serialises_with_camel_snake_field_names_matching_frontend() {
        let body = LabelerPoliciesResponse {
            label_values: vec!["spam".into(), "porn".into()],
            label_value_definitions: serde_json::json!([{
                "identifier": "spam",
                "severity": "inform",
                "blurs": "none",
                "defaultSetting": "warn",
                "locales": []
            }]),
            subscriber_likes: None,
        };
        let json = serde_json::to_value(&body).expect("serialize");
        assert!(json.get("label_values").is_some());
        assert!(json.get("label_value_definitions").is_some());
        assert!(json.get("subscriber_likes").is_some());
        assert!(json["subscriber_likes"].is_null());
    }
}
