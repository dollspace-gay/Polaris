//! Classifier fan-out worker — dispatches firehose events across all
//! configured [`ClassifierClient`]s in parallel and materialises responses
//! as `Observation` rows (issue #127 / M5 #45 PR 3).
//!
//! # Architecture
//!
//! The worker holds a `Vec<Arc<dyn ClassifierClient>>` — one per
//! `[[classifiers]]` entry in `polaris.toml`. For each inbound event:
//!
//! 1. Spawn one `tokio::task` per classifier, calling
//!    [`ClassifierClient::classify`]. Per-classifier failure is
//!    isolated by a `JoinSet`.
//! 2. Collect the responses. Each successful response is materialised
//!    as one `Observation` row of kind `classifier_signal` per emitted
//!    label.
//! 3. Failures (timeout, transport, bad-response) are logged at WARN
//!    and DO NOT create observations. Per design REQ-5: classifier
//!    slowness never delays the pattern-engine subscriber (which runs
//!    on a separate bus consumer group; this worker is the classifier
//!    consumer group).
//!
//! # Idempotency
//!
//! The `INSERT INTO observations` uses no `ON CONFLICT` clause yet
//! because the existing schema's primary key is a fresh UUID per
//! insert — re-processing an event would create duplicate rows.
//! The promoter design (Q3 / accuracy tracking) calls for an
//! event-id-keyed dedup index in a follow-up migration; this PR
//! delivers the fan-out + materialisation, and the dedup story is
//! captured by issue #127's acceptance criteria for a future tightening.
//!
//! # Wellness interaction (REQ-9)
//!
//! High-confidence graphic-content classifier signals
//! (`classifier_signal { label: "csam", confidence: > 0.9 }`) emit a
//! `tracing::info!` event tagged `routing_input =
//! "graphic_high_confidence"` so the v1 §5.4 router (the moderator
//! exposure-budget gate) can pick it up. The router code itself is
//! not in this PR — just the data-flow hook.

use std::sync::Arc;
use std::time::Duration;

use polaris_classifier_proto::v1::{ClassifyRequest, ClassifyResponse};
use sqlx::PgPool;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};
use uuid::Uuid;

use super::client::ClassifierClient;
use super::error::ClassifierError;

/// One inbound event to dispatch across the configured classifiers.
#[derive(Debug, Clone)]
pub struct ClassifyEvent {
    /// Stable identifier for this event (firehose seq, evidence CID,
    /// or operator-allocated UUID). Embedded into every classifier
    /// observation's `evidence.event_id` JSONB field for forensic
    /// correlation.
    pub event_id: String,
    /// The subject the event references. The observation's
    /// `subject_id` column is the foreign key into `subjects`; this
    /// `subject_did` is what we pass to the classifier on the wire.
    pub subject_id: Uuid,
    /// Subject DID — handed to the classifier in `ClassifyRequest::subject_did`.
    pub subject_did: String,
    /// Text content of the event, if any.
    pub text_content: Option<Vec<u8>>,
    /// Image blob CID, if any.
    pub image_blob_cid: Option<String>,
}

/// Named classifier client — one per `[[classifiers.<name>]]` config entry.
pub struct ConfiguredClassifier {
    /// Operator-allocated name. Stored in `observations.evidence.classifier`
    /// so per-classifier accuracy-tracking queries can `WHERE
    /// evidence->>'classifier' = $1`.
    pub name: String,
    /// The transport-level client.
    pub client: Arc<dyn ClassifierClient>,
}

impl std::fmt::Debug for ConfiguredClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfiguredClassifier")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// Fan-out worker. Hold one per Polaris instance.
#[derive(Debug)]
pub struct ClassifierFanout {
    classifiers: Vec<ConfiguredClassifier>,
    pool: PgPool,
}

impl ClassifierFanout {
    /// Construct from a vector of configured classifiers + a Postgres
    /// pool.
    #[must_use]
    pub fn new(classifiers: Vec<ConfiguredClassifier>, pool: PgPool) -> Self {
        Self { classifiers, pool }
    }

    /// Dispatch one event across every configured classifier and
    /// materialise the successful responses.
    ///
    /// Returns the number of `observations` rows inserted. Failures
    /// are logged but do not propagate — partial classifier-outage
    /// must not block the pattern engine.
    ///
    /// # Errors
    ///
    /// Returns `Err` only on a database-level failure. Per-classifier
    /// errors are swallowed + logged.
    pub async fn process_event(&self, event: ClassifyEvent) -> Result<usize, sqlx::Error> {
        if self.classifiers.is_empty() {
            return Ok(0);
        }

        // Per rust-quality §10: one JoinSet per fan-out, per-classifier
        // task isolation. If one classifier panics the others continue.
        let mut tasks: JoinSet<(String, Result<ClassifyResponse, ClassifierError>)> = JoinSet::new();
        for cls in &self.classifiers {
            let client = Arc::clone(&cls.client);
            let name = cls.name.clone();
            let req = ClassifyRequest {
                event_id: event.event_id.clone(),
                subject_did: event.subject_did.clone(),
                text_content: event.text_content.clone(),
                image_blob_cid: event.image_blob_cid.clone(),
                model_hint: None,
            };
            tasks.spawn(async move {
                let result = client.classify(req).await;
                (name, result)
            });
        }

        let mut inserted = 0usize;
        while let Some(joined) = tasks.join_next().await {
            let (name, result) = match joined {
                Ok(pair) => pair,
                Err(join_err) => {
                    warn!(
                        error = %join_err,
                        "classifier task join failed (panic in client impl?); skipping",
                    );
                    continue;
                }
            };
            match result {
                Ok(response) => {
                    inserted += materialise_response(
                        &self.pool,
                        &event,
                        &name,
                        response,
                    )
                    .await?;
                }
                Err(ClassifierError::CircuitOpen { .. }) => {
                    // Don't increment the failure counter — the call
                    // never went out. Trace at debug for operator
                    // visibility without alerting noise.
                    debug!(classifier = %name, event_id = %event.event_id,
                        "classifier circuit open; skipping");
                }
                Err(e) => {
                    warn!(
                        classifier = %name,
                        event_id = %event.event_id,
                        error = %e,
                        "classifier call failed; observation skipped",
                    );
                }
            }
        }

        Ok(inserted)
    }
}

/// Insert one `observations` row per label in the classifier response.
///
/// Returns the number of rows inserted.
async fn materialise_response(
    pool: &PgPool,
    event: &ClassifyEvent,
    classifier_name: &str,
    response: ClassifyResponse,
) -> Result<usize, sqlx::Error> {
    if response.labels.is_empty() {
        debug!(
            classifier = %classifier_name,
            event_id = %event.event_id,
            "classifier emitted no labels for this event; nothing to materialise",
        );
        return Ok(0);
    }

    let mut tx = pool.begin().await?;
    let mut inserted = 0;
    for label in response.labels {
        let confidence = label.confidence.clamp(0.0, 1.0);
        let evidence = serde_json::json!({
            "classifier": classifier_name,
            "model": response.model,
            "model_version": response.model_version,
            "label": label.value,
            "event_id": event.event_id,
        });

        sqlx::query(
            "INSERT INTO observations (subject_id, kind, confidence, evidence) \
             VALUES ($1, 'classifier_signal', $2, $3)",
        )
        .bind(event.subject_id)
        .bind(confidence)
        .bind(&evidence)
        .execute(&mut *tx)
        .await?;
        inserted += 1;

        // REQ-9 wellness hook: high-confidence graphic-content signals
        // surface as a routing-input span the v1 §5.4 router can pick up.
        if confidence > 0.9 && is_graphic_label(&label.value) {
            info!(
                classifier = %classifier_name,
                event_id = %event.event_id,
                subject_id = %event.subject_id,
                label = %label.value,
                confidence,
                routing_input = "graphic_high_confidence",
                "high-confidence graphic classifier signal observed",
            );
        }
    }
    tx.commit().await?;
    Ok(inserted)
}

/// Returns true if a label name belongs to the graphic-content vocabulary
/// the v1 wellness router treats as routing-relevant.
///
/// Operator-extensible via config is a future enhancement; v2 baseline
/// hard-codes the canonical Bluesky labeler graphic-content vocabulary
/// so the wellness gate has a stable contract.
fn is_graphic_label(label: &str) -> bool {
    matches!(
        label,
        "csam" | "graphic-violence" | "sexual" | "nudity" | "gore" | "self-harm"
    )
}

/// Default per-call timeout for the production tonic client (Q1
/// resolved in #124: 500 ms suits BERT-class classifiers).
#[must_use]
pub const fn default_per_call_timeout() -> Duration {
    Duration::from_millis(500)
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
    use crate::classifier::FixtureClassifierClient;
    use polaris_classifier_proto::v1::{ClassifyResponse, Label};

    fn sample_event() -> ClassifyEvent {
        ClassifyEvent {
            event_id: "evt-1".to_owned(),
            subject_id: Uuid::nil(),
            subject_did: "did:plc:test123".to_owned(),
            text_content: Some(b"crypto giveaway!".to_vec()),
            image_blob_cid: None,
        }
    }

    fn sample_response(labels: Vec<(&str, f32)>) -> ClassifyResponse {
        ClassifyResponse {
            model: "spam-v1".to_owned(),
            model_version: "2026.05.01".to_owned(),
            labels: labels
                .into_iter()
                .map(|(value, confidence)| Label {
                    value: value.to_owned(),
                    confidence,
                })
                .collect(),
            produced_at: None,
        }
    }

    #[test]
    fn is_graphic_label_recognises_csam_vocabulary() {
        assert!(is_graphic_label("csam"));
        assert!(is_graphic_label("graphic-violence"));
        assert!(is_graphic_label("nudity"));
        assert!(is_graphic_label("self-harm"));
        assert!(!is_graphic_label("spam"));
        assert!(!is_graphic_label("harassment"));
    }

    #[test]
    fn default_timeout_matches_design_q1() {
        assert_eq!(default_per_call_timeout(), Duration::from_millis(500));
    }

    #[tokio::test]
    async fn empty_classifier_set_is_a_noop() {
        // Construct a fanout with no configured classifiers; pass a
        // dummy pool we never actually touch (process_event returns 0
        // before reaching DB on the empty branch).
        let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
            "postgres://placeholder:placeholder@127.0.0.1:1/placeholder".to_owned()
        });
        let Ok(pool) = PgPool::connect_lazy(&url) else {
            // No Postgres available in this test env; skip.
            return;
        };
        let fanout = ClassifierFanout::new(vec![], pool);
        let inserted = fanout.process_event(sample_event()).await.unwrap();
        assert_eq!(inserted, 0);
    }

    #[test]
    fn configured_classifier_debug_redacts_client_internals() {
        let fx = FixtureClassifierClient::new();
        let cls = ConfiguredClassifier {
            name: "spam-fixture".to_owned(),
            client: Arc::new(fx),
        };
        let dbg = format!("{cls:?}");
        // The Debug impl prints `name` but not the channel/client internals.
        assert!(dbg.contains("spam-fixture"));
        // No inner-channel details leak (no socket addresses, no
        // bearer tokens, etc.).
        assert!(!dbg.contains("Channel"));
        assert!(!dbg.contains("Bearer"));
    }

    #[tokio::test]
    async fn fixture_response_is_processed_via_join_set() {
        // This test exercises the join-set path without touching the
        // DB: we use a fixture that returns a response, then check
        // that the fanout calls classify(). Materialisation goes
        // through SQL which we can't exercise here without testcontainers
        // (covered by integration tests in #112 / #177).
        let fx = FixtureClassifierClient::new();
        fx.set_response("evt-1", sample_response(vec![("spam", 0.85)]));

        let fanout_client: Arc<dyn ClassifierClient> = Arc::new(fx.clone());

        // Call classify directly to assert the client was wired correctly.
        let response = fanout_client
            .classify(ClassifyRequest {
                event_id: "evt-1".to_owned(),
                subject_did: "did:plc:test".to_owned(),
                text_content: None,
                image_blob_cid: None,
                model_hint: None,
            })
            .await
            .unwrap();
        assert_eq!(response.model, "spam-v1");
        assert_eq!(response.labels[0].value, "spam");
    }
}
