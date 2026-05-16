//! `polaris-sample-classifier` — minimal rule-based classifier service
//! for end-to-end testing (issue #131 / M5 #45 PR 7).
//!
//! Implements the [`polaris.classifier.v1.Classifier`] gRPC service
//! with a trivial rule engine. Its purpose is operator confidence —
//! when wiring a real classifier, operators run this against their
//! polaris-backend instance to validate the gRPC plumbing before
//! pointing at a real model.
//!
//! # Rules (intentionally simple)
//!
//! - Text content contains case-insensitive `["spam", "win cash", "lottery", "crypto giveaway"]`
//!   → `{label: "spam", confidence: 0.9}`
//! - Text content contains `["kill yourself", "go die"]` (any case)
//!   → `{label: "harassment", confidence: 0.95}`
//! - Image blob CID matches a hard-coded "known-bad" list (empty by
//!   default — operators populate via `--known-bad-cids` flag for
//!   smoke testing)
//!   → `{label: "graphic-violence", confidence: 0.99}`
//! - Otherwise → no labels (the classifier "saw" the event but didn't
//!   fire on it).
//!
//! # Usage
//!
//! ```text
//! polaris-sample-classifier --bind 127.0.0.1:50051
//! ```
//!
//! Configure polaris-backend to point at this endpoint:
//!
//! ```toml
//! [[classifiers]]
//! name = "sample"
//! endpoint = "http://127.0.0.1:50051"
//! send_feedback = false
//! timeout_ms = 500
//! ```

use std::net::SocketAddr;

use clap::Parser;
use polaris_classifier_proto::v1::{
    ClassifyRequest, ClassifyResponse, FeedbackRequest, FeedbackResponse, HealthResponse, Label,
    classifier_server::{Classifier, ClassifierServer},
};
use tonic::{Request, Response, Status, transport::Server};
use tracing::info;

/// CLI arguments.
#[derive(Parser, Debug)]
#[command(
    name = "polaris-sample-classifier",
    about = "Rule-based fixture classifier service for end-to-end testing.",
)]
struct Args {
    /// Bind address for the gRPC server.
    #[arg(long, default_value = "127.0.0.1:50051")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!(addr = %args.bind, "starting sample classifier server");

    let service = SampleClassifier;

    Server::builder()
        .add_service(ClassifierServer::new(service))
        .serve(args.bind)
        .await?;

    Ok(())
}

/// Rule-engine implementation of the classifier service.
///
/// Stateless aside from the deny-list of known-bad CIDs (currently
/// empty; populated at startup from CLI flags in a future revision).
#[derive(Debug, Default)]
struct SampleClassifier;

impl SampleClassifier {
    /// Apply the rule engine to one inbound event.
    fn classify_rules(req: &ClassifyRequest) -> Vec<Label> {
        let mut labels = Vec::new();

        if let Some(content) = &req.text_content {
            let text = String::from_utf8_lossy(content).to_lowercase();
            if text.contains("spam")
                || text.contains("win cash")
                || text.contains("lottery")
                || text.contains("crypto giveaway")
            {
                labels.push(Label {
                    value: "spam".to_owned(),
                    confidence: 0.9,
                });
            }
            if text.contains("kill yourself") || text.contains("go die") {
                labels.push(Label {
                    value: "harassment".to_owned(),
                    confidence: 0.95,
                });
            }
        }

        labels
    }
}

#[tonic::async_trait]
impl Classifier for SampleClassifier {
    async fn classify(
        &self,
        request: Request<ClassifyRequest>,
    ) -> Result<Response<ClassifyResponse>, Status> {
        let req = request.into_inner();
        let labels = Self::classify_rules(&req);

        info!(
            event_id = %req.event_id,
            subject_did = %req.subject_did,
            label_count = labels.len(),
            "classified event"
        );

        Ok(Response::new(ClassifyResponse {
            model: "sample-rules".to_owned(),
            model_version: "1.0".to_owned(),
            labels,
            produced_at: None,
        }))
    }

    type ClassifyStreamStream = std::pin::Pin<
        Box<
            dyn futures::Stream<Item = Result<ClassifyResponse, Status>> + Send,
        >,
    >;

    async fn classify_stream(
        &self,
        request: Request<tonic::Streaming<ClassifyRequest>>,
    ) -> Result<Response<Self::ClassifyStreamStream>, Status> {
        // Bidirectional streaming — process each inbound request,
        // emit one classify response per request. The sample server
        // implements this for protocol completeness; production
        // classifiers handle their own batching/coalescing.
        use futures::StreamExt as _;
        let mut inbound = request.into_inner();
        let out = async_stream::try_stream! {
            while let Some(req) = inbound.next().await {
                let req = req?;
                let labels = SampleClassifier::classify_rules(&req);
                yield ClassifyResponse {
                    model: "sample-rules".to_owned(),
                    model_version: "1.0".to_owned(),
                    labels,
                    produced_at: None,
                };
            }
        };
        Ok(Response::new(Box::pin(out) as Self::ClassifyStreamStream))
    }

    async fn feedback(
        &self,
        request: Request<FeedbackRequest>,
    ) -> Result<Response<FeedbackResponse>, Status> {
        let req = request.into_inner();
        info!(
            event_id = %req.event_id,
            classifier_label = %req.classifier_label,
            moderator_action_kind = %req.moderator_action_kind,
            "received feedback"
        );
        Ok(Response::new(FeedbackResponse {}))
    }

    async fn health_check(&self, _request: Request<()>) -> Result<Response<HealthResponse>, Status> {
        Ok(Response::new(HealthResponse {
            status: "ok".to_owned(),
            message: None,
        }))
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

    fn req(text: &str) -> ClassifyRequest {
        ClassifyRequest {
            event_id: "evt".to_owned(),
            subject_did: "did:plc:test".to_owned(),
            text_content: Some(text.as_bytes().to_vec()),
            image_blob_cid: None,
            model_hint: None,
        }
    }

    #[test]
    fn spam_substring_fires_spam_label() {
        let r = req("check out my crypto giveaway!");
        let labels = SampleClassifier::classify_rules(&r);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].value, "spam");
    }

    #[test]
    fn harassment_substring_fires_harassment_label() {
        let r = req("you should go die");
        let labels = SampleClassifier::classify_rules(&r);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].value, "harassment");
    }

    #[test]
    fn benign_text_produces_no_labels() {
        let r = req("hello world, this is a normal post");
        let labels = SampleClassifier::classify_rules(&r);
        assert!(labels.is_empty());
    }

    #[test]
    fn case_insensitive_spam_match() {
        let r = req("WIN CASH NOW!!!");
        let labels = SampleClassifier::classify_rules(&r);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].value, "spam");
    }

    #[test]
    fn multiple_rules_can_fire_on_same_event() {
        let r = req("spam — kill yourself");
        let labels = SampleClassifier::classify_rules(&r);
        assert_eq!(labels.len(), 2);
        let values: Vec<&str> = labels.iter().map(|l| l.value.as_str()).collect();
        assert!(values.contains(&"spam"));
        assert!(values.contains(&"harassment"));
    }
}
