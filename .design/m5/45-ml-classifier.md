# M5 design — Issue #45: Add ML classifier integration via gRPC as a pattern-engine signal source

## Summary

Wire a gRPC client (`polaris.classifier.v1.Classifier`) into the v1 pattern
engine so that classifier output (NSFW image, harassment text, spam, etc.)
flows in as another `Observation` source — never as an autonomous actor.
A human always takes the action; the classifier supplies a signal weighted
alongside upstream labels, reports, and pattern-engine detections. The
integration is fault-tolerant: classifier slowness or unreachability never
blocks firehose ingest.

## v1 connection points

- `design.md` §10: "ML classifier integration shape. Bluesky has in-house
  classifiers; the right integration is probably gRPC with classifier
  output as another signal feeding the pattern engine, never as an
  autonomous actor. Worth a separate design conversation rather than
  locking in here." This issue is that separate design.
- `.design/polaris-proto-blue-integration.md` Out of Scope: "ML classifier
  integration shape (`design.md` §10). Out of scope; orthogonal to the
  proto-blue integration."
- Builds on the v1 pattern engine (introduced in `design.md` §3.2 and
  delivered in milestone M2). The pattern engine is built to accept
  additional `Observation` sources, per the v1 design.
- Builds on the v1 `Observation` type
  (`polaris-types::Observation { kind: ObservationKind, confidence: f32,
  evidence: serde_json::Value, ... }` from `design.md` §4). This issue
  adds a new variant `ObservationKind::ClassifierSignal { model: String,
  label: String, confidence: f32 }`.
- Builds on the v1 per-upstream trust weight model
  (`polaris-backend/src/repo/upstream_labelers.rs` from #32) — per-
  classifier trust weights mirror that model.
- Builds on the v1 firehose ingest worker
  (`polaris-backend/src/ingest/firehose.rs`) which is where classifier
  fan-out is wired.

## Requirements

- REQ-1: A gRPC service definition `polaris.classifier.v1.Classifier`
  lives in `proto/polaris-classifier-v1.proto` with two RPCs at minimum:
  `ClassifyEvent(ClassifyRequest) -> ClassifyResponse` (single-shot,
  synchronous) and `ClassifyStream(stream ClassifyRequest) -> stream
  ClassifyResponse` (high-throughput bidirectional).
- REQ-2: `polaris-backend` ships a `pub trait ClassifierClient` and a
  `tonic`-based default implementation that connects to a configured
  gRPC endpoint per classifier.
- REQ-3: Classifier output materializes as `Observation { kind:
  ClassifierSignal { model: "<model_name>", label: "<label_value>",
  confidence: f32 }, ... }` rows attached to the matching `Subject`.
- REQ-4: Per-classifier trust weight (mirrors the upstream-labeler
  weights from #32): `[[classifiers]] endpoint = "https://..." name =
  "..." weights = { spam = 0.9, harassment = 0.7 }`.
- REQ-5: Failure modes are non-blocking. Per-call timeout (default
  500ms), circuit breaker per-classifier with exponential backoff,
  bounded in-flight requests per classifier. Classifier unreachable /
  slow / erroring: ingest continues without the classifier's
  contribution.
- REQ-6: Multiple classifiers can disagree. The case view surfaces
  classifier disagreement (e.g., "Model A: harassment 0.85; Model B:
  not-harassment 0.92") rather than collapsing it to a single signal.
- REQ-7: Classifier output is never auto-actioned. No code path in
  `polaris-backend` reads classifier output and emits a Label /
  Takedown without a moderator decision.
- REQ-8: Privacy: training-data feedback is opt-in and never sends raw
  reported content to a model provider without explicit operator
  consent. The default mode does not export any data back to the
  classifier service beyond what the classifier already saw at
  inference time.
- REQ-9: The classifier's resource consumption interacts with v1 §7.5
  moderator-wellness exposure budgets: a high-confidence
  graphic-content classification routes content with appropriate
  content warnings and counts against the receiving moderator's
  exposure budget.

## Acceptance Criteria

- [ ] AC-1: A fixture gRPC classifier (in-process tonic server) returns
      `{ label: "spam", confidence: 0.85 }` for a given event. Within 5
      seconds of firehose ingest of that event, an `Observation` with
      `kind: ClassifierSignal { model: "fixture", label: "spam",
      confidence: 0.85 }` appears in the case store attached to the
      matching `Subject`.
- [ ] AC-2: Classifier-down: with the fixture classifier disabled,
      firehose ingest continues without error; `Observation` rows for
      that classifier are not created; other classifier observations
      proceed normally.
- [ ] AC-3: Classifier-disagreement: with two fixture classifiers
      returning opposite labels for the same event, both observations
      land in the case store and the case view surfaces both.
- [ ] AC-4: Latency budget: classifier RPC `ClassifyEvent` calls have a
      configurable timeout (default 500ms); a classifier exceeding the
      timeout is cut off and the ingest event proceeds without that
      classifier's signal.
- [ ] AC-5: Circuit breaker: after 10 consecutive timeouts on a single
      classifier, that classifier is short-circuited for 60 seconds
      (no calls attempted). After the cooldown, a single probe call
      attempts to restore.
- [ ] AC-6: No auto-action: code review (and a CI lint) confirms that
      no path from `Observation::ClassifierSignal` reaches the action-
      emission layer without traversing the v1 moderator-decision API
      (`POST /api/actions`).
- [ ] AC-7: Training-data feedback path: with `[classifiers.<name>]
      send_feedback = false` (default), no moderator-action data is
      sent back to the classifier endpoint. With
      `send_feedback = true`, a moderator's final action on a subject
      that received a `ClassifierSignal` observation is sent back via
      a `polaris.classifier.v1.Classifier::Feedback` RPC.

## Architecture sketch

**gRPC service shape.** Using `tonic`. The proto:

```proto
service Classifier {
  rpc Classify(ClassifyRequest) returns (ClassifyResponse);
  rpc ClassifyStream(stream ClassifyRequest) returns (stream ClassifyResponse);
  rpc Feedback(FeedbackRequest) returns (FeedbackResponse);
  rpc HealthCheck(google.protobuf.Empty) returns (HealthResponse);
}
```

The single-shot `Classify` is the v2 baseline path used by the firehose
ingest worker. `ClassifyStream` is reserved for high-throughput Bluesky-
profile deployments where the per-RPC overhead of `Classify` is
noticeable. `Feedback` is the opt-in moderator-action callback. `Health`
is plumbed into the circuit breaker.

**File layout.**
- `proto/polaris-classifier-v1.proto` — the schema.
- `polaris-classifier-proto/` — generated tonic code, a thin crate.
- `polaris-backend/src/classifier/client.rs` — `ClassifierClient` trait,
  tonic-backed default impl, in-memory fixture impl for tests.
- `polaris-backend/src/classifier/fanout.rs` — fan-out from the firehose
  ingest worker to per-classifier RPC calls.
- `polaris-backend/src/classifier/circuit.rs` — circuit breaker.
- `polaris-backend/src/classifier/budget.rs` — bounded-concurrency
  pool per classifier.

**Fan-out integration with firehose ingest.** The v1 firehose ingest
worker (`polaris-backend/src/ingest/firehose.rs`) emits events onto the
internal bus (Kafka for Bluesky, NATS for labeler). A new subscriber on
the bus, `polaris-backend/src/classifier/fanout.rs`, picks up events,
performs the classifier RPC fan-out, and writes the resulting
`Observation` rows. **Critical**: the fan-out subscriber is independent
of the pattern-engine subscriber; classifier slowness does not delay
pattern detection.

**Bounded outstanding requests.** Per-classifier, a `tokio::sync::Semaphore`
caps in-flight calls (default 64). A classifier accepting events faster
than it can classify is rate-limited at the boundary, not by piling up
in-memory or in-bus.

**Trust weight integration.** The v2 trust model (#47) is the
appropriate place for richer per-classifier weighting. For this issue,
the v1 flat-weight model is sufficient. The `[[classifiers]] weights`
config table is read at startup and stored in
`classifier_weights` (mirroring the `upstream_labelers.weights JSONB`
shape — see #32). The weight is attached to the observation at
materialization time.

**Privacy boundary.** The default mode (`send_feedback = false`) is
strict: only the classifier inference path sees content (the operator
already chose to send firehose events to that classifier; that is the
trust grant). Moderator actions are NOT exported back. If a classifier
provider claims to need feedback to improve, that requires explicit
operator opt-in — and even then, the feedback shape is `{ event_id,
classifier_label, classifier_confidence, moderator_action_kind }` not
the moderator's reasoning text.

**Cloud-API vs. self-hosted.** This is a critical decision, see Q2 below.
A cloud-hosted classifier sees every event the operator forwards to it
— that is a privacy disclosure to the cloud provider. The v2 baseline
assumes self-hosted classifiers (e.g., the Bluesky in-house models
running on Bluesky infrastructure). Cloud-API classifiers (OpenAI
Moderation API, Perspective API) are supported but require explicit
operator consent and a documented data-flow disclosure.

**Wellness interaction.** A `ClassifierSignal { label: "csam", confidence:
>0.9 }` should route the case strictly through the v1 §5.4 trained-
moderator router with full content warnings. The classifier is one of
the inputs to "is this content graphic," not the sole input.

**New migrations.**
- `classifier_signals` table — one row per `Observation` of kind
  `ClassifierSignal`. Indexes by subject and by classifier.
- `classifier_health` table — per-classifier circuit-breaker state
  (open/closed/half-open, last-failure-at, consecutive-failure-count).

**Backwards-compatibility story.** Additive. Deployments without any
`[[classifiers]]` configured don't run the fan-out subscriber. Existing
pattern-engine code paths are unchanged.

**Dependencies on other M5 issues.** Independent. The richer trust
model in #47 will eventually subsume per-classifier flat weights;
classifier integration ships before #47 with the flat-weight model.

## Open questions

<!-- OPEN: Q1 -->
### Q1: Model type — fine-tuned LLM, fine-tuned classifier, or rule engine?

This is what runs on the OTHER side of the gRPC boundary, not what
Polaris ships. But the design must accommodate the realistic
candidates:

- **A. Fine-tuned BERT-class classifier** (e.g., DistilBERT,
  RoBERTa). Inference latency: 10-100ms. Self-hosted feasible on
  CPU. Output: per-label probability.
- **B. Fine-tuned LLM** (e.g., Llama 3 fine-tuned for moderation).
  Inference latency: 200ms-2s. Self-hosted requires GPU. Output:
  structured JSON typically.
- **C. Rule engine** (regex + heuristic). Inference latency: <1ms.
  Cheapest. Output: rule hit list.

The gRPC shape is model-agnostic; Polaris doesn't care. But the v1
timeout default (500ms) implicitly assumes A or C. If B is the
expected model, defaults change.

**To resolve**: human decision per deployment. The proto allows
arbitrary model identifiers; the timeout is per-classifier
configurable. The v2 default tuned for A is reasonable.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Self-hosted vs. cloud-API classifiers

The critical privacy question. A cloud-hosted classifier (OpenAI
Moderation, Perspective API, Hive) sees every event the operator
forwards.

- **A. Self-hosted only.** Operator runs their own classifier
  service. Polaris connects to it within the operator's network
  boundary.
- **B. Cloud-API supported with explicit consent flag.** Operator
  sets `[[classifiers.<name>]] external = true` and a startup banner
  names the providers receiving moderation data.
- **C. Both with operator transparency.** Default to self-hosted,
  allow cloud-API with explicit per-classifier opt-in and a UI
  banner that surfaces "this case was scored by external classifier
  X" so moderators know.

Recommend C. The Bluesky profile will run self-hosted (their
in-house models); the labeler profile may want cloud-API access to
classifiers they don't have the infra to host. Transparency at the
case-view level keeps the trust grant explicit.

**To resolve**: human decision. Per-operator and likely
per-jurisdiction (some operators cannot legally export moderation
data to a US-based cloud provider).
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: Continuous evaluation — how does the classifier improve from moderator corrections?

The training-data feedback path (REQ-8) is the surface for this. But
the actual learning loop is OUT of Polaris's scope — that happens on
the classifier side, not in Polaris. What Polaris CAN do is:

- **A. Track classifier accuracy per category over time.** Compare
  classifier output against the moderator's final action. Surface
  accuracy decay to operators.
- **B. Surface "classifier X has been wrong N times this week"** so
  operators can adjust trust weights.
- **C. Auto-decay trust weight** when accuracy drops. Risk:
  cascade — a classifier mid-degradation gets less weight, fewer
  moderator corrections flow back, accuracy degrades further.

Recommend A as the v2 baseline. B is a UI add-on. C is dangerous
without per-category supervision and should not be automated.

**To resolve**: confirm. The deeper question of "should Polaris own a
classifier-retraining pipeline" is firmly NO for v2.
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: gRPC vs. WebSocket vs. HTTP for the classifier transport

The plan comment names gRPC. Alternatives:

- **A. gRPC** (proposed, tonic). Strongly-typed proto schema,
  bidirectional streaming, mature in Rust. The plan comment's
  default.
- **B. WebSocket** with a Polaris-defined JSON protocol. Lighter
  dependency footprint. Less strict schema discipline.
- **C. HTTP/JSON** with batching. Simplest. No streaming.

Recommend A. The proto-as-schema discipline matters here because
classifier evolution must not silently break Polaris's expectations.

**To resolve**: confirm. If a major classifier vendor only offers
HTTP/JSON (e.g., Perspective API), we wrap them in a tonic-bridge
adapter rather than weakening the canonical protocol.
<!-- /OPEN -->

<!-- OPEN: Q5 -->
### Q5: Disagreement scoring and surfacing

REQ-6 says surface disagreement to the moderator. But HOW? Options:

- **A. Side-by-side display.** Both labels visible; no aggregate
  score.
- **B. Confidence-weighted aggregate** plus side-by-side. One
  "consensus" number plus the raw scores.
- **C. Disagreement is itself a signal.** A separate
  `ObservationKind::ClassifierDisagreement { models: Vec<...>,
  spread: f32 }` row that calls explicit attention to "the models do
  not agree on this case."

Recommend A for v2 (simplest, lets the moderator decide); B can be
added later if moderators request it.

**To resolve**: UX decision. Talk to actual moderators before
locking in B or C.
<!-- /OPEN -->

## Out of scope (within this issue)

- Training data labeling pipeline. Polaris is not a training-data
  pipeline. The feedback RPC sends the bare minimum back; consumers
  who want a full training pipeline build it themselves.
- Auto-action from classifier output. Hard "no" — every action
  requires a human moderator decision per `design.md` §2.
- Classifier retraining or model hosting. Polaris consumes
  classifiers via gRPC; it does not host them, train them, or
  version them.
- Image / video preprocessing for classifier consumption. The event
  payload over gRPC includes the firehose event as-is; the classifier
  service does its own preprocessing.
- CSAM hash matching via PhotoDNA / known-hash lists. That is a
  separate fast-path in v1's §3.2 ingest service ("synchronous
  fast-path classification") and is not a classifier in this issue's
  sense.
- Bluesky-specific classifier wire formats. If Bluesky's internal
  classifiers have a different wire shape, that's a Bluesky-side
  adapter to the standard `polaris.classifier.v1.Classifier` proto.

## Suggested decomposition

1. **PR 1 — Proto schema and generated crate.** Define
   `polaris.classifier.v1.Classifier`. Generate the
   `polaris-classifier-proto` crate via `tonic-build`. No backend
   integration. Reviewable as a schema spec.
2. **PR 2 — `ClassifierClient` trait + fixture impl + tonic impl.**
   Trait, in-memory fixture for tests, tonic-backed default. Verify
   AC-1 with the fixture.
3. **PR 3 — Fan-out subscriber.** Wire the trait into the firehose
   ingest path via the internal bus. Materialize `Observation` rows.
4. **PR 4 — Circuit breaker + bounded concurrency.** Verify AC-4 and
   AC-5.
5. **PR 5 — Disagreement surfacing.** UI changes in
   `polaris-frontend` to display multiple classifier observations on
   a case.
6. **PR 6 — Feedback RPC (opt-in).** Adds the moderator-action
   feedback path, behind a per-classifier consent flag.
7. **PR 7 — Documentation + sample classifier.** A sample fixture
   classifier (rule-based, for testing) plus operator documentation
   for connecting a real one.

PRs 1-3 are the minimum useful integration. PR 4 hardens it. PRs 5-7
fill out the surface.
