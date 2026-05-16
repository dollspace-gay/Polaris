# Classifier integration

How to wire an ML classifier service into a running Polaris deployment.

Polaris consumes classifier output as another `Observation` source —
**never as an autonomous actor**. A human moderator always takes the
final action; the classifier's role is to surface a signal alongside
reports, upstream labels, and pattern-engine detections (`design.md`
§2).

This document covers:

1. The wire contract (proto + privacy boundary)
2. Standing up the sample classifier for end-to-end validation
3. Registering a real classifier (self-hosted)
4. Cloud-API classifiers (operator-consent flow)
5. Tuning timeouts + circuit breaker + concurrency budget
6. Opt-in feedback
7. Observability + troubleshooting

---

## 1. Wire contract

Polaris implements the gRPC client side of
`polaris.classifier.v1.Classifier` (issue #125 / M5 #45). The proto
lives at `proto/polaris-classifier-v1.proto`; the generated Rust types
are in the `polaris-classifier-proto` crate.

Four RPCs:

| RPC | Purpose |
|-----|---------|
| `Classify(ClassifyRequest) → ClassifyResponse` | Single-shot synchronous classification. The v2 baseline path. |
| `ClassifyStream(stream … → stream …)` | Bidirectional streaming for high-throughput deployments. |
| `Feedback(FeedbackRequest) → FeedbackResponse` | **Opt-in** moderator-action callback. Default off. |
| `HealthCheck(google.protobuf.Empty) → HealthResponse` | Probe wired into the circuit breaker. |

### Privacy boundary

The classifier service sees:

- Subject DID
- Event content (text + image blob CID, if any)
- Operator-allocated event ID

The classifier service **does not** see (when properly configured):

- Moderator identity
- Moderator reasoning text
- Reporter identity
- Audit-chain hashes
- Exposure-tracking state

When `send_feedback = true` is explicitly set, the feedback payload
adds:

- `classifier_label` (what the classifier said)
- `classifier_confidence` (its score)
- `moderator_action_kind` (`label`/`takedown`/`mute`/`warn`/`escalate`/`no_action`)

The feedback path is enforced at the `build_feedback()` function
signature in `polaris-backend/src/classifier/feedback.rs` — internal
state can't leak because the function won't accept it as input.

---

## 2. End-to-end validation with the sample classifier

Polaris ships a rule-based fixture classifier so operators can validate
the gRPC plumbing before pointing at a real model.

```sh
# Terminal 1 — start the sample classifier on the default port.
cargo run --bin polaris-sample-classifier --release
# Listens on 127.0.0.1:50051
```

```toml
# polaris.toml — register the sample as a configured classifier.
[[classifiers]]
name = "sample"
endpoint = "http://127.0.0.1:50051"
send_feedback = false   # default; explicit for documentation
timeout_ms = 500        # AC-4
```

```sh
# Terminal 2 — start polaris-backend pointed at the same DB as usual.
cargo run --bin polaris-backend
```

When the firehose ingests an event, the fan-out worker dispatches it
to the sample classifier. The sample's rules fire on text containing
`spam`, `crypto giveaway`, `kill yourself`, etc.; you can confirm an
`observations` row with `kind='classifier_signal'` appears in Postgres:

```sql
SELECT id, subject_id, kind, confidence,
       evidence->>'classifier' AS classifier,
       evidence->>'label' AS label,
       detected_at
FROM observations
WHERE kind = 'classifier_signal'
ORDER BY detected_at DESC
LIMIT 10;
```

---

## 3. Self-hosted classifiers (recommended default)

For Bluesky's first-party deployment (or any operator with in-house
ML capacity), running the classifier inside the operator's network
boundary is the right default. No event data crosses an organisational
boundary.

The classifier service implements `polaris.classifier.v1.Classifier`
in any language with a gRPC stack — Rust, Python, Go, Java, …. The
`polaris-classifier-proto` crate's `.proto` is the source of truth;
generate bindings via `tonic-prost-build` for Rust, `grpcio-tools`
for Python, etc.

Typical deployment shapes:

- **Fine-tuned BERT (CPU)** — `~10-100ms` per inference; fits within
  the 500ms default `timeout_ms`.
- **Fine-tuned LLM (GPU)** — `~200ms-2s`; raise `timeout_ms` for the
  classifier accordingly.
- **Rule engine** — `<1ms`; default timeout is more than enough.

---

## 4. Cloud-API classifiers (operator-consent flow)

For labelers without in-house ML, a cloud-API classifier (OpenAI
Moderation, Perspective API, Hive, …) is permitted but requires
explicit operator consent (Q2-C from #124, the design's resolved
question).

```toml
[[classifiers]]
name = "openai-mod"
endpoint = "https://classifier-adapter.example.com:50051"
external = true   # Q2-C: surfaces a banner in the case view
send_feedback = false
timeout_ms = 1500
```

Cloud-API classifiers typically don't speak Polaris's proto natively;
host an adapter that translates `Classify(ClassifyRequest)` calls into
the cloud provider's HTTP API and back. Polaris does not ship a
turnkey adapter; building one is a per-provider engagement.

When `external = true`, the case-view UI surfaces a banner
**"this case was scored by external classifier `<name>`"** so
moderators have explicit knowledge of which signals crossed an
organisational boundary.

---

## 5. Tuning timeouts, circuit breaker, concurrency budget

Per-classifier config:

```toml
[[classifiers]]
name = "spam-bert"
endpoint = "http://classifier-spam.internal:50051"
timeout_ms = 500                       # AC-4 default
consecutive_failure_threshold = 10     # AC-5 default
cooldown_secs = 60                     # AC-5 default
max_in_flight = 64                     # AC-4 default
```

### Timeout

The per-call timeout (default `500ms` from Q1 in #124) is applied by
`TonicClassifierClient::classify` via `tokio::time::timeout`. A
classifier exceeding it surfaces as `ClassifierError::Timeout`, counts
toward the consecutive-failure threshold, and produces no observation
row for that call.

### Circuit breaker (AC-5)

After 10 consecutive failures (configurable), the breaker transitions
`Closed → Open` for a 60-second cooldown. During cooldown, no calls
to that classifier are attempted; `classify()` returns
`ClassifierError::CircuitOpen` immediately.

After the cooldown, the breaker transitions to `HalfOpen`. The next
call is the single probe; on success → `Closed`, on failure → `Open`
with a fresh cooldown.

### Concurrency budget (AC-4)

Each classifier has a per-classifier `tokio::sync::Semaphore` with
`max_in_flight` permits (default 64). A classifier accepting events
faster than it can process is rate-limited at the boundary; the
fan-out worker drops the over-budget event (logged at WARN) rather
than piling up in-memory.

---

## 6. Opt-in feedback

`send_feedback = true` causes the action endpoint to fire a `Feedback`
RPC after each moderator action on an event the classifier scored:

```toml
[[classifiers]]
name = "spam-bert"
endpoint = "http://classifier-spam.internal:50051"
send_feedback = true   # opt-in
```

The feedback payload contains only four fields (privacy boundary
enforced at the `build_feedback()` function signature):

- `event_id`
- `classifier_label`
- `classifier_confidence`
- `moderator_action_kind`

It does NOT contain:

- Moderator identity (verified by AC-7's prost-encoded grep test)
- Moderator reasoning text
- Reporter identity
- Audit-chain hashes

A startup banner names every classifier with `send_feedback = true`
so the operator can see at a glance which classifiers receive
moderator-action data.

---

## 7. Observability + troubleshooting

### Metrics

Each classifier exposes these series via the Polaris `/metrics`
endpoint (Prometheus text format):

- `polaris_classifier_calls_total{classifier, outcome}` — counter
- `polaris_classifier_latency_seconds{classifier}` — histogram
- `polaris_classifier_breaker_state{classifier}` — gauge (0=Closed,
  1=HalfOpen, 2=Open)

(Some of these counters land via #176 — federation metrics PR — which
introduces the broader `polaris_*` series. Track the issue for current
status.)

### Tracing

Every classifier dispatch emits a `tracing::info!` event with
structured fields:

```text
classifier=spam-bert event_id=evt-abc123 subject_did=did:plc:xyz789
labels_emitted=1 outcome=ok
```

Filter via `RUST_LOG=polaris_backend::classifier=info`.

High-confidence graphic-content signals (`confidence > 0.9` AND label
∈ {`csam`, `graphic-violence`, `sexual`, `nudity`, `gore`,
`self-harm`}) emit an additional span with `routing_input =
"graphic_high_confidence"` for the v1 §5.4 wellness router to pick up.

### Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `ClassifierError::Timeout` in logs | Classifier slower than `timeout_ms` | Raise `timeout_ms` per classifier, OR optimise inference latency |
| `ClassifierError::CircuitOpen` | Breaker tripped after consecutive failures | Investigate classifier health; verify `HealthCheck` returns ok; once classifier recovers, the breaker auto-probes after `cooldown_secs` |
| `ClassifierError::RateLimited` | `max_in_flight` permits exhausted | Either raise `max_in_flight`, OR investigate why classifier is slow (high in-flight ⇒ slow processing) |
| `ClassifierError::Transport(tonic::Status { code: Unavailable, … })` | gRPC channel closed | Restart classifier; verify TLS config matches between Polaris and classifier |
| `ClassifierError::BadResponse` | Classifier returned malformed response | Operator bug on classifier side; check the classifier service's logs |

---

## See also

- `proto/polaris-classifier-v1.proto` — wire schema
- `polaris-classifier-proto/` — generated Rust types
- `polaris-backend/src/classifier/` — client + fan-out + breaker
- `lexicons/mapping-matrix.md` — privacy-boundary reference (parallel
  to the federation mapping discipline)
- `design.md` §10 — original ML classifier integration design notes
- `.design/m5/45-ml-classifier.md` — M5 design doc for this epic
