# llm-fixture-adapter

Minimal gRPC fixture for the `polaris.classifier.v1.Classifier`
service. Returns canned `RecommendResponse`s so an operator can walk
through the Polaris LLM moderation-assist plumbing without standing up
a real model.

Implements:

- `Recommend` — returns a configurable canned recommendation.
- `HealthCheck` — returns `ok`.

Returns `Status::unimplemented` for `Classify`, `ClassifyStream`, and
`Feedback`. The fixture is `Recommend`-only by design; a real
deployment routes those RPCs to its production classifier adapter.

## Running

The fixture is **not** a workspace member. Build and run it directly
against its own manifest:

```sh
cargo run --manifest-path examples/llm-fixture-adapter/Cargo.toml
# Listens on 127.0.0.1:50052 by default.
```

`RUST_LOG=info` surfaces every `Recommend` call. The fixture emits a
structured `tracing::info!` per RPC (event_id, subject_did,
subject_kind, incident_id) so an operator can confirm the wire-up by
watching the fixture's stderr while clicking around in the Polaris
dashboard.

## Pointing Polaris at the fixture

Add the fixture as a configured classifier with `recommend_endpoint`
pointing at `http://127.0.0.1:50052`. The exact stanza shape lives in
`docs/ops/llm-moderation.md` (the LLM moderation operator guide); the
short form is the same as `docs/ops/classifier-integration.md`'s
classifier block but with the fixture's endpoint.

## Configuration

All knobs are environment variables; the fixture reads them once at
startup. Invalid values fall back to the documented defaults with a
`tracing::warn!`.

| Env var                            | Default                            | Notes                                           |
|------------------------------------|------------------------------------|-------------------------------------------------|
| `FIXTURE_LISTEN_ADDR`              | `127.0.0.1:50052`                  | `host:port` to bind.                            |
| `FIXTURE_RECOMMEND_ACTION_KIND`    | `warn`                             | One of `label`, `warn`, `takedown`, `no_action`, `escalate`, `mute`. |
| `FIXTURE_RECOMMEND_CONFIDENCE`     | `0.6`                              | Float in `[0.0, 1.0]`. Below ~0.7 the safety floors usually downgrade to `assisted`/`manual`. |
| `FIXTURE_RECOMMEND_LABEL_VALUE`    | `""` (empty)                       | Used only when `action_kind = label`.           |
| `FIXTURE_RECOMMEND_POLICY_IDENT`   | `polaris.spam`                     | Must exist in `mod_policies`; the dispatcher rejects citations to unknown identifiers. |
| `FIXTURE_MODEL_NAME`               | `polaris-fixture`                  | Echoed to the dispatcher's audit row.           |
| `FIXTURE_MODEL_VERSION`            | `v1`                               | Echoed to the dispatcher's audit row.           |
| `FIXTURE_PROMPT_TEMPLATE_ID`       | `polaris.fixture.recommend.v1`     | Echoed to the dispatcher's audit row.           |

## What the fixture does not do

The fixture has no model. It returns the same canned response for
every request. It does not:

- Look at the case content.
- Consult any policy.
- Vary its confidence.
- Learn from `Feedback` (`Feedback` returns `Status::unimplemented`).

Wire a real LLM adapter behind a real `Recommend` implementation
before promoting any policy to autonomous mode in production. See
`docs/ops/llm-moderation.md` for the production wire-up tutorial.
