# LLM moderation assist

How to wire an LLM adapter into Polaris, enable autonomous moderation
on a per-policy basis, and run the deployment safely.

Polaris extends the existing classifier gRPC substrate
(`proto/polaris-classifier-v1.proto`) with a fifth RPC, `Recommend`,
that takes a hydrated case bundle and returns a structured moderation
judgment. The recommendation is consumed in three operator-selectable
modes per policy:

- `manual` — recommendation shows in the case-view advisory panel; a
  human moderator decides.
- `assisted` — recommendation lands in a `pending_auto_actions` queue
  as a draft; a moderator clicks approve / reject.
- `autonomous` — when confidence + safety floors clear, the action is
  emitted to atproto without human review. The reversible window lets
  a moderator overturn within 24 hours.

The autonomous mode is the load-bearing capability — it makes
moderation scale — but every other mechanism in this design exists to
make autonomous **safe enough to ship**. Read the safety floors
section before flipping any policy to `autonomous`.

This document covers:

1. Wire-up tutorial (fixture adapter end-to-end).
2. Per-policy autonomy enablement (with dry-run calibration).
3. Safety floors in plain English.
4. Kill-switch usage.
5. Reading the audit page.
6. Common adapters.

## What's shipped vs. what's pending

The following pieces are landed on `main` today and exercised by
integration tests:

- gRPC `Recommend` RPC on `polaris.classifier.v1.Classifier`.
- Dispatcher with three-mode routing (manual / assisted / autonomous).
- Eight server-side safety floors (`polaris-backend/src/llm/safety_floors.rs`).
- Reversal-rate circuit breaker (`polaris_llm_reversal_rate` gauge +
  auto-pause writer).
- Pending-auto-actions assisted queue + approve / reject endpoints
  (`/api/queue/pending-auto-actions`).
- Admin audit page (`/admin/llm/audit`) with model / policy / reversal /
  date-range filters and keyset pagination.
- Global kill switch (`POST` / `DELETE /api/admin/llm/pause`).
- Dry-run calibration job (`POST /api/admin/llm/dry-run`,
  `GET /api/admin/llm/dry-run/{job_id}`) — no-side-effect replay of
  closed historical incidents through the LLM with per-case agreement
  scoring.
- Feedback loop: reversal, assisted-reject, and 24-hour confirmation
  `Feedback` RPCs.
- Two example adapters: the in-tree Rust gRPC `llm-fixture-adapter`,
  and the Python `llm-prompt-reference` against Qwen 2.5 32B Instruct
  Q3_K_M.

Enabling the substrate is a single env-var: `POLARIS_LLM_ENDPOINT`
pointing at the gRPC adapter. On boot, `polaris-backend` connects a
`TonicClassifierClient` against that endpoint, seeds the deterministic
`autonomous-agent` moderator row that `actions.moderator_id` requires
for autonomous emit, constructs the `RecommendDispatcher` with the
live `LabelEmitter` attached (so autonomous actions reach atproto),
and installs it onto `ApiState` via
`ApiState::with_llm_dispatcher(...)`. When the env-var is unset, the
dispatcher slot stays `None` and every LLM API route returns the "no
dispatcher configured" branch — the deployment runs as a pure human-
moderation labeler.

Connect failures abort startup. The LLM substrate is opt-in (operators
set the env-var deliberately), so a misconfiguration here should fail
closed rather than silently downgrade the policy autonomy modes the
operator just spent days calibrating.

---

## 1. Wire-up tutorial

Polaris ships a Rust gRPC fixture under
`examples/llm-fixture-adapter/` that returns a canned
`RecommendResponse`. Use it to validate the wire path end-to-end
before standing up a real model.

### Start the fixture

The fixture is not a workspace member. Build and run it against its
own manifest:

```sh
cargo run --manifest-path examples/llm-fixture-adapter/Cargo.toml
# Listens on 127.0.0.1:50052 by default; honours FIXTURE_LISTEN_ADDR.
```

Set the canned recommendation via env vars (defaults in parens):

```sh
FIXTURE_RECOMMEND_ACTION_KIND=warn        # warn | label | takedown | no_action
FIXTURE_RECOMMEND_CONFIDENCE=0.6           # 0.0..=1.0
FIXTURE_RECOMMEND_LABEL_VALUE=""           # only used when kind=label
FIXTURE_RECOMMEND_POLICY_IDENT=polaris.spam
FIXTURE_MODEL_NAME=polaris-fixture
FIXTURE_MODEL_VERSION=v1
FIXTURE_PROMPT_TEMPLATE_ID=polaris.fixture.recommend.v1
RUST_LOG=info cargo run --manifest-path examples/llm-fixture-adapter/Cargo.toml
```

The default sits at `confidence = 0.6` so a freshly-seeded policy
(default `autonomous_confidence_threshold = 0.95`,
`assisted_confidence_threshold = 0.7`) downgrades to `manual`. To
exercise the autonomous path with the fixture, raise the fixture's
confidence (`FIXTURE_RECOMMEND_CONFIDENCE=0.97`) AND lower the
policy's `autonomous_confidence_threshold` to match (see § 2).

### Point Polaris at the fixture

The fixture implements the same `polaris.classifier.v1.Classifier`
service as a real classifier — Polaris consumes it through the same
config block `docs/ops/classifier-integration.md` documents, with the
endpoint pointing at the fixture's listen address and the
recommend-specific timeout raised to match the LLM RPC's 15s default:

```toml
[[classifiers]]
name = "llm-fixture"
endpoint = "http://127.0.0.1:50052"
send_feedback = false
timeout_ms = 15000   # REQ-A5 default for Recommend
```

Restart `polaris-backend` so the new classifier registers.

### Trigger a recommendation

Two ways to drive the dispatcher against the fixture:

1. **Pull (moderator-initiated).** Open any case in the dashboard; a
   `POST /api/cases/:incident_id/llm-recommendation` from the case-view
   client drives `DispatchTrigger::Pull`. The dispatcher hydrates the
   case bundle, calls the fixture's `Recommend`, persists the response
   as an `LlmRecommendation` observation, and routes per the policy's
   `autonomy_mode`. With the fixture's default config (warn, 0.6) the
   outcome is `Advisory` — the recommendation shows in the case-view
   sidebar but no draft or action is created.

2. **Push (ingest-driven).** A new report on a subject whose covering
   policy is in `assisted` or `autonomous` mode enqueues a
   `DispatchTrigger::Push` for the dispatcher. The same code path
   applies; per-subject debounce (15 minutes default) and queue-depth
   ceiling (500 default) shed load on this trigger only.

Confirm the wire-up by querying the observations table:

```sql
SELECT id, subject_id, kind, confidence,
       evidence->>'request_content_hash' AS req_hash,
       detected_at
FROM observations
WHERE kind = 'llm_recommendation'
ORDER BY detected_at DESC
LIMIT 10;
```

The `evidence` JSONB carries the full `RecommendResponse` plus the
SHA-256 of the canonicalised `RecommendRequest` for replay-determinism
checks (REQ-D2 in the design doc).

---

## 2. Per-policy autonomy enablement

Autonomy is configured per policy through the existing admin policies
API. The workbook lives in `mod_policies`; the LLM-relevant columns
are:

| Column                                 | Purpose                                                                                   |
|----------------------------------------|-------------------------------------------------------------------------------------------|
| `autonomy_mode`                        | `manual` / `assisted` / `autonomous`. Default `manual`.                                   |
| `autonomous_action_kinds`              | Subset of `{label, warn, takedown}` allowed for autonomous emission (REQ-S2).             |
| `autonomous_confidence_threshold`      | Auto-fire requires `confidence >=` this value (REQ-S1).                                   |
| `assisted_confidence_threshold`        | Below this value, drop from `assisted` to `manual` (REQ-S1).                              |
| `autonomous_rate_limit_per_hour`       | Per-policy cap on autonomous actions per hour (REQ-S5). Default 60.                       |
| `autonomous_reversal_breaker_threshold`| 7-day reversal-rate at which the breaker trips (REQ-S6). Default 0.15.                    |
| `autonomous_paused_until`              | NULL = active; future timestamp = paused (set by the breaker or by an explicit admin call).|
| `human_required_always`                | `TRUE` blocks autonomous emission unconditionally (REQ-S8, CSAM-class policies).          |

### Walk-through: flip `polaris.spam` to `assisted`

1. Read the current policy:

   ```sh
   curl -s -H 'cookie: <admin-session>' \
        /api/admin/policies/polaris.spam | jq .
   ```

2. Patch the autonomy mode:

   ```sh
   curl -X PATCH -H 'cookie: <admin-session>' \
        -H 'content-type: application/json' \
        -d '{"autonomy_mode":"assisted","autonomous_action_kinds":["label","warn"]}' \
        /api/admin/policies/polaris.spam
   ```

   The policy edit API refuses changes that would violate REQ-G1/G2/G3
   (no autonomous emission on `human_required_always = TRUE`, no
   account-takedown autonomous, no kinds outside `{label, warn,
   takedown}`).

3. Trigger a fresh recommendation against a case covered by the
   policy (Pull or Push); the outcome should now be `AssistedDraft`
   when confidence ≥ `assisted_confidence_threshold` and `Advisory`
   otherwise.

### Promoting to `autonomous`

The design's hard requirement (REQ-H2): before flipping any policy to
`autonomous`, run a **dry-run calibration** against the last N closed
cases. The job replays each historical incident through the configured
LLM in no-side-effect mode (the runner writes only to `dry_run_jobs`
and `dry_run_results`; no observations, no actions, no atproto emission)
and scores each case against the action the human moderator actually
recorded.

Kick off a job (admin-only):

```sh
curl -sS -X POST -H 'cookie: <admin-session>' \
     -H 'content-type: application/json' \
     -d '{"policy_identifier":"polaris.spam","lookback_days":30}' \
     /api/admin/llm/dry-run
# {"job_id":"<uuid>"}
```

Poll for progress + agreement rate:

```sh
curl -sS -H 'cookie: <admin-session>' \
     /api/admin/llm/dry-run/<uuid> | jq .
# {
#   "id": "...",
#   "state": "running" | "done" | "failed",
#   "policy_identifier": "polaris.spam",
#   "lookback_days": 30,
#   "cases_evaluated": 217,
#   "agreements": 198,
#   "disagreements": 19,
#   "errors": 0,
#   "agreement_rate": 0.912,
#   "disagreement_sample": [
#     {"incident_id": "...", "llm_action_kind": "warn",
#      "llm_confidence": 0.74, "human_action_kind": "no_action",
#      "llm_reasoning": "Sustained reply pattern after stop signal."}
#     // … up to 20
#   ]
# }
```

Inputs are bounded server-side: `lookback_days` clamps to `[1, 90]`
and per-job replay tops out at 500 cases (`MAX_CASES_PER_JOB`). The
runner re-implements the dispatcher's "hydrate → recommend → record"
slice as its own narrow path rather than wrapping the dispatcher with
a `dry_run = true` flag, because a missing-skip in that flag would
risk real side effects landing in production.

A safe promotion ladder once you have a job report in hand:

- Agreement rate ≥ 95% on the policy AND the disagreement sample
  doesn't show concentrated `human=no_action, llm=takedown` rows
  (the most consequential failure mode) — candidate for `assisted`.
- A moderator-shift week of `assisted` operation where rejection rate
  on the LLM's drafts stayed in line with the dry-run miss rate —
  candidate for `autonomous` with `{label, warn}`.
- A second shift-week of clean autonomous operation — candidate for
  enabling `takedown` in `autonomous_action_kinds`.

Always promote `{label}` and `{warn}` before `{takedown}` —
takedown autonomy carries the heaviest blast radius and is the last
verb to enable. Account-level takedowns can never auto-fire even when
`{takedown}` is in `autonomous_action_kinds` (REQ-G2 / safety floor
S3, gated at three independent layers).

The breaker (REQ-S6) auto-pauses any policy whose 7-day reversal rate
exceeds the configured threshold (default 15%), so an autonomy
promotion is reversible without an admin click — the policy's
`autonomous_paused_until` column gets stamped to `now() + 24h` and
the dispatcher falls back to `assisted` on the next recommend.

---

## 3. Safety floors in plain English

Polaris enforces eight server-side safety floors (REQ-S1..S8). Every
floor is a sufficient stop: any single trip downgrades a
recommendation from `autonomous` to either `assisted` (soft, the
moderator can still approve in the queue) or `manual` (hard, the case
becomes advisory-only). The floors are evaluated in **hardest-block
first** order so an operator reading the structured logs sees the
most consequential cause:

1. **CSAM / regulatory hard block (S8).** A policy with
   `human_required_always = TRUE` can never auto-fire, regardless of
   any other configuration. Hard block.

2. **Global kill switch (S7).** While
   `polaris_setup_state.global_autonomous_pause_until` carries a
   future timestamp, every `Recommend` call is downgraded to manual.
   Hard block. (See § 4 for the toggle.)

3. **Reversal-rate circuit breaker (S6).** 7-day human-reversal rate
   for the policy exceeds its threshold (default 15%). Hard block;
   tripping also writes `autonomous_paused_until = now() + 24h` so
   the policy stops trying without operator intervention.

4. **Per-policy rate limit (S5).** Autonomous actions on the policy
   in the last hour have hit the configured cap (default 60/hour).
   Soft downgrade — the recommendation lands in the assisted queue
   for moderator approval.

5. **Subject cooldown (S4).** A human moderator ruled `no_action` or
   `reverse` on this subject in the last 30 days
   (`POLARIS_AUTONOMOUS_SUBJECT_COOLDOWN_DAYS` override available).
   The human's verdict stands; soft downgrade for re-review.

6. **Account-takedown gate (S3).** `takedown` is only autonomously
   eligible against `subject_kind = post`. Account-level takedowns
   are always human-required. Hard block.

7. **Action-kind gate (S2).** The recommended kind must be in the
   policy's `autonomous_action_kinds` AND in the global eligible set
   `{label, warn, takedown}`. `escalate`, `mute`, `no_action`,
   `reverse` can never auto-fire. Hard block.

8. **Confidence floor (S1).** `confidence ≥
   autonomous_confidence_threshold` is required to auto-fire. Between
   the two thresholds → assisted (soft downgrade); below the assisted
   threshold → manual (hard block).

The floors are owned by
`polaris-backend/src/llm/safety_floors.rs`. Every evaluation bumps
the `polaris_llm_safety_floor_tripped_total{policy, floor}` counter
(REQ-I1), so an operator can read "S4 was evaluated 1000 times,
tripped 12 of them" as Grafana queries against the timeseries.

---

## 4. Kill-switch usage

The global kill switch is the one-click "stop the bleeding" lever for
incident response. While engaged, every `Recommend` call is
downgraded to manual regardless of per-policy autonomy — the operator
does not need to remember per-policy state to halt every autonomous
action at once.

### Engage

`POST /api/admin/llm/pause` with an optional `until` timestamp:

```sh
# Pause until 4pm UTC today:
curl -X POST -H 'cookie: <admin-session>' \
     -H 'content-type: application/json' \
     -d '{"until":"2026-05-18T16:00:00Z"}' \
     /api/admin/llm/pause

# Pause forever (until an explicit DELETE):
curl -X POST -H 'cookie: <admin-session>' \
     -H 'content-type: application/json' \
     -d '{}' \
     /api/admin/llm/pause
# {"paused_until":"9999-12-31T23:59:59Z"}
```

Both calls audit-log `kind = "llm_pause_engaged"` with the moderator
id and the resulting timestamp.

### Verify

Two ways:

1. Read the column directly:

   ```sql
   SELECT global_autonomous_pause_until FROM polaris_setup_state;
   ```

2. Drive a `Recommend` against a case that would normally route
   autonomous and observe the safety_floors trace:

   ```text
   llm safety floor tripped
       policy_identifier="polaris.spam"
       floor="global_pause"
       downgrade_to_manual=true
       detail="global autonomous pause active until 9999-12-31T23:59:59Z"
   ```

   The `polaris_llm_safety_floor_tripped_total{floor="global_pause"}`
   counter on `/metrics` also rises one per evaluation.

### Clear

`DELETE /api/admin/llm/pause`:

```sh
curl -X DELETE -H 'cookie: <admin-session>' /api/admin/llm/pause
# 204 No Content
```

Audit-logs `kind = "llm_pause_cleared"`. Idempotent — clearing a
non-paused state is a no-op write that still records the operator's
action.

---

## 5. Reading the audit page

Every autonomous-agent action carries an audit envelope beyond the
human-action shape (REQ-F1):

- `actor_kind = 'autonomous_agent'`.
- `llm_observation_id` — points at the `LlmRecommendation`
  observation that produced the action. The observation's
  `evidence` JSONB has the full LLM response payload for replay.
- `model`, `model_version`, `prompt_template_id` — adapter
  attribution.
- `recommendation_confidence` — the LLM's confidence value.
- `input_hash` — SHA-256 of the canonicalised `RecommendRequest`,
  so a future audit can verify the same case wouldn't produce a
  different decision (replay determinism, REQ-D2).

The `/admin/llm/audit` admin page renders this audit envelope as a
filterable list. Query-string filters: `?model=<name>`,
`?policy=<identifier>` (matches any cited policy on the row),
`?reversed=true|false`, `?from=<RFC3339>`, `?to=<RFC3339>`, plus
`?cursor=<opaque>` for keyset pagination (default page size 50, hard
ceiling 200). Each row expands to reveal the full `LlmRecommendation`
observation's `evidence` payload and the SHA-256 `input_hash` for
replay-determinism checks. The admin REST surface is
`GET /api/admin/llm/audit`; both the page and the API gate on
`Role::Admin`.

If you need the raw SQL view (post-mortem reading from a replica, or
a one-off Grafana panel), the same shape is available directly:

```sql
SELECT a.id, a.kind, a.created_at,
       a.model, a.model_version, a.recommendation_confidence,
       a.input_hash,
       o.evidence->>'overall_reasoning' AS llm_reasoning,
       array(SELECT policy_identifier FROM action_policy_citations
             WHERE action_id = a.id) AS policies,
       (SELECT id FROM actions r
        WHERE r.reverses_action_id = a.id LIMIT 1) AS reversed_by
FROM actions a
LEFT JOIN observations o ON o.id = a.llm_observation_id
WHERE a.actor_kind = 'autonomous_agent'
ORDER BY a.created_at DESC
LIMIT 50;
```

The full audit-chain hash binds the LLM action audit envelope as one
cohesive payload (`audit_log` table; `polaris-backend/src/audit/log.rs`)
— post-hoc tampering with "what the LLM said" is detectable via
`AuditLog::verify_chain`.

---

## 6. Common adapters

Polaris does not ship a turnkey adapter for any specific model. The
`polaris.classifier.v1.Classifier` proto is the source of truth;
adapters translate `Recommend(RecommendRequest)` calls into a model's
native API and back.

Sketches of common shapes (all are operator-built; none are first-
party):

- **vLLM / TGI / llama.cpp (self-hosted).** Wrap the model's OpenAI-
  compatible HTTP API behind a thin Rust/Python/Go gRPC server that
  translates `RecommendRequest` into a structured prompt (the
  `policies` + `subject_context` + `prior_actions` arrays render
  cleanly into a chat-template). Return the model's parsed JSON as
  the `RecommendedAction` set.

- **Anthropic Claude (cloud).** Build a `tool_use`-shaped adapter:
  one tool definition per `RecommendedAction` field, the model's
  tool-use payload becomes the wire response. The
  `external = true` classifier-config flag must be set (per
  `docs/ops/classifier-integration.md` § 4) so moderators see the
  "external classifier" banner in the case view.

- **OpenAI / Azure OpenAI (cloud).** Same shape as Anthropic; use
  the `tools` / `function_calling` parameter for a structured
  return.

- **Bedrock / Vertex AI (cloud).** Same shape; the adapter's surface
  is `RecommendRequest` → provider-specific call → `RecommendResponse`.

All adapter authors:

- Honour the request's `event_id` — echo it back on the response so
  the dispatcher's trace correlation works.
- Respect `max_response_tokens` — truncating reasoning is fine;
  inventing a recommendation past the budget is not.
- Cite only policies present in the request's `policies` array. The
  dispatcher rejects citations to unknown identifiers as adapter
  contract violations (`DispatchError::UnknownCitedPolicy` →
  `400 Bad Request`).
- Use stable `prompt_template_id` strings so the audit envelope
  identifies which prompt version produced each action.

---

## See also

- `proto/polaris-classifier-v1.proto` — wire schema (`Recommend` is
  the fifth RPC).
- `.design/llm-moderation-assist.md` — full design doc with every
  REQ-* requirement traced.
- `docs/ops/classifier-integration.md` — sibling guide for the
  `Classify` / `ClassifyStream` / `Feedback` / `HealthCheck` RPCs.
- `examples/llm-fixture-adapter/` — the fixture binary used in § 1.
- `polaris-backend/src/llm/safety_floors.rs` — the eight server-side
  invariants in code.
- `polaris-backend/src/llm/recommend_dispatcher.rs` — dispatcher
  state machine and metric emission points.
