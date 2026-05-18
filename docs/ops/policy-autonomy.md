# Policy autonomy and the safety floor

Per-policy autonomy controls let the LLM dispatcher fire actions
without a human in the loop. This document covers the safety
invariants Polaris enforces server-side regardless of what the LLM
recommends, the rationale for marking a policy human-required, and the
operator workflow during incidents.

Design source of truth:
[`.design/mod-policy-workbook.md`](../../.design/mod-policy-workbook.md)
(REQ-G1, REQ-G2, REQ-G3) and
[`.design/llm-moderation-assist.md`](../../.design/llm-moderation-assist.md)
(REQ-S8, the dispatcher floor). Related operator docs:
[`policy-management.md`](policy-management.md),
[`quick-start.md`](quick-start.md),
[`classifier-integration.md`](classifier-integration.md),
[`upgrade.md`](upgrade.md),
[`runbook.md`](runbook.md).

## What `human_required_always` means

`human_required_always` is the safety floor: a boolean column on every
row of `mod_policies`. When `TRUE`, that policy can never run with
`autonomy_mode = autonomous`, regardless of every other field. The
shipped seed marks `polaris.csam = true` — see
[`deploy/seeds/mod-policies.yml`](../../deploy/seeds/mod-policies.yml).

The floor is a database-level fact, not a convention. The same column
gates three independent server paths so no single bypass (cache
staleness, dispatcher bug, direct insert through a compromised
privileged role) can autonomously action a human-required policy.

Operators set `human_required_always = TRUE` on any policy where the
characteristic moderation decision warrants the cost of a human
reviewer per action. The seed marks CSAM; operators routinely mark
account-level takedowns, doxxing policies, legal-exposure categories,
and any region-specific compliance rule similarly.

## The three enforcement layers

Each layer is independent and pinned by a regression test. Tripping
any one rejects the autonomous action before any side effect lands.

### Layer 1 — Workbook edit API

`PATCH /api/admin/policies/:identifier` and `POST /api/admin/policies`
reject any write that would leave the row in
`human_required_always = TRUE AND autonomy_mode = 'autonomous'`. The
response is `4xx` (`412 Precondition Failed`) with the wire-load-
bearing body:

```json
{
  "code": "policy_autonomy_forbidden",
  "message": "policy is marked human_required_always; flip that off first if you really mean to autonomously enforce"
}
```

Regression-pinned in
[`polaris-backend/tests/policy_human_required_never_autonomous.rs`](../../polaris-backend/tests/policy_human_required_never_autonomous.rs)::`policy_edit_api_rejects_autonomous_mode_on_human_required_policy`.

The same handler also enforces REQ-G1: `autonomous_action_kinds` is
gated to the subset `{label, warn, takedown}`. `escalate`, `mute`,
`no_action`, and `reverse` cannot autonomously fire even if an
operator tries — the rejection is `400 bad_request` and the message
names `autonomous_action_kinds`.

### Layer 2 — Action-create API

When an action arrives at the action-create handler with
`actor_kind = 'autonomous_agent'`, the handler re-validates the cited
policies' current rows and rejects on any
`human_required_always = TRUE`:

```json
{
  "code": "policy_autonomy_forbidden",
  "identifier": "polaris.csam"
}
```

with status `403 Forbidden`. Regression-pinned by
`action_create_rejects_autonomous_agent_citing_human_required_policy`.

The same handler enforces REQ-G2: an autonomous `takedown` against a
subject with `kind = 'account'` is rejected with
`account_takedown_autonomous_forbidden` (`403 Forbidden`). Account-
level takedowns are always a human decision, even when the policy
itself permits autonomous post-level takedowns. Regression-pinned by
`action_create_rejects_autonomous_takedown_on_account_subject`.

### Layer 3 — LLM dispatcher safety floor

The dispatcher re-reads `human_required_always` and
`autonomous_paused_until` on **every** recommend call — there is no
TTL on the safety floor. A stale in-memory cache can never produce an
autonomous fire because the floor check goes straight to the DB. The
dispatcher's per-recommendation evaluation of REQ-S8 lives at
[`polaris-backend/src/llm/safety_floors.rs`](../../polaris-backend/src/llm/safety_floors.rs)
and is regression-covered by 15 cases in
[`polaris-backend/tests/llm_safety_floors.rs`](../../polaris-backend/tests/llm_safety_floors.rs)
per `.design/llm-moderation-assist.md` AC-6.

Every floor evaluation increments
`polaris_llm_safety_floor_tripped_total{policy, floor}` (Prometheus
counter), so an operator reads "how often did the LLM try" without
scraping logs. Each trip also emits a structured
`tracing::warn!("llm safety floor tripped", floor, policy_identifier,
downgrade_to_manual, detail)` line.

## When to mark a policy human-required

The factors that justify the per-action cost of a human reviewer:

- **Legal exposure / reporting pipelines.** The seed sets
  `polaris.csam = TRUE` because every action triggers a NCMEC report
  pipeline; misclassification has criminal-law consequences for the
  operator. Operators in EU jurisdictions routinely add similar
  floors for DSA-illegal-content categories tied to formal removal
  orders.
- **Irreversibility / blast radius.** Account-level takedowns destroy
  follower graphs and replyable history; mass-mute reaches dozens of
  follower feeds in a single call. Reversing either is hours of work
  even when the decision was wrong.
- **Child safety.** Anything depicting, sexualising, or facilitating
  harm to minors. Even confident classifiers should escalate to a
  human who can preserve evidence and route the report correctly.
- **Doxxing / personal-information exposure.** A wrong autonomous
  takedown on a misidentified "doxxing" post can amplify the harm; a
  missed one leaves PII in distribution. Operators usually want a
  human reading the post and the surrounding thread before either.
- **Account takedowns more broadly.** REQ-G2 already blocks
  autonomous *account*-kind takedowns at the action-create layer;
  marking the underlying policy `human_required_always = TRUE` is
  belt-and-braces and clarifies operator intent.
- **Legal carve-outs (parody, fair use, news reporting).** Policies
  where the decision turns on intent or context (copyright fair-use,
  satire-bordering harassment) routinely produce LLM false positives;
  the cost of a human reviewer is lower than the cost of fielding
  reversal complaints.

Real-world starting set most operators converge on:

- `polaris.csam` (shipped).
- Any policy whose suggested kinds include account-level takedown.
- Doxxing / private-information policies.
- Self-harm and suicide-related policies (specialist routing needed).
- Politically-exposed-person policies (false-positive risk is high).

Mark the policy via the admin UI (Autonomy tab → `human_required_always:
true`, fill in change summary, save) or via the YAML seed:

```yaml
- identifier: polaris.doxxing
  # ... other fields ...
  human_required_always: true
  autonomy_mode: manual           # MUST be manual or assisted
  autonomous_action_kinds: []     # safety-floor invariant
```

## The pause / resume workflow

Two granularities, both reversible.

### Per-policy pause (admin UI / endpoint)

Pauses autonomy for one policy without bumping the version. The
dispatcher re-reads `autonomous_paused_until` on every recommend
call, so paused policies fall through to assisted mode within one
call window.

```sh
# Pause polaris.spam until tomorrow morning UTC (incident-response
# typical: "let us drain the queue manually before re-engaging the
# LLM").
curl -sS -X POST https://mod.example.com/api/admin/policies/polaris.spam/pause \
  -H "Content-Type: application/json" \
  --cookie polaris_session=<your-cookie> \
  -d '{"until":"2026-05-19T08:00:00Z"}'

# Pause indefinitely (empty body = "until 9999-12-31"):
curl -sS -X POST https://mod.example.com/api/admin/policies/polaris.spam/pause \
  --cookie polaris_session=<your-cookie>

# Resume:
curl -sS -X DELETE https://mod.example.com/api/admin/policies/polaris.spam/pause \
  --cookie polaris_session=<your-cookie>
```

Both write a `policy_paused` / `policy_resumed` audit-log row carrying
`identifier`, `until`, and `moderator_id`. The reversal-circuit-
breaker job (LLM-6 / `polaris_llm_reversal_rate`) writes the same
column when the rolling reversal rate breaches the operator-set
threshold; an operator reads "who paused this?" off the audit-log
event's `actor` field and distinguishes manual vs. circuit-breaker
pauses there.

### Global kill switch

The global autonomy kill switch is the one-click "stop the bleeding"
lever for incident response. It pauses every policy's autonomous
emission in a single call without touching individual
`autonomous_paused_until` columns. The dispatcher reads the global
flag first; per-policy pauses remain in force as the second gate, so
clearing the global does not silently un-pause a policy that was
paused per-policy.

The state lives at
`polaris_setup_state.global_autonomous_pause_until`. Two endpoints:

```sh
# Engage (until a specific time, or indefinitely if body is empty):
curl -sS -X POST https://mod.example.com/api/admin/llm/pause \
  -H "Content-Type: application/json" \
  --cookie polaris_session=<your-cookie> \
  -d '{"until":"2026-05-19T08:00:00Z"}'

# Engage forever (until an explicit clear):
curl -sS -X POST https://mod.example.com/api/admin/llm/pause \
  --cookie polaris_session=<your-cookie> -d '{}'
# {"paused_until":"9999-12-31T23:59:59Z"}

# Clear:
curl -sS -X DELETE https://mod.example.com/api/admin/llm/pause \
  --cookie polaris_session=<your-cookie>
# 204 No Content
```

Both write an `llm_pause_engaged` / `llm_pause_cleared` audit-log
row with the moderator id and the resulting timestamp. The clear is
idempotent — calling it on a non-paused state still records the
operator's action. See [`llm-moderation.md`](llm-moderation.md) § 4
for the full operator runbook.

### What happens to in-flight recommendations

The dispatcher re-reads the autonomy gate **per call**, not per
session. In-flight recommendations that were enqueued before the
pause:

- Drafts already written to the assisted-mode review queue stay
  queued. A moderator can approve or reject them as normal; pausing
  autonomy does not retract the draft.
- Recommendations being formed at the moment of pause see the new
  state on the next DB read, which is before any auto-fire decision.
- Already-fired autonomous actions are not retracted by a pause —
  reversal is a separate moderator action.

## Operating with autonomy on

Two pieces of operator hygiene every deploy needs before flipping a
policy to `autonomy_mode = autonomous`.

### Dry-run calibration first

The dry-run calibration job replays the last N closed incidents
through the configured LLM in no-side-effect mode and scores each
case against the human moderator's actual outcome. It writes only to
the `dry_run_jobs` and `dry_run_results` tables — no observations,
no actions, no atproto emission — so an operator can confidently
calibrate against production data.

```sh
# Kick off (admin-only):
curl -sS -X POST https://mod.example.com/api/admin/llm/dry-run \
  -H "Content-Type: application/json" \
  --cookie polaris_session=<your-cookie> \
  -d '{"policy_identifier":"polaris.spam","lookback_days":30}'
# {"job_id": "<uuid>"}

# Poll:
curl -sS https://mod.example.com/api/admin/llm/dry-run/<uuid> \
  --cookie polaris_session=<your-cookie>
# Returns cases_evaluated / agreements / disagreements / errors /
# agreement_rate plus a capped sample of the disagreement rows so
# you can spot calibration patterns at a glance.
```

`lookback_days` clamps server-side to `[1, 90]`; per-job replay tops
out at 500 cases. The full runbook (recommended agreement-rate
thresholds for moving manual → assisted → autonomous, how to read the
disagreement sample) lives in [`llm-moderation.md`](llm-moderation.md)
§ 2.

The fallback for operators who want a second confirmation signal is
still the `assisted` mode pipeline: run the policy in `assisted` for
a moderator-shift week, review the drafts the LLM produced, and
measure how often a moderator disagreed with the recommendation.

### Monitor the reversal rate

The reversal-rate circuit breaker watches the rolling fraction of
autonomous actions that get reversed within their `reversible_until`
window. Exceeding the operator-set rate stamps
`autonomous_paused_until = now() + 24h` on the offending policy and
records the pause with audit-log actor `circuit-breaker:<rule>` so
operators can distinguish breaker-driven pauses from manual ones.

The metric the breaker watches is published on `/metrics` as
`polaris_llm_reversal_rate` (per-policy gauge); the threshold lives
on the policy row itself (`autonomous_reversal_breaker_threshold`,
default 0.15). Operators read the gauge to spot a quietly-misbehaving
policy before the breaker fires: sustained 10%+ reversal on any
autonomous policy is a smell even if the rolling window hasn't
crossed the alarm threshold yet.

## Where to look when something goes wrong

Three primary surfaces. Use them in this order during an incident.

1. **Audit log** (`/api/admin/audit`, hash-chained envelope). Filter
   on `kind = 'policy_paused'`, `kind = 'policy_amended'`, or any
   action-creation `kind` to reconstruct "who changed what when". The
   chain verifier (see [`runbook.md`](runbook.md) §audit) is the
   tampering check.

   The dedicated admin LLM audit page lives at `/admin/llm/audit`
   with filters `?model=`, `?policy=`, `?reversed=`, `?from=`,
   `?to=`. Each row expands to reveal the full `LlmRecommendation`
   observation `evidence` payload + the SHA-256 `input_hash`, so
   reviewing "what did the LLM say when this autonomous label fired"
   does not require raw SQL.

2. **Metrics** (`/metrics`, Prometheus-format). Key gauges and
   counters:
   - `polaris_llm_reversal_rate{policy=...}` — rolling reversal
     fraction. Spike → circuit breaker is about to trip.
   - `polaris_llm_safety_floor_tripped_total{policy, floor}` — every
     time the dispatcher's per-recommendation evaluation tripped a
     safety floor. Labels: `policy` (identifier), `floor` (one of
     `human_required` / `global_pause` / `reversal_breaker` /
     `rate_limit` / `subject_cooldown` / `account_takedown` /
     `action_kind` / `confidence`).
   - `polaris_llm_dispatcher_recommendations_total{outcome=...}` —
     manual / assisted-draft / autonomous-fire fan-out.

3. **Structured log search.** The dispatcher and the action-create
   handler emit one structured log line per decision. Useful greps
   during a postmortem:

   ```sh
   # Every time the safety floor stopped an autonomous fire on this
   # policy in the last 24h:
   journalctl -u polaris-backend --since '24h ago' \
     | grep -F 'policy_autonomy_forbidden' \
     | grep -F 'polaris.csam'

   # Every autonomous fire and its cited policy identifiers:
   docker compose logs polaris-backend --since 24h \
     | grep -F 'actor_kind="autonomous_agent"'

   # The pause / resume trail for one policy:
   docker compose logs polaris-backend \
     | grep -E 'policy_(paused|resumed)' \
     | grep -F 'polaris.harassment'
   ```

If autonomy "isn't working" — i.e. the LLM recommended an action and
nothing happened — the rejection always lands in one of three places:
the dispatcher safety-floor log line (recommendation suppressed
before action-create), the action-create API rejection log line
(action submitted but refused), or the audit-log `policy_paused`
event (per-policy pause is in force). Walk those three before
suspecting the dispatcher itself.
