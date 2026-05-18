# Policy management

How operators add, amend, and cite the structured policies moderators
enforce against. Replaces the hardcoded `KNOWN_POLICY_REFS` placeholder
from M3; every action now snapshots `(identifier, version)` into
`action_policy_citations` so historical audit can always pin the exact
wording in force at the time.

Design source of truth:
[`.design/mod-policy-workbook.md`](../../.design/mod-policy-workbook.md).
Related operator docs:
[`quick-start.md`](quick-start.md),
[`classifier-integration.md`](classifier-integration.md),
[`upgrade.md`](upgrade.md),
[`policy-autonomy.md`](policy-autonomy.md).

## What this is

`mod_policies` is the structured, versioned policy register. Each row
is one `(identifier, version)` pair — `identifier` is human-stable
(`polaris.harassment`), `version` increments on every edit. Querying
"the current version of policy X" is
`WHERE identifier = $1 AND effective_until IS NULL`; querying "the
version that bound an action submitted last month" is
`WHERE identifier = $1 AND version = $2`. The legacy
`actions.policy_refs TEXT[]` column is retained as a read-only mirror
for backward compatibility; the structured citation lives in
`action_policy_citations`.

Three things this replaces:

- **Hardcoded identifiers.** The five `KNOWN_POLICY_REFS`
  (`polaris.harassment`, `polaris.spam`, `polaris.csam`,
  `polaris.impersonation`, `polaris.copyright`) are now seed rows in
  `mod_policies`; operators add, retire, or amend any of them without
  a code change.
- **Free-text reasoning as the only link.** Actions used to carry
  `reasoning` plus a flat `policy_refs` array. They now also carry per-
  citation `(identifier, version)` rows in `action_policy_citations`
  so a moderator's action is machine-linkable to the specific clause
  that was violated.
- **No autonomy controls.** Policies now carry per-row autonomy mode,
  thresholds, allowed action kinds, and a pause window — the LLM
  dispatcher (see [`policy-autonomy.md`](policy-autonomy.md)) reads
  these on every recommend call.

## The admin UI

The page lives at `/admin/policies`. Requires `Role::Admin`; non-admin
moderators get the inline Forbidden banner. Two-pane layout: sortable
filterable list on the left, detail+edit form on the right (mirrors
`/admin/moderators`).

### Add a new policy

1. Open `/admin/policies`.
2. Click **New policy**. The form requires `identifier` (human-stable,
   immutable after create), `name`, `description`, `scope`
   (`account` | `post` | `both`), `severity`
   (`inform` | `alert` | `hide` | `remove`), `decision_criteria` (≥ 64
   characters, Markdown), and at least one `suggested_action_kinds`
   entry. Threshold defaults are 0.95 (autonomous) / 0.70 (assisted).
3. Submit. The server inserts version 1, writes a `policy_created`
   audit-log entry in the same transaction, and returns the populated
   detail view.

### Amend a policy

1. Select the policy in the left pane.
2. Edit any field. The `decision_criteria` textarea has `Edit` /
   `Preview` tabs; `Preview` renders the saved Markdown via the same
   component the case-view uses for moderator reasoning.
3. Fill in **change summary** — required, free-text, surfaced in the
   history panel.
4. Click **Save**. The server writes a new row at `version = prior + 1`,
   stamps the prior row's `effective_until = now()`, writes a
   `policy_amended` audit-log entry with a field-level diff snapshot,
   and returns the new current version. Concurrent amendments serialise
   cleanly; the loser sees `409 Conflict` with body
   `{ "code": "policy_version_stale", "current_version": N }`.

### View version history + diff

The **Version history** panel below the detail form lists prior
versions oldest-first, each with `change_summary`, author moderator id,
`created_at`, and a `Diff` link. Click the link or hit
`GET /api/admin/policies/:identifier/diff?from=N&to=M` directly to
fetch a per-field diff. Only fields that differ appear under
`changes`; audit metadata (`id`, `created_*`, `effective_*`,
`supersedes_id`, `change_summary`, `autonomous_paused_until`) is
excluded — it trivially differs on every amendment.

### Pause / resume autonomy

The **Autonomy** tab on the policy detail view shows
`autonomy_mode`, `autonomous_action_kinds`, the two thresholds, and
`autonomous_paused_until`. Editing any field creates a new version
(every edit bumps the version) with the operator's `change_summary`
required, so you always have a "why did we flip this policy to
autonomous?" audit trail.

To pause without bumping the version (e.g. during an incident), use
the pause endpoint instead — it writes only the
`autonomous_paused_until` column:

```sh
# Pause polaris.harassment until a specific timestamp:
curl -sS -X POST https://mod.example.com/api/admin/policies/polaris.harassment/pause \
  -H "Content-Type: application/json" \
  --cookie polaris_session=<your-cookie> \
  -d '{"until":"2026-12-31T00:00:00Z"}'

# Pause forever (empty body or `{}`):
curl -sS -X POST https://mod.example.com/api/admin/policies/polaris.harassment/pause \
  --cookie polaris_session=<your-cookie>

# Resume:
curl -sS -X DELETE https://mod.example.com/api/admin/policies/polaris.harassment/pause \
  --cookie polaris_session=<your-cookie>
```

Both write a `policy_paused` / `policy_resumed` audit-log row. The LLM
dispatcher re-reads `autonomous_paused_until` on every recommend call,
so paused policies fall through to assisted mode within one call
window — no cache invalidation needed.

## Seed YAML shape

The seed file lives at `deploy/seeds/mod-policies.yml`. On first boot
the backend reads it via the loader at
[`polaris-backend/src/seed/mod_policies.rs`](../../polaris-backend/src/seed/mod_policies.rs):
if `mod_policies` is empty AND a bootstrap admin exists (someone who
finished the OAuth setup wizard and got pinned), every entry is
inserted as version 1 attributed to that admin. Already-populated
tables are never touched (idempotent on re-boot of an existing
deployment).

Path resolution order:

1. `POLARIS_POLICY_SEED_PATH` env var (explicit override).
2. `/etc/polaris/seeds/mod-policies.yml` (container image default).
3. `<workspace>/deploy/seeds/mod-policies.yml` (dev `cargo run`
   fallback).

The first path that exists wins. An env var pointing at a missing path
fails the lookup rather than silently falling through.

One full entry:

```yaml
- identifier: polaris.harassment
  name: Targeted harassment
  description: >-
    Sustained, targeted abuse aimed at an individual or a small group —
    repeated insults, dogpiling, threats of harm, doxxing, or
    coordinated brigading.
  scope: both          # account | post | both
  severity: alert      # inform | alert | hide | remove
  decision_criteria: >-
    Apply when content is directed at a specific person or small group
    AND exhibits at least one of: explicit slurs at the target,
    repeated unwanted contact after a clear stop signal, threats of
    physical or sexual harm, disclosure of private contact / location
    information, or visible coordination across accounts to amplify
    the targeting.
  examples_positive:
    - excerpt: "@victim you should kill yourself, here's your home address"
      context: Replied 6 times in 20 minutes after the target blocked the sender.
      expected_action_kind: takedown
  examples_negative:
    - excerpt: "this take is dumb and so is the person who wrote it"
      context: Single low-effort dunk in a public political thread.
      why_not_a_violation: Rude but not sustained or targeted to the
        harassment-policy bar; route via no_action.
  suggested_action_kinds: [label, warn, takedown]
  linked_label_value: harassment
  exceptions: >-
    Public officials acting in their public capacity have a higher
    threshold for "harassment".
  human_required_always: false
  autonomy_mode: manual           # manual | assisted | autonomous
  autonomous_action_kinds: []     # subset of {label, warn, takedown}
  autonomous_confidence_threshold: 0.95
  assisted_confidence_threshold: 0.70
```

Field constraints the loader (and the DB CHECKs) enforce:

- `decision_criteria` ≥ 64 characters.
- `scope` ∈ `{account, post, both}`.
- `severity` ∈ `{inform, alert, hide, remove}`.
- `autonomy_mode` ∈ `{manual, assisted, autonomous}`.
- `suggested_action_kinds` non-empty, subset of the `actions.kind`
  vocabulary.
- `autonomous_action_kinds` subset of `{label, warn, takedown}` (REQ-G1
  safety floor — `escalate`/`mute`/`no_action`/`reverse` cannot
  auto-fire even if you try).
- Thresholds in `[0.0, 1.0]`.
- `human_required_always: true` is **incompatible** with
  `autonomy_mode: autonomous`. The loader refuses the combination
  before insert; the admin API rejects the same combo with
  `policy_autonomy_forbidden`. See
  [`policy-autonomy.md`](policy-autonomy.md).

Validation failures point at the offending entry by `identifier`. A
mid-load failure rolls every prior insert back inside the same
transaction — there is no partial-load state.

## `polaris-setup seed-policies`

Post-install bulk import. Same parser as the first-boot loader; the
file shape is identical to `deploy/seeds/mod-policies.yml`.

```sh
# Default: import new identifiers as v1, skip any already in the DB.
polaris-setup seed-policies --file ./our-policies.yml

# Replace: amend every existing identifier (writes a new version with
# change_summary = "Imported from <path> at <RFC3339 timestamp>").
polaris-setup seed-policies --file ./our-policies.yml --replace
```

The subcommand reads `DATABASE_URL` from the environment, opens a
small connection pool, and dispatches per-policy. Without `--replace`,
identifiers already present are skipped (logged INFO); with
`--replace`, they are amended (a new version is written, the prior
row's `effective_until` is stamped). Identifiers not yet in the table
are always inserted as v1, attributed to the pinned bootstrap admin.

Pre-mutation safety scan: the binary refuses to import if any incoming
policy has `human_required_always = TRUE` AND the live row for that
identifier currently has `autonomy_mode != 'manual'`. The seed file
cannot retroactively floor a policy that is currently autonomous —
flip autonomy back to manual via
`DELETE /api/admin/policies/<id>/pause` (or the admin UI) and re-run.

Exit codes (REQ-E3):

- `0` — success: rows imported, or no-op skip (everything already
  present without `--replace`).
- `1` — user / validation error: bad flags, YAML parse failure, schema
  violation (vocabulary, length, threshold range), or the
  human-required hard-block tripped.
- `2` — IO / internal failure: seed file not found, `DATABASE_URL`
  unset, DB connection failure, no pinned bootstrap admin yet
  (complete the OAuth setup wizard first).

Per-row decisions go to stderr as structured `tracing::info!` lines
the operator can grep — `seed-policies: skip` / `seed-policies: insert
v1` / `seed-policies: amend` — plus a final summary with insert /
amend / skip counts.

## The moderator browse view

Non-admin moderators read policies at `/policies` (no `/admin`
prefix). Same two-pane layout, no edit affordances, no autonomy tab.
Requires `Role::Moderator` or higher — anyone who can take a
moderation action can read the rules they're enforcing.

Use it during a case: the read-only detail view shows
`decision_criteria`, the example arrays, `suggested_action_kinds`, and
`exceptions`. The version-history panel and the diff view are
admin-only; a moderator who wants to know "did the rule change since
my last action?" asks an admin to share the diff URL.

## Citing a policy in an action

The action-create API
([`polaris-backend/src/api/cases.rs`](../../polaris-backend/src/api/cases.rs))
validates every `policy_refs` entry against
`mod_policies::current_by_identifier` (per-process LRU cache, TTL
60 s). The action insert and the per-citation inserts into
`action_policy_citations` run inside a single transaction, so a
partial citation is never visible.

```sh
# Moderator submits an action citing two policies. The server snapshots
# the current version of each into action_policy_citations.
curl -sS -X POST https://mod.example.com/api/cases/<case-id>/actions \
  -H "Content-Type: application/json" \
  --cookie polaris_session=<your-cookie> \
  -d '{
    "kind": "label",
    "label": "harassment",
    "reasoning": "Account 24 reply chain after target's clear stop signal.",
    "policy_refs": ["polaris.harassment"]
  }'
```

Rejections you may see:

- `400 unknown_policy_ref` — `identifier` is not in `mod_policies`.
  Body carries `{ "code": "unknown_policy_ref", "identifier": "<id>" }`.
- `400 policy_retired` — the identifier exists but its current row is
  tombstoned. Body carries `retired_at`.
- `409 policy_version_stale` — the LLM/UI cited a specific version
  that was superseded between recommend and approve. Body carries
  `current_version`; refetch and resubmit.
- `403 policy_autonomy_forbidden` — the action was submitted by an
  autonomous agent citing a `human_required_always = TRUE` policy.
  See [`policy-autonomy.md`](policy-autonomy.md).

Reversal actions (`kind = 'reverse'`) write their own
`action_policy_citations` rows with the **current** version at
reversal time. The original action's citations are untouched; an audit
reader joining both surfaces "the original cited harassment v3; we
reversed under harassment v5 which clarified the satire exception".

## Reading audit history

Every policy edit emits one of three structured audit-log events
keyed in the hash-chained `audit_log` table:

| Event kind        | Payload                                                                              |
|-------------------|--------------------------------------------------------------------------------------|
| `policy_created`  | `{ identifier, version: 1, moderator_id }`                                           |
| `policy_amended`  | `{ identifier, from_version, to_version, change_summary, moderator_id }`             |
| `policy_paused`   | `{ identifier, until, moderator_id }`                                                |
| `policy_resumed`  | `{ identifier, moderator_id }`                                                       |

Two query shapes operators reach for most:

```sql
-- "Every action that cited harassment v3" — supports the
-- (policy_identifier, policy_version) index on action_policy_citations.
SELECT a.id, a.created_at, a.kind, a.moderator_id
FROM   action_policy_citations c
JOIN   actions a ON a.id = c.action_id
WHERE  c.policy_identifier = 'polaris.harassment'
  AND  c.policy_version    = 3
ORDER  BY a.created_at DESC;

-- "Full edit timeline for one policy"
SELECT version, change_summary, created_by_moderator_id, created_at,
       effective_from, effective_until, is_retired
FROM   mod_policies
WHERE  identifier = 'polaris.harassment'
ORDER  BY version;
```

The hash-chained envelope on `audit_log` makes post-hoc tampering with
policy history detectable — re-running the chain verifier
(`docs/ops/runbook.md` §audit) is the operator-side check before
declaring a historical audit "intact".

The admin LLM audit page at `/admin/llm/audit` surfaces
recommendation → action linkage with filters `?model=`, `?policy=`,
`?reversed=`, `?from=`, `?to=`, so reviewing "what did the LLM say
when this autonomous label fired against harassment v5" does not
require raw SQL. See [`llm-moderation.md`](llm-moderation.md) § 5.
