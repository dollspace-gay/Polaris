# Feature: Mod policy workbook (structured policy data model + autonomy controls)

## Summary

Polaris currently models moderation rules as two unstructured things:

1. A hardcoded slice `KNOWN_POLICY_REFS` at
   [`polaris-backend/src/api/policy.rs`](polaris-backend/src/api/policy.rs)
   listing five placeholder identifiers
   (`polaris.harassment`, `polaris.spam`, `polaris.csam`,
   `polaris.impersonation`, `polaris.copyright`) — annotated in code as
   a placeholder that M3 was supposed to replace.
2. Each moderator's free-text `reasoning` column on the `actions`
   table (required, ≥10 chars). Search-indexable but not queryable as
   structured policy.

This shape was acceptable while Polaris was a hand-moderated tool but
blocks three downstream capabilities the operator now needs:

- **Operator-configurable rules.** Today the operator cannot add a
  policy, retire one, or amend the wording of one. The five placeholder
  identifiers are baked in at compile time.
- **Citable structure in actions.** The free-text `reasoning` field
  lets a moderator write whatever they want; there's no machine-readable
  link from "this action" to "the specific clause that was violated".
- **Autonomous moderation by an LLM advisor** (see
  `.design/llm-moderation-assist.md`). An LLM that doesn't read
  structured rules can only produce vague, unauditable suggestions; an
  LLM that can fire actions autonomously can only do so safely if there
  is a versioned, citable policy register it must ground against and
  per-policy autonomy controls the operator can toggle.

This design specifies the workbook data model, the operator edit UI,
the action-API integration that replaces the hardcoded slice, the
seed file that pre-populates the five placeholders for existing
deployments, and — critically — the autonomy-control fields on each
policy (mode, confidence floors, allowed-action-kinds, pause state)
that the downstream LLM-assist design will consume.

The workbook is useful **standalone** — even without the LLM
integration, an operator gets searchable structured policy reference
material, versioned amendments with audit trail, and per-action
machine-readable policy citations. The LLM-assist design depends on
this design landing first.

## Requirements

### A. Data model

- REQ-A1: New table `mod_policies` stores one row per
  `(identifier, version)` pair. Identifier is human-stable
  (`polaris.harassment`); version is a monotonically-increasing
  integer that bumps on every edit. Querying "current version of
  policy X" is `WHERE identifier = $1 AND effective_until IS NULL`;
  querying "what was version Y" is `WHERE identifier = $1 AND
  version = $2`. The `actions` table cites
  `(identifier, version)` so a historical action always points at the
  exact wording that was in force at the time it was emitted.

- REQ-A2: Required columns:
  - `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` — row identity.
  - `identifier TEXT NOT NULL` — human-stable (`polaris.harassment`).
  - `version INTEGER NOT NULL` — 1, 2, 3 … on edit.
  - `name TEXT NOT NULL` — short human-readable title.
  - `description TEXT NOT NULL` — one-paragraph summary of what the
    policy is enforcing. Rendered at the top of the moderator-facing
    detail view and embedded in the LLM context (see
    `.design/llm-moderation-assist.md`).
  - `scope TEXT NOT NULL` — `'account' | 'post' | 'both'`. Matches the
    atproto `LabelValueDefinition.targets` shape.
  - `severity TEXT NOT NULL` — `'inform' | 'alert' | 'hide' | 'remove'`.
    Reuses the atproto label-severity vocabulary; lets the policy and
    its declared label stay aligned.
  - `decision_criteria TEXT NOT NULL` — Markdown-formatted multi-line
    text. The clauses the moderator (and the LLM) reads to decide
    whether the policy applies to a given case. Constrained ≥ 64 chars
    so a one-word placeholder fails to insert.
  - `examples_positive JSONB NOT NULL DEFAULT '[]'` — array of
    `{ excerpt: string, context: string, expected_action_kind: action_kind }`.
    Worked examples of cases that violate this policy.
  - `examples_negative JSONB NOT NULL DEFAULT '[]'` — array of
    `{ excerpt: string, context: string, why_not_a_violation: string }`.
    Worked examples of cases that *look like* this policy but aren't
    — the false-positive corpus.
  - `suggested_action_kinds TEXT[] NOT NULL` — non-empty subset of the
    `actions.kind` enum (`label`, `warn`, `takedown`, `mute`,
    `escalate`, `no_action`, `reverse`). The kinds that *typically*
    apply when this policy is violated.
  - `linked_label_value TEXT` — nullable. If set, references a value
    declared in `polaris_setup_state.label_values`. When the action
    kind is `label`, the action's `label_value` should normally match
    this.
  - `exceptions TEXT` — nullable. Free-text describing when the
    policy doesn't apply (e.g. "satire, when the parodic intent is
    obvious from the post's labels or the author's pinned post").
  - `human_required_always BOOLEAN NOT NULL DEFAULT FALSE` — when
    `TRUE`, this policy can never run in `autonomy_mode =
    'autonomous'`; attempts to set it are rejected at the API
    layer (REQ-G3). The seed file sets this `TRUE` for the
    `polaris.csam` placeholder; operators can mark other policies
    the same way for any reason that the rule requires a human
    (account-level takedowns, doxxing, anything tagged with the
    atproto `!hide` severity by the operator's judgment).

- REQ-A3: Autonomy-control columns (consumed by
  `.design/llm-moderation-assist.md`):
  - `autonomy_mode TEXT NOT NULL DEFAULT 'manual'` — one of
    `'manual' | 'assisted' | 'autonomous'`. `manual` (default) means
    the LLM may suggest but never auto-creates an action. `assisted`
    means the LLM creates a draft action in a per-moderator review
    queue; nothing emits to atproto without the moderator clicking
    approve. `autonomous` means the LLM creates the action AND emits
    to atproto when its confidence exceeds the autonomous threshold;
    the human reverses if wrong.
  - `autonomous_action_kinds TEXT[] NOT NULL DEFAULT '{}'` — subset of
    the `actions.kind` enum that may auto-fire when `autonomy_mode =
    'autonomous'`. Default empty; the operator broadens explicitly.
    The full set of *eligible* kinds is gated at the API layer to
    `{label, warn, takedown}` (post-level takedown only — REQ-G2),
    with `escalate`, `mute`, `no_action`, and `reverse` always
    requiring a human.
  - `autonomous_confidence_threshold REAL NOT NULL DEFAULT 0.95` —
    0.0 ≤ x ≤ 1.0. The LLM recommendation must report at least this
    confidence to auto-fire; otherwise it falls through to assisted.
  - `assisted_confidence_threshold REAL NOT NULL DEFAULT 0.7` —
    minimum confidence for an assisted-mode draft to land in the
    review queue.
  - `autonomous_paused_until TIMESTAMPTZ` — nullable. When non-null
    and in the future, autonomous actioning is suspended for this
    policy (kill switch and circuit-breaker outputs both set this).

- REQ-A4: Audit columns:
  - `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`.
  - `created_by_moderator_id UUID NOT NULL REFERENCES moderators(id)`
    — who edited this version into being.
  - `effective_from TIMESTAMPTZ NOT NULL DEFAULT now()` — when this
    version started binding moderation decisions.
  - `effective_until TIMESTAMPTZ` — null while current, set to the
    successor's `effective_from` when superseded.
  - `supersedes_id UUID REFERENCES mod_policies(id)` — null for the
    initial version; points at the prior version row otherwise.
  - `change_summary TEXT` — nullable. Short note "why this version was
    written" surfaced in the version-history view.

- REQ-A5: Indexes:
  - `UNIQUE (identifier, version)` — duplicates are a bug.
  - `CREATE INDEX ON mod_policies (identifier) WHERE effective_until
    IS NULL` — the dominant query is "latest version of policy X".
  - `CREATE INDEX ON mod_policies (autonomy_mode) WHERE
    autonomy_mode <> 'manual' AND effective_until IS NULL` — fast
    "which policies are currently auto-firing" lookup for the
    operator dashboard and the LLM dispatcher.

### B. Action API integration

- REQ-B1: A new table `action_policy_citations` carries the
  `(action_id, policy_identifier, policy_version)` triple for each
  citation on an action. Required columns:
  - `action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE`.
  - `policy_identifier TEXT NOT NULL` — copied from
    `mod_policies.identifier` at action-create time.
  - `policy_version INTEGER NOT NULL` — copied from
    `mod_policies.version` at action-create time (snapshot, so a
    later workbook amendment never rewrites history).
  - `created_at TIMESTAMPTZ NOT NULL DEFAULT now()` — same instant
    as the action's `created_at`; kept here for query convenience
    when reading citations in isolation.

  Foreign key:
  - `FOREIGN KEY (policy_identifier, policy_version) REFERENCES
    mod_policies (identifier, version) ON DELETE RESTRICT` — the
    workbook never destructively deletes a policy version
    (REQ-F1 supersession is non-destructive), so the FK is
    enforceable and prevents a stray citation to a non-existent
    `(identifier, version)` pair.

  Indexes:
  - `PRIMARY KEY (action_id, policy_identifier, policy_version)` —
    natural composite key; an action can cite multiple policies
    but never the same `(identifier, version)` twice.
  - `CREATE INDEX ON action_policy_citations
    (policy_identifier, policy_version)` — supports the
    "show me every action that cited harassment v3" admin query.

- REQ-B2: The existing `actions.policy_refs TEXT[]` column is
  retained as a **read-only legacy mirror** for backward
  compatibility — populated with the flat list of identifiers
  (no version) on write so existing readers continue working, but
  the structured citation lives in `action_policy_citations`. A
  future migration may drop `actions.policy_refs` once all readers
  are migrated; this design does not block on that follow-up.

- REQ-B3: At action-create time
  ([`cases.submit_action`](polaris-backend/src/api/cases.rs)),
  each cited identifier is validated against `mod_policies WHERE
  identifier = $1 AND effective_until IS NULL`. Unknown
  identifiers reject with `400 Bad Request` body
  `{ "code": "unknown_policy_ref", "identifier": "<offender>" }`.
  Retired policies (rows with `is_retired = TRUE`, REQ-F1)
  reject with `400` body `{ "code": "policy_retired",
  "identifier": "<id>", "retired_at": "..." }`. The action insert
  + the per-citation inserts into `action_policy_citations`
  happen in a single transaction so a partial citation is never
  visible.

- REQ-B4: The hardcoded `KNOWN_POLICY_REFS` slice in
  [`polaris-backend/src/api/policy.rs`](polaris-backend/src/api/policy.rs)
  is removed. The function that previously checked the slice now
  reads `mod_policies` (with a per-process LRU cache keyed on
  `identifier`, TTL 60 s) so the hot action-create path stays
  fast.

- REQ-B5: Reversal actions (`kind = 'reverse'`) write their own
  rows into `action_policy_citations` with the *current* policy
  version at reversal time. The original action's citation rows
  stay untouched (the original cites the original version; the
  reversal cites whatever version is in force when the reverse
  happens). An audit reader joining both surfaces the version
  delta so a reviewer can see "the original action cited
  harassment v3; we reversed it under harassment v5 which
  clarified the satire exception".

### C. Admin REST API

- REQ-C1: All endpoints below require `Role::Admin` per the existing
  admin RBAC ([`polaris-backend/src/api/admin_moderators.rs`](polaris-backend/src/api/admin_moderators.rs)
  is the pattern). Non-admin moderators get `403 Forbidden` on every
  write path; reads on `GET /api/policies` (the moderator-facing
  read-only browse view) require `Role::Moderator` or higher.

- REQ-C2: Endpoints:
  - `GET /api/policies` — list current versions. Filters: `?scope=`,
    `?autonomy_mode=`, `?q=` (free-text over name + description +
    decision_criteria). Returns the policy DTO without the example
    arrays (kept compact for the index list).
  - `GET /api/policies/:identifier` — current version, full payload
    including examples.
  - `GET /api/policies/:identifier/history` — admin-only.
    Returns the full version chain (oldest first), each entry's
    `change_summary`, `created_by`, `created_at`, and a diff URL.
  - `GET /api/policies/:identifier/:version` — admin-only. Specific
    historical version, full payload.
  - `POST /api/admin/policies` — admin-only. Create a brand-new
    policy (initial version = 1).
  - `PATCH /api/admin/policies/:identifier` — admin-only. Edit
    creates a new version, supersedes the prior. Body fields the
    operator wants to change; unspecified fields inherit from the
    prior version. Required: `change_summary`.
  - `POST /api/admin/policies/:identifier/pause` — admin-only.
    Set `autonomous_paused_until` to a moderator-supplied timestamp
    (or `forever`, which writes `'9999-12-31'`). Records an
    audit-log entry.
  - `DELETE /api/admin/policies/:identifier/pause` — admin-only.
    Clears `autonomous_paused_until` (resumes auto-firing). Audit-
    logged.

- REQ-C3: Endpoints return JSON with the DTO defined in
  `polaris-backend/src/api/dto.rs::ModPolicyDto`. The wasm frontend
  consumes the same DTO via the existing `PolarisApiClient` trait.

- REQ-C4: Per-version diff is computed server-side on demand at
  `GET /api/admin/policies/:identifier/diff?from=N&to=M`. Returns a
  per-field diff `{ field_name: { from: value, to: value } }`.
  Cheap to compute (rows are small); avoiding client-side diff means
  the moderator UI is simpler.

### D. Admin frontend page

- REQ-D1: New page at `/admin/policies` (Leptos route added in
  `polaris-frontend/src/navigation.rs`). Two-pane layout: a sortable
  filterable list on the left, the selected policy's detail+edit form
  on the right. Mirrors the `/admin/moderators` layout convention.

- REQ-D2: The detail form shows current version with collapsible
  example arrays. A "version history" panel lists prior versions
  with their `change_summary` and per-version diff links. The
  `decision_criteria` field renders as a Markdown `<textarea>`
  with two tabs above it (`Edit` and `Preview`); the `Preview`
  tab renders the saved Markdown via the same Markdown component
  the case-view uses for moderator reasoning, so the operator sees
  what the moderators will actually read. No live side-by-side
  preview — the audience is technical, the field is infrequently
  edited, and keeping the wasm bundle lean matters
  (`tests/styles_coverage.rs` already monitors total bundle
  growth).

- REQ-D3: An admin-only "autonomy" tab on each policy detail view
  shows the current `autonomy_mode`, `autonomous_action_kinds`,
  thresholds, and pause state. Editing any of these creates a new
  version (REQ-A1: every edit bumps the version) with the operator's
  `change_summary` field required, so we always have a "why did we
  flip this policy to autonomous?" audit trail.

- REQ-D4: Read-only browse view at `/policies` (no `/admin` prefix)
  for non-admin moderators to look up rules during a case. Same
  layout, no edit affordances, no autonomy-tab.

### E. Operator seeding

- REQ-E1: A YAML seed file at `deploy/seeds/mod-policies.yml` ships
  with the five existing placeholder identifiers
  (`polaris.harassment`, `polaris.spam`, `polaris.csam`,
  `polaris.impersonation`, `polaris.copyright`) as initial v1
  policies with reasonable text and `autonomy_mode = 'manual'`. The
  operator can override the seed file path via
  `POLARIS_POLICY_SEED_PATH` env var; the default is shipped inside
  the container image at `/etc/polaris/seeds/mod-policies.yml`.

- REQ-E2: At backend startup, if `mod_policies` is empty, the seed
  file is loaded as v1 of each policy. Already-populated tables are
  not touched (idempotent on existing deployments). Loaded by
  `created_by_moderator_id = (the bootstrap admin)`; the system
  refuses to seed if no bootstrap admin exists yet — this couples
  policy seeding to the existing setup-wizard flow.

- REQ-E3: `polaris-setup` (the install CLI) gets a new subcommand
  `polaris-setup seed-policies --file <path>` that imports a YAML
  file into `mod_policies` at any time post-install. Used when the
  operator wants to bulk-load a different policy set or replicate
  another deployment's workbook.

### F. Versioning + history

- REQ-F1: Every edit creates a *new row*; the old row is preserved
  with `effective_until` set to `now()`. There is no destructive
  edit. Deletion is implemented as "supersede with a tombstone
  version" — the new row has `is_retired = TRUE` (new column) and
  `effective_until = '9999-12-31'`. Lookup still finds the
  tombstone row, surfaces "this policy was retired on Y by Z" in
  the UI, and rejects citations to it on new actions.

- REQ-F2: The audit log gets a new event type `policy_amended`
  (alongside the existing `first_user_admin_grant`,
  `moderator_role_granted`, etc.). Body includes `identifier`,
  `from_version`, `to_version`, `actor`, `change_summary`, and a
  field-level diff snapshot. The existing audit-log envelope and
  hash-chain ensure post-hoc tampering with policy history is
  detectable.

### G. Safety floors (consumed by LLM-assist design)

- REQ-G1: The set of action kinds that are *eligible* to appear in
  `autonomous_action_kinds` is gated server-side at policy
  create/edit. The eligible set is exactly `{label, warn, takedown}`.
  `escalate` (semantically routes to a human), `mute` (high
  blast-radius), `no_action` (a non-action), and `reverse` (must be a
  deliberate human override) cannot be auto-fired even if the
  operator tries to set them.

- REQ-G2: When `takedown` is in `autonomous_action_kinds`, an
  additional constraint applies at action-create time: the action's
  subject must have `kind = 'post'`. Account-level takedowns
  (`subjects.kind = 'account'`) are never autonomous; they always
  require a human moderator. Enforced at the action API, not just at
  the LLM dispatcher, so the database invariant holds even if the
  LLM bypasses the dispatcher.

- REQ-G3: Any policy with `human_required_always = TRUE` (REQ-A2)
  has a hard server-side block: `autonomy_mode` cannot be set to
  `autonomous` on it, regardless of any other field. The check
  happens at:
  - the policy edit API (`PATCH /api/admin/policies/:identifier`)
    on every write — attempts return `403` body
    `{ "code": "policy_autonomy_forbidden", "reason":
    "policy is marked human_required_always; flip that off first
    if you really mean to autonomously enforce" }`,
  - the LLM dispatcher (per `.design/llm-moderation-assist.md`
    REQ-S8) on every recommendation evaluation — even if a stale
    in-memory cache held a non-`autonomous` mode, the dispatcher
    re-reads `human_required_always` on every call,
  - and the action-create API — even a directly-constructed
    autonomous action (bypassing the dispatcher entirely)
    rejects when `actor_kind = 'autonomous_agent'` and any cited
    policy has `human_required_always = TRUE`.

  This three-layer enforcement means no single bypass (cache
  staleness, dispatcher bug, direct DB injection through a
  compromised privileged role) can autonomously action a
  human-required policy. The seed file (REQ-E1) sets
  `human_required_always = TRUE` on the `polaris.csam` placeholder.
  Operators mark other policies similarly via the admin UI; the
  rationale (legal exposure, NCMEC reporting pipelines, false-
  positive harm, account-level damage, doxxing irreversibility) is
  documented in `docs/ops/policy-autonomy.md`.

## Acceptance Criteria

- AC-1: Migration `polaris-backend/migrations/<next>_mod_policies.sql`
  creates the `mod_policies` table with all columns from REQ-A1
  through REQ-A4 and the indexes from REQ-A5. `sqlx migrate run`
  succeeds on a fresh DB and on the latest test fixture DB.

- AC-2: `polaris-backend/src/repo/mod_policies.rs` exposes the typed
  repo API (`insert_initial`, `amend`, `current_by_identifier`,
  `at_version`, `history`, `list`, `pause`, `resume`). Every SQL
  call uses `sqlx::query!` or `sqlx::query_as!` (parameterized;
  per `.crosslink/rules/global.md` "parameterized queries only").

- AC-2b: A second migration creates the `action_policy_citations`
  table (REQ-B1) with the composite primary key + FK to
  `mod_policies(identifier, version)` + the per-policy index.
  `polaris-backend/src/repo/action_policy_citations.rs` exposes
  `insert_for_action(tx, action_id, &[(identifier, version)])` and
  `citations_for_action(action_id)`. The action-create handler
  invokes `insert_for_action` inside the same transaction as the
  action INSERT (REQ-B3 atomicity).

- AC-3: The hardcoded `KNOWN_POLICY_REFS` slice in
  [`polaris-backend/src/api/policy.rs`](polaris-backend/src/api/policy.rs)
  is removed. Action-create reads `mod_policies` via the LRU cache.
  An existing action-create test exercising an unknown identifier
  passes the rejection check against the new code path.

- AC-4: New admin endpoints from REQ-C2 are routed in
  `polaris-backend/src/api/mod.rs` and gated by the existing
  `Role::Admin` extractor pattern.

- AC-5: Admin frontend page at `/admin/policies` and read-only
  browse view at `/policies` render against a populated DB. The
  routes are added to `polaris-frontend/src/navigation.rs` and the
  CSS lives at `polaris-frontend/styles/admin-policies.css`.
  `styles_coverage`, `styles_tokens`, and `styles_contrast` tests
  pass against the new selectors.

- AC-6: Seed file `deploy/seeds/mod-policies.yml` exists with five
  policies and is loaded on first boot. Re-running the setup against
  an already-seeded DB does not duplicate rows
  (regression test: `tests/policy_seed_idempotent.rs`).

- AC-7: An existing `tests/case_api.rs` test verifies that an
  action created with a stale policy version (one that was
  superseded between the LLM-recommend call and the moderator's
  approve click) is rejected with `409 Conflict` body
  `{ "code": "policy_version_stale", "current_version": N }`.

- AC-8: REQ-G3 hard block is regression-tested across all three
  enforcement layers in
  `tests/policy_human_required_never_autonomous.rs`:
  - PATCH `polaris.csam` (which has `human_required_always = TRUE`
    from seed) attempting `autonomy_mode = 'autonomous'` returns
    `403 policy_autonomy_forbidden`.
  - A direct action insert with
    `actor_kind = 'autonomous_agent'` citing a
    `human_required_always = TRUE` policy is rejected at the
    action-create API.
  - The LLM dispatcher coverage of this floor lives in the
    LLM-assist design's test suite
    (`tests/llm_safety_floors.rs` per
    `.design/llm-moderation-assist.md` AC-6).

- AC-9: `cargo build`, `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo test --workspace`, `cargo fmt --all --check`
  all pass on the changed tree.

## Architecture

### Files added / modified

```
polaris-backend/
  migrations/
    00000000000046_mod_policies.sql               (new)
    00000000000047_action_policy_citations.sql    (new)
  src/
    repo/mod_policies.rs                          (new)
    repo/action_policy_citations.rs               (new)
    api/
      admin_policies/
        mod.rs                                    (new)
        dto.rs                                    (new)
        handlers.rs                               (new)
      policies/                                   (new — read-only browse)
        mod.rs
        handlers.rs
      policy.rs                                   (modified — drop KNOWN_POLICY_REFS)
      cases.rs                                    (modified — validate against mod_policies)
      mod.rs                                      (modified — route registration)
      dto.rs                                      (modified — add ModPolicyDto)
    bin/polaris_setup.rs                          (modified — add seed-policies subcommand)
  tests/
    policy_seed_idempotent.rs                     (new)
    policy_csam_never_autonomous.rs               (new)
    policy_version_pinning.rs                     (new)
    admin_policies_endpoint.rs                    (new)
polaris-frontend/
  src/
    pages/
      admin_policies.rs                           (new)
      policies.rs                                 (new — read-only browse)
    navigation.rs                                 (modified — routes + admin nav link)
    api_client/
      dto.rs                                      (modified — ModPolicyDto)
      mod.rs                                      (modified — list_policies, get_policy, etc.)
      native.rs                                   (modified)
      wasm.rs                                     (modified)
  styles/
    admin-policies.css                            (new)
deploy/
  seeds/
    mod-policies.yml                              (new)
docs/
  ops/
    policy-management.md                          (new)
    policy-autonomy.md                            (new — REQ-G3 rationale + safety guidance)
```

### Data flow

1. **Setup-wizard boot:** if `mod_policies` is empty AND a bootstrap
   admin exists, load `deploy/seeds/mod-policies.yml` as v1 rows of
   each policy (REQ-E2).
2. **Action create:** the moderator's POST `/api/cases/:id/actions`
   includes `policy_refs: ["polaris.harassment"]` in the body. The
   handler looks each up via the LRU-cached
   `mod_policies::current_by_identifier`, snapshots the current
   version into the action's stored citation, and rejects unknown
   identifiers (REQ-B2, REQ-B3).
3. **Admin edits a policy:** PATCH `/api/admin/policies/polaris.spam`
   with a partial body + required `change_summary`. The repo inserts
   a new row with `version = prior + 1`, sets the prior row's
   `effective_until = now()`, writes a `policy_amended` audit-log
   event. The new version is what subsequent action-creates cite
   (REQ-A1, REQ-F1, REQ-F2).
4. **Admin flips autonomy mode:** same path as a content edit; this
   is just edits to `autonomy_mode`, `autonomous_action_kinds`,
   thresholds. The downstream LLM dispatcher (see
   `.design/llm-moderation-assist.md`) reads these fields per-case
   to decide whether to auto-fire.
5. **Admin pauses a policy's autonomy:** POST
   `/api/admin/policies/:id/pause` writes
   `autonomous_paused_until`. The LLM dispatcher checks this
   timestamp on every recommend call and downgrades the effective
   mode to `manual` for the paused window.

### Concurrency and transactions

- Policy amendments take a row-level lock on the current version
  before inserting the successor + updating `effective_until`,
  under a single transaction. Concurrent edits serialize cleanly;
  the loser gets a `409 Conflict` body `{ "code":
  "policy_version_stale", "current_version": N }` (mirrors REQ-A7).
- Action create reads via the LRU cache; the cache key is
  `(identifier, current_version_at_read_time)`. Cache invalidation
  is a no-op (entries TTL out at 60 s) — staleness for that long
  is acceptable on the hot path; the action will still cite a
  valid version, just possibly one version behind.

### RBAC

The `Role::Admin` extractor pattern from `admin_moderators.rs` is
reused verbatim. The only addition is the read-only browse view at
`/policies` which extracts `Role::Moderator` or higher (anyone who
can take a moderation action can read the rules they're enforcing).

## Out of scope

- LLM evaluation of cases against policies. That's
  `.design/llm-moderation-assist.md`. This design only defines the
  data model + UI + autonomy *controls*; the LLM that *uses* them
  is downstream.
- Migration of historical free-text `actions.reasoning` to
  structured citations. Existing actions keep their freeform refs;
  only new actions go through the validator (REQ-B2).
- Policy import/export from other moderation systems (Ozone,
  upstream Bluesky labelers, etc.). A future
  `polaris-setup import-ozone-config` would belong on a separate
  design.
- Per-region / per-locale policy variants. The data model could
  support it (add a `locale TEXT` column) but the operator-facing
  surface stays single-locale for now.

## Resolved decisions

Three forks that were open in the first draft, all resolved before
this design moves to implementation:

- **Action citation shape** — decided in favour of a separate
  `action_policy_citations` table with a composite foreign key to
  `mod_policies(identifier, version)`. Encoded in REQ-B1 through
  REQ-B5 and AC-2b. The legacy `actions.policy_refs TEXT[]` column
  is retained read-only as a backward-compat mirror; a later
  follow-up may retire it once all readers migrate.

- **Human-required policy marker** — decided in favour of a
  first-class `human_required_always BOOLEAN` column on
  `mod_policies` (REQ-A2). Generalises the always-human floor
  beyond a single hardcoded CSAM identifier; operators mark any
  policy human-only the same way. Three-layer enforcement
  (workbook edit API, action-create API, LLM dispatcher) means no
  single bypass can produce an autonomous action against a
  human-required policy (REQ-G3 + LLM design REQ-S8).

- **Markdown editor for `decision_criteria`** — decided in favour
  of a plain `<textarea>` with an `Edit` / `Preview` tab toggle
  rendering via the same Markdown component used for moderator
  reasoning (REQ-D2). No live side-by-side preview; the wasm
  bundle stays lean and the operator audience is technical enough
  not to need an in-place WYSIWYG.

## Dependencies

This design is the **prerequisite** for
`.design/llm-moderation-assist.md`. The LLM-assist design reads:

- `mod_policies` rows as the "rules the LLM must reason against"
  (REQ-A1 through REQ-A4).
- `autonomy_mode`, `autonomous_action_kinds`,
  `autonomous_confidence_threshold`,
  `assisted_confidence_threshold`, `autonomous_paused_until`
  (REQ-A3) as the per-policy autonomy controls the LLM dispatcher
  consults before firing.
- The safety floors REQ-G1, REQ-G2, REQ-G3 as the always-on
  invariants enforced server-side regardless of what the LLM
  recommends.

This design does NOT depend on any LLM-related work; it is shippable
and useful standalone (moderators get structured rules they can
look up and cite).
