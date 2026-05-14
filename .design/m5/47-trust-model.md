# M5 design — Issue #47: Add richer cross-labeler trust model with per-source per-category time-decay weights

## Summary

Replace v1's flat per-upstream-labeler trust weight with a richer model:
per-source × per-category weights, per-source × per-subject-class
weights, time-decay (older labels carry less weight), and operator-defined
custom expressions. The v1 schema (`upstream_labelers.weights JSONB`) was
deliberately shaped to absorb this richer policy without a migration; this
issue is the implementation that fills in the JSONB.

## v1 connection points

- `design.md` §10: "Cross-labeler trust model. How do operators express
  'I trust labeler X for spam signals but not for harassment signals'?
  Per-labeler-per-category weights are the obvious answer; a richer
  model may be warranted." This issue answers it.
- `.design/polaris-proto-blue-integration.md` §G ("Inbound third-party
  labels"): "The per-category trust weight from `design.md` §10 is
  captured by storing the weight on the `Observation` itself at ingest
  time — refining the trust model later (e.g., source × category ×
  time-decay) only requires changing the weight-computation function,
  not the schema."
- Builds on v1 #32 `upstream_labelers.weights JSONB` schema. That JSONB
  column is the canonical config surface for this issue. v1 used it for
  a single `weight` float per upstream; this issue expands what lives
  there.
- Builds on v1 `Observation { kind: ExternalLabel { source: Did,
  label_value: String, weight: f32 }, ... }` shape. The `weight` field
  on the observation is computed at ingest time by the trust function;
  this issue changes the function, not the field.
- Also relevant to #45 (ML classifier integration) — once classifier
  signals exist, the trust model applies to them too. v1 has flat
  per-classifier weights (also via the `weights JSONB` pattern). This
  issue subsumes both labels and classifiers into one unified trust
  function.

## Requirements

- REQ-1: Trust function is pure: `fn weight(observation: &Observation,
  policy: &TrustPolicy, now: DateTime<Utc>) -> f32`. Result always in
  `[0.0, 1.0]`. Easily testable in isolation.
- REQ-2: A `TrustPolicy` supports at minimum:
  - Per-source flat weight (back-compat with v1).
  - Per-source × per-category weight.
  - Per-source × per-subject-class weight (e.g., "trust X for posts
    but not for accounts").
  - Time decay (exponential half-life, operator-configurable per
    source).
  - Custom expressions (Q1 below: DSL or structured form?).
- REQ-3: Default templates are shipped: "moderate trust for spam,
  default decay 30d," "high trust for CSAM hash matches, no decay,"
  "low trust for harassment, default decay 7d." Operators pick a
  template or write their own.
- REQ-4: Backward-compatible: a v1 `weights JSONB` containing only the
  flat `weight: 0.8` continues to work. The trust function falls back
  to flat-per-source weight when richer policy is absent.
- REQ-5: A "preview" UI in the operator admin surface shows: "with this
  policy, recent labels from source X have weight Y" for a sampled set
  of recent observations.
- REQ-6: Trust-policy changes are audited. Changing `weights JSONB`
  writes an entry to `audit_log` with the diff between old and new
  policy.
- REQ-7: Misconfiguration safety: an obviously-broken policy (e.g.,
  weight > 1.0, negative decay half-life) is rejected at save time
  with a clear error. The trust function NEVER returns a value
  outside `[0.0, 1.0]`, even if asked to operate on a saved-but-
  bad policy (clamped at evaluation time as a defense-in-depth).
- REQ-8: An operator audit path: a `polaris trust-policy explain
  <observation_id>` admin command shows "this observation's weight is
  $w because [decomposition: source=$x, category=$y, time-decay
  factor=$z, etc.]"

## Acceptance Criteria

- [ ] AC-1: Property test: for 10,000 randomly-generated
      `(Observation, TrustPolicy, time)` tuples, `weight()` returns a
      value in `[0.0, 1.0]`.
- [ ] AC-2: Snapshot test: a representative `TrustPolicy` applied to a
      representative set of `Observations` yields a stable weight map
      (committed snapshot file; CI fails on drift).
- [ ] AC-3: v1 backward-compat: an `upstream_labelers` row with
      `weights JSONB` containing only `{"flat": 0.8}` produces the
      same observation weights as v1 did.
- [ ] AC-4: Time decay: an observation labeled at $t_0$ with a 30-day
      half-life policy has weight $w_0$ at $t_0$ and weight $w_0/2$
      at $t_0 + 30d$ (within floating-point tolerance).
- [ ] AC-5: Per-category weight: a `TrustPolicy` of `{spam: 0.9,
      harassment: 0.0}` on an upstream labeler produces weight 0.9
      for observations of category `spam` and weight 0.0 for
      observations of category `harassment`.
- [ ] AC-6: Misconfiguration: saving a `TrustPolicy` with
      `flat_weight: 1.5` fails the save endpoint with a 400 error.
- [ ] AC-7: Audit: changing an upstream's `TrustPolicy` produces an
      `audit_log` entry containing the old and new policies (or a
      diff).
- [ ] AC-8: `polaris trust-policy explain <obs_id>` outputs a
      human-readable decomposition of the weight for the given
      observation.

## Architecture sketch

**`TrustPolicy` shape.** Roughly:

```rust
struct TrustPolicy {
    flat_weight: Option<f32>,
    per_category: HashMap<String, f32>,
    per_subject_class: HashMap<SubjectKind, f32>,
    time_decay: Option<TimeDecay>,
    custom: Option<CustomExpr>,
}

struct TimeDecay {
    half_life_days: f32,
}

enum CustomExpr {
    Dsl(String),       // a parsed DSL expression
    Structured(...),   // see Q1
}
```

Serializes to/from the v1 `upstream_labelers.weights JSONB` column.
Backward compat: a v1 single-float `weight` deserializes as
`TrustPolicy { flat_weight: Some(w), ..Default::default() }`.

**Weight composition.** Multiplicative composition of contributing
factors:

```
weight =
    flat_weight_factor          // 1.0 if no flat, else the flat weight
  * per_category_factor         // 1.0 if no category match, else the category weight
  * per_subject_class_factor    // 1.0 if no subject-class match, else the subject-class weight
  * time_decay_factor           // 1.0 if no decay, else exp(-ln(2)*age/half_life)
  * custom_factor               // 1.0 if no custom, else result of custom expression
```

Order of evaluation does not matter (multiplication is commutative).
Each factor is in `[0.0, 1.0]`; the product stays in `[0.0, 1.0]`.

**File / module layout.**
- `polaris-trust/` — new workspace crate. Pure logic, no DB
  dependencies. `weight()` lives here.
- `polaris-trust/src/lib.rs` — `TrustPolicy`, `weight()`,
  `explain()`.
- `polaris-trust/src/parse.rs` — DSL parser (if Q1 resolves to DSL).
- `polaris-trust/src/structured.rs` — alternative structured form (if
  Q1 resolves to structured).
- `polaris-trust/src/templates.rs` — shipped default templates.
- `polaris-backend/src/ingest/upstream_labels.rs` — point-of-use
  (already exists in v1). Replaces v1's flat-weight lookup with a
  `polaris_trust::weight()` call.
- `polaris-backend/src/admin/trust_policy.rs` — admin endpoints for
  reading, writing, previewing.
- `polaris-frontend/src/admin/trust_policy/` — UI for editing
  policies with the preview.

**No new migrations.** The v1 `upstream_labelers.weights JSONB` column
absorbs the richer policy. The same column now contains a richer JSON
structure rather than a single float; the deserializer handles both
shapes via Q4 below.

**Audit integration.** Trust-policy changes go through the v1
`audit_log` (already hash-chained per `design.md` §6). A new audit
entry kind `kind = 'trust-policy-change'` carries the old and new
policy.

**Performance.** Trust evaluation runs once per inbound observation
on the ingest path. The trust function is pure and cheap (a few
arithmetic ops, a hashmap lookup, no I/O). Caching is not needed in
v2; if it becomes hot later, cache per-source after the first
evaluation.

**Backwards-compatibility story.** A v1 `weights JSONB` value of
`{"flat": 0.8}` is parsed by the new code as
`TrustPolicy { flat_weight: Some(0.8), ..Default::default() }` and
produces the same weight. AC-3 verifies this. Operators can upgrade
without policy changes; they enrich policies opt-in over time.

**Dependencies on other M5 issues.** Soft-related to #45 (classifier
integration): the same trust function applies to classifier
observations as to label observations. The v1 #45 design uses
`weights JSONB` on classifier config in the same shape; this issue's
function works for both. Independent of #42, #43, #44, #46, #48,
#49.

## Open questions

<!-- OPEN: Q1 -->
### Q1: DSL vs. structured config form for the custom expression

The plan comment mentions "operator-defined custom expressions."
Options:

- **A. Structured config only.** The above factors (flat,
  per-category, per-subject-class, time-decay) are all that's
  supported. No DSL. Custom logic requires a code change. Simplest.
- **B. Mini-DSL.** A small expression language, e.g.:
  `if observation.category == "spam" then 0.9 * decay(60d)
   else if recent(7d) then 0.5 else 0.0`. Implemented with `nom` or
  `chumsky`. Powerful; risk of operators writing bugs.
- **C. JSON Logic / Rego.** Established expression language with
  existing parsers. Less invented. Bigger dependency.

Recommend A for v2 baseline (covers all stated use cases) with B as a
follow-up if operator demand justifies it. C is overkill for the
scope.

**To resolve**: confirm with target operators. If the stated cases
(per-category, per-class, time-decay) cover their needs, A is
enough.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Time decay model — exponential, linear, or step?

- **A. Exponential half-life** (proposed). `weight *=
  exp(-ln(2) * age / half_life)`. Smooth; the natural model for
  "trust fades over time." One parameter (half-life).
- **B. Linear decay.** `weight *= max(0, 1 - age / lifespan)`.
  Hard cutoff at `lifespan`. Simpler to reason about; less
  realistic.
- **C. Step function.** `weight *= w_age_bracket`. Discrete brackets
  (e.g., "<1d: 1.0, 1-7d: 0.8, 7-30d: 0.5, >30d: 0.0"). Easiest to
  explain; harder to tune.

Recommend A. Mathematically clean; operators understand "half-life"
because radioactive decay is a common analogy.

**To resolve**: confirm. If operators push back on the math,
consider C.
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: How do operators audit their trust assignments?

REQ-8 specifies a `polaris trust-policy explain <obs_id>` command and
REQ-5 specifies a preview UI. But auditing assignments at scale
("show me every observation weighted under 0.1 in the last week so I
can sanity-check the policy") needs more:

- **A. The admin UI gets a "weighted observations" filter.** Sort by
  weight; filter by source, category, time.
- **B. A `polaris trust-policy report` command** generates a CSV
  summary.
- **C. Trust decisions are visible on individual case views.** Each
  observation row shows its weight and the policy components.

Recommend C as the primary path (moderator sees the weight when they
see the observation) plus A as the admin path.

**To resolve**: UX decision with operator input.
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: Deserialization of the v1 → v2 JSONB shape

The v1 JSONB looks like `{"flat": 0.8}` or possibly
`{"weight": 0.8}` (depends on v1's actual choice; verify against
#32 at implementation time). The v2 JSONB carries the richer
`TrustPolicy`. Options:

- **A. Untagged enum deserialization.** Serde tries the rich form
  first; falls back to the v1 form. Risk: ambiguity if shapes overlap.
- **B. Versioned discriminator.** Add a `"version": 2` field;
  deserializer dispatches by version. Cleanest; requires a one-time
  data migration to add `"version": 1` to existing rows.
- **C. Migration on first write.** Existing rows stay in v1 form;
  they're rewritten as v2 form the first time the operator edits
  them. Eventually-consistent migration.

Recommend B. Clean, explicit, one migration script. The migration is
trivial (`UPDATE upstream_labelers SET weights =
jsonb_set(weights, '{version}', '1') WHERE weights ->> 'version' IS
NULL`).

**To resolve**: confirm.
<!-- /OPEN -->

<!-- OPEN: Q5 -->
### Q5: What is the right default policy?

REQ-3 ships default templates. The question is which template is the
v1 → v2 default for an existing upstream that hasn't been edited.

- **A. The v1 flat weight, unchanged.** Migration adds
  `"version": 2` but the policy is logically equivalent to v1. No
  change in behavior post-upgrade.
- **B. The v1 flat weight, with a default decay applied** (e.g.,
  30d half-life). Implicit behavior change.
- **C. A neutral policy** (flat 0.5). Explicit reset.

Recommend A. Upgrading to v2 must not silently change moderation
outcomes.

**To resolve**: confirm. A is the safe default.
<!-- /OPEN -->

<!-- OPEN: Q6 -->
### Q6: Misconfiguration boost-attack risk

The plan comment flags: "trust-model misconfiguration silently
boosting bad labels."

Mitigations:

- A. Hard cap at policy save time (weight > 1.0 rejected,
  REQ-7).
- B. Hard cap at evaluation time (clamp to `[0.0, 1.0]` no matter
  what, REQ-7 defense-in-depth).
- C. Alert on a policy change that increases aggregate weight by
  >2x on a backfill simulation.
- D. Two-person rule: trust-policy changes require senior
  co-sign, similar to the v1 pattern-action senior co-sign.

A and B are in the requirements. C and D are open questions —
both are reasonable safeguards but neither is strictly necessary.

**To resolve**: decide on C and D as a follow-up. v2 baseline ships
A and B.
<!-- /OPEN -->

## Out of scope (within this issue)

- Trust models for FEDERATED labels (the labels arriving via #43
  cross-instance federation). Federated labels are observations like
  any other; this issue's trust function applies to them. But the
  cross-instance trust relationship (do you trust peer instance Y's
  labels at all?) is governed by the #43 federation peer config,
  not by this trust policy.
- Machine learning of trust weights from moderator agreement
  patterns. "Polaris automatically adjusts trust based on outcomes"
  is out of scope; it is a research project, not a v2 deliverable.
- A web-of-trust style transitive model. Trust is per-source, not
  transitive.
- Real-time policy evaluation streams (e.g., "show me weights
  recomputed every second"). v2 evaluates at observation-ingest time
  and on explicit preview.
- Per-moderator trust (a moderator trusting one upstream more than
  another, individually). v2 is per-instance.
- Cross-classifier-vs-label trust calibration. v2's function works on
  both; calibration (is classifier X's 0.9 the "same trust" as
  upstream Y's 0.9?) is operator-defined.

## Suggested decomposition

1. **PR 1 — `polaris-trust` crate skeleton.** `TrustPolicy` struct,
   `weight()` function with flat-only support, property tests for
   AC-1 and AC-3. Replaces v1's flat-weight lookup with a
   `polaris_trust::weight()` call. Behavior-equivalent to v1.
2. **PR 2 — Per-category weights.** Adds `per_category` to
   `TrustPolicy`; AC-5 verified.
3. **PR 3 — Time decay.** Adds `TimeDecay`; AC-4 verified.
4. **PR 4 — Per-subject-class weights.** Adds `per_subject_class`.
5. **PR 5 — Templates + admin endpoints.** Shipped defaults;
   GET/POST `/api/admin/upstream-labelers/<id>/trust-policy`.
   Audit integration (REQ-6).
6. **PR 6 — Preview UI.** Frontend admin surface for editing
   policies with the per-observation preview.
7. **PR 7 — Explain command + case-view integration.**
   `polaris trust-policy explain`, per-observation weight
   visibility in case view.
8. **PR 8 — Optional: DSL or richer custom expression.** Conditional
   on Q1 resolution.

Each PR is reviewable independently. PRs 1-5 are the substantive
implementation; PRs 6-7 are UX; PR 8 is the optional follow-on.
