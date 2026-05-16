# Polaris Lexicons — Backwards-Compatibility Policy

This directory contains the ATProto Lexicon JSON sources for Polaris-owned
record types. These files define the **wire format** for cross-instance
federation — the shape that flows between Polaris labeler instances.

> **NSID namespace:** `gay.dollspace.polaris.*`
> Per Q1-A (issue #100): the first-operator domain is used. Renames are cheap
> via codegen re-generation; the namespace is stable until the first
> cross-instance federation handshake activates.

## Contents

| File | NSID | Type | Description |
|------|------|------|-------------|
| `polaris/escalation.json` | `gay.dollspace.polaris.escalation` | record | Primary cross-instance escalation record |
| `polaris/observation.json` | `gay.dollspace.polaris.observation` | object defs | Embedded observation variant shapes |
| `polaris/evidence-pointer.json` | `gay.dollspace.polaris.evidencePointer` | object | Content-addressed evidence CAR reference |

## Architecture context

The internal Polaris type system (`polaris-types`) and the wire types
(`polaris-lexicons`) are **parallel type hierarchies** with an explicit
mapping layer (`polaris-types::lexicon_mapping`). This separation exists
for two reasons:

1. **Internal evolution independence.** A new field added to `polaris-types`
   in a release should not require a Lexicon revision and a federation-network
   coordination event. Internal types evolve at Polaris release cadence; wire
   types evolve at federation-coordination cadence.

2. **Privacy boundary.** The mapping layer is the single enforcement point for
   "these fields never cross instance boundaries." Fields like `moderatorId`,
   `auditChainHash`, `reporterDid`, and `exposureMetadata` exist in
   `polaris-types` but are never present in any Lexicon shape. The Lexicon JSON
   in this directory IS the privacy contract — if a field is absent here, it
   cannot appear on the wire.

---

## Backwards-compatibility rules

Lexicon changes fall into three categories. The rules differ by category.

### Rule 1: Adding a non-breaking field

A field is **non-breaking** when:

- It is **optional** at the Lexicon level (not in `required`).
- It has a **serde-default** equivalent in the generated Rust code (i.e.
  deserializes to a known default when absent).
- Existing records that lack the field remain valid per the new schema.
- Existing implementations that ignore unknown fields continue to work.

**Procedure:**

1. Add the field to the JSON Lexicon file with no entry in `required`.
2. Add a `description` explaining the semantics and the version it was added.
3. Re-run `cargo xtask gen-lexicons` to regenerate `polaris-lexicons/src/`.
4. In the generated Rust code, annotate the field with
   `#[serde(default, skip_serializing_if = "Option::is_none")]` (or the
   appropriate default for non-optional types).
5. Update `polaris-types::lexicon_mapping` to populate the new field from
   the internal type, or leave it as the serde default if there is no
   internal equivalent.
6. Update `mapping-matrix.md` to document whether the new field maps to an
   internal field or is wire-only.
7. Bump `polaris-lexicons` as a **patch** version (`0.x.y -> 0.x.(y+1)`).
   No federation coordination required — existing peers ignore unknown fields.

### Rule 2: Deprecating a field

Deprecation follows a **one-release retention** policy: a field is deprecated
in release N and removed in release N+1 (minimum 90 days between N and N+1 if
federation peers are active).

**Procedure:**

1. Add `"deprecated": true` and a `"deprecatedDescription"` to the field's
   Lexicon JSON entry explaining the replacement.
2. In the generated Rust struct, add `#[deprecated(note = "...")]` to the
   field.
3. In `polaris-types::lexicon_mapping`, emit a `tracing::warn!` when the
   deprecated field is populated, and ensure the replacement field is
   populated instead.
4. Bump `polaris-lexicons` as a **minor** version (`0.x.y -> 0.(x+1).0`).
5. In release N+1: remove the field from the Lexicon JSON. This is a
   **breaking change** — see Rule 3.

### Rule 3: Bumping a Lexicon revision (breaking change)

A breaking change is any change that makes previously valid records invalid,
or that removes or renames a required field. Breaking changes require:

1. **Federation-network coordination.** All active peer instances must agree
   to adopt the new Lexicon version before any instance emits records under
   it. Coordinate via the federation handshake defined in issue #43.
2. **`polaris-lexicons` major version bump** (`0.x.y -> 1.0.0` or
   `M.x.y -> (M+1).0.0`). The major version is the federation-wire version.
3. A **migration plan** documented in `CHANGELOG.md` and `lexicons/README.md`
   stating: the old Lexicon NSID (if it changes), the new NSID, what records
   produced under the old version mean under the new schema (or that they are
   rejected), and the coordination window.
4. The Lexicon JSON file keeps the same NSID path; the `"revision"` field in
   the Lexicon header (if present) is incremented. Do **not** create a new
   file like `escalation-v2.json` — the NSID is the stable identifier that
   peers compile into their code.

> **Why not a new NSID for each version?** ATProto Lexicon convention treats
> the NSID as a stable identifier. Creating `polaris.escalationV2` forces
> every peer to update its code explicitly; using a revision field inside the
> same NSID allows implementations to negotiate capabilities via the version
> number while using the same code path.

---

## Worked example: adding `escalation.priorityHint` as a non-breaking change

This example shows the complete change set for adding an optional
`priorityHint` field to the escalation record. Copy this pattern for any
non-breaking field addition.

### Step 1 — JSON Lexicon diff

In `lexicons/polaris/escalation.json`, inside `defs.main.record.properties`,
add after `"createdAt"`:

```json
"priorityHint": {
  "type": "string",
  "description": "Optional hint from the source labeler about the urgency of this escalation. 'low' means the source labeler considers this informational only and the target should review at its normal cadence. 'normal' is the default when absent. 'high' means the source labeler believes the content poses active harm and requests expedited review. The target labeler is not obligated to honor this hint — it applies its own prioritization policy.",
  "knownValues": ["low", "normal", "high"]
}
```

Note: `priorityHint` is **not** added to the `required` array. Existing
records that lack this field remain valid.

Full diff context for `defs.main.record`:

```json
{
  "type": "object",
  "required": [
    "source",
    "target",
    "subject",
    "reason",
    "observations",
    "createdAt"
  ],
  "properties": {
    "source": { ... },
    "target": { ... },
    "subject": { ... },
    "reason": { ... },
    "observations": { ... },
    "evidence": { ... },
    "createdAt": { ... },
    "priorityHint": {
      "type": "string",
      "description": "Optional hint from the source labeler about the urgency of this escalation. ...",
      "knownValues": ["low", "normal", "high"]
    }
  }
}
```

### Step 2 — Codegen output sketch

After running `cargo xtask gen-lexicons`, the generated Rust struct in
`polaris-lexicons/src/generated/gay/dollspace/polaris/escalation.rs` gains:

```rust
/// Optional hint from the source labeler about the urgency of this
/// escalation. See the Lexicon description for semantics.
///
/// `None` is equivalent to `"normal"` — the absence of a hint means
/// the source labeler did not express a preference.
#[serde(
    default,
    skip_serializing_if = "Option::is_none",
    rename = "priorityHint"
)]
pub priority_hint: Option<EscalationPriorityHint>,
```

And a new enum is generated:

```rust
/// Urgency hint variants for [`MainRecord::priority_hint`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EscalationPriorityHint {
    Low,
    Normal,
    High,
}

impl Default for EscalationPriorityHint {
    fn default() -> Self {
        Self::Normal
    }
}
```

> **Note:** The codegen output shape above is a sketch. Actual field names,
> module paths, and serde annotations are determined by `proto-blue-codegen`
> at generation time. The sketch is accurate to the proto-blue-codegen
> conventions observed in `proto-blue-api`'s generated output; verify against
> actual output after running `cargo xtask gen-lexicons`.

### Step 3 — Mapping function update sketch

In `polaris-types/src/lexicon_mapping.rs`, the mapping from internal
`polaris_types::Escalation` to wire `polaris_lexicons::escalation::MainRecord`
gains a `priority_hint` field population:

```rust
use polaris_lexicons::escalation::EscalationPriorityHint;
use polaris_types::Escalation;

// Before the change, the mapping omits priority_hint (it defaults to None):
fn map_escalation_to_wire(src: &Escalation) -> Result<MainRecord, MappingError> {
    Ok(MainRecord {
        source: src.source_did.to_string(),
        target: src.target_did.to_string(),
        subject: map_subject(&src.subject)?,
        reason: src.reason.clone(),
        observations: map_observations(&src.observations)?,
        evidence: map_evidence(&src.evidence)?,
        created_at: src.created_at.to_rfc3339(),
        // priority_hint was absent here before the field existed
    })
}

// After the change — populate from the internal Escalation's priority field
// (assuming polaris-types gains a matching field in a coordinated PR):
fn map_escalation_to_wire(src: &Escalation) -> Result<MainRecord, MappingError> {
    Ok(MainRecord {
        source: src.source_did.to_string(),
        target: src.target_did.to_string(),
        subject: map_subject(&src.subject)?,
        reason: src.reason.clone(),
        observations: map_observations(&src.observations)?,
        evidence: map_evidence(&src.evidence)?,
        created_at: src.created_at.to_rfc3339(),
        priority_hint: src.priority_hint.as_ref().map(|p| match p {
            polaris_types::EscalationPriority::Low    => EscalationPriorityHint::Low,
            polaris_types::EscalationPriority::Normal => EscalationPriorityHint::Normal,
            polaris_types::EscalationPriority::High   => EscalationPriorityHint::High,
        }),
    })
}
```

If the internal `polaris_types::Escalation` does not yet have a
`priority_hint` equivalent (because the internal and wire types are decoupled),
the field is simply left as `None` in the mapping, which is valid:

```rust
priority_hint: None, // populated when internal type gains the field
```

**Version bump:** This is a non-breaking addition — bump `polaris-lexicons`
as a patch version (e.g. `0.1.0 -> 0.1.1`). No federation coordination
required.

---

## Validation

To validate Lexicon JSON files against the proto-blue schema validator:

```bash
# Available from PR 2 onwards (issue #102):
cargo xtask validate-lexicons lexicons/polaris/*.json

# Manual JSON syntax check (available now):
python3 -m json.tool lexicons/polaris/escalation.json > /dev/null && echo OK
python3 -m json.tool lexicons/polaris/observation.json > /dev/null && echo OK
python3 -m json.tool lexicons/polaris/evidence-pointer.json > /dev/null && echo OK
```

The `cargo xtask validate-lexicons` command is added in PR 2 (issue #102)
when the `polaris-lexicons` crate and its codegen task are introduced.
Until then, the JSON syntax check above is the baseline.

---

## Field naming conventions

All Lexicon field names use **camelCase** per ATProto convention. The
`proto-blue-codegen` generator converts camelCase Lexicon field names to
`snake_case` Rust field names automatically. Do not use `snake_case` in
Lexicon JSON — the codegen cannot round-trip `snake_case` names correctly.

All type-discriminated unions use ATProto's `$type` field convention for
the active variant tag. The embedded `observationKind` string type in
`gay.dollspace.polaris.observation` provides the closed `knownValues` list
that validators use to reject unknown variant tags.

Every field in every Lexicon def has a `description`. This is enforced by
review — the proto-blue Lexicon validator surfaces field descriptions in
error messages, making missing descriptions a debugging hazard.
