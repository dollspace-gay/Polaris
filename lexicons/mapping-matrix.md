# Polaris Lexicon mapping matrix

Canonical reference for the field-by-field mapping between internal
`polaris-types` domain structs and the wire-side `polaris-lexicons`
generated types. Maintained alongside the `polaris-types::lexicon_mapping`
module (issue #103). When you change a mapping function, update this
matrix; when you add a new field, decide which column it belongs in
BEFORE writing code.

The matrix is also the auditable record of what crosses the privacy
boundary: every `dropped — internal only` row is a field the source
labeler keeps and the receiving instance never sees.

---

## Legend (mapping rule)

| Rule | Meaning |
|------|---------|
| `identity` | Field copies byte-for-byte between internal and wire forms. The wire field has the same semantics; only the Rust type wrapper differs (e.g., internal `String` ↔ wire `proto_blue_syntax::Did`). |
| `scaled-int` | Internal `f32` in `[0.0, 1.0]` ↔ wire `i64` in `[0, 1000]`. ATProto Lexicons have no native float; scaled-integer is the standard encoding. The mapping function multiplies by `1000.0` to-wire and divides by `1000.0` from-wire, with explicit `clamp(0.0, 1.0)` defense-in-depth (rust-quality §6). |
| `rename` | Field copies semantically but the names differ (typically camelCase on the wire vs snake_case in Rust). The codegen handles this via `#[serde(rename_all = "camelCase")]`. |
| `dropped — internal only` | Field exists in internal type but is NEVER serialized to the wire. The mapping function omits it; the wire shape has no field for it. Each drop is annotated with `// privacy: <field> never federated` in source. |
| `default-filled` | Field exists on the wire but is absent on the internal type. The from-wire mapping populates the internal field from a default; the to-wire mapping omits it (or sends the default). |
| `union dispatch` | Field is a discriminated union; the mapping handles each variant explicitly. |

---

## `gay.dollspace.polaris.escalation`

Maps to `polaris_types::Escalation`. Record type (Lexicon `type: "record"`,
key: `tid`).

| Internal field (`Escalation`) | Wire field (`escalation::Main`) | Rule | Notes |
|-------------------------------|--------------------------------|------|-------|
| `id: EscalationId` | — | `dropped — internal only` | Internal primary key. Never federated. Receiver allocates its own ID for the materialized escalation. |
| `source_did: String` | `source: proto_blue_syntax::Did` | `rename`/typed-wrap | Internal plain string; wire validated DID newtype. Mapping returns `MappingError::MalformedDid` on invalid input. |
| `target_did: String` | `target: proto_blue_syntax::Did` | `rename`/typed-wrap | Same. |
| `subject: SubjectRef` | `subject: String` (DID or AT-URI) | `union dispatch` | The internal enum (`SubjectRef::Did(String)` vs `SubjectRef::AtUri(String)`) collapses to a single wire string. The wire field's `format` is left as a generic string (not `did` or `at-uri`) because either is valid here; the discriminator is the format of the string itself. Receivers parse + validate. Per Q4-A (closed #100): non-ATProto subjects are not federated, so this field is always a DID or AT-URI on the wire. |
| `reason: String` | `reason: String` | `identity` | Free-text reasoning summary. NOT the original moderator's full reasoning — that's an internal-only field on `Action`. The source labeler may include a sanitised summary here. |
| `observations: Vec<EmbeddedObservation>` | `observations: Vec<EmbeddedObservation>` | `union dispatch` (per element) | See the EmbeddedObservation row below for the per-element shape. |
| `evidence: Vec<EvidencePointer>` | `evidence: Option<Vec<EvidencePointer>>` | `identity` (per element) | Internal `Vec` (possibly empty) maps to wire `Option<Vec>` (None when empty). |
| `created_at: chrono::DateTime<Utc>` | `created_at: proto_blue_syntax::Datetime` | `rename`/typed-wrap | The wire newtype enforces RFC 3339 formatting. |
| (no internal field) | — | — | The wire record's `$type` is fixed as `gay.dollspace.polaris.escalation` by codegen; no mapping needed. |

---

## `gay.dollspace.polaris.escalation::embeddedObservation`

Maps to `polaris_types::EmbeddedObservation`. Object type embedded in
`escalation::Main::observations`.

| Internal field (`EmbeddedObservation`) | Wire field | Rule | Notes |
|----------------------------------------|------------|------|-------|
| `confidence: f32` | `confidence: i64` | `scaled-int` | `f32` in `[0.0, 1.0]` ↔ wire `i64` in `[0, 1000]`. The mapping function clamps internal input to `[0.0, 1.0]` before scaling and clamps wire input to `[0, 1000]` before dividing — defense-in-depth (rust-quality §6). |
| `observation: ObservationKind` | `observation: EmbeddedObservationObservationRefs` | `union dispatch` | Five-arm union: ImageHashCluster, AccountCohort, ReplyBrigade, ExternalLabel, ClassifierSignal. The two internal-only `ObservationKind` variants (`ReportVolumeAnomaly`, `ModeratorBehaviorAnomaly`) return `MappingError::UnsupportedVariant` on to-wire — they carry operator-internal data that violates the privacy boundary. |

---

## `gay.dollspace.polaris.observation::imageHashCluster`

Maps to `polaris_types::ObservationKind::ImageHashCluster`.

| Internal | Wire | Rule | Notes |
|----------|------|------|-------|
| `hash: String` | `hash: String` | `identity` | Perceptual hash (SimHash / pHash). Opaque to receivers. |
| `distance: u32` | `distance: i64` | `identity` (u32 → i64 cast) | Hamming distance to the cluster centroid. |

## `gay.dollspace.polaris.observation::accountCohort`

Maps to `polaris_types::ObservationKind::AccountCohort`.

| Internal | Wire | Rule | Notes |
|----------|------|------|-------|
| `cohort_id: String` | `cohort_id: String` | `identity` | Opaque cohort id local to the source labeler (per Lexicon description). |
| `similarity_score: f32` | `similarity_score: i64` | `scaled-int` | `[0.0, 1.0]` ↔ `[0, 1000]`. |

## `gay.dollspace.polaris.observation::replyBrigade`

Maps to `polaris_types::ObservationKind::ReplyBrigade`.

| Internal | Wire | Rule | Notes |
|----------|------|------|-------|
| `thread_uri: String` | `thread_uri: AtUri` | `rename`/typed-wrap | Wire is a typed AtUri newtype. |

## `gay.dollspace.polaris.observation::externalLabel`

Maps to `polaris_types::ObservationKind::ExternalLabel`.

| Internal | Wire | Rule | Notes |
|----------|------|------|-------|
| `source: Did` (internal newtype) | `source: Did` (wire newtype) | `identity` | Both sides use a typed DID. |
| `label_value: String` | `label_value: String` | `identity` | Opaque to Polaris; vocabulary is the upstream labeler's. |
| `weight: f32` | `weight: i64` | `scaled-int` | `[0.0, 1.0]` ↔ `[0, 1000]`. Informational only — receivers apply their own weight. |

## `gay.dollspace.polaris.observation::classifierSignal`

Maps to `polaris_types::ObservationKind::ClassifierSignal`.

| Internal | Wire | Rule | Notes |
|----------|------|------|-------|
| `model: String` | `model: String` | `identity` | Classifier model identifier (e.g. `csam-detector-v3`). Opaque. |
| `label: String` | `label: String` | `identity` | Classifier-emitted label string; model-specific vocabulary. |
| `confidence: f32` | `confidence: i64` | `scaled-int` | `[0.0, 1.0]` ↔ `[0, 1000]`. |

---

## Internal-only `ObservationKind` variants (NEVER federated)

These two variants of `polaris_types::ObservationKind` exist in the
internal enum but have NO corresponding wire shape. The mapping function
returns `MappingError::UnsupportedVariant { discriminator: "…" }` when
asked to convert them to the wire form. They are documented here so
future contributors do not accidentally try to add them.

| Variant | Internal fields | Why never federated |
|---------|-----------------|---------------------|
| `ReportVolumeAnomaly` | window counts, anomaly thresholds | Operator-internal accounting; reveals the source labeler's internal alerting thresholds, which is itself a sensitive operational signal. |
| `ModeratorBehaviorAnomaly` | `moderator_id`, anomaly score | Contains a `ModeratorId`. Per REQ-5: moderator identity NEVER federates. |

---

## `gay.dollspace.polaris.evidencePointer`

Maps to `polaris_types::EvidencePointer`. Embedded object (no `main` record
def; referenced by escalation's `evidence` field).

| Internal field | Wire field | Rule | Notes |
|----------------|------------|------|-------|
| `car_cid: String` | `car_cid: Cid` | `rename`/typed-wrap | Internal plain string; wire validated CID newtype. |
| `media_type: String` | `media_type: String` | `identity` | RFC 6838 media type string (e.g. `application/vnd.ipld.car`). |
| `byte_length: u64` | `byte_length: i64` | `identity` (u64 → i64 cast, clamp on `>= i64::MAX`) | The wire uses signed `i64`; the mapping rejects byte-lengths that exceed `i64::MAX` with `MappingError::FieldOutOfRange`. |

---

## Fields never federated (consolidated)

For audit clarity, this is the explicit list of `polaris-types` fields
that the mapping layer DROPS at the to-wire boundary. Each drop is
annotated in `polaris-types/src/lexicon_mapping/mod.rs` with a
`// privacy: <field> never federated` comment.

- `Escalation::id` (internal primary key)
- `moderator_id` on any internal type that carries one (Incident, Action, EscalationMessage, ModeratorBehaviorAnomaly observation)
- `audit_chain_hash` on any audited row (Action, Incident, EscalationMessage)
- `reporter_did` from referenced incidents (the subject DID flows, the reporter DID does not)
- `exposure_tracking_metadata` (the moderator's exposure budget state)
- `notes` on Action (internal moderator notes — distinct from `Escalation::reason` which is the explicit federation-safe summary)
- Internal anomaly thresholds (ReportVolumeAnomaly content)

The privacy unit test in `polaris-types/tests/lexicon_mapping_privacy.rs`
asserts via `serde_json::to_string` that none of these substrings appear
in any wire-serialized form.

---

## Updating this matrix

When you change `polaris-types/src/lexicon_mapping/mod.rs`:

1. Update the relevant row(s) in this matrix.
2. If the change adds a new field, decide its column BEFORE writing code:
   - Wire-side new field that should propagate to the internal type → add internal field + `identity` row.
   - Wire-side new field that's optional and the internal type doesn't care about → `default-filled` row.
   - Internal-side new field that must never federate → `dropped — internal only` row + explicit annotation in source.
3. If the change adds a new `ObservationKind` variant: decide whether it federates. If yes, add the wire shape to `lexicons/polaris/observation.json` + regenerate codegen + add a matrix row. If no, add an entry to the "Internal-only `ObservationKind` variants" table above + ensure the to-wire mapping function returns `MappingError::UnsupportedVariant`.
4. If the change adds a new scalar-confidence-like field: use `scaled-int` (per the precedent set by `confidence`, `similarity_score`, `weight`). Document the encoding in the field's Lexicon `description`.

The CI markdown-lint job catches broken links and heading drift. Every
matrix row that names a Rust type must reference a type that actually
exists in `polaris-types/src/lib.rs`'s re-exports.
