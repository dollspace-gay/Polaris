//! Observation repository — CRUD over the `observations` table.
//!
//! Maps [`polaris_types::Observation`] / `NewObservation` to and from the
//! `observations` row shape in `00000000000006_observations.sql`.
//!
//! # Storage representation
//!
//! [`polaris_types::ObservationKind`] is a serde-tagged enum
//! (`#[serde(tag = "kind", content = "data")]`). The DB splits this in two:
//!
//! - The `kind` column is a `TEXT` discriminator with a `CHECK (kind IN
//!   (...))` constraint, taking values like `image_hash_cluster`. This is
//!   the same string that
//!   [`polaris_types::ObservationKind::discriminator`] returns.
//! - The full per-variant payload (`{"hash": "...", "distance": 3}`) is
//!   serialized to the `evidence` JSONB column alongside any free-form
//!   additional context the detector wanted to attach.
//!
//! On read, the repo reconstructs the `serde(tag, content)`-shaped JSON
//! value from the two columns and deserializes it back into the enum. The
//! split is necessary because the per-variant payload schemas differ; a
//! single JSONB column with `serde(internally_tagged)` storage would lose
//! the CHECK-constraint-backed discriminator.
//!
//! # Trigger interaction
//!
//! Inserting an observation fires the per-statement AFTER trigger in
//! migration `00000000000007_risk_signals_trigger.sql`, which rewrites the
//! parent subject's `risk_signals` JSONB column. The trigger runs inside
//! the caller's transaction; from the repo's perspective the insert is a
//! single statement that also updates `subjects.risk_signals` as a side
//! effect.

use chrono::{DateTime, Utc};
use polaris_types::{Observation, ObservationId, ObservationKind, SubjectId};
use sqlx::PgPool;

use super::RepoError;

// Re-export so consumers can name `polaris_backend::repo::NewObservation`
// alongside the other `New<Type>` inputs without learning about polaris-types.
// The type itself is owned by polaris-types because it's part of the
// public wire surface (serde-derived).
pub use polaris_types::NewObservation;

/// Compile-time contract for the observation repository.
pub trait ObservationRepo: Send + Sync {
    /// Insert a new observation. The Postgres trigger refreshes the parent
    /// subject's `risk_signals` snapshot as a side effect.
    fn insert(
        &self,
        new: NewObservation,
    ) -> impl std::future::Future<Output = Result<Observation, RepoError>> + Send;

    /// List observations attached to `subject_id`, newest first.
    fn list_by_subject(
        &self,
        subject_id: SubjectId,
    ) -> impl std::future::Future<Output = Result<Vec<Observation>, RepoError>> + Send;
}

/// Postgres-backed [`ObservationRepo`] implementation.
#[derive(Debug, Clone)]
pub struct PgObservationRepo {
    pool: PgPool,
}

impl PgObservationRepo {
    /// Build a [`PgObservationRepo`] over the given pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl ObservationRepo for PgObservationRepo {
    async fn insert(&self, new: NewObservation) -> Result<Observation, RepoError> {
        let (discriminator, payload) = split_kind(&new.kind)?;
        let evidence = merge_evidence(payload, new.evidence.clone())?;
        let row = sqlx::query!(
            r#"
            INSERT INTO observations (subject_id, kind, confidence, evidence)
            VALUES ($1, $2, $3, $4)
            RETURNING id, subject_id, kind, confidence, evidence, detected_at
            "#,
            new.subject_id.0,
            discriminator,
            new.confidence,
            evidence,
        )
        .fetch_one(&self.pool)
        .await?;

        decode_observation(
            row.id,
            row.subject_id,
            &row.kind,
            row.confidence,
            &row.evidence,
            row.detected_at,
        )
    }

    async fn list_by_subject(&self, subject_id: SubjectId) -> Result<Vec<Observation>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT id, subject_id, kind, confidence, evidence, detected_at
            FROM observations
            WHERE subject_id = $1
            ORDER BY detected_at DESC
            "#,
            subject_id.0,
        )
        .fetch_all(&self.pool)
        .await?;

        let mut observations = Vec::with_capacity(rows.len());
        for row in rows {
            observations.push(decode_observation(
                row.id,
                row.subject_id,
                &row.kind,
                row.confidence,
                &row.evidence,
                row.detected_at,
            )?);
        }
        Ok(observations)
    }
}

// ── private encoders / decoders ─────────────────────────────────────────

/// Split a typed [`ObservationKind`] into the DB discriminator (`kind`
/// column) and the JSON payload of its per-variant fields (a JSON object
/// that becomes part of the `evidence` JSONB column).
///
/// The serde wire form is `{"kind": "...", "data": {...}}`; we strip the
/// tag and forward the `data` half as the variant payload.
fn split_kind(kind: &ObservationKind) -> Result<(&'static str, serde_json::Value), RepoError> {
    let discriminator = kind.discriminator();
    let envelope = serde_json::to_value(kind).map_err(|e| RepoError::Decode {
        message: format!("ObservationKind serialize failed: {e}"),
    })?;
    // `serde(tag = "kind", content = "data")` produces an object; lift the
    // `data` field into the payload we'll merge into `evidence`. A variant
    // with no fields (none today, but future-proof) would have no `data`
    // key — fall back to `{}` in that case.
    let payload = match envelope {
        serde_json::Value::Object(mut map) => map
            .remove("data")
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
        other => {
            return Err(RepoError::Decode {
                message: format!("ObservationKind serialized to non-object: {other}"),
            });
        }
    };
    Ok((discriminator, payload))
}

/// Merge the per-variant payload with the caller-supplied free-form
/// `evidence` value.
///
/// Both halves live in the same `evidence` JSONB column. The payload keys
/// (e.g. `hash`, `distance` for `ImageHashCluster`) are merged into the
/// outer object; any overlapping keys from the caller's `evidence` take
/// precedence (callers can override but typically supply disjoint context).
/// If the caller's `evidence` is not a JSON object we wrap it as
/// `{ "extra": <value> }` so the merged shape is always an object.
fn merge_evidence(
    payload: serde_json::Value,
    extra: serde_json::Value,
) -> Result<serde_json::Value, RepoError> {
    let serde_json::Value::Object(mut merged) = payload else {
        return Err(RepoError::Decode {
            message: format!("ObservationKind payload not a JSON object: {payload}"),
        });
    };
    match extra {
        serde_json::Value::Object(extra_map) => {
            for (k, v) in extra_map {
                merged.insert(k, v);
            }
        }
        serde_json::Value::Null => {}
        other => {
            merged.insert("extra".to_owned(), other);
        }
    }
    Ok(serde_json::Value::Object(merged))
}

/// Rebuild an [`Observation`] from its DB columns.
///
/// The reverse of [`split_kind`] + [`merge_evidence`]: reconstruct the
/// `{"kind": "<discriminator>", "data": {<payload>}}` envelope and feed it
/// to serde to get the typed [`ObservationKind`]. Keys outside the
/// variant's payload schema are left in `evidence` for the caller.
fn decode_observation(
    id: uuid::Uuid,
    subject_id: uuid::Uuid,
    kind: &str,
    confidence: f32,
    evidence: &serde_json::Value,
    detected_at: DateTime<Utc>,
) -> Result<Observation, RepoError> {
    // Reconstruct the serde envelope. We pass the entire stored `evidence`
    // object as `data` and rely on serde's `deny_unknown_fields = false`
    // default to ignore detector-extra keys when reading. The polaris-types
    // `ObservationKind` is not declared `#[serde(deny_unknown_fields)]`, so
    // this round-trip is lossless for the typed payload and forward-
    // tolerant of detector-attached metadata.
    let envelope = serde_json::json!({
        "kind": kind,
        "data": evidence,
    });
    let typed_kind: ObservationKind =
        serde_json::from_value(envelope).map_err(|e| RepoError::Decode {
            message: format!(
                "ObservationKind deserialize from kind={kind:?}, evidence={evidence}: {e}"
            ),
        })?;

    Ok(Observation {
        id: ObservationId(id),
        subject_id: SubjectId(subject_id),
        kind: typed_kind,
        confidence,
        evidence: evidence.clone(),
        detected_at,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use polaris_types::{Did, LabelValue, ModeratorId};

    /// The encode → decode pair must round-trip every variant. This is a
    /// pure-data test (no DB) — it proves the typed↔(discriminator, JSONB)
    /// transform on its own.
    #[test]
    fn split_then_decode_round_trips_each_kind() {
        let cases = vec![
            ObservationKind::ImageHashCluster {
                hash: "deadbeef".to_owned(),
                distance: 3,
            },
            ObservationKind::AccountCohort {
                cohort_id: "c-42".to_owned(),
                similarity_score: 0.91,
            },
            ObservationKind::ReplyBrigade {
                thread_uri: "at://did:plc:x/app.bsky.feed.post/1".to_owned(),
            },
            ObservationKind::ReportVolumeAnomaly {
                category: "spam".to_owned(),
                z_score: 4.7,
            },
            ObservationKind::ExternalLabel {
                source: Did::new("did:plc:upstream"),
                label_value: LabelValue::new("spam"),
                weight: 0.6,
            },
            ObservationKind::ClassifierSignal {
                model: "csam-v3".to_owned(),
                label: "csam".to_owned(),
                confidence: 0.99,
            },
            ObservationKind::ModeratorBehaviorAnomaly {
                moderator_id: ModeratorId::new(),
                action_count: 137,
                window_secs: 3600,
            },
        ];
        for k in cases {
            let (disc, payload) = split_kind(&k).expect("split");
            let merged = merge_evidence(payload, serde_json::Value::Null).expect("merge");
            // Mimic the DB read: we pass the merged JSONB back through
            // decode_observation alongside the discriminator.
            let obs = decode_observation(
                uuid::Uuid::nil(),
                uuid::Uuid::nil(),
                disc,
                0.5,
                &merged,
                chrono::Utc::now(),
            )
            .expect("decode");
            assert_eq!(obs.kind, k);
        }
    }
}
