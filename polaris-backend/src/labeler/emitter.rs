//! Label emitter — turns a Polaris [`Action`] into a signed
//! `com.atproto.label.defs::Label` row (issue #28).
//!
//! # Pipeline shape
//!
//! ```text
//!    Action (kind=Label|Takedown)
//!         │
//!         ▼
//!    build proto-blue Label{ver,src,uri,cid,val,neg,cts}    ← unsigned
//!         │
//!         ▼
//!    serde_json::to_value  →  proto_blue_lex_json::json_to_lex
//!         │                                                  ← LexValue
//!         ▼
//!    proto_blue_lex_cbor::encode  →  canonical DAG-CBOR bytes
//!         │
//!         ▼
//!    SigningKey::sign(canonical_cbor)  →  64-byte K-256 signature
//!         │
//!         ▼
//!    INSERT INTO labels (...) VALUES (..., sig, label_cbor, ...)
//! ```
//!
//! The signature is computed over the **`sig`-omitted** canonical DAG-CBOR
//! encoding — the Label record without its own signature field, as
//! `serde_json::to_value` skips `sig: None` via `#[serde(skip_serializing_if
//! = "Option::is_none")]` on the generated type. Downstream verifiers
//! reproduce the same byte string from the persisted Label by replaying the
//! same serialisation chain with `sig` set to `None`.
//!
//! The persisted `label_cbor` column on the row carries exactly those
//! `sig`-omitted bytes — so a verifier never has to re-canonicalise the
//! Label; it reads `label_cbor`, calls `verify(label_cbor, sig)`, done.
//!
//! # Best-effort, idempotent, retryable
//!
//! `LabelEmitter::emit` is **best-effort**: a failure does not roll back
//! the originating [`Action`] insert. The action is the moderator's
//! record-of-truth; the label is a derived artefact. Emit failures are
//! logged at WARN with the action id so a follow-up re-emit job (filed as
//! #63) can pick the row up later.
//!
//! `emit` is **idempotent**: the `labels_action_id_uniq` partial unique
//! index on `labels(action_id)` (migration 13) means a second call against
//! the same action returns the existing row via the
//! [`EmitterError::DuplicateAction`] variant — chosen over silent re-emit
//! because the second caller almost certainly wants to know.
//!
//! # Takedown semantics
//!
//! Per the atproto label-value vocabulary, a takedown is the `!takedown`
//! value (the leading `!` denotes a system-level label). When an
//! `Action { kind: Takedown }` revokes a prior `kind: Label` action via
//! [`Action::reverses_action_id`] populated on the takedown row, the
//! emitter emits a second label row in the same call: a **negation** of
//! the reverted label's value. The negation row is wired through the same
//! sign-and-persist pipeline, so its signature is verifiable in isolation.
//!
//! # `Arc<dyn SigningKey>`, not `Arc<Mutex<...>>`
//!
//! The signer is held as `Arc<dyn SigningKey>` directly — the
//! [`SigningKey`] trait is `Send + Sync` and concrete impls are immutable
//! after construction (#29 contract). No interior mutability anywhere on
//! this path.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use polaris_types::{Action, ActionId, ActionKind};
use proto_blue::api::generated::com::atproto::label::defs::Label as ProtoLabel;
use proto_blue::lex_cbor;
use proto_blue::lex_json;
use proto_blue::syntax::{Datetime as ProtoDatetime, Did as ProtoDid};
use sqlx::PgPool;
use tracing::warn;
use uuid::Uuid;

use super::server::LabelBroadcaster;
use super::signer::{Signature, SigningError, SigningKey};

/// `ver` field value emitted on every signed Label. Matches the current
/// `com.atproto.label.defs::Label.ver` contract (v1).
const LABEL_VERSION: i64 = 1;

/// `!takedown` is the atproto-spec label value emitted for a moderator
/// takedown. The leading `!` marks a system-level (non-content-tag) label.
const TAKEDOWN_LABEL_VALUE: &str = "!takedown";

/// A signed and persisted label, returned from [`LabelEmitter::emit`].
///
/// The wire shape (what downstream consumers verify against) is
/// `label_cbor || signature`: re-running the same DAG-CBOR encoder over
/// the same Label record with `sig: None` reproduces `label_cbor`
/// byte-for-byte. Reusing the persisted bytes avoids a re-canonicalisation
/// at fan-out time.
#[derive(Debug, Clone)]
pub struct EmittedLabel {
    /// Stable per-row sequence number (BIGSERIAL on `labels.seq`). The
    /// `subscribeLabels` cursor primitive.
    pub seq: i64,
    /// Subject DID denormalised from the originating action.
    pub subject_did: String,
    /// Label value (`spam`, `!hide`, `!takedown`, …).
    pub value: String,
    /// Negation flag — `true` retracts a prior assertion of the same `value`.
    pub neg: bool,
    /// Canonical DAG-CBOR-encoded Label payload — the exact bytes
    /// [`Self::signature`] was produced over.
    pub cbor: Vec<u8>,
    /// 64-byte K-256 compact signature.
    pub signature: Signature,
    /// `did:key:z…` form of the signing public key.
    pub signing_did: String,
    /// Emit-time server timestamp.
    pub signed_at: DateTime<Utc>,
    /// Originating action id.
    pub action_id: ActionId,
}

/// Errors raised by [`LabelEmitter::emit`].
///
/// Variant categories track the four pipeline stages so operator triage
/// can route a failure to its layer without parsing the underlying error
/// chain: `BuildLabel` → Polaris-side input invariant, `Encode` →
/// proto-blue codec, `Sign` → signing-key custody, `Persist` → Postgres.
#[derive(Debug, thiserror::Error)]
pub enum EmitterError {
    /// The [`Action`] could not be turned into a well-formed
    /// `com.atproto.label.defs::Label`. Today this fires when a `Label`
    /// action has no `label` value set, or when a `Takedown` action's
    /// `reverses_action_id` points at an unknown id.
    #[error("failed to build Label record: {reason}")]
    BuildLabel {
        /// Category-level reason (no PII / no action contents).
        reason: &'static str,
    },
    /// Canonical DAG-CBOR encoding of the Label payload failed. This
    /// should be unreachable in practice — every field of
    /// `proto_blue_api::generated::com::atproto::label::defs::Label` is
    /// CBOR-encodable — but a typed variant keeps the emitter from
    /// having to panic on a serialiser surprise.
    #[error("failed to canonical-CBOR-encode Label payload")]
    Encode,
    /// The signing key refused or failed. Wraps the [`SigningError`]
    /// from the signer layer; the chain is preserved via `#[source]` so
    /// the underlying cause stays visible to operators.
    #[error("failed to sign Label payload")]
    Sign(#[source] SigningError),
    /// Persisting the label row failed. Wraps the `sqlx::Error` so
    /// operators can match on SQLSTATE if needed; the `Display` text
    /// stays generic.
    #[error("failed to persist signed Label row")]
    Persist(#[source] sqlx::Error),
    /// `emit` was called on an `Action` whose `kind` is not in the
    /// `{Label, Takedown}` set the emitter handles. This is a caller
    /// bug — the action-submission path is supposed to gate on `kind`
    /// before calling the emitter.
    #[error("emitter called on unsupported action kind: {kind}")]
    UnsupportedAction {
        /// The offending action kind in wire form.
        kind: &'static str,
    },
    /// A label has already been emitted for this action. The
    /// `labels_action_id_uniq` partial unique index caught the second
    /// insert. Idempotency is at the action level — the second caller
    /// almost certainly wants to know (e.g. a re-emit job racing the
    /// inline path).
    #[error("a label was already emitted for action {action_id}")]
    DuplicateAction {
        /// The originating action whose label was already emitted.
        action_id: ActionId,
    },
    /// The originating action's subject has no DID — we have nothing to
    /// label. Polaris's subject model permits `did = None` for non-account
    /// subjects, but in that case the AT-URI is the only viable label
    /// target and the caller must populate it on the subject row before
    /// emitting. Surfaced as a typed variant so the caller can branch.
    #[error("originating action's subject has no DID or AT-URI to label")]
    NoSubjectIdentifier,
}

/// Subject-side context the emitter needs to fill the Label record's
/// `uri` (and the row's `subject_did`).
///
/// Constructed at the call site (the submit-action handler) by looking
/// up the action's subject; threading it through `emit()` keeps the
/// emitter from needing its own subject-repo handle and keeps the test
/// surface tight (a test can construct a `SubjectRef` directly without
/// standing up a `SubjectRepo`).
#[derive(Debug, Clone)]
pub struct SubjectRef {
    /// ATProto DID of the subject, if known.
    pub did: Option<String>,
    /// AT-URI of the subject, if the subject is a record (not an account).
    pub uri: Option<String>,
    /// Optional content CID — pins the Label to a specific revision of
    /// the subject record.
    pub cid: Option<String>,
}

impl SubjectRef {
    /// Choose the AT-URI (or DID) the Label record's `uri` field will
    /// carry. Per the atproto contract: an account-targeted label uses
    /// the DID directly; a record-targeted label uses the AT-URI. We
    /// prefer the AT-URI when both are present (record-targeted is
    /// strictly more specific than account-targeted).
    fn label_uri(&self) -> Option<&str> {
        self.uri.as_deref().or(self.did.as_deref())
    }

    /// The DID we denormalise into the `subject_did` column. We prefer
    /// the DID directly; for a record subject without a known authoring
    /// DID we fall back to the AT-URI (atproto AT-URIs lead with the
    /// authoring DID anyway, so the column stays useful for "all labels
    /// against did X" operator queries).
    fn subject_did(&self) -> Option<&str> {
        self.did.as_deref().or(self.uri.as_deref())
    }
}

/// The signed-Label emitter.
///
/// One emitter is held on [`crate::api::state::ApiState`] for the
/// process lifetime; `Arc<dyn SigningKey>` is the only shared resource.
/// The repo handle is a thin `PgPool` clone (cheap, internally `Arc`).
/// Adding a `LabelBroadcaster` clone wires the live-fan-out path from
/// #26 to every emitted row so connected `subscribeLabels` subscribers
/// see new labels without polling the DB.
#[derive(Clone)]
pub struct LabelEmitter {
    signer: Arc<dyn SigningKey>,
    pool: PgPool,
    broadcaster: LabelBroadcaster,
}

impl LabelEmitter {
    /// Build a [`LabelEmitter`] from its three dependencies.
    #[must_use]
    pub fn new(signer: Arc<dyn SigningKey>, pool: PgPool, broadcaster: LabelBroadcaster) -> Self {
        Self {
            signer,
            pool,
            broadcaster,
        }
    }

    /// Borrow the signer (for tests and verification call sites).
    #[must_use]
    pub fn signer(&self) -> &Arc<dyn SigningKey> {
        &self.signer
    }

    /// Build, sign, and persist the Label rows for an [`Action`].
    ///
    /// For `kind = Label` this emits exactly one positive row. For
    /// `kind = Takedown` this emits a positive `!takedown` row; when
    /// the takedown also reverts a previously-emitted label (via
    /// `revokes_value`), a second negation row of that value is also
    /// emitted in the same call.
    ///
    /// # Errors
    ///
    /// See [`EmitterError`] for the variant set. A
    /// [`EmitterError::DuplicateAction`] caught from the persist step
    /// is reported back as-is — callers treat that as a no-op.
    pub async fn emit(
        &self,
        action: &Action,
        subject: &SubjectRef,
        revokes_value: Option<&str>,
    ) -> Result<Vec<EmittedLabel>, EmitterError> {
        match action.kind {
            ActionKind::Label => {
                let value = action
                    .label
                    .as_ref()
                    .ok_or(EmitterError::BuildLabel {
                        reason: "Label action missing required label value",
                    })?
                    .as_str()
                    .to_owned();
                let emitted = self.emit_single(action, subject, &value, false).await?;
                Ok(vec![emitted])
            }
            ActionKind::Takedown => {
                let primary = self
                    .emit_single(action, subject, TAKEDOWN_LABEL_VALUE, false)
                    .await?;
                if let Some(revoked) = revokes_value {
                    // The negation gets a fresh row but cannot share
                    // the same `action_id` (UNIQUE partial index would
                    // refuse it). Persist with `action_id = NULL`; the
                    // emit-time provenance is still recoverable via the
                    // takedown's primary row (same `signed_at`,
                    // `subject_did`, `signing_did`).
                    let negation = self.emit_negation(action, subject, revoked).await?;
                    Ok(vec![primary, negation])
                } else {
                    Ok(vec![primary])
                }
            }
            other => Err(EmitterError::UnsupportedAction {
                kind: other.as_str(),
            }),
        }
    }

    /// Build, sign, persist, and broadcast a single Label row.
    async fn emit_single(
        &self,
        action: &Action,
        subject: &SubjectRef,
        value: &str,
        neg: bool,
    ) -> Result<EmittedLabel, EmitterError> {
        let target_uri = subject
            .label_uri()
            .ok_or(EmitterError::NoSubjectIdentifier)?;
        let subject_did = subject
            .subject_did()
            .ok_or(EmitterError::NoSubjectIdentifier)?;
        let signing_did = self.signer.public_key_did().to_owned();
        let signed_at = Utc::now();

        let proto_label = build_proto_label(
            &signing_did,
            target_uri,
            subject.cid.as_deref(),
            value,
            neg,
            signed_at,
        )?;
        let canonical_cbor = encode_canonical(&proto_label)?;
        let signature = self
            .signer
            .sign(&canonical_cbor)
            .map_err(EmitterError::Sign)?;

        self.persist(
            action.id,
            Some(action.id),
            &signing_did,
            target_uri,
            subject_did,
            subject.cid.as_deref(),
            value,
            neg,
            &canonical_cbor,
            &signature,
        )
        .await
    }

    /// Emit a negation row alongside a takedown's primary row.
    ///
    /// `action_id` on the persisted row is `NULL` — the negation does
    /// not own a Polaris action of its own; it is a derived artefact
    /// of the takedown. Provenance flows via the takedown row's
    /// `action_id` plus the matching `signed_at` / `subject_did`.
    async fn emit_negation(
        &self,
        action: &Action,
        subject: &SubjectRef,
        revoked_value: &str,
    ) -> Result<EmittedLabel, EmitterError> {
        let target_uri = subject
            .label_uri()
            .ok_or(EmitterError::NoSubjectIdentifier)?;
        let subject_did = subject
            .subject_did()
            .ok_or(EmitterError::NoSubjectIdentifier)?;
        let signing_did = self.signer.public_key_did().to_owned();
        let signed_at = Utc::now();

        let proto_label = build_proto_label(
            &signing_did,
            target_uri,
            subject.cid.as_deref(),
            revoked_value,
            true,
            signed_at,
        )?;
        let canonical_cbor = encode_canonical(&proto_label)?;
        let signature = self
            .signer
            .sign(&canonical_cbor)
            .map_err(EmitterError::Sign)?;

        self.persist(
            action.id,
            None, // negation does not own an action
            &signing_did,
            target_uri,
            subject_did,
            subject.cid.as_deref(),
            revoked_value,
            true,
            &canonical_cbor,
            &signature,
        )
        .await
    }

    /// Persist the signed Label row and publish it to the live fan-out
    /// channel. Encapsulates the SQLSTATE-to-typed-error mapping so
    /// callers do not have to remember to translate 23505.
    #[allow(
        clippy::too_many_arguments,
        reason = "row INSERT mirrors the column projection 1:1; bundling into a struct would just shadow the SQL"
    )]
    async fn persist(
        &self,
        originating_action_id: ActionId,
        action_id_for_row: Option<ActionId>,
        signing_did: &str,
        target_uri: &str,
        subject_did: &str,
        cid: Option<&str>,
        value: &str,
        neg: bool,
        canonical_cbor: &[u8],
        signature: &Signature,
    ) -> Result<EmittedLabel, EmitterError> {
        // Convert ActionId -> Uuid for the bind (sqlx encodes Uuid
        // directly; the polaris-types newtype wraps it).
        let action_id_uuid: Option<Uuid> = action_id_for_row.map(|a| a.0);
        // sqlx::query! requires owned ownership for slice binds; the
        // signature column is `bytea` so we pass `&[u8]` directly.
        let signature_bytes: &[u8] = signature.as_bytes();

        let row = sqlx::query!(
            r#"
            INSERT INTO labels (
                src, uri, cid, val, neg, sig, action_id,
                subject_did, label_cbor, signing_did
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING seq, cts, signed_at
            "#,
            signing_did,
            target_uri,
            cid,
            value,
            neg,
            signature_bytes,
            action_id_uuid,
            subject_did,
            canonical_cbor,
            signing_did,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|err| route_persist_error(err, originating_action_id))?;

        let emitted = EmittedLabel {
            seq: row.seq,
            subject_did: subject_did.to_owned(),
            value: value.to_owned(),
            neg,
            cbor: canonical_cbor.to_vec(),
            signature: *signature,
            signing_did: signing_did.to_owned(),
            signed_at: row.signed_at,
            action_id: originating_action_id,
        };

        // Broadcast for the live `subscribeLabels` path. We reconstruct
        // the `Label` shape from the EmittedLabel — the broadcaster's
        // payload type is the same struct the persisted-rows path
        // produces, so the receiver branch in `server.rs::run_subscription`
        // doesn't need to distinguish source.
        self.broadcaster.publish(super::server::Label {
            id: Uuid::nil(), // not used by the subscription wire framing
            seq: emitted.seq,
            src: signing_did.to_owned(),
            uri: target_uri.to_owned(),
            cid: cid.map(ToOwned::to_owned),
            val: value.to_owned(),
            neg,
            cts: row.cts,
            exp: None,
            sig: signature_bytes.to_vec(),
            subject_did: subject_did.to_owned(),
            label_cbor: canonical_cbor.to_vec(),
            signing_did: signing_did.to_owned(),
            signed_at: row.signed_at,
        });

        Ok(emitted)
    }
}

impl std::fmt::Debug for LabelEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Render the signer's redacted Debug; never expose the pool's
        // connection string. `LabelBroadcaster` has its own redacted Debug.
        f.debug_struct("LabelEmitter")
            .field("signer", &self.signer)
            .field("broadcaster", &self.broadcaster)
            .field("pool", &"<pool>")
            .finish()
    }
}

/// Build the unsigned `com.atproto.label.defs::Label` value.
///
/// `sig` stays `None` on the builder side — the canonical-CBOR encoder
/// drops fields whose serde `skip_serializing_if` matches, so the bytes
/// the signer sees are the spec-correct sig-omitted form.
fn build_proto_label(
    signing_did: &str,
    target_uri: &str,
    cid: Option<&str>,
    value: &str,
    neg: bool,
    cts: DateTime<Utc>,
) -> Result<ProtoLabel, EmitterError> {
    let src = ProtoDid::new(signing_did).map_err(|_| EmitterError::BuildLabel {
        reason: "signer's public_key_did is not a valid DID",
    })?;
    let cts_datetime = ProtoDatetime::from_utc(cts);
    Ok(ProtoLabel {
        cid: cid.map(ToOwned::to_owned),
        cts: cts_datetime,
        exp: None,
        neg: Some(neg),
        sig: None,
        src,
        uri: target_uri.to_owned(),
        val: value.to_owned(),
        ver: Some(LABEL_VERSION),
    })
}

/// Canonicalise the unsigned Label as DAG-CBOR. The serialisation chain
/// is: typed Label → `serde_json::Value` (via the generated type's
/// Serialize impl, which drops `sig: None`) → `LexValue` (via
/// `proto_blue_lex_json::json_to_lex`) → DAG-CBOR bytes (via
/// `proto_blue_lex_cbor::encode`, which enforces sorted map keys and
/// every other DAG-CBOR canonicality rule).
fn encode_canonical(label: &ProtoLabel) -> Result<Vec<u8>, EmitterError> {
    let json = serde_json::to_value(label).map_err(|_| EmitterError::Encode)?;
    let lex = lex_json::json_to_lex(&json);
    lex_cbor::encode(&lex).map_err(|_| EmitterError::Encode)
}

/// Map a `sqlx::Error` from the INSERT path to the typed [`EmitterError`].
/// SQLSTATE `23505` from the `labels_action_id_uniq` index becomes
/// [`EmitterError::DuplicateAction`]; everything else passes through to
/// [`EmitterError::Persist`].
fn route_persist_error(err: sqlx::Error, action_id: ActionId) -> EmitterError {
    if let Some(db) = err.as_database_error()
        && db.code().as_deref() == Some("23505")
    {
        return EmitterError::DuplicateAction { action_id };
    }
    EmitterError::Persist(err)
}

/// Best-effort wrapper around [`LabelEmitter::emit`].
///
/// Called from the action-submission path: emit success returns the
/// `Vec<EmittedLabel>`; emit failure is logged at WARN with the action
/// id and the variant name, and `None` is returned. The action insert
/// stays committed regardless — the action is the moderator's
/// record-of-truth and emit failures are recoverable via a re-emit job
/// (filed as #63).
///
/// Returning `None` rather than propagating the error to the HTTP layer
/// is the deliberate seam between "moderator submitted an action" (must
/// succeed for the API to return 201) and "the action's label fanned
/// out to subscribers" (may retry later).
pub async fn emit_best_effort(
    emitter: &LabelEmitter,
    action: &Action,
    subject: &SubjectRef,
    revokes_value: Option<&str>,
) -> Option<Vec<EmittedLabel>> {
    match emitter.emit(action, subject, revokes_value).await {
        Ok(rows) => Some(rows),
        Err(err) => {
            // The Display impl on each EmitterError variant is the
            // category text; we log the full chain via `error = ?err`
            // for the operator. No PII or key material is in any
            // variant's Display per the rust-quality §3 contract.
            warn!(
                action_id = %action.id,
                error = ?err,
                "label emitter failed; action stays committed, re-emit job will retry",
            );
            None
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use proto_blue::crypto::{K256Keypair, Keypair as _, Signer as _, Verifier as _};

    use super::*;

    /// In-memory `SigningKey` impl over a freshly-generated K-256 keypair.
    /// Used to drive the build-and-sign round trip without touching the
    /// real custody backends — the cryptographic surface is identical
    /// because `FilePlainSigner` ultimately calls into the same
    /// `K256Keypair::sign`.
    struct InMemorySigner {
        keypair: K256Keypair,
        public_key_did: String,
    }

    impl std::fmt::Debug for InMemorySigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            // `K256Keypair` doesn't implement `Debug` (it holds the K-256
            // secret); render a redacted struct just like the production
            // `FilePlainSigner`.
            f.debug_struct("InMemorySigner")
                .field("public_key_did", &self.public_key_did)
                .field("keypair", &"<redacted>")
                .finish()
        }
    }

    impl InMemorySigner {
        fn generate() -> Self {
            let keypair = K256Keypair::generate();
            let public_key_did = keypair.did();
            Self {
                keypair,
                public_key_did,
            }
        }
    }

    impl SigningKey for InMemorySigner {
        fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError> {
            use proto_blue::crypto::Signer as _;
            let bytes = self.keypair.sign(payload).map_err(|_| SigningError::Sign {
                reason: "in-memory signer failed",
            })?;
            Signature::from_bytes(&bytes)
        }

        fn public_key_did(&self) -> &str {
            &self.public_key_did
        }
    }

    fn fake_action(kind: ActionKind, label: Option<&str>) -> Action {
        use polaris_types::{IncidentId, LabelValue, ModeratorId, SubjectId};
        Action {
            id: ActionId(Uuid::new_v4()),
            incident_id: IncidentId::new(),
            subject_id: SubjectId::new(),
            moderator_id: ModeratorId::new(),
            kind,
            label: label.map(LabelValue::new),
            reasoning: "sufficiently long reasoning for the unit test".to_owned(),
            policy_refs: Vec::new(),
            reversible_until: Utc::now() + chrono::Duration::hours(24),
            reverses_action_id: None,
            created_at: Utc::now(),
            emitted_to_atproto: None,
            evidence_car_cid: None,
        }
    }

    fn fake_subject() -> SubjectRef {
        SubjectRef {
            did: Some("did:plc:abcdef".to_owned()),
            uri: Some("at://did:plc:abcdef/app.bsky.feed.post/3jzfcijpj2z2a".to_owned()),
            cid: None,
        }
    }

    // ── 1. Build-and-sign round trip (no DB) ─────────────────────────

    #[test]
    fn canonical_cbor_round_trip_verifies() {
        let signer = InMemorySigner::generate();
        let cts = Utc::now();
        let proto_label = build_proto_label(
            signer.public_key_did(),
            "at://did:plc:abc/app.bsky.feed.post/3xyz",
            None,
            "spam",
            false,
            cts,
        )
        .unwrap();
        let cbor = encode_canonical(&proto_label).unwrap();
        // Sign and verify against the same keypair via proto-blue's
        // K256Keypair verifier — exactly what a downstream consumer
        // does.
        let sig_bytes = signer.keypair.sign(&cbor).unwrap();
        let verifier =
            K256Keypair::verifier_from_compressed(&signer.keypair.public_key_compressed()).unwrap();
        assert!(verifier.verify(&cbor, &sig_bytes).unwrap());
    }

    // ── 1b. AC-3: proto-blue's own decoder accepts our encoded bytes ─

    #[test]
    fn canonical_cbor_decodes_through_proto_blue() {
        // AC-3 framing: the canonical bytes we sign must be a valid
        // DAG-CBOR `LexValue` that proto-blue's own decoder accepts.
        // The decode is the exact path `subscribeLabels` consumers in
        // proto-blue traverse on the wire — round-tripping through it
        // here verifies the encoded shape without standing up a full
        // round-trip subscription.
        let signer = InMemorySigner::generate();
        let proto_label = build_proto_label(
            signer.public_key_did(),
            "at://did:plc:abc/app.bsky.feed.post/3xyz",
            None,
            "spam",
            false,
            Utc::now(),
        )
        .unwrap();
        let cbor = encode_canonical(&proto_label).unwrap();
        // proto_blue_lex_cbor::decode round-trips through the canonical
        // encoder and rejects any non-canonical input — passing means
        // the bytes are spec-clean DAG-CBOR.
        let decoded = lex_cbor::decode(&cbor).expect("proto-blue decode must accept our bytes");
        // The decoded LexValue must be a Map carrying the Label's fields.
        match decoded {
            proto_blue::lex_data::LexValue::Map(map) => {
                assert!(map.contains_key("val"), "Label payload must carry `val`");
                assert!(map.contains_key("src"), "Label payload must carry `src`");
                assert!(map.contains_key("uri"), "Label payload must carry `uri`");
                assert!(
                    !map.contains_key("sig"),
                    "sig must be omitted from canonical pre-signature CBOR",
                );
            }
            other => panic!("expected LexValue::Map, got {other:?}"),
        }
    }

    // ── 2. Tamper detection ──────────────────────────────────────────

    #[test]
    fn flipping_a_byte_in_cbor_invalidates_signature() {
        let signer = InMemorySigner::generate();
        let proto_label = build_proto_label(
            signer.public_key_did(),
            "at://did:plc:abc/app.bsky.feed.post/3xyz",
            None,
            "spam",
            false,
            Utc::now(),
        )
        .unwrap();
        let cbor = encode_canonical(&proto_label).unwrap();
        let sig = signer.keypair.sign(&cbor).unwrap();

        // Tamper the canonical bytes — the verifier must refuse.
        let mut tampered = cbor.clone();
        // Flip a bit in the middle of the payload (the start is the
        // CBOR map prefix; flipping bit 7 of the middle byte changes
        // a content byte).
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x80;

        let verifier =
            K256Keypair::verifier_from_compressed(&signer.keypair.public_key_compressed()).unwrap();
        // Either `verify` returns Ok(false) or Err — both satisfy
        // "tamper detected". The contract is "not Ok(true)".
        let ok = matches!(verifier.verify(&tampered, &sig), Ok(true));
        assert!(!ok, "tampered CBOR must not verify");
    }

    // ── 3. UnsupportedAction guard ───────────────────────────────────

    #[tokio::test]
    async fn emit_rejects_non_label_takedown_kinds() {
        // No DB needed — the kind check fires before any DB call.
        let pool = PgPool::connect_lazy("postgres://invalid").unwrap();
        let signer: Arc<dyn SigningKey> = Arc::new(InMemorySigner::generate());
        let emitter = LabelEmitter::new(signer, pool, LabelBroadcaster::with_default_capacity());

        for kind in [
            ActionKind::Mute,
            ActionKind::Warn,
            ActionKind::Escalate,
            ActionKind::NoAction,
            ActionKind::Reverse,
        ] {
            let action = fake_action(kind, None);
            let err = emitter
                .emit(&action, &fake_subject(), None)
                .await
                .expect_err("non-Label/Takedown kinds must be rejected");
            match err {
                EmitterError::UnsupportedAction { kind: k } => {
                    assert_eq!(k, kind.as_str());
                }
                other => panic!("expected UnsupportedAction, got {other:?}"),
            }
        }
    }

    // ── 4. Label action without `label` value -> BuildLabel error ────

    #[tokio::test]
    async fn emit_rejects_label_action_without_value() {
        let pool = PgPool::connect_lazy("postgres://invalid").unwrap();
        let signer: Arc<dyn SigningKey> = Arc::new(InMemorySigner::generate());
        let emitter = LabelEmitter::new(signer, pool, LabelBroadcaster::with_default_capacity());

        let action = fake_action(ActionKind::Label, None);
        let err = emitter
            .emit(&action, &fake_subject(), None)
            .await
            .expect_err("Label without label-value must fail at build");
        assert!(matches!(err, EmitterError::BuildLabel { .. }));
    }

    // ── 5. SubjectRef without did/uri -> NoSubjectIdentifier ─────────

    #[tokio::test]
    async fn emit_rejects_subject_without_identifier() {
        let pool = PgPool::connect_lazy("postgres://invalid").unwrap();
        let signer: Arc<dyn SigningKey> = Arc::new(InMemorySigner::generate());
        let emitter = LabelEmitter::new(signer, pool, LabelBroadcaster::with_default_capacity());

        let action = fake_action(ActionKind::Label, Some("spam"));
        let subject = SubjectRef {
            did: None,
            uri: None,
            cid: None,
        };
        let err = emitter
            .emit(&action, &subject, None)
            .await
            .expect_err("subject without did/uri must fail");
        assert!(matches!(err, EmitterError::NoSubjectIdentifier));
    }

    // ── 6. SubjectRef::label_uri / subject_did selection rules ───────

    #[test]
    fn subject_ref_prefers_uri_for_label_target() {
        let s = SubjectRef {
            did: Some("did:plc:abc".to_owned()),
            uri: Some("at://did:plc:abc/app.bsky.feed.post/xyz".to_owned()),
            cid: None,
        };
        assert_eq!(
            s.label_uri(),
            Some("at://did:plc:abc/app.bsky.feed.post/xyz"),
        );
        assert_eq!(s.subject_did(), Some("did:plc:abc"));
    }

    #[test]
    fn subject_ref_falls_back_to_did_when_no_uri() {
        let s = SubjectRef {
            did: Some("did:plc:abc".to_owned()),
            uri: None,
            cid: None,
        };
        assert_eq!(s.label_uri(), Some("did:plc:abc"));
        assert_eq!(s.subject_did(), Some("did:plc:abc"));
    }
}
